# ct/forwarder.py
#
# Read certstream events from a websocket and forward domains into Kafka.
#
# Env vars:
#   KAFKA_BOOTSTRAP_SERVERS   (default "localhost:29092")
#   KAFKA_TOPIC               (default "ct-events")
#   CERTSTREAM_WS             (default "ws://127.0.0.1:4000")
#   SAMPLE_EVERY_N            (default "1" -> no sampling; legacy modulo sampler)
#   FLUSH_EVERY               (default "500" messages between flushes)
#   FLUSH_TIMEOUT_SEC         (default "5.0" seconds)
#   CT_TRIAGE_CONFIG          (override path to config/triage.json)
#   CT_LOW_PRIORITY_DIR       (override low-priority spool directory)
#   CT_METRICS_LOG_EVERY_SEC  (default "30" seconds between counter log lines)
#   CT_OUTBOX_DIR             (default ct/data/outbox; durable copy of events Kafka could not take)
#   CT_OUTBOX_MAX_AGE_DAYS    (default "7")
#   CT_OUTBOX_REPLAY_EVERY_SEC (default "5" seconds between outbox replay attempts)
#   CT_PRODUCER_RETRY_SEC     (default "5" seconds between Kafka reconnect attempts)
#
# Delivery: events are sent to Kafka with an idempotent, acks=all producer. If Kafka
# is unreachable (at startup or later) or a send fails, the event is appended to the
# local outbox instead of being dropped -- CertStream has no replay, so this is the
# only copy -- and replayed oldest-first once Kafka is back. SIGTERM flushes and exits.
#
# Intake flow per domain (triage.route_domain; see config/triage.json):
#   score >= pass_threshold            -> forward to Kafka with score+reasons
#   score <  pass_threshold, sampled   -> append to low-priority jsonl spool
#   score <  pass_threshold, unsampled -> drop
# Scoring runs before sampling so a high scorer is never sampled away.

import os
import json
import time
import re
import signal
import threading
import logging
from datetime import datetime, timezone

from websocket import WebSocketApp
from kafka import KafkaProducer
from kafka.errors import KafkaTimeoutError, KafkaError, NoBrokersAvailable

try:
    from ct.ingest import backoff, triage, outbox
except ImportError:  # running as a plain script from ct/ingest/
    import backoff
    import triage
    import outbox

# ---------- config ----------

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "ct-events")
WS_URL = os.getenv("CERTSTREAM_WS", "ws://127.0.0.1:4000")
SAMPLE_EVERY_N = int(os.getenv("SAMPLE_EVERY_N", "1"))  # 1 = no sampling

FLUSH_EVERY = int(os.getenv("FLUSH_EVERY", "500"))
FLUSH_TIMEOUT_SEC = float(os.getenv("FLUSH_TIMEOUT_SEC", "5.0"))

THIS_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "data"))
LOW_PRIORITY_DIR = os.getenv("CT_LOW_PRIORITY_DIR", os.path.join(DATA_DIR, "low_priority"))
os.makedirs(LOW_PRIORITY_DIR, exist_ok=True)

METRICS_LOG_EVERY_SEC = float(os.getenv("CT_METRICS_LOG_EVERY_SEC", "30"))

OUTBOX_DIR = os.getenv("CT_OUTBOX_DIR", os.path.join(DATA_DIR, "outbox"))
OUTBOX_MAX_AGE_DAYS = float(os.getenv("CT_OUTBOX_MAX_AGE_DAYS", "7"))
OUTBOX_REPLAY_EVERY_SEC = float(os.getenv("CT_OUTBOX_REPLAY_EVERY_SEC", "5"))
PRODUCER_RETRY_SEC = float(os.getenv("CT_PRODUCER_RETRY_SEC", "5"))

TRIAGE_CFG = triage.load_config()

logging.basicConfig(
    level=logging.INFO,
    format="[ct-forwarder] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ct-forwarder")

log.info(
    "starting forwarder: ws=%s  kafka=%s  topic=%s  SAMPLE_EVERY_N=%d  FLUSH_EVERY=%d",
    WS_URL,
    BOOTSTRAP,
    TOPIC,
    SAMPLE_EVERY_N,
    FLUSH_EVERY,
)

# ---------- Kafka producer (created lazily; never at import) ----------
#
# Creating KafkaProducer at import time meant a down broker crashed the process
# (NoBrokersAvailable) before any retry logic existed, so launchd respawned it every
# 10 s while CertStream kept emitting certificates nobody recorded.

_outbox = outbox.Outbox(OUTBOX_DIR)
_producer = None
_producer_next_try = 0.0
_producer_lock = threading.Lock()
_stop = threading.Event()


def _get_producer():
    """The shared producer, connecting if needed. May BLOCK for a couple of seconds
    when the broker is down, so only startup and the background tick call it, never
    the websocket callback. Failed attempts are retried every PRODUCER_RETRY_SEC."""
    global _producer, _producer_next_try
    with _producer_lock:
        if _producer is not None:
            return _producer
        now = time.monotonic()
        if now < _producer_next_try:
            return None
        try:
            _producer = KafkaProducer(
                bootstrap_servers=BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda v: v.encode("utf-8"),
                linger_ms=50,
                acks="all",
                enable_idempotence=True,    # retries can no longer duplicate or reorder within a partition
                retries=5,
                request_timeout_ms=30000,
                max_block_ms=2000,          # bound how long one send() can stall
            )
            log.info("connected to Kafka at %s", BOOTSTRAP)
        except (NoBrokersAvailable, KafkaError) as e:
            _producer_next_try = now + PRODUCER_RETRY_SEC
            log.warning("Kafka unavailable at %s (%r); buffering to the outbox, retry in %.0fs",
                        BOOTSTRAP, e, PRODUCER_RETRY_SEC)
            return None
        return _producer


def _mark_producer_broken(p):
    """Drop a producer that just failed so later events go straight to the outbox
    (no more blocking send() calls) until the background tick reconnects."""
    global _producer, _producer_next_try
    with _producer_lock:
        if _producer is p:
            _producer = None
            _producer_next_try = time.monotonic() + PRODUCER_RETRY_SEC
    try:
        p.close(timeout=0)      # buffered records fail fast and reach the outbox via their errbacks
    except Exception:  # noqa: BLE001
        pass


def _to_outbox(event: dict, reason=None):
    _outbox.append(event)
    _counters["outbox_appended"] += 1
    if reason is not None:
        log.warning("delivery failed (%r); event %s kept in the outbox", reason, event.get("id"))


def _deliver(key: str, event: dict):
    """Send one event to Kafka without ever blocking on a connect; anything that can't
    be delivered is persisted to the outbox (CertStream cannot replay it)."""
    p = _producer
    if p is None:
        _to_outbox(event)
        return False
    try:
        fut = p.send(TOPIC, key=key, value=event)
    except KafkaError as e:                    # includes KafkaTimeoutError (metadata/buffer stall)
        _to_outbox(event, e)
        _mark_producer_broken(p)
        return False
    if fut is not None and hasattr(fut, "add_errback"):
        def _failed(exc, ev=event, prod=p):    # delivery failed AFTER retries were exhausted
            _to_outbox(ev, exc)
            _mark_producer_broken(prod)
        fut.add_errback(_failed)
    return True


def replay_outbox(force: bool = False):
    """Reconnect if needed, then replay buffered events oldest-first."""
    p = _get_producer()
    if p is None or not _outbox.has_pending():
        return None
    failures = []

    def _send(ev):
        fut = p.send(TOPIC, key=ev["domain"], value=ev)
        if fut is not None and hasattr(fut, "add_errback"):
            fut.add_errback(lambda exc: failures.append(exc))

    def _flush():
        try:
            p.flush(timeout=FLUSH_TIMEOUT_SEC * 3)
        except KafkaError:
            return False
        return not failures

    result = _outbox.replay(_send, _flush)
    if result["replayed"]:
        _counters["outbox_replayed"] += result["replayed"]
        log.info("outbox replay: %d event(s) delivered, %d file(s) kept", result["replayed"], result["failed_files"])
    if result["failed_files"]:
        _mark_producer_broken(p)
    return result


def _maintenance_tick():
    """One pass of background upkeep: reconnect to Kafka and drain the outbox."""
    try:
        replay_outbox()
    except Exception:  # noqa: BLE001  upkeep must never take the forwarder down
        log.exception("outbox maintenance failed")


def _maintenance_loop():
    while not _stop.is_set():
        _maintenance_tick()
        _stop.wait(OUTBOX_REPLAY_EVERY_SEC)


# One synchronous attempt at startup so a healthy start sends immediately. It can
# only log a warning on failure; it can no longer crash the process.
_get_producer()


# how many messages we’ve queued since last flush
_sent_since_flush = 0

# ---------- intake metrics ----------

_counters = {
    "ingested": 0,        # domains seen after cleaning/regex
    "sampled_out": 0,     # dropped by deterministic sampling
    "triage_passed": 0,   # score >= threshold, forwarded to Kafka
    "triage_deferred": 0, # score <  threshold, spooled to low-priority
    "outbox_appended": 0, # could not be delivered to Kafka now; kept on disk
    "outbox_replayed": 0, # delivered from the outbox after Kafka returned
}
_last_metrics_log = time.monotonic()


def _maybe_log_metrics():
    global _last_metrics_log
    now = time.monotonic()
    if now - _last_metrics_log >= METRICS_LOG_EVERY_SEC:
        log.info(
            "intake counters: ingested=%d sampled_out=%d triage_passed=%d triage_deferred=%d "
            "outbox_appended=%d outbox_replayed=%d",
            _counters["ingested"],
            _counters["sampled_out"],
            _counters["triage_passed"],
            _counters["triage_deferred"],
            _counters["outbox_appended"],
            _counters["outbox_replayed"],
        )
        _last_metrics_log = now


def _spool_low_priority(event: dict):
    """Append a below-threshold event to the day's low-priority jsonl spool."""
    ds = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(LOW_PRIORITY_DIR, f"ds={ds}.jsonl")
    try:
        with open(path, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        log.error("failed to spool low-priority event: %r", e)

domain_re = re.compile(r"^[A-Za-z0-9\-\._*]+$")


def clean_domain(d: str) -> str:
    if not isinstance(d, str):
        return ""
    d = d.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def evt(domain: str, offset: int = 0):
    # RFC3339 UTC with 'Z' so Spark can parse easily
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": f"ct-{int(time.time() * 1000)}-{offset}",
        "domain": domain,
        "tld": domain.split(".")[-1] if "." in domain else None,
        "event_ts": now,
        "producer_ts": now,
        "source": "certstream",
    }


def _maybe_flush():
    """Flush producer occasionally; don't scream on soft timeouts."""
    global _sent_since_flush
    p = _producer
    if _sent_since_flush <= 0 or p is None:
        return
    try:
        p.flush(timeout=FLUSH_TIMEOUT_SEC)
        _sent_since_flush = 0
    except KafkaTimeoutError as e:
        # This usually means broker is slow or unreachable; producer will keep retrying.
        log.warning("Kafka flush timeout after %.1fs (will retry later): %r", FLUSH_TIMEOUT_SEC, e)


def on_message(_ws, msg):  # str or bytes (see skip_utf8_validation in the main loop)
    global _sent_since_flush
    try:
        data = json.loads(msg)
        leaf = (data.get("data") or {}).get("leaf_cert") or {}
        doms = leaf.get("all_domains") or []
        if not doms:
            return

        batch_sent = 0
        for i, raw in enumerate(doms):
            if (i % SAMPLE_EVERY_N) != 0:
                continue
            d = clean_domain(raw)
            if not d or not domain_re.match(d):
                continue

            _counters["ingested"] += 1

            # cheap local triage first, then sampling for low scorers only
            decision, score, reasons = triage.route_domain(d, TRIAGE_CFG)
            if decision == triage.DROP:
                _counters["sampled_out"] += 1
                continue

            event = evt(d, i)
            event["triage_score"] = round(score, 4)
            event["triage_reasons"] = reasons

            if decision == triage.SPOOL:
                _counters["triage_deferred"] += 1
                _spool_low_priority(event)
                continue

            _counters["triage_passed"] += 1

            # enqueue event to Kafka (async); undeliverable events go to the outbox
            _deliver(d, event)
            batch_sent += 1
            _sent_since_flush += 1

            # flush every FLUSH_EVERY messages
            if _sent_since_flush >= FLUSH_EVERY:
                _maybe_flush()

        if batch_sent:
            log.debug("sent %d domains from one CT message", batch_sent)
        _maybe_log_metrics()

    except KafkaError as e:
        # Real Kafka error (broker down, auth, etc.)
        log.error("Kafka error while sending; messages may be dropped: %r", e)
    except Exception as e:
        # JSON parse or other unexpected error
        log.error("parse/send error: %r", e)


def on_open(_ws):
    log.info("[ct] ws %s → kafka %s topic %s", WS_URL, BOOTSTRAP, TOPIC)


def on_error(_ws, e):
    log.error("[ct] ws error: %r", e)


def on_close(*_):
    log.warning("[ct] ws closed")


def _on_sigterm(_signum, _frame):
    """launchd stops the job with SIGTERM. Python's default is to die at once, which
    skips the `finally:` below and drops whatever the producer still buffers. Raising
    SystemExit unwinds through that finally (flush + close) instead."""
    log.info("SIGTERM received, shutting down (flush + close)")
    raise SystemExit(0)


# ---------- main loop ----------

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _on_sigterm)
    _outbox.prune(OUTBOX_MAX_AGE_DAYS)
    if _outbox.has_pending():
        log.warning("outbox has %d event(s) from a previous run; will replay when Kafka is reachable",
                    _outbox.pending_count())
    threading.Thread(target=_maintenance_loop, name="outbox-maintenance", daemon=True).start()
    try:
        delay = 0.0
        while True:
            started = time.monotonic()
            try:
                ws = WebSocketApp(
                    WS_URL,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close,
                )
                ws.on_open = on_open
                # skip_utf8_validation: without the optional `wsaccel` C extension,
                # websocket-client validates every text frame's UTF-8 in pure
                # Python (_validate_utf8 + _decode). Profiled live: that was ~67%
                # of this process's CPU -- more than triage, JSON and Kafka
                # combined -- which is what made the forwarder fall behind and
                # CertStream skip ~1,000+ certs/s. on_message receives raw bytes
                # when this is set; json.loads() decodes them in C (and a
                # malformed message just raises inside on_message, which already
                # logs and carries on).
                ws.run_forever(ping_interval=30, ping_timeout=20, skip_utf8_validation=True)
            except KeyboardInterrupt:
                log.info("KeyboardInterrupt, shutting down...")
                break
            except Exception as e:
                log.error("[ct] websocket crashed: %r", e)
            # run_forever() returns (it does not raise) when the connection is
            # refused or drops, so this must pace EVERY pass -- sleeping only in
            # the except branch left a down CertStream being retried ~850x/sec.
            # See ct/ingest/backoff.py.
            ran_for = time.monotonic() - started
            delay = backoff.next_delay(delay, ran_for)
            if delay > 0:
                log.warning("[ct] connection lasted %.1fs; reconnecting in %.0fs", ran_for, delay)
                time.sleep(delay)
    finally:
        _stop.set()
        try:
            _maybe_flush()
        finally:
            if _producer is not None:
                _producer.close(timeout=5)
            log.info("Kafka producer closed (outbox pending: %d)", _outbox.pending_count())
