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
#
# Intake flow per domain (see config/triage.json for knobs):
#   1. deterministic sampling (triage.should_sample) -> drop or keep
#   2. local triage score (triage.triage_score):
#        score >= pass_threshold -> forward to Kafka with score+reasons
#        score <  pass_threshold -> append to low-priority jsonl spool

import os
import json
import time
import re
import logging
from datetime import datetime, timezone

from websocket import WebSocketApp
from kafka import KafkaProducer
from kafka.errors import KafkaTimeoutError, KafkaError

try:
    from ct.ingest import triage
except ImportError:  # running as a plain script from ct/ingest/
    import triage

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

TRIAGE_CFG = triage.load_config()
TRIAGE_PASS_THRESHOLD = float(TRIAGE_CFG["triage"]["pass_threshold"])

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

# ---------- Kafka producer ----------

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    key_serializer=lambda v: v.encode("utf-8"),
    linger_ms=50,
    acks="all",
    retries=5,
    request_timeout_ms=30000,
)

# how many messages we’ve queued since last flush
_sent_since_flush = 0

# ---------- intake metrics ----------

_counters = {
    "ingested": 0,        # domains seen after cleaning/regex
    "sampled_out": 0,     # dropped by deterministic sampling
    "triage_passed": 0,   # score >= threshold, forwarded to Kafka
    "triage_deferred": 0, # score <  threshold, spooled to low-priority
}
_last_metrics_log = time.monotonic()


def _maybe_log_metrics():
    global _last_metrics_log
    now = time.monotonic()
    if now - _last_metrics_log >= METRICS_LOG_EVERY_SEC:
        log.info(
            "intake counters: ingested=%d sampled_out=%d triage_passed=%d triage_deferred=%d",
            _counters["ingested"],
            _counters["sampled_out"],
            _counters["triage_passed"],
            _counters["triage_deferred"],
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
    if _sent_since_flush <= 0:
        return
    try:
        producer.flush(timeout=FLUSH_TIMEOUT_SEC)
        _sent_since_flush = 0
    except KafkaTimeoutError as e:
        # This usually means broker is slow or unreachable; producer will keep retrying.
        log.warning("Kafka flush timeout after %.1fs (will retry later): %r", FLUSH_TIMEOUT_SEC, e)


def on_message(_ws, msg: str):
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

            # deterministic sampling (brand/suspicious-TLD hits bypass it)
            if not triage.should_sample(d, TRIAGE_CFG):
                _counters["sampled_out"] += 1
                continue

            # cheap local triage before anything hits downstream enrichment
            score, reasons = triage.triage_score(d, TRIAGE_CFG)
            event = evt(d, i)
            event["triage_score"] = round(score, 4)
            event["triage_reasons"] = reasons

            if score < TRIAGE_PASS_THRESHOLD:
                _counters["triage_deferred"] += 1
                _spool_low_priority(event)
                continue

            _counters["triage_passed"] += 1

            # enqueue event to Kafka (async)
            producer.send(TOPIC, key=d, value=event)
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


# ---------- main loop ----------

if __name__ == "__main__":
    try:
        while True:
            try:
                ws = WebSocketApp(
                    WS_URL,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close,
                )
                ws.on_open = on_open
                ws.run_forever(ping_interval=30, ping_timeout=20)
            except KeyboardInterrupt:
                log.info("KeyboardInterrupt, shutting down...")
                break
            except Exception as e:
                log.error("[ct] websocket crashed, retrying in 5s: %r", e)
                time.sleep(5)
    finally:
        try:
            _maybe_flush()
        finally:
            producer.close()
            log.info("Kafka producer closed")
