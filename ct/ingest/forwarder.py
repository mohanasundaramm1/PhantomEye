# ct/forwarder.py
#
# Read certstream events from a websocket and forward domains into Kafka.
#
# Env vars:
#   KAFKA_BOOTSTRAP_SERVERS   (default "localhost:29092")
#   KAFKA_TOPIC               (default "ct-events")
#   CERTSTREAM_WS             (default "ws://127.0.0.1:4000")
#   SAMPLE_EVERY_N            (default "1" -> no sampling)
#   FLUSH_EVERY               (default "500" messages between flushes)
#   FLUSH_TIMEOUT_SEC         (default "5.0" seconds)

import os
import json
import time
import re
import logging
from datetime import datetime, timezone

from websocket import WebSocketApp
from kafka import KafkaProducer
from kafka.errors import KafkaTimeoutError, KafkaError

# ---------- config ----------

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "ct-events")
WS_URL = os.getenv("CERTSTREAM_WS", "ws://127.0.0.1:4000")
SAMPLE_EVERY_N = int(os.getenv("SAMPLE_EVERY_N", "1"))  # 1 = no sampling

FLUSH_EVERY = int(os.getenv("FLUSH_EVERY", "500"))
FLUSH_TIMEOUT_SEC = float(os.getenv("FLUSH_TIMEOUT_SEC", "5.0"))

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

            # enqueue event to Kafka (async)
            producer.send(TOPIC, key=d, value=evt(d, i))
            batch_sent += 1
            _sent_since_flush += 1

            # flush every FLUSH_EVERY messages
            if _sent_since_flush >= FLUSH_EVERY:
                _maybe_flush()

        if batch_sent:
            log.debug("sent %d domains from one CT message", batch_sent)

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
