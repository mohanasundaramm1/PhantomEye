import importlib
import json
import sys

import pytest


@pytest.fixture
def fw(tmp_path, monkeypatch):
    """The real forwarder module, with Kafka stubbed and the spool in tmp_path
    (importing it normally would connect a KafkaProducer and write into the
    real low-priority spool)."""
    import kafka

    class Producer:
        sent = []

        def __init__(self, *a, **k):
            pass

        def send(self, topic, key=None, value=None, **k):
            Producer.sent.append((key, value))

        def flush(self, *a, **k):
            pass

    Producer.sent = []
    monkeypatch.setattr(kafka, "KafkaProducer", Producer)
    monkeypatch.setenv("CT_LOW_PRIORITY_DIR", str(tmp_path))
    sys.modules.pop("ct.ingest.forwarder", None)
    mod = importlib.import_module("ct.ingest.forwarder")
    mod.Producer = Producer
    yield mod
    sys.modules.pop("ct.ingest.forwarder", None)


def _cert_msg(*domains):
    return json.dumps({"data": {"leaf_cert": {"all_domains": list(domains)}}})


def test_str_and_bytes_messages_are_handled_identically(fw, tmp_path):
    msg = _cert_msg("secure-paypal-login.tk", "example.com", "www.example.org")
    fw.on_message(None, msg)
    after_str = (dict(fw._counters), len(fw.Producer.sent))
    for k in fw._counters:
        fw._counters[k] = 0
    fw.Producer.sent.clear()
    fw.on_message(None, msg.encode("utf-8"))        # what skip_utf8_validation=True delivers
    assert (dict(fw._counters), len(fw.Producer.sent)) == after_str
    assert fw._counters["ingested"] == 3


def test_malformed_bytes_are_logged_and_skipped_not_fatal(fw):
    # with UTF-8 validation off, a bad frame must not take down the connection:
    # on_message has to swallow it.
    fw.on_message(None, b"\xff\xfe\x00 not json at all")
    fw.on_message(None, b'{"data": {"leaf_cert": {"all_domains": ["ok.example.com"]}}}'.replace(b"ok", b"\xff\xfe"))
    assert fw._counters["ingested"] == 0
    fw.on_message(None, _cert_msg("still-works.example.com").encode())   # and it keeps processing
    assert fw._counters["ingested"] == 1


def test_high_scoring_domain_is_forwarded_to_kafka(fw):
    fw.on_message(None, _cert_msg("secure-paypal-login-verify.tk").encode())
    assert [k for k, _ in fw.Producer.sent] == ["secure-paypal-login-verify.tk"]


# ---------------------------------------------------------------------------
# R-02: Kafka being down must not crash the forwarder or lose events.
# CertStream has no replay, so undeliverable events go to a durable outbox and
# are replayed when Kafka returns.
# ---------------------------------------------------------------------------

@pytest.fixture
def fwc(tmp_path, monkeypatch):
    """The forwarder with a controllable fake Kafka: Producer.available (broker
    reachable at connect time) and Producer.mode ('ok' | 'raise' | 'errback')."""
    import kafka
    from kafka.errors import KafkaTimeoutError, NoBrokersAvailable

    class Producer:
        available = True
        mode = "ok"
        sent = []

        def __init__(self, *a, **k):
            if not Producer.available:
                raise NoBrokersAvailable()

        def send(self, topic, key=None, value=None, **k):
            if Producer.mode == "raise":
                raise KafkaTimeoutError("metadata update timed out")
            if Producer.mode == "errback":
                class _Failed:
                    def add_errback(self, cb):
                        cb(RuntimeError("delivery failed after retries"))
                return _Failed()
            Producer.sent.append((key, value))
            return None

        def flush(self, *a, **k):
            pass

        def close(self, *a, **k):
            pass

    Producer.available, Producer.mode, Producer.sent = True, "ok", []
    monkeypatch.setattr(kafka, "KafkaProducer", Producer)
    monkeypatch.setenv("CT_LOW_PRIORITY_DIR", str(tmp_path / "spool"))
    monkeypatch.setenv("CT_OUTBOX_DIR", str(tmp_path / "outbox"))
    monkeypatch.setenv("CT_PRODUCER_RETRY_SEC", "0")
    monkeypatch.setenv("CT_OUTBOX_REPLAY_EVERY_SEC", "0")

    def load():
        sys.modules.pop("ct.ingest.forwarder", None)
        mod = importlib.import_module("ct.ingest.forwarder")
        mod.Producer = Producer
        return mod

    Producer.load = staticmethod(load)
    yield Producer
    sys.modules.pop("ct.ingest.forwarder", None)


def test_import_survives_kafka_being_down(fwc):
    fwc.available = False
    fw = fwc.load()                       # used to raise NoBrokersAvailable at import
    assert fw._producer is None


def test_events_are_kept_in_the_outbox_while_kafka_is_down(fwc):
    fwc.available = False
    fw = fwc.load()
    fw.on_message(None, _cert_msg("secure-paypal-login.tk", "example.com", "www.example.org"))
    assert fw._counters["triage_passed"] >= 1
    assert fwc.sent == []                                            # nothing reached Kafka
    assert fw._outbox.pending_count() == fw._counters["triage_passed"]   # every forwardable event is on disk


def test_outbox_is_replayed_when_kafka_returns(fwc):
    fwc.available = False
    fw = fwc.load()
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    n = fw._outbox.pending_count()
    assert n >= 1

    fwc.available = True                                             # broker is back
    fw.replay_outbox(force=True)

    assert len(fwc.sent) == n
    assert {v["domain"] for _, v in fwc.sent} == {"secure-paypal-login.tk"}
    assert fw._outbox.pending_count() == 0


def test_a_send_that_raises_goes_to_the_outbox(fwc):
    fw = fwc.load()
    fwc.mode = "raise"                                               # connected, but sends time out
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    assert fw._outbox.pending_count() == fw._counters["triage_passed"] >= 1


def test_a_delivery_failure_callback_goes_to_the_outbox(fwc):
    fw = fwc.load()
    fwc.mode = "errback"                                             # kafka reports the delivery failed later
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    assert fw._outbox.pending_count() == fw._counters["triage_passed"] >= 1


def test_healthy_path_does_not_use_the_outbox(fwc):
    fw = fwc.load()
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    assert len(fwc.sent) == fw._counters["triage_passed"] >= 1
    assert fw._outbox.pending_count() == 0


def test_sigterm_handler_exits_so_the_finally_block_flushes(fwc):
    fw = fwc.load()
    with pytest.raises(SystemExit):
        fw._on_sigterm(15, None)


def test_after_a_send_failure_later_events_skip_kafka_instead_of_blocking(fwc):
    """A connected producer whose broker died blocks every send() for max_block_ms.
    On the first failure the producer is marked broken; later events must go
    straight to the outbox without calling send() again (the websocket thread
    cannot afford to stall: CertStream skips what we don't read)."""
    fw = fwc.load()
    fwc.mode = "raise"
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    assert fw._producer is None                                      # marked broken

    fwc.mode = "ok"
    fwc.available = False                                            # broker still down
    before = len(fwc.sent)
    fw.on_message(None, _cert_msg("login-secure-paypal.tk"))
    assert len(fwc.sent) == before                                   # send() was not even attempted
    assert fw._outbox.pending_count() >= 2


def test_maintenance_tick_reconnects_and_replays(fwc):
    fwc.available = False
    fw = fwc.load()
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    n = fw._outbox.pending_count()
    assert n >= 1 and fw._producer is None

    fwc.available = True
    fw._maintenance_tick()                                           # what the background thread runs

    assert fw._producer is not None
    assert len(fwc.sent) == n and fw._outbox.pending_count() == 0


def test_on_message_never_tries_to_connect(fwc):
    """Connecting can block for seconds when the broker is down; only the
    background tick (and startup) may do it."""
    fwc.available = False
    fw = fwc.load()
    fwc.available = True                      # broker is back, but nobody has run the tick yet
    fw.on_message(None, _cert_msg("secure-paypal-login.tk"))
    assert fw._producer is None               # on_message did not reconnect
    assert fw._outbox.pending_count() >= 1    # it just buffered
