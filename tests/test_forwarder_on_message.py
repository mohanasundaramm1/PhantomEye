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
