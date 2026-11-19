"""Feed download policy (R-03): permanent HTTP errors must fail at once instead of
being retried, and an Auth-Key must never appear in an error message."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "airflow", "dags"))
from feed_fetch import (PermanentFeedError, TransientFeedError, fetch_feed,  # noqa: E402
                        redact, urlhaus_feed_url)


class Resp:
    def __init__(self, status, text="x" * 2000):
        self.status_code, self.text = status, text

    @property
    def ok(self):
        return self.status_code < 400


class Session:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), 0

    def get(self, url, **kw):
        self.calls += 1
        r = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        if isinstance(r, Exception):
            raise r
        return r


NOSLEEP = lambda s: None  # noqa: E731


def test_a_410_fails_immediately_without_retrying():
    s = Session(Resp(410, "Gone"))
    with pytest.raises(PermanentFeedError):
        fetch_feed(s, "https://feed.example/x.csv", min_len=100, sleep=NOSLEEP)
    assert s.calls == 1                       # the old code made 3 attempts per task try (about 27 requests a day)


@pytest.mark.parametrize("status", [401, 403, 404, 410])
def test_every_permanent_status_is_permanent(status):
    with pytest.raises(PermanentFeedError):
        fetch_feed(Session(Resp(status)), "https://feed.example/x", min_len=1, sleep=NOSLEEP)


def test_a_5xx_is_retried_then_reported_as_transient():
    s = Session(Resp(503), Resp(503), Resp(503))
    with pytest.raises(TransientFeedError):
        fetch_feed(s, "https://feed.example/x", min_len=1, tries=3, sleep=NOSLEEP)
    assert s.calls == 3


def test_a_transient_error_then_success_returns_the_response():
    s = Session(Resp(502), Resp(200, "ok" * 500))
    assert fetch_feed(s, "https://feed.example/x", min_len=100, sleep=NOSLEEP).status_code == 200


def test_network_exceptions_are_transient_and_redacted():
    key = "SECRETKEY123"
    s = Session(ConnectionError(f"failed to reach https://h/{key}/recent.csv"))
    with pytest.raises(TransientFeedError) as e:
        fetch_feed(s, f"https://h/{key}/recent.csv", min_len=1, tries=1, sleep=NOSLEEP, secrets=(key,))
    assert key not in str(e.value) and "***" in str(e.value)


def test_a_too_short_body_is_transient():
    with pytest.raises(TransientFeedError):
        fetch_feed(Session(Resp(200, "tiny")), "https://feed.example/x", min_len=1000, tries=1, sleep=NOSLEEP)


def test_redact_masks_every_secret_and_ignores_empty_ones():
    assert redact("a/KEY1/b KEY2", ("KEY1", "KEY2", "", None)) == "a/***/b ***"


def test_urlhaus_without_a_key_fails_permanently_with_instructions():
    with pytest.raises(PermanentFeedError) as e:
        urlhaus_feed_url({})
    assert "URLHAUS_AUTH_KEY" in str(e.value) and "auth.abuse.ch" in str(e.value)


def test_urlhaus_key_is_placed_in_the_url_path_and_reported_as_a_secret():
    url, secrets = urlhaus_feed_url({"URLHAUS_AUTH_KEY": "abc123"})
    assert url == "https://urlhaus-api.abuse.ch/v2/files/exports/abc123/recent.csv" and secrets == ("abc123",)


def test_urlhaus_explicit_url_overrides_and_supports_a_key_placeholder():
    url, secrets = urlhaus_feed_url({"URLHAUS_FEED_URL": "https://mirror.example/{key}/all.csv", "URLHAUS_AUTH_KEY": "k"})
    assert url == "https://mirror.example/k/all.csv" and secrets == ("k",)


# ---- host extraction (found with the real URLhaus feed: ftp:// URLs became the host "ftp") ----
from feed_fetch import host_from_url  # noqa: E402


@pytest.mark.parametrize("url,host", [
    ("ftp://45.90.163.37/jklarm5", "45.90.163.37"),            # was "ftp"
    ("http://115.48.146.158:46145/i", "115.48.146.158"),
    ("https://Example.COM/x?y=1", "example.com"),
    ("example.com/path", "example.com"),                       # no scheme at all
    ("ftp://user:pw@host.example:21/f", "host.example"),
    ("sftp://files.example/x", "files.example"),
])
def test_host_from_url_handles_any_scheme(url, host):
    assert host_from_url(url) == host


def test_host_from_url_returns_none_for_junk():
    assert host_from_url("") is None
