# airflow/dags/feed_fetch.py
"""Download policy for the OSINT feeds (no Airflow imports, so it is unit-testable).

Why: urlhaus_ingest retried a permanent "410 Gone" 3x per task try, times the child
DAG's retries, times the orchestrator's retries (about 27 requests a day to a dead
endpoint), for weeks. A permanent HTTP error will not heal by retrying, so it must
fail at once with a clear message; only transient problems (network errors, 5xx,
truncated bodies) are retried.

Secrets: abuse.ch now requires an Auth-Key *inside the URL*. Any message that may
contain the URL goes through redact() first.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse

PERMANENT_STATUSES = frozenset({401, 403, 404, 410})


class PermanentFeedError(RuntimeError):
    """Retrying cannot help (gone, forbidden, missing key). Fail the task without retries."""


class TransientFeedError(RuntimeError):
    """Worth retrying (network error, 5xx, truncated body)."""


def redact(text: str, secrets=()) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def fetch_feed(session, url: str, *, min_len: int, tries: int = 3, sleep=time.sleep,
               timeout=(5, 45), headers=None, secrets=()):
    """GET a feed. Returns the response, or raises PermanentFeedError / TransientFeedError."""
    safe_url = redact(url, secrets)
    last: Exception | None = None
    for attempt in range(tries):
        try:
            r = session.get(url, timeout=timeout, headers=headers)
        except Exception as e:  # noqa: BLE001  network errors are transient
            last = TransientFeedError(redact(f"{type(e).__name__}: {e}", secrets))
            sleep(2)
            continue
        if r.status_code in PERMANENT_STATUSES:
            raise PermanentFeedError(
                f"HTTP {r.status_code} from {safe_url}: the feed is gone or requires credentials; "
                f"retrying cannot fix this"
            )
        if r.ok and len(r.text) >= min_len:
            return r
        last = TransientFeedError(f"Bad response (status={r.status_code}, len={len(r.text)}) from {safe_url}")
        if attempt < tries - 1:
            sleep(2)
    raise last if last else TransientFeedError(f"feed fetch failed: {safe_url}")


def urlhaus_feed_url(environ) -> tuple[str, tuple]:
    """(url, secrets) for the URLhaus CSV. The old public csv_online URL returns 410
    permanently; abuse.ch now requires a free Auth-Key placed in the URL path.

    URLHAUS_FEED_URL  optional full URL; "{key}" is replaced by the Auth-Key.
    URLHAUS_AUTH_KEY  free key from https://auth.abuse.ch/ (required).
    """
    key = (environ.get("URLHAUS_AUTH_KEY") or "").strip()
    explicit = (environ.get("URLHAUS_FEED_URL") or "").strip()
    if not key:
        raise PermanentFeedError(
            "URLhaus now requires an Auth-Key (the old public download URL returns 410 Gone). "
            "Create a free account at https://auth.abuse.ch/ and set URLHAUS_AUTH_KEY in .env."
        )
    if explicit:
        return explicit.replace("{key}", key), (key,)
    return f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", (key,)


_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def host_from_url(u) -> str | None:
    """Hostname of a feed URL, for any scheme. The ingest DAGs used to prepend
    "http://" unless the URL started with http(s)://, so "ftp://1.2.3.4/x" became
    "http://ftp://1.2.3.4/x" whose hostname is "ftp": a bogus domain in the labels."""
    u = str(u).strip()
    if not _SCHEME.match(u):
        u = "http://" + u
    return urlparse(u).hostname
