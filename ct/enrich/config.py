# ct/enrich/config.py
"""Single source of truth for enrichment knobs.

Loads config/enrichment.json (path overridable via ENRICHMENT_CONFIG env var)
and merges it over hard-coded defaults, so a partial config file is fine.
"""
from __future__ import annotations

import json
import os
from copy import deepcopy

THIS_DIR = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, "config", "enrichment.json")

DEFAULTS = {
    "queue": {
        "dir": "ct/data/enrich_queue",
        "batch_size": 200,
        "max_attempts": 3,
    },
    "rate_limits": {
        "whois_rps": 1.0,   # ~1 WHOIS/RDAP request per second
        "dns_rps": 20.0,
    },
    "timeouts": {
        "whois_seconds": 10.0,
        # Non-reliable_tlds domains are federated to a per-TLD registry of
        # variable latency -- a longer budget here means a registry that's
        # just slower (not broken) doesn't get miscounted as a failure and
        # doesn't trip circuit_breaker_other. See reliable_tlds below.
        "whois_seconds_other_tld": 20.0,
        "dns_seconds": 5.0,
    },
    "tiers": {
        "triage_threshold": 0.5,
        "missing_triage_is_high_priority": True,
    },
    "cache_ttls": {
        "whois_days": 7,
        "dns_hours": 24,
        "geo_hours": 24,
    },
    "circuit_breaker": {
        "failure_threshold": 5,
        "cooldown_seconds": 300,
    },
    # Separate, independently-tunable breaker for WHOIS/RDAP calls to
    # non-reliable_tlds domains. Without this split, a run of failures on a
    # handful of flaky-registry domains (common: they cluster together in a
    # batch, since a CT burst tends to share a TLD) trips ONE shared breaker
    # and then blocks WHOIS for every domain -- including perfectly healthy
    # .com/.net/.org lookups -- for the full cooldown. Found live: 96% of a
    # day's WHOIS failures were "circuit_open" rejections, not real failures,
    # and over a third of those rejected were .com domains that work fine
    # when tested directly. See ct/enrich/tiers.py::_tld_bucket().
    "circuit_breaker_other": {
        "failure_threshold": 5,
        "cooldown_seconds": 300,
    },
    # TLDs whose RDAP is well-established and fast (Verisign .com/.net, PIR
    # .org) -- everything else is federated to a per-TLD registry of much
    # more variable reliability/latency and gets its own breaker + a longer
    # timeout budget (see timeouts.whois_seconds_other_tld) so a registry
    # that's merely slow, not broken, doesn't get miscounted as a failure.
    "reliable_tlds": ["com", "net", "org"],
    "paths": {
        "lookups_dir": "lookups",
        "enriched_dir": "ct/data/enriched",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None = None) -> dict:
    path = path or os.getenv("ENRICHMENT_CONFIG", DEFAULT_CONFIG_PATH)
    cfg = deepcopy(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, "r") as f:
            cfg = _deep_merge(cfg, json.load(f))
    cfg["_config_path"] = path
    return cfg


def abspath(cfg: dict, rel: str) -> str:
    """Resolve a config path relative to the repo root unless already absolute."""
    return rel if os.path.isabs(rel) else os.path.join(REPO_ROOT, rel)
