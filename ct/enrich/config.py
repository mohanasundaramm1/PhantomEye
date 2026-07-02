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
