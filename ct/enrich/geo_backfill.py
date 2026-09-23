# ct/enrich/geo_backfill.py
"""Cold-path GeoIP backfill for IPs discovered by the CT lane.

Why this exists
---------------
`ct/enrich/tiers.py` looks geo up as "Tier 1: GeoIP from local cache only" --
it deliberately makes no network call, because the hot path must never block on
a rate-limited third party. That is the right call for the hot path, but nothing
was filling the cache for CT-discovered IPs:

  * the DNS step writes rows of the shape {puny_domain, ip} into
    dns_geo_cache.parquet -- resolution only, no country;
  * `dns_ip_geo_ingest` (airflow/dags/dns_ip_geo_dag.py) *does* geo-enrich, but
    sources its domains from silver/labels_union -- the OSINT lane, not the CT
    lane;
  * ip_geo_cache.parquet, which enrich_worker's "geo" cache pointed at, had no
    writer anywhere in the repo.

Net effect: every row carrying a country was older than the 24h geo TTL, and
every row inside the TTL had country=NULL, so `sample_country` was NULL on 100%
of scored rows while DNS resolution itself was working fine.

This module closes that loop the same way the WHOIS backfill does: find the
cache rows the hot path could not satisfy, resolve them out-of-band at a safe
rate, and write the answers back where the next hot pass will find them.

Deliberately writes into dns_geo_cache.parquet (not a new file): the DNS step
already creates exactly one row per (puny_domain, ip) there, so filling the geo
columns in place keeps a single row per observation instead of forcing a join
across two caches with different TTLs.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, List

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = ("status,country,countryCode,regionName,city,lat,lon,isp,org,as,"
                 "asname,reverse,proxy,hosting,query")
BATCH_SIZE = 100          # ip-api free-tier batch maximum
THROTTLE_SECONDS = 1.5    # matches dns_ip_geo_dag's pacing against the same host
# country_code (ISO-3166 alpha-2) is carried alongside the display name because
# ct_observations.sample_country is VARCHAR(8) -- sized for a code, not a name.
# Writing "United States" there raises StringDataRightTruncation at ingest.
GEO_COLUMNS = ("country", "country_code", "region", "city", "lat", "lon", "asn",
               "asn_name", "isp", "org", "reverse", "proxy", "hosting")


def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.7,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["POST"]))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": "phantomeye-geo-backfill/1.0"})
    return s


def _lookup(session: requests.Session, ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Batch-resolve IPs to geo fields. Mirrors dns_ip_geo_dag._ip_geo_batch so
    both writers produce identically-shaped rows in the same cache."""
    out: Dict[str, Dict[str, Any]] = {}
    for i in range(0, len(ips), BATCH_SIZE):
        chunk = ips[i:i + BATCH_SIZE]
        body = [{"query": ip, "fields": IP_API_FIELDS} for ip in chunk]
        try:
            r = session.post(IP_API_BATCH_URL, json=body, timeout=(3, 20))
            r.raise_for_status()
            for rec in r.json():
                ip = rec.get("query")
                if not ip:
                    continue
                if rec.get("status") != "success":
                    out[ip] = {}       # negative cached: don't re-ask every run
                    continue
                out[ip] = {
                    "country": rec.get("country"),
                    "country_code": rec.get("countryCode"),
                    "region": rec.get("regionName"),
                    "city": rec.get("city"),
                    "lat": rec.get("lat"),
                    "lon": rec.get("lon"),
                    "asn": (rec.get("as") or "").split(" ")[0] if rec.get("as") else None,
                    "asn_name": rec.get("asname"),
                    "isp": rec.get("isp"),
                    "org": rec.get("org"),
                    "reverse": rec.get("reverse"),
                    "proxy": rec.get("proxy"),
                    "hosting": rec.get("hosting"),
                }
        except Exception as e:
            # Best-effort by design: a geo miss degrades a panel, it must never
            # fail the DAG or block scoring.
            log.warning("ip-api batch failed (%s..%s): %s", chunk[:1], chunk[-1:], e)
        time.sleep(THROTTLE_SECONDS)
    return out


def _atomic_write(df: pd.DataFrame, path: str) -> None:
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)


def backfill(cache_path: str, max_ips: int = 500, dry_run: bool = False) -> dict:
    """Fill geo columns for cache rows that have an IP but no country.

    Returns a summary dict; safe to run repeatedly and safe to interrupt (the
    parquet is replaced atomically, so a kill mid-run leaves the old file intact).
    """
    if not os.path.exists(cache_path):
        log.warning("[geo-backfill] no cache at %s", cache_path)
        return {"pending": 0, "resolved": 0, "written": 0}

    df = pd.read_parquet(cache_path)
    for col in GEO_COLUMNS:
        if col not in df.columns:
            df[col] = None

    has_ip = df["ip"].notna() & (df["ip"].astype(str).str.len() > 0)
    # Rows written before country_code existed carry a display name but no ISO
    # code, and the code is the field that actually reaches ct_observations --
    # so "already has country" is not sufficient to consider a row done.
    needs_geo = has_ip & (df["country"].isna() | df["country_code"].isna())
    pending_ips = sorted(set(df.loc[needs_geo, "ip"].astype(str)))
    log.info("[geo-backfill] %d rows need geo across %d distinct IPs",
             int(needs_geo.sum()), len(pending_ips))

    if dry_run or not pending_ips:
        return {"pending": len(pending_ips), "resolved": 0, "written": 0}

    targets = pending_ips[:max_ips]
    resolved = _lookup(_session(), targets)
    hits = {ip: g for ip, g in resolved.items() if g.get("country") or g.get("country_code")}
    log.info("[geo-backfill] resolved %d/%d IPs", len(hits), len(targets))
    if not hits:
        return {"pending": len(pending_ips), "resolved": 0, "written": 0}

    written = 0
    ip_str = df["ip"].astype(str)
    for ip, geo in hits.items():
        mask = (ip_str == ip) & (df["country"].isna() | df["country_code"].isna())
        n = int(mask.sum())
        if not n:
            continue
        for col, val in geo.items():
            if col in df.columns:
                df.loc[mask, col] = val
        written += n

    _atomic_write(df, cache_path)
    log.info("[geo-backfill] wrote geo onto %d rows", written)
    return {"pending": len(pending_ips), "resolved": len(hits), "written": written}


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", default=None,
                    help="path to dns_geo_cache.parquet (default: from config)")
    ap.add_argument("--max-ips", type=int, default=500,
                    help="cap per run; the queue drains across runs")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    cache = args.cache
    if cache is None:
        from ct.enrich.enrich_worker import load_config, abspath
        cfg = load_config()
        cache = os.path.join(abspath(cfg, cfg["paths"]["lookups_dir"]),
                             "dns_geo_cache.parquet")

    summary = backfill(cache, max_ips=args.max_ips, dry_run=args.dry_run)
    print(f"[geo-backfill] {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
