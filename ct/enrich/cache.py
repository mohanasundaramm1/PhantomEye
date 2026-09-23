# ct/enrich/cache.py
"""Parquet-backed lookup caches with TTL + hit/miss accounting.

Extends the existing lookups/*.parquet pattern (whois_cache.parquet,
dns_geo_cache.parquet, ip_geo_cache.parquet): every row carries a
`fetched_at` UTC timestamp; rows older than the cache TTL are treated
as misses and re-fetched/upserted. Writes are atomic temp-swap.
"""
from __future__ import annotations

import logging
import os
import tempfile

import pandas as pd

log = logging.getLogger(__name__)


def atomic_to_parquet(df: pd.DataFrame, final_path: str):
    """Atomic write: temp file in the same dir, then os.replace (POSIX-atomic)."""
    os.makedirs(os.path.dirname(final_path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=os.path.dirname(final_path) or ".")
    os.close(fd)
    try:
        df.to_parquet(tmp, index=False)
        os.replace(tmp, final_path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


class ParquetTTLCache:
    """Keyed parquet cache. Multiple rows per key are allowed (e.g. domain->ips)."""

    def __init__(self, name: str, path: str, key_col: str, ttl_seconds: float,
                 now=lambda: pd.Timestamp.now(tz="UTC")):
        self.name = name
        self.path = path
        self.key_col = key_col
        self.ttl = pd.Timedelta(seconds=float(ttl_seconds))
        self._now = now
        self.hits = 0
        self.misses = 0
        self.expired = 0
        self._df = self._load()
        self._index = self._build_index()

    def _load(self) -> pd.DataFrame:
        if os.path.exists(self.path):
            try:
                df = pd.read_parquet(self.path)
            except Exception as e:
                log.warning("[cache:%s] unreadable (%s); recreating empty cache", self.name, e)
                df = pd.DataFrame()
        else:
            df = pd.DataFrame()
        if self.key_col not in df.columns:
            df[self.key_col] = pd.Series(dtype=str)
        if "fetched_at" not in df.columns:
            df["fetched_at"] = pd.NaT
        df[self.key_col] = df[self.key_col].astype(str)
        df["fetched_at"] = pd.to_datetime(df["fetched_at"], utc=True, errors="coerce")
        return df

    def _build_index(self) -> dict:
        """key -> positional row indices.

        get() previously did `self._df[self._df[key_col] == key]`, a full linear
        scan per lookup. That is fine for a few hundred rows and pathological once
        a cache grows: the geo cache is consulted once per resolved IP per domain,
        so an O(n) probe against a ~58k-row frame turns a hot-path pass into
        minutes. Indexing once per load makes each probe O(1).
        """
        if self._df.empty:
            return {}
        idx: dict = {}
        for pos, key in enumerate(self._df[self.key_col].to_numpy()):
            idx.setdefault(key, []).append(pos)
        return idx

    def get(self, key: str) -> pd.DataFrame | None:
        """Fresh rows for key, or None on miss (absent OR expired)."""
        positions = self._index.get(str(key))
        if not positions:
            self.misses += 1
            return None
        rows = self._df.iloc[positions]
        if rows.empty:
            self.misses += 1
            return None
        age = self._now() - rows["fetched_at"]
        fresh = rows[age < self.ttl]
        if fresh.empty:
            self.misses += 1
            self.expired += 1
            return None
        self.hits += 1
        return fresh.copy()

    def upsert(self, rows: list[dict] | pd.DataFrame):
        """Replace all rows for the affected keys with the new rows (stamped now)."""
        new_df = pd.DataFrame(rows) if not isinstance(rows, pd.DataFrame) else rows.copy()
        if new_df.empty:
            return
        new_df[self.key_col] = new_df[self.key_col].astype(str)
        if "fetched_at" not in new_df.columns or new_df["fetched_at"].isna().all():
            new_df["fetched_at"] = self._now()
        new_df["fetched_at"] = pd.to_datetime(new_df["fetched_at"], utc=True, errors="coerce")
        keys = set(new_df[self.key_col])
        kept = self._df[~self._df[self.key_col].isin(keys)]
        self._df = pd.concat([kept, new_df], ignore_index=True)
        # Positions shift on every concat, so the index is rebuilt rather than
        # patched -- correctness over cleverness; upserts are far rarer than gets.
        self._index = self._build_index()

    def flush(self):
        atomic_to_parquet(self._df, self.path)

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total else 0.0

    def log_stats(self):
        log.info(
            "[cache:%s] hits=%d misses=%d (expired=%d) hit_rate=%.1f%% size=%d",
            self.name, self.hits, self.misses, self.expired,
            self.hit_rate * 100.0, len(self._df),
        )
