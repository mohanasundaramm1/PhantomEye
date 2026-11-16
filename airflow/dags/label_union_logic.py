# airflow/dags/label_union_logic.py
"""Pure logic of the labels_union DAG (no Airflow imports, so it is unit-testable)."""
from __future__ import annotations

import pandas as pd

SOURCES = ("openphish", "urlhaus")


class NoSourceData(RuntimeError):
    """No feed produced silver for the day; writing an empty union would hide that."""


def combine_sources(frames: dict) -> tuple[pd.DataFrame, dict]:
    """Union whichever sources have data. One dead feed must not block the others.

    frames: {"openphish": df|None, "urlhaus": df|None}. Returns (union, lineage), where
    lineage records which sources were included/missing so a partial day is visible.
    Raises NoSourceData when nothing at all is available.
    """
    present = {s: int(len(df)) for s, df in frames.items() if df is not None and len(df)}
    if not present:
        raise NoSourceData(f"no silver input for any source ({', '.join(sorted(frames))})")
    parts = [
        frames[s].assign(seen_in_urlhaus=(s == "urlhaus"), seen_in_openphish=(s == "openphish"))
        for s in sorted(present)
    ]
    union = pd.concat(parts, ignore_index=True)
    lineage = {
        "sources_included": sorted(present),
        "sources_missing": sorted(set(frames) - set(present)),
        "rows_by_source": present,
    }
    return union, lineage
