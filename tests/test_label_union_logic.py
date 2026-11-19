"""Label union (R-03): one dead source must not block the others, and 'no data at all' must fail loudly."""
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "airflow", "dags"))
from label_union_logic import NoSourceData, combine_sources  # noqa: E402


def _df(domain):
    return pd.DataFrame({"domain": [domain], "url": [f"http://{domain}/x"], "first_seen": [pd.Timestamp("2026-11-01", tz="UTC")],
                         "label": ["phishing"], "source": ["s"]})


def test_openphish_only_still_produces_a_union_and_records_what_is_missing():
    union, lineage = combine_sources({"openphish": _df("a.example"), "urlhaus": None})
    assert list(union["domain"]) == ["a.example"]
    assert lineage["sources_included"] == ["openphish"] and lineage["sources_missing"] == ["urlhaus"]
    assert bool(union["seen_in_openphish"].iloc[0]) and not bool(union["seen_in_urlhaus"].iloc[0])


def test_empty_frames_count_as_missing():
    _, lineage = combine_sources({"openphish": _df("a.example"), "urlhaus": pd.DataFrame()})
    assert lineage["sources_missing"] == ["urlhaus"]


def test_both_sources_present_are_combined():
    union, lineage = combine_sources({"openphish": _df("a.example"), "urlhaus": _df("b.example")})
    assert sorted(union["domain"]) == ["a.example", "b.example"]
    assert lineage["rows_by_source"] == {"openphish": 1, "urlhaus": 1}


def test_no_source_at_all_raises_instead_of_writing_an_empty_partition():
    with pytest.raises(NoSourceData):
        combine_sources({"openphish": None, "urlhaus": pd.DataFrame()})
