"""Pure-logic test for export_analyst_labels.py's feedback-schema adapter --
deliberately a SEPARATE file from test_export_analyst_labels.py, which has a
module-level skipif(not db reachable) marker that would otherwise wrongly
skip this too (it needs no DB at all)."""
import pandas as pd

from product.export_analyst_labels import to_feedback_schema


def test_to_feedback_schema_maps_columns_correctly():
    df = pd.DataFrame({
        "raw_host": ["a.evil.tk"],
        "registered_domain": ["evil.tk"],
        "label": [0],
        "disposed_at": [pd.Timestamp("2026-07-08T12:00:00Z")],
    })
    out = to_feedback_schema(df)
    assert list(out.columns) == ["domain", "label", "source", "ingest_date"]
    assert out.iloc[0]["domain"] == "evil.tk"
    assert out.iloc[0]["label"] == 0
    assert out.iloc[0]["source"] == "analyst_disposition"
    assert out.iloc[0]["ingest_date"] == "2026-07-08"


def test_to_feedback_schema_falls_back_to_raw_host_when_registered_domain_missing():
    df = pd.DataFrame({
        "raw_host": ["a.evil.tk"],
        "registered_domain": [None],
        "label": [1],
        "disposed_at": [pd.Timestamp("2026-07-08T12:00:00Z")],
    })
    out = to_feedback_schema(df)
    assert out.iloc[0]["domain"] == "a.evil.tk"


def test_to_feedback_schema_preserves_confirmed_and_negative_labels():
    df = pd.DataFrame({
        "raw_host": ["a.tk", "b.tk"],
        "registered_domain": ["a.tk", "b.tk"],
        "label": [1, 0],
        "disposed_at": [pd.Timestamp("2026-07-08"), pd.Timestamp("2026-07-08")],
    })
    out = to_feedback_schema(df)
    assert list(out["label"]) == [1, 0]
