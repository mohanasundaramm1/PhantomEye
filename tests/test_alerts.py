"""Failure alerts (R-03): a failed task must leave a durable record, and secrets must not leak into it."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "airflow", "dags"))
import alerts  # noqa: E402


class TI:
    task_id, try_number, log_url = "urlhaus_fetch", 3, "http://airflow/log/1"


class DR:
    run_id = "scheduled__2026-11-15T02:30:00+00:00"


def _ctx(exc):
    return {"dag": type("D", (), {"dag_id": "urlhaus_ingest"})(), "task_instance": TI(), "dag_run": DR(), "exception": exc}


def test_failure_is_appended_as_one_json_line(tmp_path, monkeypatch):
    path = tmp_path / "alerts.jsonl"
    monkeypatch.setenv("ALERTS_PATH", str(path))
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    alerts.notify_failure(_ctx(RuntimeError("HTTP 410 from the feed")))
    alerts.notify_failure(_ctx(RuntimeError("second")))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["dag_id"] for r in rows] == ["urlhaus_ingest"] * 2
    assert rows[0]["task_id"] == "urlhaus_fetch" and "410" in rows[0]["error"] and rows[0]["ts"]


def test_secrets_from_the_environment_are_redacted(tmp_path, monkeypatch):
    path = tmp_path / "a.jsonl"
    monkeypatch.setenv("ALERTS_PATH", str(path))
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "TOPSECRETKEY")
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    alerts.notify_failure(_ctx(RuntimeError("GET https://h/TOPSECRETKEY/recent.csv failed")))
    text = path.read_text()
    assert "TOPSECRETKEY" not in text and "***" in text


def test_an_unwritable_path_never_raises(monkeypatch):
    monkeypatch.setenv("ALERTS_PATH", "/proc/definitely/not/writable/alerts.jsonl")
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    alerts.notify_failure(_ctx(RuntimeError("x")))        # an alerting bug must not fail the task again


def test_ntfy_push_is_only_attempted_when_a_topic_is_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "a.jsonl"))
    posted = []
    monkeypatch.setattr(alerts, "_post", lambda url, body, title: posted.append((url, title)))
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    alerts.notify_failure(_ctx(RuntimeError("x")))
    assert posted == []
    monkeypatch.setenv("NTFY_TOPIC", "my-secret-topic")
    alerts.notify_failure(_ctx(RuntimeError("x")))
    assert posted and posted[0][0] == "https://ntfy.sh/my-secret-topic"
