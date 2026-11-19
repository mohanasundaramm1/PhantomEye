# airflow/dags/alerts.py
"""on_failure_callback shared by every DAG (R-03).

Before this, no DAG alerted on failure: the label pipeline was blocked for three
weeks and nothing told anyone. Now every failed task:
  1. appends one JSON line to ALERTS_PATH (default /opt/airflow/ct/data/alerts/alerts.jsonl,
     i.e. ct/data/alerts/alerts.jsonl on the host), and
  2. if NTFY_TOPIC is set, also pushes a short message to https://ntfy.sh/<topic>
     (off by default; the topic name is the secret, so keep it in .env).
An alerting bug must never fail the task a second time, so everything is best effort.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_SECRET_ENV_VARS = ("URLHAUS_AUTH_KEY", "NTFY_TOPIC")


def _redact(text: str) -> str:
    for name in _SECRET_ENV_VARS:
        val = os.environ.get(name)
        if val:
            text = text.replace(val, "***")
    return text


def format_alert(context: dict) -> dict:
    ti = context.get("task_instance")
    dag = context.get("dag")
    dr = context.get("dag_run")
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "dag_id": getattr(dag, "dag_id", None),
        "task_id": getattr(ti, "task_id", None),
        "run_id": getattr(dr, "run_id", None),
        "try_number": getattr(ti, "try_number", None),
        "error": _redact(str(context.get("exception"))[:500]),
        "log_url": getattr(ti, "log_url", None),
    }


def _post(url: str, body: str, title: str) -> None:
    import requests
    requests.post(url, data=body.encode("utf-8"), headers={"Title": title}, timeout=5)


def notify_failure(context: dict) -> None:
    try:
        alert = format_alert(context)
    except Exception:  # noqa: BLE001
        log.exception("could not format alert")
        return
    path = os.environ.get("ALERTS_PATH", "/opt/airflow/ct/data/alerts/alerts.jsonl")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:  # noqa: BLE001
        log.exception("could not write alert to %s", path)
    topic = os.environ.get("NTFY_TOPIC")
    if topic:
        try:
            _post(f"https://ntfy.sh/{topic}",
                  f"{alert['dag_id']}.{alert['task_id']} failed: {alert['error']}",
                  "Phantom Eye task failed")
        except Exception:  # noqa: BLE001
            log.exception("ntfy push failed")
