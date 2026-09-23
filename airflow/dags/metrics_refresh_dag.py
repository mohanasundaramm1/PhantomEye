"""Refresh the Metrics & Proof panel's inputs on a schedule.

Before this DAG, both files behind that panel were written ONLY by hand:
  - ml/models/registry/precision_at_k_latest.json  (ml.core.eval_precision_at_k)
  - gold/detection_timeline/latest_summary.json    (ct/score/measure_lead_time.py)
No DAG ran either script, so the panel showed "batch job has not re-run
since" (precision@K last computed 2026-09-21, lead-time 2026-07-02) while
the scoring pipeline kept running underneath it.

Runs at :30 every 6h -- after ct_enrich_and_score_dag (:00) and
campaign_radar_dag (:15) -- so each refresh reads the newest scored batch.
The two tasks are independent: a failure in one never blocks the other, and
neither can block scoring or clustering since they live in their own DAG.
"""
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

REPO_ROOT = "/opt/airflow"
ENV = f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "

default_args = {
    "owner": "ct-pipeline",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}

with DAG(
    dag_id="metrics_refresh_dag",
    default_args=default_args,
    description="Every 6h: recompute precision@K (vs. MISP) and CT-vs-blocklist lead time for the Metrics & Proof panel",
    schedule_interval="30 */6 * * *",
    start_date=datetime(2026, 9, 23),
    catchup=False,
    max_active_runs=1,
    tags=["metrics"],
) as dag:
    BashOperator(
        task_id="precision_at_k",
        bash_command=ENV + "python -m ml.core.eval_precision_at_k",
        execution_timeout=timedelta(minutes=15),
    )

    BashOperator(
        task_id="lead_time",
        bash_command=ENV + "python ct/score/measure_lead_time.py",
        execution_timeout=timedelta(minutes=20),
    )
