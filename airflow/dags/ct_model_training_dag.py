from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

# Adjust this path if your repo lives somewhere else in the Airflow environment
REPO_ROOT = "/opt/airflow"

default_args = {
    "owner": "ct-pipeline",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}

with DAG(
    dag_id="ct_model_training_dag",
    default_args=default_args,
    description="Weekly training of CT phishing vs benign baseline model",
    schedule_interval="@weekly",  # you can change to a cron if you want a specific day/time
    start_date=datetime(2025, 11, 30),
    catchup=False,
    max_active_runs=1,
) as dag:

    train_latest_baseline = BashOperator(
        task_id="train_latest_baseline",
        bash_command=f"""
        cd {REPO_ROOT} && \
        export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && \
        python ml/core/train_model.py
        """
    )

    # Verifies the promotion gate itself actually ran and produced a recent
    # decision -- NOT whether that decision was to promote or reject. A
    # rejection (champion kept, challenger regressed) is the safety mechanism
    # working correctly and must not fail this task; a missing/stale/malformed
    # decision means the gate silently didn't execute, which is the real
    # integrity risk (see ml/core/promotion_gate.py verify_latest_decision).
    verify_promotion_gate_ran = BashOperator(
        task_id="verify_promotion_gate_ran",
        bash_command=f"""
        cd {REPO_ROOT} && \
        export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && \
        python -m ml.core.promotion_gate --max-age-hours 6
        """
    )

    train_latest_baseline >> verify_promotion_gate_ran
