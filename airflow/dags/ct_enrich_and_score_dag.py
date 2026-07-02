from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

REPO_ROOT = "/opt/airflow"

default_args = {
    "owner": "ct-pipeline",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}

with DAG(
    dag_id="ct_enrich_and_score_dag",
    default_args=default_args,
    description="Every 2h: hot-score the freshest CT domains, gate on freshness, backfill WHOIS in the background",
    schedule_interval="0 */2 * * *",  # every 2 hours on the hour
    start_date=datetime(2025, 11, 30),
    catchup=False,
    max_active_runs=1,
) as dag:

    # 1) HOT PATH: enrich the newest, highest-triage CT domains WHOIS-cache-only
    #    (DNS is the only network call; no blocking on rate-limited RDAP), and
    #    advance _latest_enriched.json so scoring sees fresh data every cycle.
    #    This is what closes the freshness loop -- fresh CT -> fresh enriched in
    #    ~1-2 min instead of waiting hours for a full rate-limited drain.
    enrich_hot = BashOperator(
        task_id="enrich_hot",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"python -m ct.enrich.enrich_worker --hot"
        ),
        execution_timeout=timedelta(minutes=15),
    )

    # 2) Score the fresh enriched pointer -> gold/threat_scores.
    score_ct = BashOperator(
        task_id="score_ct_with_latest",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"python ct/score/score_ct_with_latest.py"
        ),
        execution_timeout=timedelta(minutes=15),
    )

    # 3) FRESHNESS GATE: fail the run loudly if the scored output is stale --
    #    byte-identical re-scores, or a newest scored file whose event_ts is
    #    hours old (fresh filename, stale content). A green run must mean fresh
    #    intelligence actually came out, not just that the tasks executed.
    freshness_gate = BashOperator(
        task_id="freshness_gate",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"python scripts/check_ct_freshness.py --skip-raw"
        ),
        execution_timeout=timedelta(minutes=5),
    )

    # 4) COLD BACKFILL (best-effort): drain a bounded slice of the WHOIS queue
    #    at the safe rate to warm the cache for future hot cycles. Never
    #    advances the pointer (--no-pointer) and never fails the DAG (|| true).
    enrich_backfill = BashOperator(
        task_id="enrich_backfill",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"timeout 900 python -m ct.enrich.enrich_worker --drain --no-pointer --max-batches 5 || true"
        ),
        execution_timeout=timedelta(minutes=20),
    )

    enrich_hot >> score_ct >> freshness_gate
    score_ct >> enrich_backfill
