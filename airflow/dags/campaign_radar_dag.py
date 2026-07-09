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

# ingest_observations.py and assemble_campaigns.py (product/) were, until this
# DAG, standalone CLI scripts nobody scheduled -- the campaign queue only ever
# updated when someone ran `make ingest-observations` / `make assemble-campaigns`
# by hand. Offset 15 min after ct_enrich_and_score_dag's :00 schedule so a fresh
# gold/threat_scores/*.parquet file (written by that DAG's score_ct_with_latest
# task) is reliably on disk before this DAG's ingest step reads "the newest
# scored parquet" -- ingest_observations.py has no dependency-wait of its own,
# it just globs for the newest file, so this ordering is what keeps it from
# racing a still-being-written scored file most cycles.
with DAG(
    dag_id="campaign_radar_dag",
    default_args=default_args,
    description="Every 2h: project scored observations into Postgres and assemble them into brand-attributed campaign clusters",
    schedule_interval="15 */2 * * *",
    start_date=datetime(2026, 7, 3),
    catchup=False,
    max_active_runs=1,
) as dag:

    # 1) Project the newest scored parquet into ct_observations (upsert by
    #    raw_host+event_ts -- see product/ingest_observations.py).
    ingest_observations = BashOperator(
        task_id="ingest_observations",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"python -m product.ingest_observations"
        ),
        execution_timeout=timedelta(minutes=10),
    )

    # 2) Cluster candidate observations into brand-attributed campaigns
    #    (see product/assemble_campaigns.py). Cheap relative to the enrichment
    #    drain jobs -- no time-budget logic needed here, just a sane ceiling.
    assemble_campaigns = BashOperator(
        task_id="assemble_campaigns",
        bash_command=(
            f"cd {REPO_ROOT} && export PYTHONPATH=$PYTHONPATH:{REPO_ROOT} && "
            f"python -m product.assemble_campaigns"
        ),
        execution_timeout=timedelta(minutes=10),
    )

    ingest_observations >> assemble_campaigns
