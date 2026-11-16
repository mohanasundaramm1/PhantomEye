"""Structural checks on the Airflow DAGs (run INSIDE the Airflow image; see ci.yml).

Parse success alone proves little. These assertions pin the properties whose absence
caused real incidents (R-03): one failed feed blocking every other source, no failure
alerting, a pipeline run that looks green while a source is dead.
"""
import os
import sys

from airflow.models import DagBag
from airflow.utils.trigger_rule import TriggerRule

dags_dir = os.environ.get("DAGS_DIR", "/opt/airflow/dags")
bag = DagBag(dag_folder=dags_dir, include_examples=False)
errors = []

for path, err in bag.import_errors.items():
    errors.append(f"IMPORT ERROR {os.path.basename(path)}: {err.splitlines()[-1] if err else err}")

for dag_id, dag in bag.dags.items():
    if not (dag.default_args or {}).get("on_failure_callback"):
        errors.append(f"{dag_id}: no on_failure_callback in default_args (failures would be silent)")

orch = bag.dags.get("pipeline_orchestrator")
if orch is None:
    errors.append("pipeline_orchestrator missing")
else:
    def tid(suffix):
        m = [t for t in orch.task_ids if t.endswith(suffix)]
        assert len(m) == 1, f"expected exactly one task ending {suffix!r}, got {m}"
        return m[0]

    try:
        op_silver, uh_bronze, union = tid("openphish_silver"), tid("urlhaus_bronze"), tid("labels_union")
        if uh_bronze in orch.get_task(op_silver).upstream_task_ids:
            errors.append("openphish_silver depends on urlhaus_bronze: a dead URLhaus blocks OpenPhish")
        if uh_bronze in orch.get_task(op_silver).get_flat_relative_ids(upstream=True):
            errors.append("openphish_silver transitively depends on urlhaus_bronze")
        if orch.get_task(union).trigger_rule != TriggerRule.ALL_DONE:
            errors.append(f"labels_union trigger_rule is {orch.get_task(union).trigger_rule}, expected all_done")
        if not orch.has_task("assert_no_failed_tasks"):
            errors.append("assert_no_failed_tasks missing: a degraded run would look green")
        elif orch.get_task("assert_no_failed_tasks").trigger_rule != TriggerRule.ALL_DONE:
            errors.append("assert_no_failed_tasks must use trigger_rule all_done")
        if (orch.default_args or {}).get("retries") != 0:
            errors.append("orchestrator retries must be 0 (child DAGs own their retries)")
    except Exception as e:  # noqa: BLE001  report, never crash, so every problem is listed
        errors.append(f"orchestrator structure: {type(e).__name__}: {e}")

    for t in orch.tasks:
        target = getattr(t, "trigger_dag_id", None)
        if target and target not in bag.dags:
            errors.append(f"{t.task_id} triggers unknown DAG {target!r}")

print(f"checked {len(bag.dags)} DAGs, {len(errors)} problem(s)")
for e in errors:
    print(" -", e)
sys.exit(1 if errors else 0)
