"""Product application DB (campaign-radar layer).

Metadata assertions always run (pure, no DB). The live-DB check skips cleanly
when APP_DATABASE_URL isn't reachable, so unit CI without Postgres still passes
while a dev box running `docker compose up -d app-db` gets real coverage.
"""
import pytest

from product.db import Base, ping
from product import models  # noqa: F401  registers tables on Base.metadata


def test_models_registered_on_metadata():
    assert {"ct_observations", "watchlist_brands"} <= set(Base.metadata.tables)


def test_ct_observation_has_upsert_key():
    # W4 decision: exactly one row per (raw_host, event_ts) so late cold-path
    # enrichment upserts in place instead of creating duplicate observations.
    obs = Base.metadata.tables["ct_observations"]
    unique_col_sets = {
        tuple(c.name for c in con.columns)
        for con in obs.constraints
        if con.__class__.__name__ == "UniqueConstraint"
    }
    assert ("raw_host", "event_ts") in unique_col_sets


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_live_db_has_migrated_tables():
    from sqlalchemy import inspect

    from product.db import engine

    names = set(inspect(engine).get_table_names())
    assert {"ct_observations", "watchlist_brands"} <= names


def test_models_stay_sqlalchemy_1_4_compatible():
    """Regression guard: campaign_radar_dag's Airflow tasks run against
    Airflow's own bundled SQLAlchemy 1.4.52 (a hard Airflow 2.9.x constraint --
    installing 2.0 into that image risks breaking Airflow itself), while the
    host venv uses 2.0.36. product/models.py and product/db.py must stick to
    the classic Column()/declarative_base() style, which works identically
    under both -- not Mapped[]/mapped_column()/DeclarativeBase, which are
    2.0-only and silently break under 1.4 (found live: a fresh campaign_radar_dag
    run failed with ModuleNotFoundError before even reaching this, but the next
    failure in line would have been an AttributeError on DeclarativeBase).

    AST-based, not a source-text grep: this docstring itself names the
    forbidden symbols as prose, which a plain substring search would also
    flag. Only real code constructs count -- an AnnAssign using `Mapped`,
    a call to `mapped_column(...)`, or a class base named `DeclarativeBase`.
    """
    import ast

    import product.db as db_module
    import product.models as models_module

    def _name_of(node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Subscript):
            return _name_of(node.value)
        if isinstance(node, ast.Call):
            return _name_of(node.func)
        return None

    for mod in (db_module, models_module):
        tree = ast.parse(open(mod.__file__).read(), filename=mod.__file__)
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and _name_of(node.annotation) == "Mapped":
                raise AssertionError(f"{mod.__file__}: 2.0-only `Mapped[...]` annotation at line {node.lineno}")
            if isinstance(node, ast.Call) and _name_of(node.func) == "mapped_column":
                raise AssertionError(f"{mod.__file__}: 2.0-only mapped_column() call at line {node.lineno}")
            if isinstance(node, ast.ClassDef) and any(_name_of(b) == "DeclarativeBase" for b in node.bases):
                raise AssertionError(f"{mod.__file__}: 2.0-only DeclarativeBase subclass at line {node.lineno}")
