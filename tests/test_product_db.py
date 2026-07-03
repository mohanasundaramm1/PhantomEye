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
