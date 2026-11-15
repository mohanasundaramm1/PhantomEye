"""Test-session guard: DB-backed tests may only ever touch a *_test database.

Without this, product.db falls back to the real dev database
(localhost:5433/campaigns), and DB tests that call system-wide functions
(assemble(), recompute, repair...) would read and rewrite real campaigns.

How it works:
  * If APP_DATABASE_URL is unset, point it at the dedicated test database
    (override with TEST_DATABASE_URL). This happens in pytest_configure, i.e.
    before any test module imports product.db and builds its engine.
  * If APP_DATABASE_URL is set to anything whose database name does not end
    in "_test", refuse to run the session at all.

Create the local test database once with `make test-db`. If it does not
exist, ping() fails and the DB tests skip -- they never fall back to dev.
"""
import os

import pytest

DEFAULT_TEST_DATABASE_URL = "postgresql+psycopg2://app:app@localhost:5433/campaigns_test"


def pytest_configure(config):
    os.environ.setdefault(
        "APP_DATABASE_URL",
        os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL),
    )
    from sqlalchemy.engine import make_url

    db_name = make_url(os.environ["APP_DATABASE_URL"]).database or ""
    if not db_name.endswith("_test"):
        raise pytest.UsageError(
            f"Refusing to run tests against database {db_name!r}: "
            "APP_DATABASE_URL must name a database ending in '_test'. "
            "Unset APP_DATABASE_URL to use the default test DB (make test-db)."
        )
