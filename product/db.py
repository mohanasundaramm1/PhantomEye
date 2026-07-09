# product/db.py
"""Engine, session factory, declarative Base, and a liveness ping for the
campaign-radar application datastore.

Connection comes from APP_DATABASE_URL (see docker-compose.yml `app-db`). Two
different runtimes import this module: the host venv (SQLAlchemy 2.0.36, per
requirements.txt) AND the Airflow containers, which run campaign_radar_dag's
tasks against Airflow's OWN bundled SQLAlchemy 1.4.52 -- Airflow 2.9.x pins
<2.0 for its own internals, and installing 2.0 into that image risks breaking
the scheduler/webserver. So product/models.py deliberately uses the classic
declarative_base()/Column() style (not Mapped[]/mapped_column()/DeclarativeBase,
which are 2.0-only) -- it's the one mapping style that behaves identically
under both 1.4 and 2.0, so this module needs no environment-specific handling.
The query code elsewhere (select()/session.execute()/.scalars()/with_for_update())
already works under 1.4 too -- that "2.0-style" query API has been available,
opt-in, since 1.4, which is why only the model DECLARATIONS needed this care.

Default points host-run jobs/API at the Dockerized Postgres on port 5433.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

APP_DATABASE_URL = os.getenv(
    "APP_DATABASE_URL",
    "postgresql+psycopg2://app:app@localhost:5433/campaigns",
)

# pool_pre_ping avoids handing out a dead connection after the DB container
# restarts (which, under our restart:unless-stopped policy, it will).
engine = create_engine(APP_DATABASE_URL, pool_pre_ping=True, future=True)

SessionLocal = sessionmaker(
    bind=engine, autoflush=False, expire_on_commit=False, future=True
)

# Declarative base shared by all product models and Alembic autogenerate.
Base = declarative_base()


def ping() -> bool:
    """Lightweight DB liveness check (used by /health/pipeline). Never raises."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
