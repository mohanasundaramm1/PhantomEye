# product/db.py
"""Engine, session factory, declarative Base, and a liveness ping for the
campaign-radar application datastore.

Connection comes from APP_DATABASE_URL (see docker-compose.yml `app-db`).
Default points host-run jobs/API at the Dockerized Postgres on port 5433.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

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


class Base(DeclarativeBase):
    """Declarative base shared by all product models and Alembic autogenerate."""


def ping() -> bool:
    """Lightweight DB liveness check (used by /health/pipeline). Never raises."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
