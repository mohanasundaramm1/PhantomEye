# product/seed_analysts.py
"""Seed / update the analysts table from a JSON bootstrap
(config/analysts.json by default). Mirrors product/seed_brands.py's
pattern. NOT an auth system -- just populates the assignee dropdown and
"my queue" filter (see product/models.py::Analyst's docstring).

Idempotent: upserts by username, so re-running updates display_name/active
without creating duplicates.

Run:
    python -m product.seed_analysts [path/to/analysts.json]
"""
from __future__ import annotations

import json
import os
import sys

from sqlalchemy.dialects.postgresql import insert as pg_insert

from product.db import SessionLocal
from product.models import Analyst

SEED_DEFAULT = os.getenv("ANALYSTS_SEED", "config/analysts.json")


def seed(path: str = SEED_DEFAULT) -> dict:
    with open(path) as f:
        data = json.load(f)
    rows = []
    for a in data.get("analysts", []):
        username = (a.get("username") or "").strip().lower()
        if not username:
            continue
        rows.append({
            "username": username,
            "display_name": a.get("display_name") or username,
            "active": bool(a.get("active", True)),
        })
    if not rows:
        return {"seeded": 0, "path": path}
    with SessionLocal() as s:
        stmt = pg_insert(Analyst).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["username"],
            set_={"display_name": stmt.excluded.display_name, "active": stmt.excluded.active},
        )
        s.execute(stmt)
        s.commit()
    return {"seeded": len(rows), "path": path, "analysts": [r["username"] for r in rows]}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = argv[0] if argv else SEED_DEFAULT
    print(seed(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
