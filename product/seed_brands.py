# product/seed_brands.py
"""Seed / update the watchlist_brands table from a JSON bootstrap
(config/watchlist_brands.json by default). This is the "bring your own brand"
entry point: edit the JSON, run `make seed-brands`.

Idempotent: upserts by brand_name, so re-running updates aliases/priority
without creating duplicates.
"""
from __future__ import annotations

import json
import os
import sys

from sqlalchemy.dialects.postgresql import insert as pg_insert

from product.db import SessionLocal
from product.models import WatchlistBrand

SEED_DEFAULT = os.getenv("WATCHLIST_SEED", "config/watchlist_brands.json")


def seed(path: str = SEED_DEFAULT) -> dict:
    with open(path) as f:
        data = json.load(f)
    rows = []
    for b in data.get("brands", []):
        name = (b.get("brand_name") or "").strip().lower()
        if not name:
            continue
        aliases = [a.strip().lower() for a in b.get("aliases", []) if a and a.strip()]
        rows.append({
            "brand_name": name,
            "aliases": ",".join(aliases) or None,
            "priority": int(b.get("priority", 100)),
            "customer_scope": b.get("customer_scope", "default"),
            "active": bool(b.get("active", True)),
        })
    if not rows:
        return {"seeded": 0, "path": path}
    with SessionLocal() as s:
        stmt = pg_insert(WatchlistBrand).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["brand_name"],
            set_={
                "aliases": stmt.excluded.aliases,
                "priority": stmt.excluded.priority,
                "customer_scope": stmt.excluded.customer_scope,
                "active": stmt.excluded.active,
            },
        )
        s.execute(stmt)
        s.commit()
    return {"seeded": len(rows), "path": path, "brands": [r["brand_name"] for r in rows]}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = argv[0] if argv else SEED_DEFAULT
    print(seed(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
