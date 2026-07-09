"""Phase 5 watchlist CRUD API: GET/POST/PUT/DELETE /watchlist. DB-backed,
skips cleanly when app-db isn't reachable -- same pattern as
tests/test_analyst_workflow_endpoints.py. Calls endpoint functions directly
to avoid a TestClient/httpx dependency.

self_domains write-through is isolated from the real config/triage.json via
monkeypatch + tmp_path -- never touches the real file.
"""
import json

import pytest

from product.db import ping

_DB = ping()


@pytest.fixture
def isolated_triage_config(tmp_path, monkeypatch):
    path = tmp_path / "triage.json"
    path.write_text(json.dumps({"brand_self_domains": {}}))
    monkeypatch.setenv("CT_TRIAGE_CONFIG", str(path))
    return path


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_list_watchlist_shape_and_active_filter():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import WatchlistBrand

    from api.main import list_watchlist

    with SessionLocal() as s:
        active = WatchlistBrand(brand_name="zztest-active-brand", priority=100, active=True)
        inactive = WatchlistBrand(brand_name="zztest-inactive-brand", priority=100, active=False)
        s.add_all([active, inactive])
        s.commit()
        ids = [active.id, inactive.id]

        try:
            j = list_watchlist(active_only=True)
            assert j["available"] is True
            names = {b["brand_name"] for b in j["brands"]}
            assert "zztest-active-brand" in names
            assert "zztest-inactive-brand" not in names

            j_all = list_watchlist(active_only=False)
            names_all = {b["brand_name"] for b in j_all["brands"]}
            assert "zztest-inactive-brand" in names_all
        finally:
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.id.in_(ids)))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_create_watchlist_brand_success_and_duplicate_conflict(isolated_triage_config):
    from fastapi import HTTPException
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import WatchlistBrand

    from api.main import WatchlistBrandRequest, create_watchlist_brand

    req = WatchlistBrandRequest(
        brand_name="zztest-create-brand",
        aliases=["zzalias"],
        priority=175,
        self_domains=["zztest-create.example.com"],
    )
    result = create_watchlist_brand(req)
    try:
        assert result["available"] is True
        assert result["brand_name"] == "zztest-create-brand"
        assert result["aliases"] == ["zzalias"]
        assert result["self_domains"] == ["zztest-create.example.com"]

        # write-through landed in the isolated config file, not the real one
        cfg = json.loads(isolated_triage_config.read_text())
        assert cfg["brand_self_domains"]["zztest-create-brand"] == ["zztest-create.example.com"]

        # duplicate brand_name -> 409, not a raw DB error
        with pytest.raises(HTTPException) as ei:
            create_watchlist_brand(WatchlistBrandRequest(brand_name="zztest-create-brand"))
        assert ei.value.status_code == 409
    finally:
        with SessionLocal() as s:
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == "zztest-create-brand"))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_create_watchlist_brand_missing_name_is_422():
    from fastapi import HTTPException

    from api.main import WatchlistBrandRequest, create_watchlist_brand

    with pytest.raises(HTTPException) as ei:
        create_watchlist_brand(WatchlistBrandRequest(brand_name="   "))
    assert ei.value.status_code == 422


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_update_watchlist_brand_only_touches_provided_fields(isolated_triage_config):
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import WatchlistBrand

    from api.main import WatchlistBrandUpdateRequest, update_watchlist_brand

    with SessionLocal() as s:
        brand = WatchlistBrand(
            brand_name="zztest-update-brand",
            aliases="original-alias",
            priority=100,
            self_domains="original.example.com",
            active=True,
        )
        s.add(brand)
        s.commit()
        bid = brand.id

        try:
            # Only priority provided -- aliases/self_domains must survive untouched.
            result = update_watchlist_brand(bid, WatchlistBrandUpdateRequest(priority=250))
            assert result["priority"] == 250
            assert result["aliases"] == ["original-alias"]
            assert result["self_domains"] == ["original.example.com"]

            # Now touch self_domains explicitly -- write-through should fire.
            update_watchlist_brand(bid, WatchlistBrandUpdateRequest(self_domains=["new.example.com"]))
            cfg = json.loads(isolated_triage_config.read_text())
            assert cfg["brand_self_domains"]["zztest-update-brand"] == ["new.example.com"]
        finally:
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.id == bid))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_update_nonexistent_brand_is_404():
    from fastapi import HTTPException

    from api.main import WatchlistBrandUpdateRequest, update_watchlist_brand

    with pytest.raises(HTTPException) as ei:
        update_watchlist_brand(999999, WatchlistBrandUpdateRequest(priority=1))
    assert ei.value.status_code == 404


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_deactivate_watchlist_brand_soft_deletes_not_hard_deletes():
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import WatchlistBrand

    from api.main import deactivate_watchlist_brand

    with SessionLocal() as s:
        brand = WatchlistBrand(brand_name="zztest-deactivate-brand", priority=100, active=True)
        s.add(brand)
        s.commit()
        bid = brand.id

        try:
            result = deactivate_watchlist_brand(bid)
            assert result["active"] is False

            # row still exists -- soft delete, not a hard delete. expire_all()
            # first: the endpoint mutated via its own separate SessionLocal(),
            # so this session's identity-mapped `brand` object is stale until
            # forced to re-fetch.
            s.expire_all()
            row = s.execute(select(WatchlistBrand).where(WatchlistBrand.id == bid)).scalar_one_or_none()
            assert row is not None
            assert row.active is False
        finally:
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.id == bid))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_deactivate_nonexistent_brand_is_404():
    from fastapi import HTTPException

    from api.main import deactivate_watchlist_brand

    with pytest.raises(HTTPException) as ei:
        deactivate_watchlist_brand(999999)
    assert ei.value.status_code == 404
