# product/export.py
"""Egress export for a campaign cluster -- Phase 6's lowest-priority item.
Two formats:

- json: a clean structured summary (campaign + member domains + latest
  disposition) for feeding another internal tool.
- stix: a minimal, hand-built STIX 2.1 bundle (Campaign SDO + one Indicator
  SDO per member domain + "indicates" Relationship SDOs) for feeding a SIEM
  or TIP that consumes STIX. No `stix2` library dependency -- STIX 2.1
  objects are just JSON with a handful of required properties per type, and
  a bundle this small doesn't need the full SDK.

GET, not POST (the plan's own sketch used POST) -- this reads and formats
already-computed data with no side effect, so GET is the correct verb; it
also matches every other read endpoint in api/main.py (GET
/campaigns/{id}, GET /campaigns/{id}/disposition-provenance).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def _stix_ts(dt: datetime | None) -> str:
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def campaign_to_json(cluster, members: list, disposition) -> dict:
    """`members` is a list of CtObservation rows (via ClusterMember join, same
    query already used by GET /campaigns/{id}). `disposition` is the most
    recent AnalystDisposition row for this cluster, or None."""
    return {
        "export_format": "json",
        "exported_at": _stix_ts(None),
        "campaign": {
            "campaign_id": cluster.id,
            "cluster_key": cluster.cluster_key,
            "target_brand": cluster.target_brand,
            "target_workflow": cluster.target_workflow,
            "stage": cluster.stage,
            "confidence_score": round(cluster.confidence_score, 4) if cluster.confidence_score is not None else None,
            "summary_reason": cluster.summary_reason,
            "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
            "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
        },
        "disposition": None if disposition is None else {
            "verdict": disposition.verdict,
            "analyst": disposition.analyst,
            "severity": disposition.severity,
            "notes": disposition.notes,
            "created_at": disposition.created_at.isoformat() if disposition.created_at else None,
        },
        "indicators": [
            {
                "domain": o.registered_domain or o.raw_host,
                "raw_host": o.raw_host,
                "risk_score": round(o.risk_score, 4) if o.risk_score is not None else None,
                "registrar": o.registrar,
                "sample_asn": o.sample_asn,
                "first_observed": o.event_ts.isoformat() if o.event_ts else None,
            }
            for o in members
        ],
    }


def campaign_to_stix(cluster, members: list, disposition) -> dict:
    """Minimal valid STIX 2.1 bundle. Only emits indicators for domains with
    a registered_domain on record (a null domain can't become a STIX
    pattern) -- callers should treat a shorter `objects` list as normal, not
    an error; see the note field on the returned bundle-adjacent dict."""
    now = _stix_ts(None)
    created = _stix_ts(cluster.first_seen)

    campaign_id = _stix_id("campaign")
    objects = [
        {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": created,
            "modified": now,
            "name": f"{cluster.target_brand or 'unattributed'} impersonation cluster {cluster.cluster_key}",
            "description": cluster.summary_reason or "",
            "x_phantomeye_confidence_score": round(cluster.confidence_score, 4) if cluster.confidence_score is not None else None,
            "x_phantomeye_stage": cluster.stage,
        }
    ]

    skipped = 0
    for o in members:
        domain = o.registered_domain or o.raw_host
        if not domain:
            skipped += 1
            continue
        indicator_id = _stix_id("indicator")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": _stix_ts(o.event_ts),
            "modified": now,
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": _stix_ts(o.event_ts),
            "name": domain,
            "x_phantomeye_risk_score": round(o.risk_score, 4) if o.risk_score is not None else None,
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship"),
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": campaign_id,
        })

    if disposition is not None:
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": _stix_id("note"),
            "created": _stix_ts(disposition.created_at),
            "modified": now,
            "content": f"Analyst disposition: {disposition.verdict} by {disposition.analyst}"
                       + (f" -- {disposition.notes}" if disposition.notes else ""),
            "object_refs": [campaign_id],
        })

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
        "x_phantomeye_skipped_domains": skipped,
    }
