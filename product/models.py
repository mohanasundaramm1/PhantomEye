# product/models.py
"""SQLAlchemy ORM models for the campaign-radar application layer.

Day 2 slice: only the two tables the vertical slice needs first --
`ct_observations` (normalized scored observations) and `watchlist_brands`
(the "bring your own brand" pack). Campaign/cluster/disposition tables are
added as the slice deepens (Days 4-5 and the deepening tracks).

Design decisions baked in here:

- ct_observations is UPSERT-IN-PLACE, keyed by (raw_host, event_ts). The CT
  enrichment pipeline fills DNS/geo in the <5s hot path and WHOIS minutes-to-
  hours later via the cold backfill, so the same observation is re-ingested
  with more enrichment over time. The row holds the current best state; the
  immutable per-evidence timeline (evidence_events) is a later table. This is
  the resolution of the "observation mutability" ambiguity.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from product.db import Base


class CtObservation(Base):
    """One row per scored CT domain observation, projected from
    gold/threat_scores/*.parquet. Enrichment columns are updated in place as
    late cold-path data lands (upsert by raw_host+event_ts)."""

    __tablename__ = "ct_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # identity / provenance
    raw_host: Mapped[str] = mapped_column(String(512), index=True)
    registered_domain: Mapped[str | None] = mapped_column(String(320), index=True)
    event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str | None] = mapped_column(String(64))
    source_file: Mapped[str | None] = mapped_column(String(512))

    # scoring / decision (from the ML scorer + MISP fusion)
    triage_score: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float | None] = mapped_column(Float, index=True)
    risk_label_final: Mapped[int | None] = mapped_column(Integer)
    decision_reason: Mapped[str | None] = mapped_column(String(64))
    model_used: Mapped[str | None] = mapped_column(String(32))
    ti_misp_hit: Mapped[int | None] = mapped_column(Integer)

    # enrichment -- late-arriving via the cold path, upserted in place
    enrichment_level: Mapped[str | None] = mapped_column(String(16))
    registrar: Mapped[str | None] = mapped_column(String(256))
    whois_status: Mapped[str | None] = mapped_column(String(256))
    whois_created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    whois_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sample_asn: Mapped[str | None] = mapped_column(String(32))
    sample_isp: Mapped[str | None] = mapped_column(String(256))
    sample_country: Mapped[str | None] = mapped_column(String(8))
    num_unique_ips: Mapped[int | None] = mapped_column(Integer)
    num_countries: Mapped[int | None] = mapped_column(Integer)
    num_asns: Mapped[int | None] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        # the upsert conflict target (W4 decision: one row per host+event_ts)
        UniqueConstraint("raw_host", "event_ts", name="uq_obs_host_eventts"),
    )


class WatchlistBrand(Base):
    """A brand the analyst cares about -- the "bring your own brand" pack.
    Campaign target-brand attribution and customer-relevance ranking key off
    this table (seeded from a JSON/YAML bootstrap on Day 4)."""

    __tablename__ = "watchlist_brands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    brand_name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    # comma-separated aliases/tokens to also match (e.g. "paypalinc,paypal-support")
    aliases: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    customer_scope: Mapped[str] = mapped_column(String(64), default="default")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CampaignCluster(Base):
    """One infrastructure cluster = one campaign lead. Identity is a STABLE
    cluster_key (W3 decision): sha1(target_brand | burst-day | lexical-family).
    Clusters MERGE as new matching observations arrive (re-run finds the key and
    grows the cluster); they are never auto-split. Stage/merge transitions get
    logged to campaign_stage_history in a later track."""

    __tablename__ = "campaign_clusters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    status: Mapped[str] = mapped_column(String(16), default="open")
    stage: Mapped[str] = mapped_column(String(16), default="new")  # new/warming/active/confirmed/suppressed
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    target_brand: Mapped[str | None] = mapped_column(String(128), index=True)
    target_workflow: Mapped[str | None] = mapped_column(String(32))  # filled in Track C

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    summary_reason: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ClusterMember(Base):
    """Join row: an observation belongs to a cluster, with the reason/score it
    was admitted. Unique on (cluster_id, observation_id) so re-runs are
    idempotent (an observation is added to a cluster at most once)."""

    __tablename__ = "cluster_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(
        ForeignKey("campaign_clusters.id", ondelete="CASCADE"), index=True
    )
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("ct_observations.id", ondelete="CASCADE"), index=True
    )
    membership_reason: Mapped[str | None] = mapped_column(String(256))
    membership_score: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("cluster_id", "observation_id", name="uq_member_cluster_obs"),
    )
