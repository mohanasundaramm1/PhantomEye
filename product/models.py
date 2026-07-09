# product/models.py
"""SQLAlchemy ORM models for the campaign-radar application layer.

Deliberately uses the CLASSIC declarative style (Column(), not Mapped[]/
mapped_column()/DeclarativeBase) -- see product/db.py's module docstring for
why: these models are imported both by the host venv (SQLAlchemy 2.0.36) and
by Airflow's containers (campaign_radar_dag's tasks run against Airflow's own
bundled SQLAlchemy 1.4.52, which the 2.0-only declaration style can't run
under at all). Classic Column() mapping behaves identically under both.

Design decisions baked in here:

- ct_observations is UPSERT-IN-PLACE, keyed by (raw_host, event_ts). The CT
  enrichment pipeline fills DNS/geo in the <5s hot path and WHOIS minutes-to-
  hours later via the cold backfill, so the same observation is re-ingested
  with more enrichment over time. The row holds the current best state; the
  immutable per-evidence timeline lives in evidence_events. This is the
  resolution of the "observation mutability" ambiguity.
- campaign_clusters.stage transitions are centralized in
  product/stage_engine.py -- see that module for the concurrency/locking
  design (stage_locked_by/stage_locked_at below exist for it).
- evidence_events.cluster_id is a direct FK (not observation_id) -- correct
  given clusters merge-never-split, so cluster is the stable identity
  evidence attaches to (product/stage_engine.py has the full reasoning).
"""
from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

from product.db import Base


class CtObservation(Base):
    """One row per scored CT domain observation, projected from
    gold/threat_scores/*.parquet. Enrichment columns are updated in place as
    late cold-path data lands (upsert by raw_host+event_ts)."""

    __tablename__ = "ct_observations"

    id = Column(Integer, primary_key=True)

    # identity / provenance
    raw_host = Column(String(512), index=True, nullable=False)
    registered_domain = Column(String(320), index=True)
    event_ts = Column(DateTime(timezone=True), index=True)
    source = Column(String(64))
    source_file = Column(String(512))

    # scoring / decision (from the ML scorer + MISP fusion)
    triage_score = Column(Float)
    risk_score = Column(Float, index=True)
    risk_label_final = Column(Integer)
    decision_reason = Column(String(64))
    model_used = Column(String(32))
    ti_misp_hit = Column(Integer)

    # enrichment -- late-arriving via the cold path, upserted in place
    enrichment_level = Column(String(16))
    registrar = Column(String(256))
    whois_status = Column(String(256))
    whois_created = Column(DateTime(timezone=True))
    whois_expires = Column(DateTime(timezone=True))
    sample_asn = Column(String(32))
    sample_isp = Column(String(256))
    sample_country = Column(String(8))
    num_unique_ips = Column(Integer)
    num_countries = Column(Integer)
    num_asns = Column(Integer)

    # Track C prep (content/lifecycle probe, disabled by default -- see
    # product/content_probe.py): schema landed a day early so Day 10 starts
    # with the columns ready. All null until the probe runs (and it won't,
    # until explicitly enabled via config/content_probe.json).
    http_status = Column(Integer)
    content_fingerprint = Column(String(64))  # sha256 of title+favicon+keyword hits
    mx_present = Column(Boolean)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        # the upsert conflict target (W4 decision: one row per host+event_ts)
        UniqueConstraint("raw_host", "event_ts", name="uq_obs_host_eventts"),
    )


class WatchlistBrand(Base):
    """A brand the analyst cares about -- the "bring your own brand" pack.
    Campaign target-brand attribution and customer-relevance ranking key off
    this table (seeded from a JSON/YAML bootstrap on Day 4)."""

    __tablename__ = "watchlist_brands"

    id = Column(Integer, primary_key=True)
    brand_name = Column(String(128), unique=True, index=True, nullable=False)
    # comma-separated aliases/tokens to also match (e.g. "paypalinc,paypal-support")
    aliases = Column(Text)
    priority = Column(Integer, default=100, nullable=False)
    customer_scope = Column(String(64), default="default", nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    # comma-separated legitimate domains for this brand (e.g. "apple.com,icloud.com").
    # A convenience mirror, not the source of truth: matching code (ct/ingest/triage.py,
    # product/assemble_campaigns.py) reads config/triage.json::brand_self_domains
    # directly. The API write-through keeps the two in sync for brands tracked here;
    # config/triage.json can still cover brands with no WatchlistBrand row at all.
    self_domains = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Analyst(Base):
    """Minimal analyst directory -- NOT an auth system (no password/session,
    no login). Exists to populate an assignee dropdown and support a "my
    queue" filter in the UI. CampaignCluster.assignee and
    AnalystDisposition.analyst deliberately stay free-text String columns,
    not a hard FK to this table: those tables already have live data, and a
    soft directory (used for dropdown population / reporting, not
    constraint enforcement) avoids a disruptive migration and a hard
    failure mode if someone assigns to a name not yet listed here."""

    __tablename__ = "analysts"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    display_name = Column(String(128))
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CampaignCluster(Base):
    """One infrastructure cluster = one campaign lead. Identity is a STABLE
    cluster_key (W3 decision): sha1(target_brand | burst-day | lexical-family).
    Clusters MERGE as new matching observations arrive (re-run finds the key and
    grows the cluster); they are never auto-split. Stage transitions are
    centralized in product/stage_engine.py, logged to evidence_events."""

    __tablename__ = "campaign_clusters"

    id = Column(Integer, primary_key=True)
    cluster_key = Column(String(64), unique=True, index=True, nullable=False)

    status = Column(String(16), default="open", nullable=False)
    stage = Column(String(16), default="new", nullable=False)  # new/warming/active/confirmed/suppressed
    confidence_score = Column(Float, default=0.0, index=True, nullable=False)

    target_brand = Column(String(128), index=True)
    target_workflow = Column(String(32))  # filled in Track C

    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    observation_count = Column(Integer, default=0, nullable=False)
    summary_reason = Column(Text)

    # Queue/assignment state (decision #1: folded in here rather than a
    # separate campaign_alerts table -- no benefit to a redundant 1:1 join at
    # this scale; this table already IS "the queue item" for its cluster).
    # server_default (not just Python-side default=) so ALTER TABLE ... NOT
    # NULL can backfill existing rows -- this column is added to a table that
    # already has data, unlike status/stage which existed since Day 4's
    # original (empty-table) migration.
    queue_status = Column(String(16), default="new", server_default="new", nullable=False)  # new/in_review/escalated/closed/suppressed
    assignee = Column(String(64))
    sla_bucket = Column(String(16))
    promoted_at = Column(DateTime(timezone=True))
    last_ranked_at = Column(DateTime(timezone=True))

    # Manual disposition lock (product/stage_engine.py). Not a bool: the UI
    # needs "confirmed by analyst X on <date>", and an audit trail needs to
    # distinguish an analyst's override from an automatic MISP-hit confirm.
    # Set atomically with `stage` by the disposition endpoint; the automatic
    # stage-evaluation path checks this but never clears it -- unlocking is
    # only ever an explicit future action.
    stage_locked_by = Column(String(64))
    stage_locked_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class EvidenceEvent(Base):
    """Immutable lifecycle timeline for a campaign cluster: cert seen, DNS
    resolved, stage transitions, disposition recorded, content-probe result,
    suppression match, etc. cluster_id is a direct FK (not observation_id) --
    correct given clusters merge-never-split (product/stage_engine.py has the
    full reasoning), so cluster is the stable identity evidence attaches to."""

    __tablename__ = "evidence_events"

    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey("campaign_clusters.id", ondelete="CASCADE"), index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False)
    observed_at = Column(DateTime(timezone=True), index=True, nullable=False)
    detail = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AnalystDisposition(Base):
    """An analyst's recorded verdict on a campaign. The MOST RECENT disposition
    for a cluster is what product/stage_engine.py's apply_stage_transition()
    treats as authoritative (it also sets stage_locked_by/stage_locked_at on
    CampaignCluster in the same transaction as this row's insert -- see
    POST /campaigns/{id}/disposition in api/main.py)."""

    __tablename__ = "analyst_dispositions"

    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey("campaign_clusters.id", ondelete="CASCADE"), index=True, nullable=False)
    verdict = Column(String(16), nullable=False)  # confirmed/suppressed/benign
    severity = Column(String(16))
    notes = Column(Text)
    actor_guess = Column(String(128))  # analyst's free-text guess at the threat actor, if any
    action_taken = Column(String(128))
    analyst = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SuppressionRule(Base):
    """An analyst-authored rule excluding matching observations from campaign
    assembly. rule_type is one of domain/registrar/asn (matching logic lives
    in product/suppression.py, reused by assemble_campaigns.py). A rule with
    expires_at in the past is inert without needing a cleanup job -- the
    matcher checks both active and expiry at read time."""

    __tablename__ = "suppression_rules"

    id = Column(Integer, primary_key=True)
    rule_type = Column(String(16), nullable=False, index=True)  # domain | registrar | asn
    match_value = Column(String(320), nullable=False)
    scope = Column(String(64), default="default", server_default="default", nullable=False)
    reason = Column(Text)
    expires_at = Column(DateTime(timezone=True))
    created_by = Column(String(64), nullable=False)
    active = Column(Boolean, default=True, server_default="true", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ClusterMember(Base):
    """Join row: an observation belongs to a cluster, with the reason/score it
    was admitted. Unique on (cluster_id, observation_id) so re-runs are
    idempotent (an observation is added to a cluster at most once)."""

    __tablename__ = "cluster_members"

    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey("campaign_clusters.id", ondelete="CASCADE"), index=True, nullable=False)
    observation_id = Column(Integer, ForeignKey("ct_observations.id", ondelete="CASCADE"), index=True, nullable=False)
    membership_reason = Column(String(256))
    membership_score = Column(Float)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("cluster_id", "observation_id", name="uq_member_cluster_obs"),
    )
