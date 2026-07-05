# Campaign Radar (`product/`)

This is the analyst-grade layer on top of the CT scoring pipeline: it turns
scored domain observations into brand-attributed **campaigns** an analyst can
review, confirm, suppress, and measure — not a flat list of scored domains.

## Architecture in one picture

```
gold/threat_scores/*.parquet  (CT scoring pipeline -- unchanged, upstream of this layer)
        |
        v
ingest_observations.py  -->  ct_observations   (Postgres, upsert by raw_host+event_ts)
        |
        v
assemble_campaigns.py   -->  campaign_clusters, cluster_members  (brand+burst+lexical-family key)
        |                    - suppression_rules checked at candidate time
        |                    - target_workflow classified (config/workflow_intent.json)
        |                    - weighted membership_score computed
        v
stage_engine.py (apply_stage_transition)  -->  evidence_events, campaign_clusters.stage
        ^  ^  ^  ^
        |  |  |  content_probe.py (disabled by default -- see below)
        |  |  disposition endpoint (api/main.py)
        |  assemble_campaigns.py
        ingest_observations.py

api/main.py  -->  GET/POST /campaigns, /suppressions, /metrics/*  -->  web/src/app/page.tsx
```

`ingest_observations.py` and `assemble_campaigns.py` run every 2 hours via
`airflow/dags/campaign_radar_dag.py` — this is NOT a manual process; the queue
populates itself. `docker compose -f airflow/docker-compose.airflow.yml`
containers reach the app-db (a separate Compose project) via
`host.docker.internal`, not `localhost` — see that DAG file's env vars if this
ever needs re-pointing.

## Bringing it up from scratch

```bash
docker compose up -d app-db                      # Postgres for this layer
.venv/bin/alembic upgrade head                   # apply all migrations
.venv/bin/python -m product.seed_brands          # load config/watchlist_brands.json
make up-all                                      # if the Airflow stack isn't already running
# campaign_radar_dag picks up from here automatically, every 2h
```

To force one cycle immediately instead of waiting:
```bash
.venv/bin/python -m product.ingest_observations
.venv/bin/python -m product.assemble_campaigns
```

## Day-to-day operations

- **Add a brand**: edit `config/watchlist_brands.json`, run
  `python -m product.seed_brands`. Takes effect on the next `assemble()` run.
- **Suppress noise**: `POST /suppressions` (`rule_type`: domain/registrar/asn).
  Takes effect on the next `assemble()` run — both for new candidates (never
  cluster) and for existing clusters whose members have all come to match
  (pushed to `stage=suppressed` automatically).
- **Review the queue**: `GET /campaigns` (the UI's "Campaign Queue" section).
  A cluster stays visible even below the confidence bar once an analyst has
  disposed it (`stage_locked_by` set) — found live during Day 8, fixed, so a
  confirmed campaign can never silently vanish from view.
- **Disposition**: `POST /campaigns/{id}/disposition` (`verdict`: confirmed/
  suppressed/benign). This LOCKS the stage — automatic re-evaluation (ingest/
  assemble/probe) can no longer move it until a new disposition is recorded.
- **Check pipeline health**: `GET /health/pipeline` (also the queue's health
  strip in the UI) — real freshness/DB/watchdog state, not decoration.
- **Check the proof**: `GET /metrics/operations`, `/metrics/lead-time`,
  `/metrics/precision-at-k` (also the "Metrics & Proof" UI section). Each one
  carries its own honesty check — a 0-sample precision@K or lead-time result
  says so explicitly rather than reading like a real number.

## The content probe is OFF by default

`product/content_probe.py` fetches suspected-malicious infrastructure
directly from this machine — real opsec exposure, distinct from every other
job here. `config/content_probe.json`'s `enabled` must be explicitly flipped
to `true` before a single network call happens. It ships fully built and
tested; nothing is half-finished, it's just gated. Enabling it is a deliberate
choice, not an oversight to fix.

## Known, accepted limitations (not bugs — documented scope cuts)

- **Brand re-attribution race** (see `product/stage_engine.py`'s docstring):
  editing `watchlist_brands` between two `assemble()` runs could theoretically
  let the same observation join a second cluster. Real but narrow; not fixed.
- **SAN/nameserver clustering** is deferred — the CT ingest pipeline doesn't
  currently capture a per-certificate identifier (`forwarder.py` explodes a
  multi-SAN cert into independent per-domain Kafka messages), so "these
  domains shared a certificate" can't be reconstructed downstream today.
- **Favicon hashing** in the content probe was scoped out (one HTTP request
  per target, not two) — documented in `content_probe.py`, not silent.
- **No auth** on mutating endpoints (`/campaigns/{id}/disposition`,
  `/suppressions`, etc.) — consistent with the rest of this API, which is
  already fully unauthenticated. This is a local, single-analyst tool.

## Reliability

Stage transitions are the one place in this layer with a row lock
(`SELECT ... FOR UPDATE` in `apply_stage_transition()`) — every other write
path here is lock-free by design (pure appends + `ON CONFLICT DO NOTHING`).
See `product/stage_engine.py`'s module docstring for the full reasoning and
the exact lost-update race this prevents; it was caught by an architecture
review before any code was written, not discovered in production.

For the reliability of the CT ingestion lane feeding this layer (the
"why is the dashboard blank" class of problem), see `ops/launchd/README.md`.
