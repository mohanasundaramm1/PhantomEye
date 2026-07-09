# PhantomEye / threat-intel — Acquisition Due-Diligence Audit

**Auditor stance:** hostile, evidence-only. Every claim cites a file:line or literal command output. Unverifiable claims are labeled `UNVERIFIED`.
**Date of audit:** 2026-07-09
**Repo:** `/Users/mohanasundarammurugasen/dev/threat-intel`, branch `feat/campaign-radar-deepening` (8 commits ahead of `master`, unmerged).

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Phase 0 — Inventory](#phase-0--inventory)
3. [Phase 1 — What Each Phase Shipped](#phase-1--what-each-phase-actually-shipped)
4. [Phase 2 — Actual Data Flow](#phase-2--actual-data-flow)
5. [Phase 3 — Code Quality & Correctness](#phase-3--code-quality--correctness)
6. [Phase 4 — Docs vs Reality](#phase-4--documentation-vs-reality)
7. [Phase 5 — End-User Workflow](#phase-5--end-user-workflow)
8. [Phase 6 — SWOT (per dimension)](#phase-6--swot)
9. [Phase 7 — Root Cause](#phase-7--root-cause-analysis)
10. [Phase 8 — Remediation Roadmap](#phase-8--remediation-roadmap)
11. [Phase 9 — Smallest Coherent Working Slice](#phase-9--smallest-coherent-working-slice)
12. [Prioritized Backlog (P0/P1/P2)](#prioritized-backlog)

---

## 1. Executive Summary

**This is not "mostly broken."** The Python unit-test suite is real and green (`285 passed` — verified, `python -m pytest -q`), the FastAPI service and Next.js console are wired to each other, and the campaign-radar Postgres workflow runs end-to-end. Someone who knows the incantations can demo a coherent vertical slice: CT domain → scored observation → brand-attributed campaign cluster → analyst disposition → export. That slice genuinely works.

**But the headline production pipeline is red, and a task recently marked "done and verified" is provably still broken in the code.**

The three findings that would stop an acquisition until resolved:

1. **`ct_enrich_and_score_dag` run-state is FAILED on recent scheduled runs, but the DAG is alive, not dead** (verified: `airflow dags list-runs`; task states show `enrich_hot`, `score_ct_with_latest`, `enrich_backfill` all `success`, only `freshness_gate` `failed`). The gate is correctly catching that the newest scored content is ~22h old (threshold 6h). **Root cause: an upstream Kafka consumer backlog** — the `ct-events` topic holds ~6.88M messages (`GetOffsetShell` latest offset 6,883,673), the forwarder is producing fresh (`event_ts` 2026-07-09T03:50:58Z live), but Spark `stream_ct` is ~22h / millions of offsets behind, draining oldest-first. `event_ts` is stamped at produce (`ct/ingest/forwarder.py:142`), `ingest_ts` at consume (`ct/ingest/stream_ct.py:175`); their ~22h gap in the raw parquet is the backlog itself. The pipeline runs; its output is not analyst-trustworthy because it is 22h stale.

2. **The "tier2 enrichment starvation" fix is not in the code — a SEPARATE problem from #1.** `ct/enrich/enrich_worker.py:333` still hardcodes `whois_mode="cache_only"` — the exact line the prior work claimed to have diagnosed and fixed. Live proof it never took effect: `SELECT enrichment_level, count(*)` returns `{tier0: 4738, tier1: 3916}` — **zero tier2 rows out of 8,654**. WHOIS/geo enrichment has never advanced past tier1, which explains the permanently-empty geo panels the UI hides. **Correction to an earlier draft: this does NOT cause finding #1's freshness failure** — `cache_only` controls enrichment depth, while `event_ts` freshness is set upstream at ingest. They are independent.

3. **~40% of the current work is uncommitted and unmerged.** 38 files are dirty (`git status --short | wc -l` → 38), including 2 Alembic migrations, 7 new modules, and 8 new test files — an entire "deepening" phase living only in the working tree. `master` does not have any of it. There is no CI (`.github/workflows` does not exist) to have caught the DAG breakage or to gate a merge.

Supporting rot: a **61 MB data tarball is committed to git** (`backup_bronze_silver_2025-10-30_1400.tgz`), a **running `investigation-api` container serves from a different repo checkout entirely** (`/Users/…/To-be-shared-FINAL-PACKAGE/threat-intel/`, not this one), duplicate-but-divergent `week5` scripts exist in two places, and the README advertises "98.8% ROC-AUC" / "Self-Driving ML Core" while the live model metadata's own promotion record carries two credibility warnings (no genuine temporal split, benign-FPR check skipped).

**Verdict:** the product-layer vertical slice (campaign radar) is acquirable and largely real. The "real-time predictive CT pipeline" that the README leads with is **currently non-functional in production** and has been for days, masked by a green unit-test suite that does not exercise the live DAG. Treat the two halves of this repo as having very different maturity.

---

## Phase 0 — Inventory

**Scale (verified):** `git ls-files | wc -l` → **146 tracked files**. Tracked distribution by top dir: `tests 21, web 20, airflow 20, ct 19, product 12, ml 11, alembic 8, ops 6, config 6`.

**Stack (discovered, correcting the brief's memory):**
- Orchestration: **Airflow 2.9.x** (14 DAGs, all parse clean — `airflow dags list-import-errors` → "No data found").
- Streaming: **Kafka + Spark Structured Streaming**, two lanes (synthetic `domain-events`, real `ct-events`). Both `pipelines/spark_stream.py` and `pipelines/spark_stream_contract.py` exist.
- Lakehouse: Bronze/Silver/Gold Parquet — **all gitignored** (`.gitignore:10-16`), present locally (`bronze 55M, silver 36M, gold 31M, ct/data 2.7G`).
- ML: **LightGBM primary + LogReg fallback**, registry under `ml/models/registry/`.
- Service: **FastAPI** (`api/main.py`, single file, ~1150 lines).
- Entity store: **PostgreSQL 15 + SQLAlchemy + Alembic** (`product/`), app-db on `:5433`.
- Frontend: **Next.js** single-page console (`web/src/app/page.tsx`).
- Correct: the brief's memory of the stack is accurate. Addition it missed: a second **Streamlit** dashboard (`ct/dashboard/ct_dashboard.py`) still in-tree.

**Orphans / abandoned / junk (all verified):**

| Item | Evidence | Verdict |
|---|---|---|
| `backup_bronze_silver_2025-10-30_1400.tgz` (61 MB) | `git ls-files \| grep tgz` returns it | Committed binary blob. Repo bloat, should never be in git. |
| `pre_migration_airflow.log` | tracked | Stale log committed to VCS. |
| `.claude/launch.json` | tracked | Local tool config committed. |
| `airflow/analyze_week5_risk_clusters.py` vs `ml/legacy/analyze_week5_risk_clusters.py` | `diff -q` → **"differ"** | Duplicate, divergent copies of the same script. |
| `airflow/train_week5_baselines.py` vs `ml/legacy/train_week5_baselines.py` | `diff -q` → **"differ"** | Same problem. |
| `airflow/dags/hello.py` | `airflow dags list` shows `hello` | "Hello from Airflow" demo DAG still shipped. |
| `misp_ingest` vs `misp_osint_ingest` | both in `airflow dags list`; `misp_ingest` is_paused=True | Two MISP DAGs, one paused — competing implementations. |
| `investigation-api` container | `docker inspect` mounts `/Users/…/To-be-shared-FINAL-PACKAGE/threat-intel/ml` | **Running service whose source is NOT in this repo.** Orphan relative to this checkout. |
| `ct/dashboard/ct_dashboard.py` (Streamlit) | exists; README:56 calls it "legacy" | Second dashboard, superseded but retained. |
| `_archive_2025-11-03/` | present on disk, **not tracked** (`git ls-files` empty) | Local archive litter (harmless to git, confusing on disk). |

**Untracked-but-live (the uncommitted "deepening" phase):** 18 untracked files incl. `alembic/versions/7c3b00ffda82_analysts.py`, `alembic/versions/a6f283fd1568_watchlist_brands_self_domains.py`, `api/agent/internal_agent.py`, `product/export.py`, `product/repair_brand_matcher_clusters.py`, `product/recompute_cluster_confidence.py`, `product/seed_analysts.py`, `ct/score/rescore_ct_observations.py`, and 8 `tests/test_*.py`. Plus 20 modified tracked files. `git status --short | wc -l` → **38**.

**Test coverage (verified):** 30 files in `tests/`, all Python. `python -m pytest -q` → **285 passed, 1 warning**. **Zero frontend tests** (`web/package.json` scripts = `dev/build/start/lint` only; no jest/vitest/playwright; `find web/src -name '*.test.*'` empty). **Zero DAG/integration tests** — nothing exercises a live Airflow run.

---

## Phase 1 — What Each Phase Actually Shipped

Boundaries inferred from commit messages (`git log --all`). The project ran in two arcs: a Jan-2026 "console" arc and a Jul-2026 "campaign-radar Day 1–12 + ML-hardening + deepening" arc.

| Phase (commit) | Stated Goal | What Actually Shipped | End-to-End? | Evidence |
|---|---|---|---|---|
| Console v1–v2 (`fec1285`,`d21c405`,`d3c2e05`, Jan) | "Elite CTI console" | Next.js + FastAPI UI shell, 3D globe, scrollbar | Partial | Globe/geo panels now hidden — 0 country coverage (page.tsx `SHOW_GEO_PANELS=false`) |
| Perplexity agent (`6fe17c8`, Jul 1) | Chat agent + network graph | Perplexity client added… | **N (removed)** | Deleted this session (`git status` shows `D api/agent/perplexity_client.py`); no API key ever configured |
| Triage + enrichment (`ae8467a`,`8fef50b`, Jul 1) | CT intake triage + tiered enrichment | Triage scorer, queue-decoupled enrichment | Partial | Enrichment reaches tier1 only; **tier2=0** (live query) |
| ML honesty (`b396206`,`4a885d9`,`0ddcab0`, Jul 1–2) | Promotion gate, de-bias, remove fake stats | Real promotion gate + FPR threshold wiring | Y | `test_promotion_gate.py` passes; meta shows gate ran |
| Reliability (`10166a1`,`00f71a6`, Jul 2) | Self-healing CT lane, fix DAGs | launchd agents, DAG repairs | UNVERIFIED | launchd is macOS-host, not checkable here; DAGs currently red (see Phase 2) |
| Campaign Radar Day 1–6 (`0e59140`…`492ce12`, Jul 2–3) | BYO-brand queue: DB, ingest, cluster, API, UI | Postgres schema, ingest, clustering, `/campaigns`, Queue UI | **Y** | `test_campaign_api.py`, `test_assemble_campaigns.py` pass; queue renders live |
| Day 7–12 (`d85e0b9`…`021ddd9`, Jul 3–5) | Stage engine, dispositions, suppressions, content probe, metrics | Stage engine, disposition/assign, suppression rules, metrics endpoints | **Y** (mostly) | Corresponding tests pass; content probe disabled-by-default by design |
| ML FP fix (`8e92fb2`,`f93eec1`, Jul 7) | Token-boundary matching + benign FPR gate | Brand matcher rewrite + retrain | Y | Tests pass; live matcher rejects `apps/able/maple` |
| **"Deepening" (UNCOMMITTED)** | Analyst workflow completion, watchlist CRUD, agent replacement, export, **enrichment tier2 fix** | Bulk actions, keyboard shortcuts, `/watchlist` CRUD, internal agent, STIX export | **Partial — tier2 fix NOT present** | 38 dirty files; `enrich_worker.py:333` still `cache_only`; tier2 still 0 |

**New capability vs churn:** Campaign Radar Days 1–12 and the deepening watchlist/agent/export work are genuinely new end-user behavior. The Jan console arc and several "fix" commits are churn/repair. The reliability + tier2 work is the category that claimed capability it did not deliver.

---

## Phase 2 — Actual Data Flow

**Intended (per README:3,10):** CertStream → Kafka → Spark → Bronze/Silver/Gold → enrich → score → campaign queue → analyst → export.

**Actual, as it runs today:**

```
CertStream (docker, up 6d) → forwarder.py → Kafka ct-events → stream_ct.py → ct/data/raw parquet
     │
     ▼
ct_enrich_and_score_dag  (every 2h)     ← FAILS EVERY RUN
     enrich_hot (whois_mode=cache_only) → tier1 ceiling, tier2 never reached
       └─ score_ct_with_latest  → writes ct_scored_*.parquet (fresh filename)
             ├─ enrich_backfill  (|| true, capped) → intended tier2 path, not keeping up
             └─ freshness_gate   → ❌ "STALE CONTENT" (22.1h old), exit 1 → DAG red
     │
     ▼ (15 min later, reads "newest scored parquet" regardless of gate)
campaign_radar_dag  (every 2h)  → SUCCESS  → ingest_observations → assemble_campaigns
     │                                        → ct_observations, campaign_clusters (Postgres)
     ▼
FastAPI /campaigns, /threats/*, /watchlist, /threats/ask, /campaigns/{id}/export
     ▼
Next.js console  (18 distinct endpoints called)
```

**Breaks and disconnects (verified):**

- **BROKEN: enrich→score freshness — CORRECTED ROOT CAUSE (this supersedes an earlier draft of this doc).** `freshness_gate` red on recent runs (`airflow dags list-runs`). The `enrich_hot`, `score_ct_with_latest`, and `enrich_backfill` tasks all **succeed**; only the gate fails, correctly flagging that the newest scored content is ~22h old. The root cause is an **upstream Kafka consumer backlog**, NOT scoring and NOT the `cache_only` enrichment setting:
  - Raw CT parquet lands with `ingest_ts` = now but `event_ts` ≈ 22h old (verified: newest raw slice `event_ts` 2026-07-08 05:31→05:47, `ingest_ts` 2026-07-09 03:26).
  - `ct-events` topic holds ~6.88M messages (`GetOffsetShell`: earliest 0, latest 6,883,673); the forwarder is producing **fresh** (newest in-topic `event_ts` 2026-07-09T03:50:58Z), so it is not source replay.
  - `event_ts` is stamped at produce time (`ct/ingest/forwarder.py:142`), `ingest_ts` at consume time (`ct/ingest/stream_ct.py:175`); the ~22h gap between them is Spark `stream_ct` draining a backlog oldest-first, unable to keep pace with the forwarder.
  - **An earlier draft of this doc incorrectly attributed the freshness failure to `enrich_worker.py:333` `cache_only` starving tier2. That is wrong: `cache_only` controls WHOIS enrichment DEPTH (→ tier2=0), which is a real but INDEPENDENT problem — `event_ts` is set at ingest, never at enrichment, so enrichment mode cannot affect freshness.** The campaign queue 15 min later still ingests the 22h-old content while reporting success.
- **DISCONNECT: `/analysts` endpoint has zero frontend callers.** Endpoint exists (`api/main.py`), but `grep -rn "analysts" web/src` → empty. Built, never wired to UI.
- **ORPHAN CONSUMER: `investigation-api` container** serves `python server.py` from `/Users/…/To-be-shared-FINAL-PACKAGE/threat-intel/` — a *different directory*. Nothing in THIS repo defines or is consumed by it. SPOF of unknown provenance.
- **DEAD PANELS: geo/ISP.** Hidden behind `SHOW_GEO_PANELS=false` because `num_countries`/`sample_country` are null for all rows (a downstream symptom of tier2=0).
- **Frontend→API map (verified):** 18 endpoints called (`/campaigns*`, `/threats/*`, `/watchlist*`, `/health/pipeline`, `/metrics/*`, `/model/status`). Endpoints existing but uncalled: `/analysts`.

**Single points of failure:** app-db (`:5433`) with hardcoded `app/app` creds (`docker-compose.yml:84-85`); the enrich→score pointer file (one bad write stalls the whole scored feed, which is exactly what's happening).

---

## Phase 3 — Code Quality & Correctness

| Concern | Finding | Evidence |
|---|---|---|
| Runs w/ current config | Python suite green; live DAG red | `pytest` 285 pass; enrich DAG failed x3 |
| Hardcoded secrets | DB creds `app/app` in compose; CORS `allow_origins=["*"]` | `docker-compose.yml:84-85`; `api/main.py` CORS block |
| Hardcoded magic | `whois_mode="cache_only"` hardcoded in worker hot path | `enrich_worker.py:333` |
| Fail loud vs silent | `enrich_backfill` wrapped `|| true` — persistent failures invisible in DAG status | `ct_enrich_and_score_dag.py` backfill task |
| Schema validation | Present for OSINT (`great_expectations` in `urlhaus_ingest.py`, `openphish_ingest.py`); DB upserts validated by SQLAlchemy | grep confirms GE usage |
| Model claims integrity | Registry meta top-level `auc/roc_auc/benign_fpr` = **None**; real numbers nested under `promotion_decision` with 2 warnings | `ct_risk_meta_latest.json`: temporal split "False/missing", benign-FPR "skipped" |
| Placeholder returns | `/threats/score` fallback returns hardcoded `risk_score:0.05, verdict:"HEURISTIC_SCORE"` on exception | `api/main.py:1069-1077` |
| Dead endpoint | `/analysts` never called | Phase 2 |
| API structure | `api/main.py` is one ~1150-line file, all routes + model loading + scoring | single-file service |
| Test realism | Unit tests substantive and DB-gated with cleanup; **no integration/DAG/frontend tests** | `tests/` inventory |

---

## Phase 4 — Documentation vs Reality

| README claim | Reality | Evidence |
|---|---|---|
| "real-time Certificate Transparency stream … every 2h enrich/score cycle" (README:10) | The 2h cycle **fails every run**; content 22h stale | `airflow dags list-runs ct_enrich_and_score_dag` |
| "Self-Driving ML Core … LightGBM (98.8% ROC-AUC)" (README:13) | Live model ROC-AUC 0.9889 with promotion warnings: no genuine temporal split, benign-FPR check skipped | `ct_risk_meta_latest.json` promotion_decision |
| ".env.example → fill in PERPLEXITY_API_KEY" (was README:96) | Perplexity removed this session; already fixed in working tree but **uncommitted** | `git status` shows README modified, not committed |
| "Production/Legacy Separation … isolating legacy to ml/legacy" (README:65) | `week5` scripts exist in BOTH `airflow/` root and `ml/legacy/`, and they **differ** | `diff -q` |
| Fresh-clone setup | `cp .env.example .env` works, but tarball (61 MB) + gitignored data mean a clone cannot reproduce Bronze/Silver/Gold; DAG will report STALE immediately | `.gitignore:10-16`; committed tarball |

**Fresh-clone dry-run (static):** `requirements.txt` is 49 lines, 36 pinned. `product/db.py` documents a real SQLAlchemy 1.4-vs-2.0 dual-runtime constraint (competent). A literal fresh clone would install, but the "real-time" pipeline would come up already-stale because the enrichment bug ships in the code.

---

## Phase 5 — End-User Workflow

**What a stranger can actually DO today, start to finish:** Run the campaign-radar slice. Bring `app-db` up, `make ingest-observations && make assemble-campaigns` (or let `campaign_radar_dag` run), open the Next.js console, and work a queue of brand-attributed impersonation campaigns: filter by brand, open a cluster, see member domains + risk, disposition it (confirm/suppress/benign), bulk-action, assign, manage the watchlist, query the chat agent for "top risk domains", and export a campaign as JSON or STIX. **This works** (285 tests + live API checks corroborate).

**Advertised capabilities, honest status:**

| Capability | Status | Evidence |
|---|---|---|
| Campaign queue / BYO-brand | **Wired E2E** | `/campaigns`, Queue UI, tests |
| Analyst disposition + stage engine | **Wired E2E** | `test_stage_engine.py`, live POST verified |
| Watchlist CRUD (uncommitted) | **Wired E2E, unmerged** | `test_watchlist_endpoints.py` pass; 200s live |
| Chat agent (uncommitted) | **Wired E2E, unmerged** | intent-router, `test_internal_agent.py` |
| STIX/JSON export (uncommitted) | **Wired E2E, unmerged** | `test_export.py`, live curl |
| Real-time CT enrich/score | **BROKEN** | DAG red, tier2=0, 22h stale |
| Geo/ISP intelligence | **Vaporware (no data)** | panels hidden, 0 country coverage |
| Blocklist/egress push | Export exists; no push/webhook | `product/export.py` is pull-only |
| MISP/OSINT ingest | Works (batch) | `misp_osint_ingest` success runs |

**One coherent workflow?** Yes — the campaign-radar analyst loop. Everything else is either supporting batch plumbing (works) or the real-time predictive story (broken/stale).

---

## Phase 6 — SWOT

**Architecture**
- S: Clean product/service/orchestration separation; documented dual-runtime SQLAlchemy handling (`product/db.py`).
- W: `api/main.py` is a 1150-line monolith; enrich→score coupled through a single fragile pointer file.
- O: Campaign-radar slice is a sellable vertical.
- T: `investigation-api` runs from a foreign checkout — undocumented SPOF.

**Code Quality / Maintainability**
- S: Substantive, cleanup-safe DB-gated tests; honest inline comments.
- W: Duplicated divergent `week5` scripts; hidden dead code (geo panels, `/analysts`).
- T: 38 uncommitted files = large unreviewed surface; no CI to enforce review.

**Data Pipeline Correctness**
- S: OSINT batch validated with great_expectations; campaign assembly idempotent.
- W/T: **Core CT pipeline red for days; tier2 enrichment never functioned (0/8654); campaign queue silently fed 22h-stale data.**

**Documentation / DX**
- S: README architecture section is detailed and mostly candid about lane separation.
- W: Overclaims real-time freshness and ML AUC; stale Perplexity setup step (fixed but uncommitted).

**Product / Usability**
- S: The analyst queue is a real, usable product.
- W: Advertised geo intel is empty; chat/watchlist/export not yet merged to `master`.

**Testing & CI**
- S: 285 green Python tests.
- W/T: **No CI at all** (`.github/workflows` absent); zero frontend/integration/DAG tests; unit suite gave false confidence while the DAG was red.

**Security**
- W: CORS `*`, DB creds `app/app` in compose, committed data tarball. Chat agent's fixed-intent design is a genuine security *positive* (no LLM tool-calling injection surface).

---

## Phase 7 — Root Cause Analysis

1. **"Done" meant "code exists / unit tests pass," not "runs end-to-end in the live system."** Confirmed by the tier2 task: marked completed and "verified," yet `enrich_worker.py:333` still holds the exact `cache_only` bug and live tier2 = 0. The verification never touched the running DAG.
2. **No CI + no integration tests → live regressions invisible.** `.github/workflows` absent. The enrich DAG can be red for 3 cycles while `pytest` stays green because nothing tests the DAG.
3. **Scope breadth over vertical depth.** Watchlist, chat, export, keyboard shortcuts all advanced in parallel (uncommitted) while the foundational CT pipeline stayed broken — energy went to new features on top of an unstable substrate.
4. **Work stranded in the working tree.** 38 dirty files, `master` untouched — no discipline of "merge a working slice before starting the next."
5. **Aspirational docs.** README's "Self-Driving," "98.8% ROC-AUC," "real-time … every 2h" were written to the intended system, not the measured one.

---

## Phase 8 — Remediation Roadmap

**Kill list (delete/deprecate — keeping them actively harms onboarding):**
- `backup_bronze_silver_2025-10-30_1400.tgz` — 61 MB blob in git. `git rm`, add to ignore, purge from history.
- `pre_migration_airflow.log`, `.claude/launch.json` — untrack.
- `airflow/analyze_week5_risk_clusters.py`, `airflow/train_week5_baselines.py` — divergent duplicates of `ml/legacy/` copies; pick one home, delete the other.
- `airflow/dags/hello.py` — demo DAG.
- One of `misp_ingest` / `misp_osint_ingest` — the paused one, once confirmed superseded.
- `_archive_2025-11-03/` — remove from disk.

**Quick fixes (<1 day each, file-level):**
- `ct/enrich/enrich_worker.py:333` — stop hardcoding `whois_mode="cache_only"` in the hot cycle (thread it from config); re-verify tier2 climbs off 0. **This is the P0.**
- Remove `|| true` from `enrich_backfill` so failures surface in DAG status.
- README:13 — replace "98.8% ROC-AUC" with the measured 0.9889 + the promotion caveats, or drop the number.
- Commit/merge or explicitly abandon the 38 dirty files. Do not leave a phase in the working tree.
- Move DB creds + CORS origins to env/config.

**Structural fixes (sequenced):**
1. Add CI (GitHub Actions): run `pytest` + `alembic upgrade head` on a throwaway PG + `airflow dags list-import-errors`. **Must precede** any further feature work.
2. Add one integration test that runs the enrich→score→freshness path against a fixture and asserts freshness OK — the test that would have caught this.
3. Fix the enrich→score pointer contract so a stale pointer fails loudly at write time, not 22h later at a gate.
4. Resolve `investigation-api` provenance — bring its source into this repo or remove the container from compose.

**Impact/Effort:** P0 = tier2 fix + backfill visibility (high impact, low effort). P0 = CI (high impact, medium effort). P1 = commit-hygiene + README honesty (medium/low). P2 = monolith split, geo backlog (low near-term impact).

---

## Phase 9 — Smallest Coherent Working Slice

**Ship this, pause everything else:** the **campaign-radar analyst loop on a freshness-honest feed**.

- **Ingestion:** existing `stream_ct.py` → `ct/data/raw` (works).
- **One processing stage:** fix `enrich_worker.py:333` so enrich→score produces *fresh* content and `freshness_gate` goes green — then `campaign_radar_dag` ingests real, current data (already works mechanically).
- **One visible output:** the existing Campaign Queue UI + disposition + export.

**Cut/pause to get there:** geo/ISP intel (no data — leave hidden), the second Streamlit dashboard, `investigation-api`, `/analysts` UI wiring, and any new features until the DAG is green in CI. **Merge this slice to `master` before adding one more "phase."**

---

## Prioritized Backlog

### P0 — blockers

**P0-A: CT lane freshness — Kafka consumer backlog (this is what makes `freshness_gate` red)**
Spark `stream_ct` cannot keep pace with the forwarder: `ct-events` holds ~6.88M messages and Spark is ~22h behind, draining oldest-first, so scored `event_ts` is ~22h stale. This is an ingest/consume-throughput problem — NOT enrichment, NOT scoring. Decide and implement one of: (a) scale/parallelize the Spark consumer to out-run production, (b) drain + reset the checkpoint offset to latest and accept a one-time gap, or (c) rate-match the forwarder to sustainable consume throughput. Verify `event_ts` on newest scored output tracks within the 6h threshold.
*Acceptance:* newest raw/scored `event_ts` is < 6h old for ≥2 consecutive cycles; `freshness_gate` returns OK; `airflow dags list-runs ct_enrich_and_score_dag` shows `success`. (Independent of P0-B.)

**P0-B: Enrichment hot path never reaches tier2 (enrichment DEPTH, not freshness)**
Fix `ct/enrich/enrich_worker.py:333` hardcoded `whois_mode="cache_only"`; make the hot-cycle WHOIS mode configurable and verify tier2 rises above 0. Note: this does NOT fix P0-A — it fixes the permanently-empty geo/WHOIS panels. Also remove `|| true` from `enrich_backfill` so failures aren't masked.
*Acceptance:* after ≥2 DAG cycles, `SELECT enrichment_level, count(*) FROM ct_observations` shows non-zero `tier2`.

**P0-3: No CI**
Add GitHub Actions running `pytest`, `alembic upgrade head` (throwaway PG), and `airflow dags list-import-errors` on every PR.
*Acceptance:* a PR that reintroduces the `cache_only` bug or breaks a migration fails CI.

**P0-4: 38 uncommitted files / unmerged deepening phase**
Review, commit, and merge the working, tested deepening work to `master`, or revert it. Nothing half-built left in the tree.
*Acceptance:* `git status --short` empty on a clean checkout; `master` contains the merged slice or the work is explicitly reverted.

### P1 — serious

**P1-1: README overclaims** — correct ROC-AUC (0.9889 + caveats) and the "real-time every 2h" claim to reflect measured behavior. *Acceptance:* no doc claim contradicts a runnable command's output.

**P1-2: Remove committed 61 MB tarball + stale logs from git** (and history). *Acceptance:* `git ls-files | grep -E 'tgz|pre_migration'` empty; repo clone size drops.

**P1-3: `investigation-api` provenance** — its source lives in a foreign checkout. Bring in-repo or remove from compose. *Acceptance:* every running container maps to source in this repo, or is documented as external.

**P1-4: Secrets/CORS** — move `app/app` and `allow_origins=["*"]` to config. *Acceptance:* no credential literals in tracked files; CORS origins env-driven.

### P2 — hygiene

**P2-1:** Delete `hello.py`, one duplicate `week5` pair, one redundant MISP DAG, `_archive_*`, Streamlit dashboard (or document as legacy). *Acceptance:* no orphan/duplicate flagged in Phase 0 remains.

**P2-2:** Wire `/analysts` into the UI or delete the endpoint. *Acceptance:* no endpoint exists without a caller.

**P2-3:** Add a smoke/integration test for enrich→score→gate and minimal frontend tests. *Acceptance:* a stale-pointer regression is caught by a test, not by manual DAG inspection.

**P2-4:** Split `api/main.py` (1150-line monolith) into routers. *Acceptance:* no single API file > ~400 lines.
