# Threat-Intel: Predictive Domain Intelligence Platform

An Airflow-orchestrated threat intelligence platform that automates the discovery, enrichment, and machine-learning-driven risk scoring of malicious domains — combining daily batch OSINT ingestion with a real-time Certificate Transparency stream (see **Architecture** below for how these are actually wired).

## 🚀 Overview

This platform is designed to bridge the gap between reactive security lists and proactive threat hunting. Instead of just ingesting known-bad URLs, this system performs active reconnaissance (WHOIS/RDAP, DNS, GeoIP) and uses a LightGBM classifier to predict the risk level of newly seen infrastructure.

### Key Features
*   **Automated Ingestion**: Daily batch pulls of OpenPhish, URLHaus, and MISP OSINT feeds (02:30 UTC via Airflow), plus a separate real-time Certificate Transparency stream (CertStream → Kafka → Spark, every 2h enrich/score cycle).
*   **Infrastructure Recon**: Automated enrichment of domains via recursive DNS and RDAP protocols.
*   **Formal Medallion Architecture**: Production-grade data lakehouse structure (Bronze → Silver → Gold) implemented via Parquet and Airflow.
*   **Self-Driving ML Core**: Standardized production pipeline in `ml/core/` using LightGBM (98.8% ROC-AUC) and Logistic Regression.
*   **Premium "Cyber Sentinel" Dashboard**: High-fidelity Streamlit interface with glassmorphism aesthetics, interactive global risk maps, and deep-dive investigation modules.

---

## 🏗️ Architecture

This platform runs as **three parallel, independently-scheduled lanes** sharing the same Medallion (Bronze → Silver → Gold) storage convention. They don't run as one unified pipeline today — the lanes below describe what's actually wired up.

### Lane 1 — Daily batch OSINT ingestion (feeds the dashboard)
`airflow/dags/pipeline_orchestrator.py` runs **daily at 02:30 UTC** (`schedule="30 2 * * *"`) and trigger-cascades: `openphish_ingest` → `urlhaus_ingest` → silver normalization (`openphish_silver`, `urlhaus_silver`) → `labels_union` → `whois_rdap_ingest` → `dns_ip_geo_ingest` → `misp_osint_ingest`. MISP OSINT lands in `silver/misp_osint` and is fused into CT scoring downstream (see Lane 2).

### Lane 2 — Real-time CT stream (the "predictive" differentiator, feeds the dashboard)
```
CertStream (docker-compose "certstream" service, ws://127.0.0.1:4000)
  -> ct/ingest/forwarder.py       (local triage/sampling, Kafka topic "ct-events")
  -> ct/ingest/stream_ct.py       (Spark: Kafka -> ct/data/raw/ds=YYYY-MM-DD parquet)
  -> ct/enrich/enrich_worker.py   (tiered DNS/WHOIS/RDAP enrichment, rate-limited)
  -> ct/score/score_ct_with_latest.py  (LightGBM/LogReg scoring + MISP fusion -> gold/threat_scores/)
```
Enrichment + scoring runs every **2 hours** via the `ct_enrich_and_score_dag` Airflow DAG. This is the lane the CertStream websocket service and `scripts/check_ct_freshness.py` (see below) exist for.

### Lane 3 — Synthetic demo lane (isolated; does NOT feed the dashboard)
```
simulator/producer.py (random fake domains, Kafka topic "domain-events")
  -> pipelines/spark_stream.py | pipelines/spark_stream_contract.py
  -> bronze/domain_events/  (local parquet only)
```
This is a schema-contract-validation testbed (`config/event.schema.json`, `pipelines/spark_stream_contract.py`) used to exercise the Kafka→Spark→Bronze plumbing and JSON-schema validation in isolation, with fabricated domains. It writes to its own `bronze/domain_events/` output and is never read by the API, the Next.js console, or the CT scoring path. Kept separate deliberately — see `.env.example` for why `KAFKA_TOPIC` must not be shared between this lane and Lane 2.

### Storage (Medallion layers)
Bronze (raw ingest) → Silver (normalized/enriched) → Gold (scored, Parquet) → served by FastAPI (`api/main.py`) to the Next.js console (`web/`).

### Technical Stack
*   **Orchestration**: Apache Airflow 2.9.3 (Custom Docker Image) — batch OSINT (Lane 1) + CT enrich/score (Lane 2)
*   **Streaming**: Kafka + Spark Structured Streaming (Lane 2 real CT stream, Lane 3 synthetic testbed)
*   **CT Source**: [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go) (Docker, see `docker-compose.yml`)
*   **Data Processing**: Python (Pandas, PyArrow)
*   **Storage**: Partitioned Parquet (Medallion Layers)
*   **Machine Learning**: LightGBM, Scikit-Learn
*   **API / Dashboard**: FastAPI (`api/`) + Next.js "Cyber Sentinel" console (`web/`), with a PHANTOM_EYE chat agent backed by Perplexity's Sonar models (`api/agent/`)
*   **Environment**: Docker Compose (Kafka stack + Airflow stack, brought up together via `make up-all`)

> A legacy Streamlit dashboard (`ct/dashboard/ct_dashboard.py`) also exists in the repo and can still be run standalone (`streamlit run ct/dashboard/ct_dashboard.py`), but the Next.js/FastAPI console under `web/` + `api/` is the actively-developed one.

---

## 🛠️ Reliability & Senior Engineering Patterns

To handle the volatility of live internet data, the platform implements several advanced engineering patterns:
*   **Auto-Healing Retries**: All network-heavy tasks (WHOIS, DNS) implement double-retry policies with exponential backoff.
*   **Atomic Persistence**: All data writes use a temp-swap mechanism to ensure Parquet partitions are never corrupted.
*   **Production/Legacy Separation**: Standardized `ml/core` for production logic, isolating legacy artifacts to `ml/legacy`.

### Self-healing real-time ingest (macOS)

The real-time CT lane (`forwarder.py` → Kafka → `stream_ct.py`) is the substrate everything downstream depends on, so it is built to survive crashes, laptop sleep, and reboots rather than failing silently:

*   **Process supervision** — `make supervise-install` registers the two host consumers as launchd agents (`KeepAlive` + `RunAtLoad`): they restart on crash and come back on login/boot/wake. See [`ops/launchd/`](ops/launchd/).
*   **Container restart policies** — Kafka, Zookeeper, Kafdrop, and certstream all run `restart: unless-stopped`, so a broker crash self-recovers instead of stranding the lane.
*   **Loud staleness alerting** — a freshness watchdog (`scripts/ct_freshness_watchdog.py`, every 5 min) checks whether fresh data is actually *landing* and fires a macOS notification if not. This catches the worst failure mode — a process that is alive but has silently stopped producing output — which process supervision alone cannot see.
*   **Non-destructive restarts** — under supervision the Spark consumer preserves its Kafka checkpoint across restarts (`CT_RESET_CHK_ON_START=0`), so an automatic restart *resumes* from the last committed offset instead of dropping everything produced during the downtime.
*   **Freshness gate** — `ct_enrich_and_score_dag` runs `scripts/check_ct_freshness.py` as a gate, failing the batch (rather than silently emitting stale scores) if raw data is old or the scorer is re-scoring a static snapshot.

Manage it with `make supervise-status` / `make supervise-uninstall`; full details in [`ops/launchd/README.md`](ops/launchd/README.md). launchd is the right fit for this laptop deployment; a server would map the same agents onto systemd units or containers.

---

## 🛡️ Privacy & Ethical Considerations

This project is built with **Privacy-by-Design** principles:
1.  **Infrastructure Focus**: The platform targets server-side artifacts (IPs, Domains) rather than personal data.
2.  **Upstream Redaction**: Utilizing RDAP protocol over legacy WHOIS for automated registrant PII redaction.
3.  **Purpose Limitation**: Scoped strictly to security research and identifying malicious infrastructure.

---

## ⚡ Quick Start

### 0. Clone and configure
```bash
git clone https://github.com/mohanasundaramm1/Threat-Intel.git
cd Threat-Intel
cp .env.example .env   # then fill in PERPLEXITY_API_KEY if you want the chat agent
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

### 1. Bring up the Docker services (Kafka + CertStream + Airflow)
```bash
make up-all
```
This runs, in order:
1.  Root `docker-compose.yml` — Zookeeper, Kafka, Kafdrop (`http://localhost:9000`), and the **certstream** service (CT websocket source, `ws://127.0.0.1:4000`).
2.  `airflow/docker-compose.airflow.yml` — Postgres, then the Airflow webserver/scheduler/triggerer (`http://localhost:8080`, default `airflow`/`airflow`).

These are kept as two separate `docker compose` projects (see Architecture note above) rather than merged, so an existing working Airflow setup isn't put at risk. Equivalent manual steps, if you'd rather run them yourself:
```bash
docker compose up -d
AIRFLOW_UID=$(id -u) docker compose -f airflow/docker-compose.airflow.yml up -d
```
Bring everything back down with `make down-all`.

Once Airflow is up, unpause `pipeline_orchestrator` (Lane 1, daily OSINT) and `ct_enrich_and_score_dag` (Lane 2, every 2h) in the Airflow UI so they run on schedule.

### 2. Start the real-time CT stream (Lane 2)
The CertStream *source* is a Docker service (started in step 1); two consumers read from it. Two ways to run them:

**Supervised (recommended, macOS)** — self-healing agents that restart on crash/sleep/reboot and alert on staleness (see [Reliability](#️-reliability--senior-engineering-patterns)):
```bash
make supervise-install     # forwarder + stream consumer + freshness watchdog
make supervise-status      # check them;  make supervise-uninstall to remove
```

**Manual (foreground, best while iterating)** — watch/restart the short scripts yourself:
```bash
# terminal A: certstream ws -> Kafka topic "ct-events"
make forward-ct

# terminal B: Kafka "ct-events" -> ct/data/raw/ (Spark)
make stream-ct
```
Don't run both ways at once — the supervised agents already run these processes. Enrichment (`ct/enrich/`) and scoring (`ct/score/`) run automatically every 2 hours via the `ct_enrich_and_score_dag` Airflow DAG started in step 1 — no extra process needed for those. To run a one-off score pass without waiting for the DAG, see `ct/score/score_ct_with_latest.py`.

### 3. Start the API and console (two more foreground processes)
```bash
# terminal C
make api      # FastAPI backend  -> http://localhost:8000

# terminal D
make web      # Next.js console  -> http://localhost:3000
```
(`scripts/start_console.sh` starts both of these together in one script if you prefer.)

### 4. (Optional) Check CT freshness
```bash
make check-freshness
```
Checks whether `ct/data/raw` has fresh partitions and whether `gold/threat_scores` looks like it's actually re-scoring new domains each cycle, rather than the same static snapshot (see `scripts/check_ct_freshness.py`). Useful as a quick sanity check after steps 1-2, or wired into cron/CI — exits non-zero on staleness.

### Summary
| # | What | How | URL |
|---|------|-----|-----|
| 1 | Kafka + CertStream + Airflow | `make up-all` | Kafdrop `:9000`, Airflow `:8080` |
| 2 | CT forwarder + stream consumer | `make supervise-install` (self-healing) or manual `make forward-ct` / `make stream-ct` | (Kafka `ct-events` -> `ct/data/raw/`) |
| 3 | FastAPI backend | `make api` | `:8000` |
| 3 | Next.js console | `make web` | `:3000` |
| — | Ingest supervision status | `make supervise-status` | (self-healing agents' health) |
| — | Freshness check | `make check-freshness` | (exits non-zero if stale) |

Legacy Streamlit dashboard, if needed:
```bash
source .venv/bin/activate
streamlit run ct/dashboard/ct_dashboard.py
```
