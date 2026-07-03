VENV_ACT = . .venv/bin/activate

# api/ and web/ are real directories in this repo; without .PHONY, `make api`
# and `make web` would be (incorrectly) considered "up to date" and no-op.
.PHONY: up down up-all down-all topic-reset produce stream stream-fast \
        stream-fresh stream-ct forward-ct api web check-freshness test \
        supervise-install supervise-uninstall supervise-status

up:
	docker compose up -d

down:
	docker compose down

# Bring up the FULL local stack in the right order:
#   1. Root compose: Kafka + Zookeeper + Kafdrop + certstream (CT websocket source)
#   2. Airflow compose: postgres -> webserver/scheduler/triggerer (daily OSINT batch DAGs)
#
# These are two separate `docker compose` projects on purpose (see README.md
# "Architecture" section) -- merging them risked breaking a working Airflow
# setup for little benefit, so this target just sequences both `up -d` calls
# instead. Safe to re-run; `docker compose up -d` is idempotent.
#
# What this target does NOT start (see README.md "Startup sequence" for why
# these stay foreground dev processes instead of Docker services):
#   - CT stream consumer:  make stream-ct
#   - FastAPI backend:     make api
#   - Next.js frontend:    make web
up-all:
	@echo "==> [1/2] root stack: kafka, zookeeper, kafdrop, certstream"
	docker compose up -d
	@echo "==> [1/2] done. Kafdrop: http://localhost:9000  CertStream: ws://127.0.0.1:4000"
	@echo "==> [2/2] airflow stack: postgres, webserver, scheduler, triggerer"
	AIRFLOW_UID=$${AIRFLOW_UID:-$$(id -u)} docker compose -f airflow/docker-compose.airflow.yml up -d
	@echo "==> [2/2] done. Airflow UI: http://localhost:8080 (default admin/admin, unless changed)"
	@echo "==> up-all complete. Remaining processes are foreground dev commands -- see README.md Quick Start:"
	@echo "      make stream-ct   (Spark: CT Kafka -> ct/data/raw)"
	@echo "      make api         (FastAPI backend, :8000)"
	@echo "      make web         (Next.js console, :3000)"

down-all:
	@echo "==> stopping airflow stack"
	docker compose -f airflow/docker-compose.airflow.yml down
	@echo "==> stopping root stack"
	docker compose down

topic-reset:
	- docker compose exec kafka kafka-topics --delete --topic domain-events --bootstrap-server kafka:9092
	docker compose exec kafka kafka-topics --create --topic domain-events --bootstrap-server kafka:9092 --replication-factor 1 --partitions 1
	docker compose exec kafka kafka-topics --list --bootstrap-server kafka:9092

produce:
	$(VENV_ACT) && python simulator/producer.py

stream:
	$(VENV_ACT) && python pipelines/spark_stream.py

stream-fast:
	$(VENV_ACT) && SPARK_TRIGGER_SECS=2 python pipelines/spark_stream.py

stream-fresh:
	rm -rf bronze dlq chk
	$(VENV_ACT) && SPARK_CHECKPOINT_DIR=./chk/dev python pipelines/spark_stream.py

# Real CT lane: forwarder.py (certstream ws -> Kafka topic ct-events) must
# already be running separately -- this only consumes ct-events -> parquet.
stream-ct:
	$(VENV_ACT) && python ct/ingest/stream_ct.py

# Real CT lane: certstream websocket (see docker-compose.yml "certstream"
# service) -> Kafka topic ct-events. Run alongside `make stream-ct`.
forward-ct:
	$(VENV_ACT) && python ct/ingest/forwarder.py

api:
	$(VENV_ACT) && uvicorn api.main:app --host 0.0.0.0 --port 8000

web:
	cd web && npm run dev -- -p 3000

# Operationalizes the audit's staleness check (see scripts/check_ct_freshness.py):
# warns/fails if ct/data/raw hasn't been touched recently, or if the last few
# gold/threat_scores files look byte-identical (scorer re-scoring a stale snapshot).
check-freshness:
	$(VENV_ACT) && python scripts/check_ct_freshness.py

# Real-time CT lane supervision (macOS launchd). Turns forwarder.py + stream_ct.py
# from unsupervised foreground processes into self-healing agents (restart on
# crash/sleep/reboot) plus a freshness watchdog that alerts on silent stalls.
# See ops/launchd/README.md. These install standing login agents; remove with
# supervise-uninstall.
supervise-install:
	./ops/launchd/install.sh

supervise-uninstall:
	./ops/launchd/uninstall.sh

# Show each agent's state/pid and the watchdog's last recorded result.
supervise-status:
	@UID_NUM=$$(id -u); \
	for label in com.phantomeye.forwarder com.phantomeye.stream-ct com.phantomeye.freshness-watchdog; do \
	  if launchctl print gui/$$UID_NUM/$$label >/dev/null 2>&1; then \
	    state=$$(launchctl print gui/$$UID_NUM/$$label 2>/dev/null | awk -F'= ' '/state = /{print $$2; exit}'); \
	    pid=$$(launchctl print gui/$$UID_NUM/$$label 2>/dev/null | awk -F'= ' '/pid = /{print $$2; exit}'); \
	    printf "  %-40s state=%s pid=%s\n" "$$label" "$${state:-?}" "$${pid:-none}"; \
	  else \
	    printf "  %-40s NOT LOADED\n" "$$label"; \
	  fi; \
	done; \
	echo "  --- last watchdog result ---"; \
	cat ops/launchd/logs/watchdog_state.json 2>/dev/null || echo "  (no watchdog run yet)"

test:
	$(VENV_ACT) && pytest -q
