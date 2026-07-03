# ct/enrich/queue.py
"""Durable file-backed pending queue for enrichment.

Layout under the queue dir:
    pending/<ts>_<uuid>.jsonl    batches waiting to be enriched
    processing/<file>.jsonl      batch currently claimed by a worker (crash-safe:
                                 stale files can be recovered back to pending/)
    processed_ledger.jsonl       one line per successfully enriched item
    failed_ledger.jsonl          items that exhausted max_attempts

Each item is a JSON object with at least:
    {"registered_domain", "domain", "triage_score", "enqueued_at", "attempts"}
"""
from __future__ import annotations

import glob
import json
import logging
import os
import uuid
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FileQueue:
    def __init__(self, base_dir: str, batch_size: int = 200, max_attempts: int = 3):
        self.base = base_dir
        self.pending_dir = os.path.join(base_dir, "pending")
        self.processing_dir = os.path.join(base_dir, "processing")
        self.processed_ledger = os.path.join(base_dir, "processed_ledger.jsonl")
        self.failed_ledger = os.path.join(base_dir, "failed_ledger.jsonl")
        self.batch_size = int(batch_size)
        self.max_attempts = int(max_attempts)
        os.makedirs(self.pending_dir, exist_ok=True)
        os.makedirs(self.processing_dir, exist_ok=True)

    # ---------- enqueue ----------

    def enqueue(self, items: list[dict]) -> str | None:
        """Write a batch of items to pending/. Stamps enqueued_at/attempts if absent."""
        if not items:
            return None
        now = _utcnow_iso()
        for it in items:
            it.setdefault("enqueued_at", now)
            it.setdefault("attempts", 0)
        name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}_{uuid.uuid4().hex[:8]}.jsonl"
        final = os.path.join(self.pending_dir, name)
        tmp = final + ".tmp"
        with open(tmp, "w") as f:
            for it in items:
                f.write(json.dumps(it) + "\n")
        os.replace(tmp, final)
        return final

    # ---------- claim / complete ----------

    def claim_batch(self) -> tuple[str, list[dict]] | None:
        """Atomically move the oldest pending batch to processing/ and return its items."""
        for path in sorted(glob.glob(os.path.join(self.pending_dir, "*.jsonl"))):
            dest = os.path.join(self.processing_dir, os.path.basename(path))
            try:
                os.rename(path, dest)  # atomic claim
            except OSError:
                continue  # someone else grabbed it
            items = []
            with open(dest) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            log.warning("[queue] skipping malformed line in %s", dest)
            return dest, items
        return None

    def complete_batch(self, claim_path: str):
        try:
            os.remove(claim_path)
        except OSError:
            pass

    def recover_stale(self):
        """Move any leftover processing files back to pending (crash recovery)."""
        for path in glob.glob(os.path.join(self.processing_dir, "*.jsonl")):
            dest = os.path.join(self.pending_dir, os.path.basename(path))
            try:
                os.rename(path, dest)
                log.info("[queue] recovered stale processing batch %s", path)
            except OSError:
                pass

    # ---------- outcomes ----------

    def record_processed(self, item: dict):
        item = dict(item)
        item["enrichment_completed_at"] = _utcnow_iso()
        with open(self.processed_ledger, "a") as f:
            f.write(json.dumps(item, default=str) + "\n")

    def requeue(self, item: dict, reason: str):
        """Requeue with attempt counter; move to failed ledger after max_attempts."""
        item = dict(item)
        item["attempts"] = int(item.get("attempts", 0)) + 1
        item["last_error"] = reason
        if item["attempts"] >= self.max_attempts:
            item["failed_at"] = _utcnow_iso()
            with open(self.failed_ledger, "a") as f:
                f.write(json.dumps(item, default=str) + "\n")
            log.warning("[queue] item %s exhausted %d attempts -> failed ledger (%s)",
                        item.get("registered_domain"), item["attempts"], reason)
        else:
            self.enqueue([item])
            log.info("[queue] requeued %s (attempt %d, reason=%s)",
                     item.get("registered_domain"), item["attempts"], reason)

    # ---------- dedup ----------

    def in_flight_domains(self) -> set[str]:
        """Registered domains currently sitting in pending/ or processing/ --
        i.e. already queued/being worked, not yet completed or failed.

        Used to make enqueue idempotent against retries: an Airflow task that
        re-runs from scratch (a normal `retries` retry, or reset_dag_run=True
        re-triggering the same execution_date) calls enqueue_domains() again
        with the same day's domain list. Without this check, every retry
        would silently pile another copy of that list into the shared queue --
        real wasted rate-limited WHOIS/DNS work, not just a cosmetic depth
        bump. Best-effort/TOCTOU-tolerant like metrics(): a file that's
        claimed between scan and read here just means (at worst) one
        duplicate slips through this pass -- never worth raising over, since
        this is a dedup optimization, not a correctness guarantee."""
        domains: set[str] = set()
        for d in (self.pending_dir, self.processing_dir):
            for path in glob.glob(os.path.join(d, "*.jsonl")):
                try:
                    f = open(path)
                except (FileNotFoundError, OSError):
                    continue  # claimed/removed between glob() and open()
                with f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            dom = json.loads(line).get("registered_domain")
                        except json.JSONDecodeError:
                            continue
                        if dom:
                            domains.add(dom)
        return domains

    # ---------- metrics ----------

    def metrics(self) -> dict:
        """Queue depth and enrichment lag (now - oldest pending enqueue time).

        Purely observational (logging/reporting), not part of claim/complete/
        requeue correctness -- must never raise. Multiple DAGs now share one
        queue directory and can drain concurrently, so a file this method
        glob()'d can legitimately be claim_batch()'d (atomically renamed into
        processing/) by another worker before this method's open() runs --
        a benign TOCTOU race, not a bug in claiming itself (os.rename is
        atomic, so the file is never partially read). Skip such files for
        this snapshot rather than crashing the caller's task."""
        depth = 0
        oldest = None
        for path in glob.glob(os.path.join(self.pending_dir, "*.jsonl")):
            try:
                f = open(path)
            except (FileNotFoundError, OSError):
                continue  # claimed by another worker between glob() and open()
            with f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    depth += 1
                    try:
                        ts = json.loads(line).get("enqueued_at")
                        if ts and (oldest is None or ts < oldest):
                            oldest = ts
                    except json.JSONDecodeError:
                        pass
        lag = None
        if oldest:
            try:
                lag = (datetime.now(timezone.utc)
                       - datetime.fromisoformat(oldest)).total_seconds()
            except ValueError:
                pass
        return {"queue_depth": depth, "oldest_enqueued_at": oldest, "enrichment_lag_seconds": lag}

    def log_metrics(self):
        m = self.metrics()
        log.info("[queue] depth=%d enrichment_lag=%ss oldest=%s",
                 m["queue_depth"],
                 f"{m['enrichment_lag_seconds']:.1f}" if m["enrichment_lag_seconds"] is not None else "n/a",
                 m["oldest_enqueued_at"])
        return m
