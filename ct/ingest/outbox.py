# ct/ingest/outbox.py
"""Durable local outbox for the CT forwarder.

Why this exists: CertStream is a live websocket with no replay. If Kafka is
unreachable while the forwarder is running, every certificate seen in that time
is gone for good unless the forwarder keeps its own copy. The outbox is that
copy: events are appended to a local file when they can't be delivered, and
replayed (oldest first) once Kafka is back.

Design:
  * ``current.jsonl`` is the open file; ``append()`` writes one JSON object per
    line to it.
  * ``replay()`` first SEALS the open file (renames it to ``sealed-<ns>.jsonl``),
    so events appended while a replay is running go to a fresh open file and can
    never be deleted along with the sealed one.
  * A sealed file is deleted only after every send in it was issued without
    error AND the producer's flush was acknowledged. Otherwise it is kept and
    retried on the next replay. A crash mid-replay therefore re-sends a file
    (at-least-once); that is safe because events carry stable IDs and the
    downstream dedup drops repeats.
  * A torn last line (process died mid-write) is skipped, not fatal.

Thread-safety: ``append`` can be called from the websocket thread and from a
Kafka producer callback thread, so it takes a lock.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import threading
import time

log = logging.getLogger("ct-forwarder.outbox")

CURRENT = "current.jsonl"


class Outbox:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)
        self._lock = threading.Lock()
        self._current = os.path.join(self.dir, CURRENT)
        self._terminate_torn_tail()

    def _terminate_torn_tail(self) -> None:
        """If a previous process died mid-write, the open file ends without a
        newline. End that line now so the next append starts on its own line
        instead of being glued onto (and corrupted by) the torn one."""
        try:
            with open(self._current, "rb+") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() == 0:
                    return
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":
                    f.write(b"\n")
        except FileNotFoundError:
            pass

    # ---------- writing ----------

    def append(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        with self._lock:
            with open(self._current, "a") as f:
                f.write(line)
                f.flush()      # to the OS: survives a process crash (not a power loss)

    def seal(self) -> str | None:
        """Rename the open file to a sealed, immutable one. Returns its path."""
        with self._lock:
            if not os.path.exists(self._current) or os.path.getsize(self._current) == 0:
                return None
            sealed = os.path.join(self.dir, f"sealed-{time.time_ns()}.jsonl")
            os.rename(self._current, sealed)
            return sealed

    # ---------- reading ----------

    def sealed_files(self) -> list[str]:
        return sorted(glob.glob(os.path.join(self.dir, "sealed-*.jsonl")))

    def has_pending(self) -> bool:
        """Cheap check (no file reads): is there anything waiting on disk?"""
        if self.sealed_files():
            return True
        try:
            return os.path.getsize(self._current) > 0
        except OSError:
            return False

    def pending_count(self) -> int:
        """Number of events waiting on disk (open + sealed files)."""
        total = 0
        paths = self.sealed_files() + ([self._current] if os.path.exists(self._current) else [])
        for p in paths:
            try:
                with open(p) as f:
                    total += sum(1 for line in f if line.strip())
            except OSError:
                pass
        return total

    def replay(self, send, flush) -> dict:
        """Replay sealed files oldest-first.

        send(event): issue one send (may raise).
        flush() -> bool: block until the sends are acknowledged; True if all were.
        Returns {"replayed": events_confirmed, "failed_files": files_kept}.
        """
        self.seal()
        replayed = 0
        failed = 0
        for path in self.sealed_files():
            events = list(self._read(path))
            if not events:
                os.remove(path)
                continue
            try:
                for ev in events:
                    send(ev)
                acked = bool(flush())
            except Exception as e:  # noqa: BLE001  the broker went away mid-replay
                log.warning("outbox replay of %s interrupted: %r (file kept)", os.path.basename(path), e)
                failed += 1
                continue
            if acked:
                os.remove(path)
                replayed += len(events)
            else:
                log.warning("outbox replay of %s not acknowledged (file kept)", os.path.basename(path))
                failed += 1
        return {"replayed": replayed, "failed_files": failed}

    @staticmethod
    def _read(path: str):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    log.warning("skipping torn/invalid line in %s", os.path.basename(path))

    # ---------- housekeeping ----------

    def prune(self, max_age_days: float = 7.0) -> int:
        """Delete sealed files older than max_age_days (never the open file)."""
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        for path in self.sealed_files():
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError:
                pass
        if removed:
            log.warning("pruned %d outbox file(s) older than %.0f days (events lost)", removed, max_age_days)
        return removed
