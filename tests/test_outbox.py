"""Durable outbox for the CT forwarder (R-02).

CertStream has no replay, so while Kafka is unreachable the forwarder must
persist events locally and replay them later, never drop them.
"""
import json
import os
import time

from ct.ingest.outbox import Outbox


def _ev(i):
    return {"id": f"ct-{i}", "domain": f"d{i}.example.com", "event_ts": "2026-11-15T00:00:00Z"}


def test_append_then_replay_sends_in_order_and_deletes_after_ack(tmp_path):
    ob = Outbox(str(tmp_path))
    for i in range(5):
        ob.append(_ev(i))
    sent = []

    result = ob.replay(send=lambda ev: sent.append(ev["id"]), flush=lambda: True)

    assert sent == [f"ct-{i}" for i in range(5)]                 # order preserved
    assert result == {"replayed": 5, "failed_files": 0}
    assert ob.pending_count() == 0                                # nothing left on disk
    assert not any(p.endswith(".jsonl") for p in os.listdir(tmp_path))


def test_file_is_kept_when_the_flush_is_not_acknowledged(tmp_path):
    ob = Outbox(str(tmp_path))
    for i in range(3):
        ob.append(_ev(i))

    result = ob.replay(send=lambda ev: None, flush=lambda: False)   # broker never acked

    assert result["failed_files"] == 1
    assert ob.pending_count() == 3                                 # still safe on disk


def test_file_is_kept_when_a_send_raises(tmp_path):
    ob = Outbox(str(tmp_path))
    for i in range(3):
        ob.append(_ev(i))

    def boom(ev):
        raise RuntimeError("kafka went away mid-replay")

    result = ob.replay(send=boom, flush=lambda: True)

    assert result["failed_files"] == 1
    assert ob.pending_count() == 3


def test_events_appended_during_replay_are_not_lost(tmp_path):
    """Replay seals the current file first, so an event appended while a replay is
    running lands in a NEW file and survives the delete of the sealed one."""
    ob = Outbox(str(tmp_path))
    ob.append(_ev(1))

    def send_and_append(ev):
        ob.append(_ev(99))              # a new event arrives mid-replay

    ob.replay(send=send_and_append, flush=lambda: True)

    assert ob.pending_count() == 1
    seen = []
    ob.replay(send=lambda ev: seen.append(ev["id"]), flush=lambda: True)
    assert seen == ["ct-99"]


def test_a_torn_last_line_does_not_block_the_rest(tmp_path):
    """If the process died mid-write the last line can be half a JSON object."""
    ob = Outbox(str(tmp_path))
    ob.append(_ev(1))
    ob.append(_ev(2))
    with open(os.path.join(tmp_path, "current.jsonl"), "a") as f:
        f.write('{"id": "ct-3", "dom')          # truncated, no newline

    sent = []
    ob.replay(send=lambda ev: sent.append(ev["id"]), flush=lambda: True)

    assert sent == ["ct-1", "ct-2"]
    assert ob.pending_count() == 0


def test_empty_outbox_replay_is_a_noop(tmp_path):
    ob = Outbox(str(tmp_path))
    assert ob.replay(send=lambda ev: 1 / 0, flush=lambda: 1 / 0) == {"replayed": 0, "failed_files": 0}


def test_prune_removes_only_sealed_files_older_than_the_limit(tmp_path):
    ob = Outbox(str(tmp_path))
    ob.append(_ev(1))
    ob.seal()
    ob.append(_ev(2))                                   # stays in the open file
    old = [p for p in os.listdir(tmp_path) if p.startswith("sealed-")][0]
    two_weeks = time.time() - 14 * 86400
    os.utime(os.path.join(tmp_path, old), (two_weeks, two_weeks))

    removed = ob.prune(max_age_days=7)

    assert removed == 1
    assert os.path.exists(os.path.join(tmp_path, "current.jsonl"))     # never touches the open file


def test_append_is_json_per_line(tmp_path):
    ob = Outbox(str(tmp_path))
    ob.append(_ev(7))
    line = open(os.path.join(tmp_path, "current.jsonl")).read().strip()
    assert json.loads(line)["id"] == "ct-7"


def test_restart_after_a_torn_write_does_not_corrupt_the_next_event(tmp_path):
    """The process died mid-write, leaving half a line with no newline. A new
    Outbox (the restarted forwarder) must not glue its first event onto it."""
    with open(os.path.join(tmp_path, "current.jsonl"), "w") as f:
        f.write('{"id": "ct-1"}\n{"id": "ct-2", "dom')       # torn tail, no newline

    ob = Outbox(str(tmp_path))
    ob.append(_ev(3))

    sent = []
    ob.replay(send=lambda ev: sent.append(ev["id"]), flush=lambda: True)
    assert sent == ["ct-1", "ct-3"]               # ct-3 survives; the torn ct-2 is skipped


def test_has_pending_is_cheap_and_accurate(tmp_path):
    ob = Outbox(str(tmp_path))
    assert ob.has_pending() is False
    ob.append(_ev(1))
    assert ob.has_pending() is True
    ob.replay(send=lambda ev: None, flush=lambda: True)
    assert ob.has_pending() is False
