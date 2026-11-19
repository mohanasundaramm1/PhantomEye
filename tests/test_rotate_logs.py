import gzip
import os
import subprocess

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "ops", "launchd", "rotate_logs.sh")


def _rotate(tmp_path, max_bytes=100, keep=3):
    env = dict(os.environ, LOG_ROTATE_DIR=str(tmp_path),
               LOG_ROTATE_MAX_BYTES=str(max_bytes), LOG_ROTATE_KEEP=str(keep))
    return subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True, check=True)


def _read_gz(p):
    return gzip.open(p, "rt").read()


def test_small_log_is_left_alone(tmp_path):
    log = tmp_path / "forwarder.err.log"
    log.write_text("tiny")
    _rotate(tmp_path)
    assert log.read_text() == "tiny"
    assert not (tmp_path / "forwarder.err.log.1.gz").exists()


def test_big_log_is_backed_up_then_truncated_in_place(tmp_path):
    log = tmp_path / "forwarder.err.log"
    log.write_text("A" * 500)
    inode = os.stat(log).st_ino
    _rotate(tmp_path)
    assert log.read_text() == ""
    assert os.stat(log).st_ino == inode          # same inode: the process's open fd stays valid
    assert _read_gz(tmp_path / "forwarder.err.log.1.gz") == "A" * 500


def test_a_process_holding_the_log_open_keeps_writing_after_rotation(tmp_path):
    log = tmp_path / "stream-ct.err.log"
    fh = open(log, "a")                           # launchd opens the log once, in append mode
    fh.write("x" * 500); fh.flush()
    _rotate(tmp_path)
    fh.write("after-rotation\n"); fh.flush(); fh.close()
    assert log.read_text() == "after-rotation\n"  # lands at the new end, not past a sparse hole


def test_several_generations_are_kept_oldest_dropped(tmp_path):
    log = tmp_path / "forwarder.err.log"
    for gen in ["one", "two", "three", "four"]:
        log.write_text(gen * 100)
        _rotate(tmp_path, keep=3)
    # newest first; "one" (the oldest of four rotations) has aged out with keep=3
    assert _read_gz(tmp_path / "forwarder.err.log.1.gz").startswith("four")
    assert _read_gz(tmp_path / "forwarder.err.log.2.gz").startswith("three")
    assert _read_gz(tmp_path / "forwarder.err.log.3.gz").startswith("two")
    assert not (tmp_path / "forwarder.err.log.4.gz").exists()


def test_a_noisy_burst_cannot_erase_the_earlier_evidence(tmp_path):
    # the incident: one generation kept, so a single spam burst overwrote the
    # only backup. Now an earlier log survives the next rotation.
    log = tmp_path / "forwarder.err.log"
    log.write_text("EVIDENCE" * 100); _rotate(tmp_path)
    log.write_text("SPAM" * 200);     _rotate(tmp_path)
    assert _read_gz(tmp_path / "forwarder.err.log.2.gz").startswith("EVIDENCE")
