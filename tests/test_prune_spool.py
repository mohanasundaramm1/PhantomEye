import datetime as dt
import os
import subprocess

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "ops", "launchd", "prune_spool.sh")


def _day(offset):
    return (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=offset)).isoformat()


def _spool(tmp_path, *offsets):
    for o in offsets:
        (tmp_path / f"ds={_day(o)}.jsonl").write_text("{}\n" * 5)


def _run(tmp_path, **extra):
    env = dict(os.environ, SPOOL_DIR=str(tmp_path), **{k: str(v) for k, v in extra.items()})
    return subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True)


def _left(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir())


def test_old_days_deleted_recent_and_today_kept(tmp_path):
    _spool(tmp_path, 0, 1, 6, 7, 8, 30)
    r = _run(tmp_path, SPOOL_KEEP_DAYS=7)
    assert r.returncode == 0
    # keep: today, 1, 6, 7 days ago (date >= today-7). delete: 8 and 30 days ago.
    assert _left(tmp_path) == sorted(f"ds={_day(o)}.jsonl" for o in (0, 1, 6, 7))
    assert "pruned 2 file(s)" in r.stdout


def test_todays_file_is_never_removed_even_with_one_day_retention(tmp_path):
    _spool(tmp_path, 0, 1, 2, 3)
    _run(tmp_path, SPOOL_KEEP_DAYS=1)
    assert f"ds={_day(0)}.jsonl" in _left(tmp_path)
    assert f"ds={_day(3)}.jsonl" not in _left(tmp_path)


def test_unrelated_files_are_left_alone(tmp_path):
    _spool(tmp_path, 30)
    for name in ["notes.txt", "ds=not-a-date.jsonl", "ds=2020-13-45.jsonl.bak", "README", "other=2020-01-01.jsonl"]:
        (tmp_path / name).write_text("keep me")
    _run(tmp_path, SPOOL_KEEP_DAYS=7)
    assert _left(tmp_path) == sorted(["notes.txt", "ds=not-a-date.jsonl", "ds=2020-13-45.jsonl.bak", "README", "other=2020-01-01.jsonl"])


def test_dry_run_lists_but_deletes_nothing(tmp_path):
    _spool(tmp_path, 0, 20, 40)
    r = _run(tmp_path, SPOOL_KEEP_DAYS=7, SPOOL_PRUNE_DRY_RUN=1)
    assert r.stdout.count("would delete") == 2
    assert len(_left(tmp_path)) == 3


def test_invalid_retention_refuses_to_run(tmp_path):
    _spool(tmp_path, 0, 20)
    for bad in ["0", "-3", "abc"]:
        r = _run(tmp_path, SPOOL_KEEP_DAYS=bad)
        assert r.returncode == 2, bad
    assert len(_left(tmp_path)) == 2     # nothing deleted by any refused run


def test_empty_retention_uses_the_default_of_seven_days(tmp_path):
    _spool(tmp_path, 3, 20)
    assert _run(tmp_path, SPOOL_KEEP_DAYS="").returncode == 0
    assert _left(tmp_path) == [f"ds={_day(3)}.jsonl"]


def test_missing_directory_is_not_an_error(tmp_path):
    r = _run(tmp_path / "does-not-exist")
    assert r.returncode == 0


def test_rotate_logs_does_not_touch_the_real_spool_when_its_dir_is_overridden(tmp_path):
    # rotate_logs.sh runs the prune too; a test of log rotation (LOG_ROTATE_DIR
    # set, SPOOL_DIR not) must never reach the real spool.
    real = os.path.join(os.path.dirname(__file__), "..", "ct", "data", "low_priority")
    before = sorted(os.listdir(real)) if os.path.isdir(real) else None
    rotate = os.path.join(os.path.dirname(SCRIPT), "rotate_logs.sh")
    env = {k: v for k, v in os.environ.items() if k != "SPOOL_DIR"}
    env.update(LOG_ROTATE_DIR=str(tmp_path), SPOOL_KEEP_DAYS="1")
    subprocess.run(["bash", rotate], env=env, capture_output=True, text=True, check=True)
    assert (sorted(os.listdir(real)) if os.path.isdir(real) else None) == before
