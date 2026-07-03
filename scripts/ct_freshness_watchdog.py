#!/usr/bin/env python
# scripts/ct_freshness_watchdog.py
#
# The "make silent failure LOUD" safety net for the real-time CT lane.
#
# WHY THIS EXISTS, separately from launchd supervision:
#   launchd KeepAlive restarts a process when it *exits*. It does NOT catch the
#   worse failure mode this project actually hit: a process that stays alive but
#   stops producing output (e.g. the Spark _spark_metadata / checkpoint mismatch
#   that made stream_ct.py run cleanly while writing zero files, or the forwarder
#   staying connected to a wedged broker). Liveness != progress. This watchdog
#   checks *output progress* -- is fresh CT data actually landing in
#   ct/data/raw? -- and shouts if not, regardless of whether the processes look
#   "up". It is the canary that would have caught the 8h outage in minutes.
#
# WHAT IT DOES:
#   1. Runs the existing scripts/check_ct_freshness.py raw-freshness check
#      (is the newest ct/data/raw file younger than --max-age-minutes?).
#   2. On STALE: fires a macOS Notification Center banner (osascript), logs a
#      loud line, and writes a marker file -- so silent failure becomes visible.
#   3. Throttles notifications (default: at most one per --notify-throttle-min)
#      so a sustained outage doesn't spam a banner every run, while still
#      re-alerting periodically so it can't be forgotten.
#   4. On RECOVERY (stale -> fresh): fires a one-shot "recovered" notification
#      and clears the marker.
#
# Designed to be run every few minutes by a launchd StartInterval agent
# (see ops/launchd/), but is a plain script -- `python scripts/ct_freshness_watchdog.py`
# works standalone for a manual spot-check too.
#
# Exit codes mirror check_ct_freshness.py: 0 fresh, 1 stale, 2 could-not-check.
# (launchd ignores these, but they make the script useful in cron/CI as well.)

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
FRESHNESS_CHECK = os.path.join(THIS_DIR, "check_ct_freshness.py")

# State/marker lives under ops/launchd/logs (gitignored) so a human (or the
# next watchdog run) can see the last known status without scraping logs.
STATE_DIR_DEFAULT = os.path.join(REPO_ROOT, "ops", "launchd", "logs")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(msg: str) -> None:
    # stdout is captured to the launchd StandardOutPath log; prefix so lines
    # are greppable and timestamped even when interleaved.
    print(f"[watchdog {_now_iso()}] {msg}", flush=True)


def _notify(title: str, message: str) -> None:
    """Best-effort macOS Notification Center banner. Never raises -- an alerting
    path that crashes the watchdog would defeat the purpose."""
    try:
        # Keep the payload simple; osascript is picky about embedded quotes.
        safe_msg = message.replace('"', "'")
        safe_title = title.replace('"', "'")
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{safe_msg}" with title "{safe_title}"'],
            check=False,
            timeout=10,
            capture_output=True,
        )
    except Exception as e:  # noqa: BLE001 - alerting must never crash the watchdog
        _log(f"notify failed (non-fatal): {e!r}")


def _read_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _write_state(path: str, state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        _log(f"could not persist state (non-fatal): {e!r}")


def _run_freshness_check(max_age_minutes: float) -> tuple[int, str]:
    """Run check_ct_freshness.py for RAW freshness only. Returns (exit_code, output).

    We only care about "is fresh data landing?" here -- the scored-staleness and
    event_ts checks belong to the batch DAG's freshness_gate, not to this
    real-time ingest canary. --skip-scored/--skip-event-ts keep this fast and
    focused on the ingest liveness signal.
    """
    max_age_hours = max_age_minutes / 60.0
    cmd = [
        sys.executable, FRESHNESS_CHECK,
        "--skip-scored", "--skip-event-ts",
        "--raw-max-age-hours", f"{max_age_hours:.4f}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 2, "freshness check timed out after 120s"
    except Exception as e:  # noqa: BLE001
        return 2, f"freshness check failed to run: {e!r}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Loud staleness watchdog for the real-time CT lane.")
    ap.add_argument("--max-age-minutes", type=float,
                    default=float(os.getenv("CT_WATCHDOG_MAX_AGE_MIN", "60")),
                    help="alert if newest ct/data/raw file is older than this (default: 60m). "
                         "The stream normally writes every few seconds, so 60m is well clear of "
                         "false positives while still catching a real outage fast.")
    ap.add_argument("--notify-throttle-min", type=float,
                    default=float(os.getenv("CT_WATCHDOG_THROTTLE_MIN", "30")),
                    help="minimum minutes between repeat STALE notifications (default: 30).")
    ap.add_argument("--state-dir", default=os.getenv("CT_WATCHDOG_STATE_DIR", STATE_DIR_DEFAULT))
    args = ap.parse_args(argv)

    state_path = os.path.join(args.state_dir, "watchdog_state.json")
    state = _read_state(state_path)
    was_stale = bool(state.get("stale", False))
    last_notified = float(state.get("last_notified_epoch", 0.0))
    now = time.time()

    code, output = _run_freshness_check(args.max_age_minutes)
    is_stale = (code == 1) or (code == 2)  # 2 = can't even check = treat as not-healthy

    if is_stale:
        reason = "raw CT data is stale" if code == 1 else "freshness check could not run"
        _log(f"STALE detected ({reason}). check_ct_freshness output:\n{output.strip()}")
        throttle_sec = args.notify_throttle_min * 60.0
        if (not was_stale) or (now - last_notified >= throttle_sec):
            _notify(
                "PhantomEye: CT ingest STALE",
                f"No fresh CT data in >{args.max_age_minutes:.0f}m. "
                f"forwarder.py / stream_ct.py may be wedged. Check: make supervise-status",
            )
            last_notified = now
            _log("fired STALE notification")
        else:
            mins_left = (throttle_sec - (now - last_notified)) / 60.0
            _log(f"STALE notification throttled ({mins_left:.0f}m until next)")
        _write_state(state_path, {
            "stale": True,
            "last_checked_epoch": now,
            "last_checked_iso": _now_iso(),
            "last_notified_epoch": last_notified,
            "last_exit_code": code,
        })
        return 1 if code == 1 else 2

    # Fresh.
    if was_stale:
        _notify("PhantomEye: CT ingest RECOVERED", "Fresh CT data is landing again.")
        _log("RECOVERED: fresh data landing again; cleared stale state")
    else:
        _log("OK: fresh CT data landing")
    _write_state(state_path, {
        "stale": False,
        "last_checked_epoch": now,
        "last_checked_iso": _now_iso(),
        "last_notified_epoch": last_notified,
        "last_exit_code": 0,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
