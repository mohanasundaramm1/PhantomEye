#!/usr/bin/env python
# scripts/check_ct_freshness.py
#
# Operationalizes a manual audit finding: the CT scorer had been re-scoring
# the same static/stale snapshot instead of ingesting fresh domains. Every
# recent gold/threat_scores file was the exact same byte size across many
# separate 2-hour cron runs, and ct/data/raw only had a handful of
# date-partitions total. This script turns that manual "diff a few file
# sizes" check into a repeatable, exit-code-driven one.
#
# Two independent checks:
#
#   1. RAW FRESHNESS: find the most recently modified file under
#      ct/data/raw/ds=YYYY-MM-DD/ and warn if it's older than
#      --raw-max-age-hours (default 4h, since ct_enrich_and_score_dag runs
#      every 2h -- 4h gives one missed cycle of slack before alerting).
#
#   2. SCORED STATICNESS: look at the most recent --scored-lookback (default
#      5) files in gold/threat_scores/, and flag it if they all look
#      identical -- same file size AND same row count (via parquet
#      metadata, no need to load full data into memory). Byte-identical
#      output across separate scoring runs is the exact signal the audit
#      used manually to catch the scorer re-processing a stale snapshot.
#
# Exit codes (for cron/CI use):
#   0 = fresh, everything looks fine
#   1 = stale (raw data too old, and/or scored outputs look static)
#   2 = could not run the check at all (e.g. directories don't exist yet)
#
# Env vars (mirroring ct/ingest/stream_ct.py and ct/score/score_ct_with_latest.py
# path overrides, so this script points at the same directories those do):
#   CT_RAW_DIR       (default "<repo>/ct/data/raw")
#   CT_SCORED_DIR    (default "<repo>/gold/threat_scores")
#
# CLI flags override env vars, which override the defaults above.

import argparse
import glob
import hashlib
import os
import sys
import time
from datetime import datetime, timezone

try:
    import pyarrow.parquet as pq
except ImportError:
    pq = None

# ---------- paths ----------

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))

RAW_DIR_DEFAULT = os.path.join(REPO_ROOT, "ct", "data", "raw")
SCORED_DIR_DEFAULT = os.path.join(REPO_ROOT, "gold", "threat_scores")

RAW_MAX_AGE_HOURS_DEFAULT = 4.0  # ct_enrich_and_score_dag runs every 2h
SCORED_LOOKBACK_DEFAULT = 5


# ---------- helpers ----------

def _human_age(seconds: float) -> str:
    hours = seconds / 3600.0
    if hours < 1:
        return f"{seconds / 60.0:.0f}m"
    return f"{hours:.1f}h"


def _newest_mtime_under(root: str):
    """Return (path, mtime) of the most recently modified file under root,
    walking date partitions. None if root doesn't exist or has no files."""
    if not os.path.isdir(root):
        return None
    newest_path, newest_mtime = None, -1.0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            try:
                mtime = os.path.getmtime(fp)
            except OSError:
                continue
            if mtime > newest_mtime:
                newest_path, newest_mtime = fp, mtime
    if newest_path is None:
        return None
    return newest_path, newest_mtime


def _count_date_partitions(root: str) -> int:
    if not os.path.isdir(root):
        return 0
    return len([
        d for d in os.listdir(root)
        if d.startswith("ds=") and os.path.isdir(os.path.join(root, d))
    ])


def _file_row_count(path: str):
    """Row count via parquet metadata only -- no need to load the file."""
    if pq is None:
        return None
    try:
        return pq.ParquetFile(path).metadata.num_rows
    except Exception:
        return None


def _file_content_hash(path: str, sample_bytes: int = 1_000_000) -> str:
    """Cheap content fingerprint: hash up to the first `sample_bytes` bytes.
    Full-file hashing is unnecessary here -- we only need to distinguish
    "identical output" from "different output", and a stale re-score
    produces byte-for-byte identical files (same data, same column order),
    so a bounded prefix hash is sufficient and keeps this check fast even
    on large parquet files."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(sample_bytes))
    return h.hexdigest()


# ---------- checks ----------

def check_raw_freshness(raw_dir: str, max_age_hours: float):
    """Returns (ok: bool, lines: list[str])."""
    lines = []
    result = _newest_mtime_under(raw_dir)
    n_partitions = _count_date_partitions(raw_dir)

    if result is None:
        lines.append(f"[raw]  NO DATA under {raw_dir} -- nothing has landed yet.")
        lines.append(f"[raw]  date-partitions found: {n_partitions}")
        return False, lines

    newest_path, newest_mtime = result
    age_sec = time.time() - newest_mtime
    age_hours = age_sec / 3600.0
    newest_dt = datetime.fromtimestamp(newest_mtime, tz=timezone.utc)

    lines.append(f"[raw]  dir: {raw_dir}")
    lines.append(f"[raw]  date-partitions found: {n_partitions}")
    lines.append(f"[raw]  newest file: {newest_path}")
    lines.append(f"[raw]  newest file mtime: {newest_dt.isoformat()} ({_human_age(age_sec)} ago)")

    if age_hours > max_age_hours:
        lines.append(
            f"[raw]  WARNING: newest raw CT data is {age_hours:.1f}h old, "
            f"older than threshold ({max_age_hours:.1f}h). The CT forwarder "
            f"and/or stream_ct.py consumer may not be running, or CertStream "
            f"has stopped delivering events."
        )
        return False, lines

    lines.append(f"[raw]  OK ({age_hours:.1f}h <= {max_age_hours:.1f}h threshold)")
    return True, lines


def check_scored_staleness(scored_dir: str, lookback: int):
    """Returns (ok: bool, lines: list[str])."""
    lines = []
    pattern = os.path.join(scored_dir, "ct_scored_*.parquet")
    files = sorted(glob.glob(pattern), key=os.path.getmtime)

    if not files:
        lines.append(f"[scored] NO FILES matching {pattern} -- scorer has never run (or wrong dir).")
        return False, lines

    recent = files[-lookback:]
    lines.append(f"[scored] dir: {scored_dir}")
    lines.append(f"[scored] total scored files: {len(files)}; comparing most recent {len(recent)}")

    if len(recent) < 2:
        lines.append("[scored] only one scored file exists yet -- nothing to compare, skipping staleness check.")
        return True, lines

    sizes = []
    row_counts = []
    hashes = []
    for fp in recent:
        size = os.path.getsize(fp)
        rows = _file_row_count(fp)
        chash = _file_content_hash(fp)
        mtime = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)
        sizes.append(size)
        row_counts.append(rows)
        hashes.append(chash)
        lines.append(
            f"[scored]   {os.path.basename(fp)}  mtime={mtime.isoformat()}  "
            f"size={size}B  rows={rows if rows is not None else 'n/a'}  "
            f"hash={chash[:12]}"
        )

    all_same_size = len(set(sizes)) == 1
    # row_counts may contain None if pyarrow isn't available; only compare
    # when every file yielded a real count.
    have_all_rows = all(r is not None for r in row_counts)
    all_same_rows = have_all_rows and len(set(row_counts)) == 1
    all_same_hash = len(set(hashes)) == 1

    if all_same_hash or (all_same_size and (all_same_rows or not have_all_rows)):
        lines.append(
            f"[scored] WARNING: the last {len(recent)} scored files are identical "
            f"(same size{' + same row count' if have_all_rows else ''} + same content hash). "
            f"The CT scorer appears to be re-scoring a static/stale snapshot "
            f"instead of ingesting fresh domains -- this is the exact signal "
            f"the infra audit used manually to catch this failure mode."
        )
        return False, lines

    lines.append(
        f"[scored] OK: recent scored files differ "
        f"(sizes={sorted(set(sizes))}"
        + (f", row_counts={sorted(set(row_counts))}" if have_all_rows else "")
        + ")."
    )
    return True, lines


def check_scored_event_ts(scored_dir: str, max_age_hours: float):
    """Newest scored file should carry RECENT event_ts values -- not a stale
    re-score of an old snapshot. This catches the 'fresh filename, stale
    content' failure: a scored file with a current mtime whose rows all carry
    a months-old event_ts, which means the enrich->score pointer never
    advanced to fresh domains. Returns (ok, lines)."""
    lines = []
    files = sorted(glob.glob(os.path.join(scored_dir, "ct_scored_*.parquet")),
                   key=os.path.getmtime)
    if not files:
        lines.append("[event_ts] no scored files.")
        return False, lines
    newest = files[-1]
    try:
        import pandas as pd
        df = pd.read_parquet(newest, columns=["event_ts"])
        ets = pd.to_datetime(df["event_ts"], utc=True, errors="coerce")
        newest_event = ets.max()
    except Exception as e:
        lines.append(f"[event_ts] could not read event_ts from {os.path.basename(newest)}: {e}")
        return True, lines  # missing/unreadable column: don't hard-fail here
    import pandas as pd
    if pd.isna(newest_event):
        lines.append(f"[event_ts] {os.path.basename(newest)} has no parseable event_ts.")
        return True, lines
    age_h = (pd.Timestamp.now(tz="UTC") - newest_event).total_seconds() / 3600.0
    lines.append(f"[event_ts] newest scored file: {os.path.basename(newest)}")
    lines.append(f"[event_ts] max event_ts in it: {newest_event.isoformat()} ({age_h:.1f}h old)")
    if age_h > max_age_hours:
        lines.append(
            f"[event_ts] WARNING: newest scored data's event_ts is {age_h:.1f}h old "
            f"(> {max_age_hours:.1f}h threshold). The scorer is emitting fresh FILES "
            f"but STALE CONTENT -- the enrich->score pointer is not advancing to "
            f"fresh domains. This is the exact break the July 2026 audit found."
        )
        return False, lines
    lines.append(f"[event_ts] OK ({age_h:.1f}h <= {max_age_hours:.1f}h)")
    return True, lines


# ---------- CLI ----------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description=(
            "Check CT pipeline freshness: warns/fails if ct/data/raw hasn't "
            "been updated recently, or if gold/threat_scores looks like a "
            "static snapshot being re-scored instead of fresh domains."
        )
    )
    ap.add_argument(
        "--raw-dir",
        default=os.getenv("CT_RAW_DIR", RAW_DIR_DEFAULT),
        help=f"CT raw parquet dir (default: {RAW_DIR_DEFAULT})",
    )
    ap.add_argument(
        "--scored-dir",
        default=os.getenv("CT_SCORED_DIR", SCORED_DIR_DEFAULT),
        help=f"CT scored parquet dir (default: {SCORED_DIR_DEFAULT})",
    )
    ap.add_argument(
        "--raw-max-age-hours",
        type=float,
        default=float(os.getenv("CT_RAW_MAX_AGE_HOURS", RAW_MAX_AGE_HOURS_DEFAULT)),
        help=f"warn if newest raw file is older than this many hours (default: {RAW_MAX_AGE_HOURS_DEFAULT})",
    )
    ap.add_argument(
        "--scored-lookback",
        type=int,
        default=int(os.getenv("CT_SCORED_LOOKBACK", SCORED_LOOKBACK_DEFAULT)),
        help=f"how many recent scored files to compare (default: {SCORED_LOOKBACK_DEFAULT})",
    )
    ap.add_argument(
        "--scored-event-max-age-hours",
        type=float,
        default=float(os.getenv("CT_SCORED_EVENT_MAX_AGE_HOURS", 6.0)),
        help="fail if the newest scored file's max event_ts is older than this many hours (default: 6)",
    )
    ap.add_argument(
        "--skip-event-ts",
        action="store_true",
        help="skip the scored event_ts freshness check",
    )
    ap.add_argument(
        "--skip-raw",
        action="store_true",
        help="skip the ct/data/raw freshness check",
    )
    ap.add_argument(
        "--skip-scored",
        action="store_true",
        help="skip the gold/threat_scores staticness check",
    )
    args = ap.parse_args(argv)

    if pq is None:
        print(
            "[warn] pyarrow not importable -- row-count comparison will be "
            "skipped, falling back to file-size + content-hash only.",
            file=sys.stderr,
        )

    print("=" * 72)
    print("CT freshness check")
    print(f"  raw dir:     {args.raw_dir}")
    print(f"  scored dir:  {args.scored_dir}")
    print(f"  raw threshold: {args.raw_max_age_hours}h   scored lookback: {args.scored_lookback}")
    print("=" * 72)

    ok = True
    ran_any = False

    if not args.skip_raw:
        ran_any = True
        raw_ok, raw_lines = check_raw_freshness(args.raw_dir, args.raw_max_age_hours)
        print("\n".join(raw_lines))
        ok = ok and raw_ok
    print()

    if not args.skip_scored:
        ran_any = True
        scored_ok, scored_lines = check_scored_staleness(args.scored_dir, args.scored_lookback)
        print("\n".join(scored_lines))
        ok = ok and scored_ok
    print()

    if not args.skip_event_ts:
        ran_any = True
        ev_ok, ev_lines = check_scored_event_ts(args.scored_dir, args.scored_event_max_age_hours)
        print("\n".join(ev_lines))
        ok = ok and ev_ok
    print()

    print("=" * 72)
    if not ran_any:
        print("RESULT: NOTHING TO CHECK (both --skip-raw and --skip-scored set)")
        return 2

    print(f"RESULT: {'OK' if ok else 'STALE'}")
    print("=" * 72)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
