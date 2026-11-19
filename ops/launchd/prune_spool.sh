#!/usr/bin/env bash
# ops/launchd/prune_spool.sh
#
# Retention for the forwarder's low-priority spool (ct/data/low_priority/
# ds=YYYY-MM-DD.jsonl): deletes day-files older than SPOOL_KEEP_DAYS (default 7).
#
# Why: the forwarder appends every below-threshold domain to a per-day jsonl and
# nothing ever removes them. After the forwarder was fixed to keep up with
# CertStream (it had been dropping ~1,000 certs/s) the spool grew ~10.9 GB/day;
# at that rate the disk fills in about two weeks -- the same failure class as the
# 178 GB log. The only reader is ml/core/fit_triage_weights.py, which needs two
# recent days.
#
# Safety:
#   - only files named exactly ds=YYYY-MM-DD.jsonl are considered; anything else
#     in the directory is left alone
#   - the cutoff is by the DATE IN THE FILENAME, never mtime, and a file dated
#     on or after (today - KEEP_DAYS) is kept, so today's file (still being
#     appended to) can never be removed
#   - the forwarder opens/appends/closes the day-file per event, holding no long-
#     lived handle, so removing an old day cannot disturb it
#   - SPOOL_KEEP_DAYS must be an integer >= 1
#   - SPOOL_PRUNE_DRY_RUN=1 lists what WOULD be deleted and deletes nothing
#
# Run every 15 min by rotate_logs.sh (the com.phantomeye.log-rotate agent).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPOOL_DIR="${SPOOL_DIR:-${SCRIPT_DIR}/../../ct/data/low_priority}"
KEEP_DAYS="${SPOOL_KEEP_DAYS:-7}"
DRY_RUN="${SPOOL_PRUNE_DRY_RUN:-0}"

if ! [[ "${KEEP_DAYS}" =~ ^[0-9]+$ ]] || (( KEEP_DAYS < 1 )); then
  echo "prune_spool: SPOOL_KEEP_DAYS must be an integer >= 1 (got '${KEEP_DAYS}'); doing nothing" >&2
  exit 2
fi
[[ -d "${SPOOL_DIR}" ]] || exit 0

# BSD date (macOS) first, GNU date (Linux/CI) as the fallback.
CUTOFF="$(date -u -v-"${KEEP_DAYS}"d +%F 2>/dev/null || date -u -d "${KEEP_DAYS} days ago" +%F)"

total_files=0
total_bytes=0
for f in "${SPOOL_DIR}"/ds=*.jsonl; do
  [[ -f "${f}" ]] || continue
  base="${f##*/}"
  day="${base#ds=}"
  day="${day%.jsonl}"
  [[ "${day}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || continue
  [[ "${day}" < "${CUTOFF}" ]] || continue
  size="$(wc -c < "${f}" 2>/dev/null | tr -d ' ')"
  size="${size:-0}"
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "would delete ${base} (${size} bytes)"
  elif rm -f -- "${f}"; then
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') pruned ${base} (${size} bytes, older than ${CUTOFF})"
  else
    echo "prune_spool: could not delete ${f}" >&2
    continue
  fi
  total_files=$(( total_files + 1 ))
  total_bytes=$(( total_bytes + size ))
done

if (( total_files > 0 )); then
  verb="pruned"; [[ "${DRY_RUN}" == "1" ]] && verb="would prune"
  echo "prune_spool: ${verb} ${total_files} file(s), ${total_bytes} bytes (keeping ${KEEP_DAYS} days, cutoff ${CUTOFF})"
fi
