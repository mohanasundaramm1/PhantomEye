#!/usr/bin/env bash
# ops/launchd/rotate_logs.sh
#
# Caps the size of the log files launchd redirects forwarder.py's and
# stream_ct.py's stdout/stderr into. Found live: forwarder.err.log grew to
# 178 GB (stream-ct.err.log to 686 MB) because launchd's StandardOutPath /
# StandardErrorPath just append forever -- nothing ever rotates them. That
# filled the disk to 5.3 GB free.
#
# copytruncate, not rename-and-recreate: both supervised processes hold their
# stdout/stderr file descriptor open for the life of the process (that's what
# StandardOutPath/StandardErrorPath do -- launchd opens the file once, at
# process start, in append mode). A rename+recreate rotation (the "logrotate"
# default) would leave that fd pointed at the now-detached, renamed file
# forever -- the live log would go dark and the "new" file would never be
# written to, silently defeating rotation. copytruncate keeps the same inode
# (`: > file` truncates in place) so the open fd keeps working; this is also
# exactly what was done by hand to recover the 178 GB (verified live: the
# forwarder kept appending correctly immediately after truncation, at offset
# 0, because it writes with O_APPEND).
#
# Several rotated generations are kept per file (`<name>.log.1.gz` newest ...
# `<name>.log.N.gz` oldest, N = LOG_ROTATE_KEEP, default 5). These are
# operational logs, not an audit trail, but ONE generation turned out to be too
# few: during a CertStream outage the forwarder's reconnect-error spam filled a
# whole 50 MB generation in 15 minutes, and the next rotation overwrote the only
# backup -- destroying the evidence of what had happened in the days before.
# With 5 generations a single noisy burst can't erase everything that came
# before it. (The burst itself is now prevented at the source: see
# ct/ingest/backoff.py.) Worst case disk use: 6 x 50 MB per file, compressed
# far smaller.
#
# Run every 15 min by com.phantomeye.log-rotate (StartInterval; see
# com.phantomeye.log-rotate.plist.template). Safe to run by hand or re-run
# anytime: does nothing to a file under MAX_BYTES.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_ROTATE_DIR:-${SCRIPT_DIR}/logs}"   # overridable so tests don't touch real logs
MAX_BYTES="${LOG_ROTATE_MAX_BYTES:-52428800}"      # 50 MB
KEEP="${LOG_ROTATE_KEEP:-5}"                        # rotated generations kept per file

rotate_one() {
  local f="$1"
  [[ -f "${f}" ]] || return 0
  local size
  # `wc -c < file`, not `stat -f %z`: BSD stat (macOS) and GNU stat (Linux CI)
  # disagree on -f, and a silent 0 here would mean "never rotate".
  size="$(wc -c < "${f}" 2>/dev/null | tr -d ' ')"
  size="${size:-0}"
  if (( size <= MAX_BYTES )); then
    return 0
  fi
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') rotating ${f} (${size} bytes)"
  # Age the existing backups: .(N-1) -> .N ... .1 -> .2 (the oldest, .N, is
  # overwritten). These are separate files, not the live log, so renaming them
  # is safe.
  local i
  for (( i = KEEP - 1; i >= 1; i-- )); do
    [[ -f "${f}.${i}.gz" ]] && mv -f "${f}.${i}.gz" "${f}.$(( i + 1 )).gz"
  done
  # Copy first (compressed), THEN truncate the same inode in place -- never
  # rm/mv the live file; see header for why that would break the open fd.
  # Only truncate if the backup was actually written: losing the log AND the
  # backup (e.g. disk full) is worse than a log that stays big one more cycle.
  if gzip -c "${f}" > "${f}.1.gz.tmp" 2>/dev/null; then
    mv -f "${f}.1.gz.tmp" "${f}.1.gz"
    : > "${f}"
  else
    rm -f "${f}.1.gz.tmp"
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') WARNING: could not back up ${f}; leaving it untruncated"
  fi
}

for f in "${LOG_DIR}"/forwarder.out.log \
         "${LOG_DIR}"/forwarder.err.log \
         "${LOG_DIR}"/stream-ct.out.log \
         "${LOG_DIR}"/stream-ct.err.log \
         "${LOG_DIR}"/watchdog.out.log \
         "${LOG_DIR}"/watchdog.err.log; do
  rotate_one "${f}"
done

# Also trim the forwarder's low-priority spool (see prune_spool.sh). Skipped
# when LOG_ROTATE_DIR is overridden (i.e. under test) unless SPOOL_DIR is too,
# so a test of log rotation can never delete real spool data by default.
if [[ -z "${LOG_ROTATE_DIR:-}" || -n "${SPOOL_DIR:-}" ]]; then
  bash "${SCRIPT_DIR}/prune_spool.sh"
fi
