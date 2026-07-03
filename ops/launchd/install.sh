#!/usr/bin/env bash
# ops/launchd/install.sh
#
# Install (or re-install) the PhantomEye real-time CT lane as supervised
# launchd user agents, so forwarder.py and stream_ct.py survive crashes,
# laptop sleep, and reboots, and a freshness watchdog shouts if ingest stalls.
#
# Idempotent: safe to re-run. It renders the *.plist.template files in this
# directory with THIS machine's real paths, writes them to
# ~/Library/LaunchAgents, stops any manually-started forwarder/stream_ct
# (so we never end up with two Spark consumers fighting over one checkpoint),
# then (re)loads all three agents.
#
# Usage:  ops/launchd/install.sh        (or:  make supervise-install)
# Remove: ops/launchd/uninstall.sh      (or:  make supervise-uninstall)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
AGENTS_DIR="${HOME}/Library/LaunchAgents"
LOG_DIR="${SCRIPT_DIR}/logs"
UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"

VENV_PY="${REPO_ROOT}/.venv/bin/python"

LABELS=(
  com.phantomeye.forwarder
  com.phantomeye.stream-ct
  com.phantomeye.freshness-watchdog
)

echo "==> PhantomEye supervisor install"
echo "    repo root: ${REPO_ROOT}"
echo "    venv py:   ${VENV_PY}"

# --- preflight ---------------------------------------------------------------
if [[ ! -x "${VENV_PY}" ]]; then
  echo "ERROR: venv python not found/executable at ${VENV_PY}" >&2
  echo "       Create the venv first (python3.11 -m venv .venv && pip install -r ...)." >&2
  exit 1
fi

# JAVA_HOME for the Spark job. Prefer Java 11 (what this project's pyspark uses),
# fall back to any installed JDK, then to deriving from `which java`.
JAVA_HOME_RESOLVED=""
if /usr/libexec/java_home -v 11 >/dev/null 2>&1; then
  JAVA_HOME_RESOLVED="$(/usr/libexec/java_home -v 11)"
elif /usr/libexec/java_home >/dev/null 2>&1; then
  JAVA_HOME_RESOLVED="$(/usr/libexec/java_home)"
elif command -v java >/dev/null 2>&1; then
  JAVA_HOME_RESOLVED="$(cd "$(dirname "$(dirname "$(readlink -f "$(command -v java)" || command -v java)")")" && pwd)"
fi
if [[ -z "${JAVA_HOME_RESOLVED}" ]]; then
  echo "WARNING: could not resolve JAVA_HOME. stream_ct.py (Spark) may fail to" >&2
  echo "         find java under launchd's minimal environment." >&2
  JAVA_HOME_RESOLVED="/usr"
fi
echo "    JAVA_HOME: ${JAVA_HOME_RESOLVED}"

# Explicit PATH for launchd's stripped environment (homebrew + system + JDK bin).
RENDER_PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:${JAVA_HOME_RESOLVED}/bin:/usr/bin:/bin:/usr/sbin:/sbin"

mkdir -p "${AGENTS_DIR}" "${LOG_DIR}"

# --- stop any MANUALLY-started streaming processes ---------------------------
# If a hand-run `make forward-ct` / `make stream-ct` is still alive, leaving it
# running alongside the supervised copy would double-produce (forwarder) or,
# worse, run two Spark consumers against the same checkpoint/output (stream_ct).
echo "==> stopping any manually-started forwarder.py / stream_ct.py ..."
pkill -f "ct/ingest/forwarder.py"  2>/dev/null && echo "    stopped a manual forwarder.py"  || true
pkill -f "ct/ingest/stream_ct.py"  2>/dev/null && echo "    stopped a manual stream_ct.py"  || true
# Give Spark a moment to release its checkpoint locks before the agent restarts it.
sleep 2

# --- render + (re)load each agent -------------------------------------------
render_plist() {
  local label="$1"
  local template="${SCRIPT_DIR}/${label}.plist.template"
  local dest="${AGENTS_DIR}/${label}.plist"

  if [[ ! -f "${template}" ]]; then
    echo "ERROR: missing template ${template}" >&2
    exit 1
  fi

  # Substitute placeholders. Use a non-/ delimiter for sed since paths contain /.
  sed \
    -e "s|__REPO_ROOT__|${REPO_ROOT}|g" \
    -e "s|__VENV_PY__|${VENV_PY}|g" \
    -e "s|__JAVA_HOME__|${JAVA_HOME_RESOLVED}|g" \
    -e "s|__PATH__|${RENDER_PATH}|g" \
    "${template}" > "${dest}"

  # Validate the rendered plist before we try to load it.
  if ! plutil -lint "${dest}" >/dev/null; then
    echo "ERROR: rendered plist failed validation: ${dest}" >&2
    exit 1
  fi

  # bootout first (ignore errors if not currently loaded), then bootstrap.
  launchctl bootout "${DOMAIN}/${label}" 2>/dev/null || true
  launchctl bootstrap "${DOMAIN}" "${dest}"
  # kickstart -k forces an immediate (re)start now, not just at next trigger.
  launchctl kickstart -k "${DOMAIN}/${label}" 2>/dev/null || true
  echo "    loaded ${label}"
}

echo "==> rendering + loading agents ..."
for label in "${LABELS[@]}"; do
  render_plist "${label}"
done

echo
echo "==> done. Current status:"
for label in "${LABELS[@]}"; do
  if launchctl print "${DOMAIN}/${label}" >/dev/null 2>&1; then
    state="$(launchctl print "${DOMAIN}/${label}" 2>/dev/null | awk -F'= ' '/state = /{print $2; exit}')"
    pid="$(launchctl print "${DOMAIN}/${label}" 2>/dev/null | awk -F'= ' '/pid = /{print $2; exit}')"
    echo "    ${label}: state=${state:-?} pid=${pid:-none}"
  else
    echo "    ${label}: NOT LOADED (check ${LOG_DIR})"
  fi
done

echo
echo "Logs:        ${LOG_DIR}/*.log"
echo "Status:      make supervise-status"
echo "Remove all:  make supervise-uninstall"
