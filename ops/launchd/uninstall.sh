#!/usr/bin/env bash
# ops/launchd/uninstall.sh
#
# Cleanly remove the PhantomEye launchd supervisor agents installed by
# install.sh. Stops all three agents and deletes their rendered plists from
# ~/Library/LaunchAgents. Does NOT touch Docker services or the repo.
#
# After this, the real-time CT lane is back to being manual (make forward-ct /
# make stream-ct) and nothing will auto-restart it.
#
# Usage: ops/launchd/uninstall.sh   (or:  make supervise-uninstall)

set -uo pipefail

AGENTS_DIR="${HOME}/Library/LaunchAgents"
UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"

LABELS=(
  com.phantomeye.forwarder
  com.phantomeye.stream-ct
  com.phantomeye.freshness-watchdog
)

echo "==> removing PhantomEye supervisor agents ..."
for label in "${LABELS[@]}"; do
  if launchctl bootout "${DOMAIN}/${label}" 2>/dev/null; then
    echo "    booted out ${label}"
  else
    echo "    ${label} was not loaded"
  fi
  dest="${AGENTS_DIR}/${label}.plist"
  if [[ -f "${dest}" ]]; then
    rm -f "${dest}"
    echo "    removed ${dest}"
  fi
done

echo
echo "==> done. The CT lane is no longer supervised."
echo "    Restart it manually with:  make forward-ct   and   make stream-ct"
echo "    (or re-supervise with:      make supervise-install )"
