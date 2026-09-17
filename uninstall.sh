#!/usr/bin/env bash
set -Eeuo pipefail
PURGE=0
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
for a in "$@"; do case "$a" in --purge) PURGE=1;; -h|--help) echo "Usage: sudo ./uninstall.sh [--purge]"; exit 0;; *) echo "Unknown option: $a" >&2; exit 2;; esac; done
systemctl disable --now flowcollector.service 2>/dev/null || true
rm -f /etc/systemd/system/flowcollector.service
systemctl daemon-reload
rm -f /usr/local/bin/flowcollector /usr/local/bin/flowgen
if (( PURGE )); then
  rm -rf /etc/flowcollector /var/lib/flowcollector /var/log/flowcollector
  id flowcollector >/dev/null 2>&1 && userdel flowcollector || true
  getent group flowcollector >/dev/null 2>&1 && groupdel flowcollector || true
  echo "Central Flow Collector removed including configuration and data."
else
  echo "Binaries/service removed. Configuration and data were preserved. Use --purge to delete them."
fi
