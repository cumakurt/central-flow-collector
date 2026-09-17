#!/usr/bin/env sh
set -eu
PREFIX=/usr/local
CONFIG_DIR=/usr/local/etc/flowcollector
DATA_DIR=/var/lib/flowcollector
PURGE=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2;;
    --config-dir) CONFIG_DIR=$2; shift 2;;
    --data-dir) DATA_DIR=$2; shift 2;;
    --purge-data) PURGE=1; shift;;
    -h|--help) echo "Usage: sudo ./uninstall-portable.sh [--prefix DIR] [--config-dir DIR] [--data-dir DIR] [--purge-data]"; exit 0;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[ -f "$HOME/Library/LaunchAgents/com.centralflowcollector.plist" ] && launchctl unload "$HOME/Library/LaunchAgents/com.centralflowcollector.plist" 2>/dev/null || true
rm -f "$PREFIX/bin/flowcollector" "$CONFIG_DIR/config.yaml"
[ "$PURGE" -eq 1 ] && rm -rf "$DATA_DIR"
echo "Portable collector binaries removed; data retained unless --purge-data was supplied."
