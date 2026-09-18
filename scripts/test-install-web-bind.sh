#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run this installer test as root in an isolated container" >&2; exit 77; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
PID=""
cleanup() { [[ -z "$PID" ]] || { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/fakebin" "$T/systemd"
printf '#!/bin/sh\nexit 0\n' > "$T/fakebin/systemctl"
chmod +x "$T/fakebin/systemctl"
install_test() {
  PATH="$T/fakebin:$PATH" FLOWCOLLECTOR_SYSTEMD_DIR="$T/systemd" "$ROOT/install.sh" \
    --prefix "$T/bin" --config-dir "$T/etc" --data-dir "$T/data" --log-dir "$T/log" \
    --user root --group root --local-storage --no-start --no-enable "$@" > "$T/install.log" 2>&1 || { cat "$T/install.log"; return 1; }
}
check_bind() {
  "$T/bin/flowcollector" config validate --config "$T/etc/config.yaml" | grep -F "web_bind=$1)"
}
install_test
check_bind 0.0.0.0
install_test --web-bind 127.0.0.1
check_bind 127.0.0.1
# Simulate an existing portal override and a legacy TLS profile.
printf '%s\n' '{"web":{"bind":"127.0.0.1","port":8080,"tls":false,"cert_file":"","key_file":""}}' > "$T/data/admin-settings.json"
sed -i '/^web:/,/^[^ ]/s/^  tls:.*/  tls: true/' "$T/etc/config.yaml"
install_test
check_bind 0.0.0.0
grep -q '"bind": "0.0.0.0"' "$T/data/admin-settings.json"
compgen -G "$T/data/admin-settings.json.backup-*" > /dev/null
install_test --web-bind 127.0.0.1
check_bind 127.0.0.1
# A missing bind key must also be inserted, not silently ignored.
sed -i '/^web:/,/^[^ ]/{ /^  bind:/d; }' "$T/etc/config.yaml"
install_test
check_bind 0.0.0.0
# The portable installer must also migrate an existing saved portal setting.
portable_test() {
  "$ROOT/install-portable.sh" --source-dir "$ROOT" --prefix "$T/portable" \
    --config-dir "$T/portable/etc" --data-dir "$T/portable/data" \
    --no-service --no-start --force "$@" > "$T/portable.log" 2>&1 || { cat "$T/portable.log"; return 1; }
}
portable_test --web-bind 127.0.0.1
cp "$T/data/admin-settings.json" "$T/portable/data/admin-settings.json"
sed -i 's/0.0.0.0/127.0.0.1/' "$T/portable/data/admin-settings.json"
portable_test
"$T/portable/bin/flowcollector" config validate --config "$T/portable/etc/config.yaml" | grep -F 'web_bind=0.0.0.0)'
portable_test --web-bind 127.0.0.1
"$T/portable/bin/flowcollector" config validate --config "$T/portable/etc/config.yaml" | grep -F 'web_bind=127.0.0.1)'
# Exercise the resulting application and access it through the container's
# non-loopback interface. No service or host configuration is changed.
"$T/bin/flowcollector" run --config "$T/etc/config.yaml" > "$T/run.log" 2>&1 & PID=$!
ADDRESS="$(hostname -I | awk '{print $1}')"
[[ -n "$ADDRESS" ]] || { echo "A non-loopback interface is required for the socket check" >&2; exit 1; }
READY=0
for _ in {1..100}; do
  if "$T/bin/flowcollector" health --url "http://$ADDRESS:8080/health" > /dev/null 2>&1; then READY=1; break; fi
  sleep .1
done
[[ "$READY" == 1 ]] || { cat "$T/run.log"; exit 1; }
grep -q 'Web listen address: 0.0.0.0:8080' "$T/run.log"
echo "fresh/upgrade/legacy TLS/portal override/explicit loopback/portable/non-loopback HTTP: PASS"
