#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "installer cluster test must run as root" >&2; exit 77; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH=amd64; [[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]] && ARCH=arm64
[[ -x "$ROOT/dist/flowcollector-linux-$ARCH" ]] || { echo "run package build first" >&2; exit 2; }
T="$(mktemp -d /tmp/flowcollector-cluster-install.XXXXXX)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fakebin" "$T/systemd1" "$T/systemd2"
cat > "$T/fakebin/systemctl" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$T/fakebin/systemctl"
# Central/standalone install generates a token.
PATH="$T/fakebin:$PATH" FLOWCOLLECTOR_SYSTEMD_DIR="$T/systemd1" "$ROOT/install.sh" \
  --prefix "$T/bin1" --config-dir "$T/etc1" --data-dir "$T/data1" --log-dir "$T/log1" \
  --user root --group root --local-storage --no-start --no-enable >"$T/central.out" 2>&1
[[ -s "$T/etc1/cluster.token" ]]
[[ "$(stat -c %a "$T/etc1/cluster.token")" == "640" ]]
grep -q 'shared_token_file: "'"$T"'/etc1/cluster.token"' "$T/etc1/config.yaml"
# Edge install uses a securely copied central token and writes heartbeat config.
PATH="$T/fakebin:$PATH" FLOWCOLLECTOR_SYSTEMD_DIR="$T/systemd2" "$ROOT/install.sh" \
  --prefix "$T/bin2" --config-dir "$T/etc2" --data-dir "$T/data2" --log-dir "$T/log2" \
  --user root --group root --local-storage --no-start --no-enable \
  --cluster-heartbeat-url 'https://central.example/api/v1/cluster/heartbeat' \
  --cluster-token-file "$T/etc1/cluster.token" \
  --cluster-global-dedup --cluster-global-dedup-url 'https://central.example/api/v1/cluster/dedup' >"$T/edge.out" 2>&1
cmp "$T/etc1/cluster.token" "$T/etc2/cluster.token"
grep -q 'heartbeat_url: "https://central.example/api/v1/cluster/heartbeat"' "$T/etc2/config.yaml"
grep -q 'shared_token_file: "'"$T"'/etc2/cluster.token"' "$T/etc2/config.yaml"
grep -q 'global_dedup_enabled: true' "$T/etc2/config.yaml"
grep -q 'global_dedup_url: "https://central.example/api/v1/cluster/dedup"' "$T/etc2/config.yaml"
echo "installer cluster token/edge configuration: PASS"
