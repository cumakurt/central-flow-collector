#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "installer integration test must run as root" >&2; exit 77; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -x "$ROOT/dist/flowcollector-linux-amd64" || "$(uname -m)" != "x86_64" ]] || { echo "run make package first" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 77; }
T="$(mktemp -d /tmp/flowcollector-installer-test.XXXXXX)"
SPID=""
cleanup(){ [[ -n "$SPID" ]] && kill "$SPID" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T"/{bin,etc,data,log,systemd,fakebin}
cat > "$T/fakebin/systemctl" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$T/fakebin/systemctl"
cat > "$T/chfake.py" <<'PY'
import http.server, urllib.parse, sys
portfile, log = sys.argv[1:]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        u=urllib.parse.urlparse(self.path)
        q=urllib.parse.parse_qs(u.query).get('query',[''])[0]
        n=int(self.headers.get('content-length','0') or 0)
        body=self.rfile.read(n).decode() if n else ''
        query=q or body
        with open(log,'a') as f: f.write(query.replace('\n',' ')+'\n')
        out=b'1\n' if (query.strip().upper().startswith('SELECT 1') or 'SELECT count()' in query) else b''
        self.send_response(200); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self,*a): pass
srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),H)
open(portfile,'w').write(str(srv.server_port))
srv.serve_forever()
PY
python3 "$T/chfake.py" "$T/port" "$T/queries.log" >"$T/server.log" 2>&1 & SPID=$!
for _ in {1..50}; do [[ -s "$T/port" ]] && break; sleep .05; done
PORT="$(cat "$T/port")"
ARCH=amd64; [[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]] && ARCH=arm64
PATH="$T/fakebin:$PATH" FLOWCOLLECTOR_SYSTEMD_DIR="$T/systemd" "$ROOT/install.sh" \
  --prefix "$T/bin" --config-dir "$T/etc" --data-dir "$T/data" --log-dir "$T/log" \
  --user root --group root --clickhouse-host 127.0.0.1 --clickhouse-port "$PORT" \
  --clickhouse-user flowcollector --clickhouse-password 'App_Test-Secret_42' \
  --clickhouse-admin-user admin --clickhouse-admin-password 'Admin_Test-Secret_42' \
  --no-start --no-enable > "$T/install.out" 2>&1

grep -q 'backend: "clickhouse"' "$T/etc/config.yaml"
grep -q "clickhouse_url: \"http://127.0.0.1:$PORT\"" "$T/etc/config.yaml"
grep -q 'FLOWCOLLECTOR_CLICKHOUSE_PASSWORD="App_Test-Secret_42"' "$T/etc/clickhouse.env"
grep -q 'EnvironmentFile=-.*/clickhouse.env' "$T/systemd/flowcollector.service"
grep -q 'CREATE DATABASE IF NOT EXISTS' "$T/queries.log"
grep -q 'CREATE USER IF NOT EXISTS' "$T/queries.log"
grep -q 'GRANT SELECT, INSERT, ALTER, CREATE' "$T/queries.log"
grep -q 'CREATE TABLE IF NOT EXISTS flowcollector.flows' "$T/queries.log"
grep -q 'MODIFY TTL receive_time + INTERVAL 7 DAY' "$T/queries.log"
[[ "$(stat -c %a "$T/etc/clickhouse.env")" == "640" ]]
! grep -q 'App_Test-Secret_42' "$T/etc/config.yaml"
echo "installer remote ClickHouse integration: PASS"

# Preconfigured multi-node cluster profile: installer validates the existing app
# credential and lets the collector create ReplicatedMergeTree + Distributed DDL.
mkdir -p "$T/cluster"/{bin,etc,data,log,systemd}
PATH="$T/fakebin:$PATH" FLOWCOLLECTOR_SYSTEMD_DIR="$T/cluster/systemd" "$ROOT/install.sh" \
  --prefix "$T/cluster/bin" --config-dir "$T/cluster/etc" --data-dir "$T/cluster/data" --log-dir "$T/cluster/log" \
  --user root --group root --clickhouse-host 127.0.0.1 --clickhouse-port "$PORT" \
  --clickhouse-user flowcollector --clickhouse-password 'Cluster_App_Secret_42' --clickhouse-no-provision \
  --clickhouse-cluster prod --clickhouse-distributed-table flows_all \
  --clickhouse-replica-path '/clickhouse/tables/{shard}/flowcollector/flows' --clickhouse-replica-name '{replica}' \
  --no-start --no-enable > "$T/cluster/install.out" 2>&1
grep -q 'clickhouse_cluster: "prod"' "$T/cluster/etc/config.yaml"
grep -q 'clickhouse_distributed_table: "flows_all"' "$T/cluster/etc/config.yaml"
grep -q 'ReplicatedMergeTree' "$T/queries.log"
grep -q 'ENGINE = Distributed' "$T/queries.log"
grep -q 'ON CLUSTER `prod`' "$T/queries.log"
echo "installer ClickHouse cluster configuration: PASS"
