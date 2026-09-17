#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
go test ./...
go vet ./...
if command -v node >/dev/null 2>&1; then node --check internal/api/static/app.js; fi
bash -n install.sh uninstall.sh
for p in netflow5 netflow9 ipfix sflow; do go test "./internal/decoder/$p" -run '^$' -fuzz=FuzzDecode -fuzztime="${FUZZTIME:-2s}"; done
