#!/usr/bin/env sh
set -eu

VERSION=4.0.0
PREFIX=/usr/local
CONFIG_DIR=/usr/local/etc/flowcollector
DATA_DIR=/var/lib/flowcollector
REPOSITORY=cumakurt/central-flow-collector
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NO_SERVICE=0
NO_START=0
FORCE=0
BUILD_FROM_SOURCE=0

usage() {
  cat <<EOF
Usage: sudo ./install-portable.sh [--version VERSION] [--prefix DIR]
  [--config-dir DIR] [--data-dir DIR] [--source-dir DIR]
  [--repository OWNER/REPO] [--build-from-source] [--no-service]
  [--no-start] [--force]
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION=$2; shift 2;;
    --prefix) PREFIX=$2; shift 2;;
    --config-dir) CONFIG_DIR=$2; shift 2;;
    --data-dir) DATA_DIR=$2; shift 2;;
    --source-dir) SOURCE_DIR=$2; shift 2;;
    --repository) REPOSITORY=$2; shift 2;;
    --build-from-source) BUILD_FROM_SOURCE=1; shift;;
    --no-service) NO_SERVICE=1; shift;;
    --no-start) NO_START=1; shift;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2;;
  esac
done

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in linux|darwin|freebsd|openbsd|netbsd) ;; *) echo "Unsupported OS: $OS" >&2; exit 2;; esac
case "$(uname -m)" in amd64|x86_64) ARCH=amd64;; arm64|aarch64) ARCH=arm64;; *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2;; esac
BINARY="$PREFIX/bin/flowcollector"
mkdir -p "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR"
[ ! -e "$BINARY" ] || [ "$FORCE" -eq 1 ] || { echo "$BINARY exists; use --force" >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/flowcollector.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
asset="flowcollector-$OS-$ARCH"
local="$SOURCE_DIR/dist/$asset"
if [ -x "$local" ]; then
  cp "$local" "$BINARY"
elif [ "$BUILD_FROM_SOURCE" -eq 1 ] || [ -f "$SOURCE_DIR/go.mod" ]; then
  command -v go >/dev/null 2>&1 || { echo "Go is required for source builds" >&2; exit 1; }
  (cd "$SOURCE_DIR" && CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -buildvcs=false -trimpath -ldflags "-s -w -X central-flow-collector/internal/buildinfo.Version=$VERSION" -o "$BINARY" ./cmd/flowcollector)
else
  command -v curl >/dev/null 2>&1 || { echo "curl is required to download release artifacts" >&2; exit 1; }
  curl -fsSL "https://github.com/$REPOSITORY/releases/download/v$VERSION/$asset" -o "$BINARY"
fi
chmod 0755 "$BINARY"

config="$CONFIG_DIR/config.yaml"
[ -f "$config" ] || cp "$SOURCE_DIR/config.example.yaml" "$config"
set_value() {
  section=$1 key=$2 value=$3 file=$4
  tmpfile="$file.tmp.$$"
  awk -v sec="$section" -v key="$key" -v value="$value" '
    $0 == sec ":" { inside=1; print; next }
    inside && /^[^[:space:]#]/ { if (!done) { print "  " key ": \"" value "\""; done=1 } inside=0 }
    inside && $0 ~ "^[[:space:]]+" key ":" { print "  " key ": \"" value "\""; done=1; next }
    { print }
    END { if (inside && !done) print "  " key ": \"" value "\"" }
  ' "$file" > "$tmpfile" && mv "$tmpfile" "$file"
}
set_value storage data_dir "$DATA_DIR" "$config"
set_value security bootstrap_file "$DATA_DIR/bootstrap-admin.txt" "$config"
set_value analytics baseline_state_file "$DATA_DIR/baseline-state.json" "$config"
"$BINARY" config validate --config "$config"

if [ "$NO_SERVICE" -eq 0 ] && [ "$OS" = darwin ]; then
  plist="$HOME/Library/LaunchAgents/com.centralflowcollector.plist"
  [ "$(id -u)" -eq 0 ] && plist=/Library/LaunchDaemons/com.centralflowcollector.plist
  mkdir -p "$(dirname "$plist")"
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict>' '<key>Label</key><string>com.centralflowcollector</string>' "<key>ProgramArguments</key><array><string>$BINARY</string><string>run</string><string>--config</string><string>$config</string></array>" '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>' "<key>WorkingDirectory</key><string>$DATA_DIR</string>" "<key>StandardOutPath</key><string>$DATA_DIR/collector.log</string>" "<key>StandardErrorPath</key><string>$DATA_DIR/collector.err</string>" '</dict></plist>' > "$plist"
  if [ "$NO_START" -eq 0 ] && command -v launchctl >/dev/null 2>&1; then launchctl load -w "$plist"; fi
elif [ "$NO_SERVICE" -eq 0 ] && [ "$OS" = freebsd ]; then
  echo "Binary installed. Add a flowcollector rc.d entry under /usr/local/etc/rc.d to enable boot startup." >&2
else
  echo "Binary and configuration installed; service manager integration is disabled or unavailable."
fi
echo "Central Flow Collector installed: $BINARY"
echo "Configuration: $config"
