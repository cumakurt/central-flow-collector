#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-4.0.0}"
OUT="${OUT:-$ROOT/dist}"
BIN_DIR="${BIN_DIR:-$ROOT/dist}"
command -v dpkg-deb >/dev/null 2>&1 || { echo 'dpkg-deb is required' >&2; exit 2; }
mkdir -p "$OUT"
for ARCH in amd64 arm64; do
  BIN="$BIN_DIR/flowcollector-linux-$ARCH"
  [ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }
  PKGROOT="$(mktemp -d)"
  trap 'rm -rf "$PKGROOT"' EXIT
  mkdir -p "$PKGROOT/DEBIAN" "$PKGROOT/usr/local/bin" "$PKGROOT/etc/flowcollector" "$PKGROOT/lib/systemd/system" "$PKGROOT/var/lib/flowcollector" "$PKGROOT/var/log/flowcollector"
  install -m 0755 "$BIN" "$PKGROOT/usr/local/bin/flowcollector"
  install -m 0640 "$ROOT/config.example.yaml" "$PKGROOT/etc/flowcollector/config.yaml"
  install -m 0644 "$ROOT/deploy/systemd/flowcollector.service" "$PKGROOT/lib/systemd/system/flowcollector.service"
  install -d "$PKGROOT/usr/share/doc/central-flow-collector"
  install -m 0644 "$ROOT/LICENSE" "$PKGROOT/usr/share/doc/central-flow-collector/LICENSE"
  install -m 0644 "$ROOT/NOTICE" "$PKGROOT/usr/share/doc/central-flow-collector/copyright"
  cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: central-flow-collector
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Cuma KURT <cumakurt@gmail.com>
Homepage: https://github.com/cumakurt/central-flow-collector
Description: High-performance Central Flow Collector & Flow Analytics Platform
 Collects NetFlow v5/v9, IPFIX and sFlow and provides centralized flow analytics.
EOF
  echo '/etc/flowcollector/config.yaml' > "$PKGROOT/DEBIAN/conffiles"
  cat > "$PKGROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group flowcollector >/dev/null 2>&1; then addgroup --system flowcollector >/dev/null 2>&1 || true; fi
if ! id flowcollector >/dev/null 2>&1; then adduser --system --ingroup flowcollector --home /var/lib/flowcollector --no-create-home --shell /usr/sbin/nologin flowcollector >/dev/null 2>&1 || true; fi
install -d -o flowcollector -g flowcollector -m 0750 /var/lib/flowcollector /var/log/flowcollector
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
exit 0
EOF
  chmod 0755 "$PKGROOT/DEBIAN/postinst"
  cat > "$PKGROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then systemctl stop flowcollector.service >/dev/null 2>&1 || true; fi
exit 0
EOF
  chmod 0755 "$PKGROOT/DEBIAN/prerm"
  dpkg-deb --build --root-owner-group "$PKGROOT" "$OUT/central-flow-collector_${VERSION}_${ARCH}.deb" >/dev/null
  rm -rf "$PKGROOT"
  trap - EXIT
done
