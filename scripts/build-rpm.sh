#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-4.0.0}"
ARCH="${ARCH:-amd64}"
BIN_DIR="${BIN_DIR:-$ROOT/dist}"
OUT="${OUT:-$ROOT/dist}"
case "$ARCH" in amd64) RPMARCH=x86_64;; arm64) RPMARCH=aarch64;; *) echo "unsupported ARCH=$ARCH" >&2; exit 2;; esac
command -v rpmbuild >/dev/null 2>&1 || { echo 'rpmbuild is required (install rpm-build/rpmdevtools on the RPM build host)' >&2; exit 2; }
BIN="$BIN_DIR/flowcollector-linux-$ARCH"
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }
TOP="$(mktemp -d)"; trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$BIN" "$TOP/SOURCES/flowcollector-linux-$ARCH"
cp "$ROOT/config.example.yaml" "$TOP/SOURCES/config.example.yaml"
cp "$ROOT/deploy/systemd/flowcollector.service" "$TOP/SOURCES/flowcollector.service"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$TOP/SOURCES/"
# --target selects the package architecture; BuildArch would require the host
# to support executing that architecture even though we only package binaries.
sed -e "s/^Version:.*/Version:        $VERSION/" -e '/^BuildArch:/d' -e "s/Source0:        flowcollector-linux-amd64/Source0:        flowcollector-linux-$ARCH/" "$ROOT/packaging/rpm/flowcollector.spec" > "$TOP/SPECS/flowcollector.spec"
# Go release binaries are already stripped. Preserve their exact bytes and
# avoid running the host's strip utility on a cross-compiled executable.
rpmbuild --target "$RPMARCH" --define "_topdir $TOP" --define '__strip /bin/true' -bb "$TOP/SPECS/flowcollector.spec"
mkdir -p "$OUT"
find "$TOP/RPMS" -type f -name '*.rpm' -exec cp -v {} "$OUT/" \;
