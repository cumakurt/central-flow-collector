#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v go >/dev/null || { echo 'Go 1.23 or newer is required' >&2; exit 2; }
if command -v sha256sum >/dev/null; then
  hash_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null; then
  hash_file() { shasum -a 256 "$1"; }
else
  echo 'sha256sum or shasum is required' >&2; exit 2
fi

VERSION="${VERSION:-4.0.0}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
# Linux is the default release target; additional targets can be requested via
# TARGETS (for example: darwin/arm64 windows/amd64 freebsd/amd64).
TARGETS="${TARGETS:-linux/amd64 linux/arm64}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
install -m 0644 "$ROOT/LICENSE" "$ROOT/NOTICE" "$OUT_DIR/"
for app in flowcollector flowgen chbench flowbench querybench; do
  rm -f "$OUT_DIR/$app-linux-"* "$OUT_DIR/$app-darwin-"* \
        "$OUT_DIR/$app-freebsd-"* "$OUT_DIR/$app-openbsd-"* \
        "$OUT_DIR/$app-netbsd-"* "$OUT_DIR/$app-windows-"*
done

ldflags="-s -w -X central-flow-collector/internal/buildinfo.Version=$VERSION -X central-flow-collector/internal/buildinfo.Commit=$COMMIT -X central-flow-collector/internal/buildinfo.BuildTime=$BUILD_TIME"
manifest="$OUT_DIR/static-builds.txt"
: > "$manifest"
for target in $TARGETS; do
  case "$target" in
    linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|freebsd/amd64|freebsd/arm64|openbsd/amd64|netbsd/amd64|windows/amd64|windows/arm64) ;;
    *) echo "unsupported target: $target" >&2; exit 2 ;;
  esac
  os="${target%/*}"
  arch="${target#*/}"
  for app in flowcollector flowgen chbench flowbench querybench; do
    suffix=""
    [ "$os" = windows ] && suffix=".exe"
    name="$app-$os-$arch$suffix"
    output="$OUT_DIR/$name"
    echo "Building $app for $target"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -buildvcs=false -trimpath -tags netgo,osusergo -ldflags "$ldflags" -o "$output" "./cmd/$app"
    printf '%s %s %s\n' "$app" "$os" "$arch" >> "$manifest"
  done
done
# The installer verifies checksums.txt, so refresh that canonical manifest as
# well as the static-build manifest whenever binaries change. Include every
# artifact currently present in dist, including existing packages and SBOMs.
canonical_tmp="$(mktemp "$OUT_DIR/.checksums.XXXXXX")"
static_tmp="$(mktemp "$OUT_DIR/.static-checksums.XXXXXX")"
(
  cd "$OUT_DIR"
  shopt -s nullglob
  binaries=(flowcollector-* flowgen-* chbench-* flowbench-* querybench-*)
  printf '%s\n' "${binaries[@]}" | sort -u | while IFS= read -r file; do
    hash_file "$file"
  done > "$static_tmp"
  files=("${binaries[@]}" central-flow-collector_*.deb *.rpm SBOM.*.json LICENSE NOTICE)
  printf '%s\n' "${files[@]}" | sort -u | while IFS= read -r file; do
    hash_file "$file"
  done
) > "$canonical_tmp"
mv "$static_tmp" "$OUT_DIR/static-checksums.txt"
mv "$canonical_tmp" "$OUT_DIR/checksums.txt"
echo "Static binaries: $OUT_DIR"
echo "Checksums: $OUT_DIR/checksums.txt"
