#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT_DIR/packaging/deb"
BUILD_DIR="$ROOT_DIR/build-deb"
VERSION="2.0.1"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy packaging skeleton
rsync -a "$PKG_DIR/" "$BUILD_DIR/"

# Place app files under /opt/dns-interceptor
install -Dm755 "$ROOT_DIR/dns_interceptor.py" "$BUILD_DIR/opt/dns-interceptor/dns_interceptor.py"
install -Dm644 "$ROOT_DIR/requirements.txt" "$BUILD_DIR/opt/dns-interceptor/requirements.txt"

# Ensure control has correct version
sed -i "s/^Version:.*/Version: $VERSION/" "$BUILD_DIR/DEBIAN/control"

# Permissions
chmod 755 "$BUILD_DIR/DEBIAN/postinst"
chmod 755 "$BUILD_DIR/usr/bin/dns-interceptor"

# Build .deb
cd "$BUILD_DIR/.."
dpkg-deb --build "$(basename "$BUILD_DIR")" "dns-interceptor_${VERSION}_all.deb"

# Show result path
ls -lah "dns-interceptor_${VERSION}_all.deb"
