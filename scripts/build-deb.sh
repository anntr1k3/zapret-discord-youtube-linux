#!/usr/bin/env bash
# Build Debian/Ubuntu .deb package for zapret-discord-youtube
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PKG_NAME="zapret-discord-youtube"
PKG_VERSION="1.0.0"
PKG_ARCH="$(dpkg --print-architecture 2>/dev/null || echo "amd64")"
PKG_FULLNAME="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

DIST_DIR="$REPO_DIR/dist"
BUILD_DIR="$(mktemp -d -t "zapret-deb-XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "=== 📦 Сборка .deb-пакета $PKG_FULLNAME ==="

mkdir -p "$DIST_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/opt/$PKG_NAME/current"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/scalable/apps"

# 1. DEBIAN/control
cat <<EOF > "$BUILD_DIR/DEBIAN/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: $PKG_ARCH
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1, nftables | iptables, curl, polkitd | policykit-1
Maintainer: anntr1k3 <https://github.com/anntr1k3/zapret-discord-youtube-linux>
Homepage: https://github.com/anntr1k3/zapret-discord-youtube-linux
Description: Zapret Discord & YouTube Linux - GTK4 GUI and system service adapter
 Full-featured Linux port of Flowseal zapret-discord-youtube with native
 GTK4/libadwaita graphical interface, pkexec root privilege separation,
 systemd service lifecycle manager, deep conflict diagnostics, and
 streaming strategy tester.
EOF

# 2. Maintainer scripts
cat <<'EOF' > "$BUILD_DIR/DEBIAN/postinst"
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
    fi
fi
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

cat <<'EOF' > "$BUILD_DIR/DEBIAN/prerm"
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop zapret_discord_youtube.service 2>/dev/null || true
        systemctl disable zapret_discord_youtube.service 2>/dev/null || true
    fi
fi
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/prerm"

cat <<'EOF' > "$BUILD_DIR/DEBIAN/postrm"
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /opt/zapret-discord-youtube 2>/dev/null || true
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postrm"

# 3. Payload copy to /opt/zapret-discord-youtube/current
TARGET_OPT="$BUILD_DIR/opt/$PKG_NAME/current"
cp -r "$REPO_DIR/src" "$TARGET_OPT/"
cp -r "$REPO_DIR/docs" "$TARGET_OPT/"
cp "$REPO_DIR/gui.py" "$TARGET_OPT/"
cp "$REPO_DIR/service.sh" "$TARGET_OPT/"
cp "$REPO_DIR/install.py" "$TARGET_OPT/"
cp "$REPO_DIR/auto_tune.sh" "$TARGET_OPT/"
cp "$REPO_DIR/auto_tune_youtube.sh" "$TARGET_OPT/"
cp "$REPO_DIR/LICENSE" "$TARGET_OPT/"
cp "$REPO_DIR/README.md" "$TARGET_OPT/"
cp "$REPO_DIR/RELEASE_NOTES_v1.0.md" "$TARGET_OPT/"

if [ -d "$REPO_DIR/custom-strategies" ]; then
    cp -r "$REPO_DIR/custom-strategies" "$TARGET_OPT/"
fi

# Clean up pycache inside package payload
find "$TARGET_OPT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_OPT" -name "*.pyc" -delete 2>/dev/null || true

# 4. /usr/bin CLI wrapper symlinks
cat <<'EOF' > "$BUILD_DIR/usr/bin/zapret-gui"
#!/bin/sh
exec /usr/bin/python3 /opt/zapret-discord-youtube/current/gui.py "$@"
EOF
chmod 755 "$BUILD_DIR/usr/bin/zapret-gui"

cat <<'EOF' > "$BUILD_DIR/usr/bin/zapret"
#!/bin/sh
exec /opt/zapret-discord-youtube/current/service.sh "$@"
EOF
chmod 755 "$BUILD_DIR/usr/bin/zapret"

# 5. Desktop and Icon
cp "$REPO_DIR/src/desktop/zapret-gui.desktop" "$BUILD_DIR/usr/share/applications/"
cp "$REPO_DIR/src/desktop/zapret-gui.svg" "$BUILD_DIR/usr/share/icons/hicolor/scalable/apps/"

# 6. Build package with dpkg-deb
DEB_FILE="$DIST_DIR/${PKG_FULLNAME}.deb"
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$DEB_FILE"

echo "✓ Пакет успешно собран:"
echo "  $DEB_FILE ($(du -h "$DEB_FILE" | cut -f1))"
echo "  Установка: sudo apt install ./dist/${PKG_FULLNAME}.deb"
