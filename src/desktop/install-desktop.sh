#!/usr/bin/env bash
# Desktop integration installer for Zapret GUI
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON_SRC="$SCRIPT_DIR/zapret-gui.svg"
DESKTOP_SRC="$SCRIPT_DIR/zapret-gui.desktop"

if [ ! -f "$ICON_SRC" ] || [ ! -f "$DESKTOP_SRC" ]; then
    echo "Ошибка: файлы zapret-gui.svg или zapret-gui.desktop не найдены в $SCRIPT_DIR" >&2
    exit 1
fi

MODE="${1:---user}"

if [ "$MODE" = "--system" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "Для системной установки (--system) требуются права root (sudo)." >&2
        exit 1
    fi
    APPS_DIR="/usr/share/applications"
    ICONS_DIR="/usr/share/icons/hicolor/scalable/apps"
else
    APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    ICONS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
fi

mkdir -p "$APPS_DIR" "$ICONS_DIR"
install -m 644 "$ICON_SRC" "$ICONS_DIR/zapret-gui.svg"
install -m 644 "$DESKTOP_SRC" "$APPS_DIR/zapret-gui.desktop"

# Refresh desktop and icon caches if utilities are available
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t "$(dirname "$(dirname "$ICONS_DIR")")" 2>/dev/null || true
fi

echo "Ярлык Zapret успешно установлен:"
echo "  - Приложение: $APPS_DIR/zapret-gui.desktop"
echo "  - Иконка:     $ICONS_DIR/zapret-gui.svg"
