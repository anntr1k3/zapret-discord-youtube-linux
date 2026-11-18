#!/usr/bin/env bash
# Desktop integration and CLI launcher installer for Zapret
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ICON_SRC="$SCRIPT_DIR/zapret-gui.svg"
DESKTOP_SRC="$SCRIPT_DIR/zapret-gui.desktop"

if [ ! -f "$ICON_SRC" ] || [ ! -f "$DESKTOP_SRC" ]; then
    echo "Ошибка: файлы zapret-gui.svg или zapret-gui.desktop не найдены в $SCRIPT_DIR" >&2
    exit 1
fi

MODE="${1:---user}"

if [[ "$MODE" != --user || $# -gt 1 || "$EUID" == 0 ]]; then
    echo "Запустите --user без sudo. Системные ярлыки поставляет пакет приложения." >&2
    exit 1
fi

APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
BIN_DIR="${HOME}/.local/bin"

# Preflight both destinations before changing any desktop files.
for command in zapret zapret-gui; do
    source_launcher="$REPO_DIR/bin/$command"
    dest="$BIN_DIR/$command"
    [[ -x "$source_launcher" ]] || { echo "Нет launcher: $source_launcher" >&2; exit 1; }
    if [[ -e "$dest" || -L "$dest" ]]; then
        if [[ ! -L "$dest" || "$(readlink -- "$dest")" != "$source_launcher" ]]; then
            echo "Уже существует $dest; перенесите этот файл отдельно перед установкой ярлыков." >&2
            exit 1
        fi
    fi
done

mkdir -p "$APPS_DIR" "$ICONS_DIR" "$BIN_DIR"
install -m 644 "$ICON_SRC" "$ICONS_DIR/zapret-gui.svg"
install -m 644 "$DESKTOP_SRC" "$APPS_DIR/zapret-gui.desktop"

for command in zapret zapret-gui; do
    [[ -L "$BIN_DIR/$command" ]] || ln -sT -- "$REPO_DIR/bin/$command" "$BIN_DIR/$command"
done

# Refresh desktop and icon caches if utilities are available
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t "$(dirname "$(dirname "$ICONS_DIR")")" 2>/dev/null || true
fi

echo "Ярлыки и утилиты Zapret успешно установлены ($MODE):"
echo "  - Приложение: $APPS_DIR/zapret-gui.desktop"
echo "  - Иконка:     $ICONS_DIR/zapret-gui.svg"
echo "  - Команды:    $BIN_DIR/zapret, $BIN_DIR/zapret-gui"
