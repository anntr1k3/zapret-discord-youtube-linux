#!/usr/bin/env bash
# Quick standalone installer for Zapret Discord & YouTube Linux
set -euo pipefail

COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_CYAN="\033[36m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"

echo -e "${COLOR_CYAN}${COLOR_BOLD}=== 🛡️ Установка Zapret Discord & YouTube Linux ===${COLOR_RESET}\n"

REPO_URL="https://github.com/anntr1k3/zapret-discord-youtube-linux.git"
INSTALL_TARGET="${HOME}/zapret-discord-youtube-linux"

if ((EUID == 0)); then
    echo "Запустите сценарий обычным пользователем; sudo нужен только пакетному менеджеру." >&2
    exit 1
fi

# Git must be present before clone. No dependency errors are suppressed.
echo -e "\n${COLOR_BOLD}[1/4] Проверка системных зависимостей...${COLOR_RESET}"

MISSING_PKGS=()
if command -v apt-get >/dev/null 2>&1; then
    for pkg in python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 nftables curl git util-linux; do
        if [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || :)" != "install ok installed" ]]; then
            MISSING_PKGS+=("$pkg")
        fi
    done
    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo -e "${COLOR_YELLOW}Необходимо установить пакеты: ${MISSING_PKGS[*]}${COLOR_RESET}"
        echo "Запуск sudo apt-get update && sudo apt-get install -y ${MISSING_PKGS[*]}"
        sudo apt-get update
        sudo apt-get install -y "${MISSING_PKGS[@]}"
    fi
elif command -v pacman >/dev/null 2>&1; then
    echo -e "${COLOR_CYAN}Arch Linux обнаружен.${COLOR_RESET}"
    sudo pacman -S --needed --noconfirm python python-gobject gtk4 libadwaita nftables curl git util-linux
elif command -v dnf >/dev/null 2>&1; then
    echo -e "${COLOR_CYAN}Fedora/RHEL обнаружен.${COLOR_RESET}"
    sudo dnf install -y python3 python3-gobject gtk4 libadwaita nftables curl git util-linux
fi

for cmd in git curl flock; do
    command -v "$cmd" >/dev/null || { echo "Установите $cmd и повторите запуск." >&2; exit 1; }
done
/usr/bin/python3 - <<'PY'
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw
if (Adw.get_major_version(), Adw.get_minor_version()) < (1, 5):
    raise SystemExit("Требуется libadwaita >= 1.5")
PY

# Resolve a file invocation relative to the script, not to the caller's CWD.
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
    PROJECT_DIR="$(dirname "$(realpath -- "$SCRIPT_PATH")")"
else
    PROJECT_DIR="$INSTALL_TARGET"
    if [[ ! -e "$PROJECT_DIR" ]]; then
        git clone "$REPO_URL" "$PROJECT_DIR"
    elif [[ -e "$PROJECT_DIR/.git" ]]; then
        git -C "$PROJECT_DIR" pull --ff-only
    else
        echo "Каталог $PROJECT_DIR не является ожидаемым checkout." >&2
        exit 1
    fi
fi

echo -e "\n${COLOR_BOLD}[2/4] Подготовка зависимостей ядра и стратегий Flowseal...${COLOR_RESET}"
if [[ -x "$PROJECT_DIR/nfqws" && -d "$PROJECT_DIR/zapret-latest" ]]; then
    echo "Существующие nfqws и стратегии сохранены."
elif [[ -e "$PROJECT_DIR/nfqws" || -e "$PROJECT_DIR/zapret-latest" ]]; then
    echo "Неполный runtime в $PROJECT_DIR: проверьте файлы перед загрузкой зависимостей." >&2
    exit 1
else
    "$PROJECT_DIR/service.sh" download-deps --default
fi

echo -e "\n${COLOR_BOLD}[3/4] Установка интеграции с рабочим столом и CLI утилит...${COLOR_RESET}"
"$PROJECT_DIR/src/desktop/install-desktop.sh" --user

echo -e "\n${COLOR_BOLD}[4/4] Завершение настройки...${COLOR_RESET}"
echo -e "${COLOR_GREEN}${COLOR_BOLD}=== Пользовательская копия Zapret подготовлена ===${COLOR_RESET}\n"
echo "Управляемый сервис не устанавливался. Для установки из GUI нужен доверенный пакет приложения."
echo -e "Способы запуска:"
echo -e "  • ${COLOR_CYAN}zapret-gui${COLOR_RESET}     — открыть нативный графический интерфейс GTK4"
echo -e "  • ${COLOR_CYAN}zapret${COLOR_RESET}         — консольное интерактивное меню управления"
echo -e "  • Ярлык в меню:   поиск «Zapret» в меню приложений GNOME / KDE"
echo -e "  • Быстрые действия: правый клик по значку Zapret в доке (Запуск / Остановка / Тестер)\n"
