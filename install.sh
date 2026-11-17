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

# 1. Determine working directory or clone repository if piped via curl
REPO_URL="https://github.com/anntr1k3/zapret-discord-youtube-linux.git"
INSTALL_TARGET="${HOME}/zapret-discord-youtube-linux"

if [ -f "./service.sh" ] && [ -f "./gui.py" ]; then
    PROJECT_DIR="$(pwd)"
    echo -e "${COLOR_GREEN}✓ Запуск из локального репозитория:${COLOR_RESET} $PROJECT_DIR"
else
    if [ ! -d "$INSTALL_TARGET" ]; then
        echo -e "${COLOR_YELLOW}Клонирование репозитория в $INSTALL_TARGET...${COLOR_RESET}"
        git clone "$REPO_URL" "$INSTALL_TARGET"
    else
        echo -e "${COLOR_GREEN}✓ Найден каталог $INSTALL_TARGET, обновление...${COLOR_RESET}"
        git -C "$INSTALL_TARGET" pull --ff-only || true
    fi
    PROJECT_DIR="$INSTALL_TARGET"
fi

cd "$PROJECT_DIR"

# 2. Package manager dependency check
echo -e "\n${COLOR_BOLD}[1/4] Проверка системных зависимостей...${COLOR_RESET}"

MISSING_PKGS=()
if command -v apt-get >/dev/null 2>&1; then
    for pkg in python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 nftables curl git; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            MISSING_PKGS+=("$pkg")
        fi
    done
    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo -e "${COLOR_YELLOW}Необходимо установить пакеты: ${MISSING_PKGS[*]}${COLOR_RESET}"
        echo "Запуск sudo apt-get update && sudo apt-get install -y ${MISSING_PKGS[*]}"
        sudo apt-get update && sudo apt-get install -y "${MISSING_PKGS[@]}"
    fi
elif command -v pacman >/dev/null 2>&1; then
    echo -e "${COLOR_CYAN}Arch Linux обнаружен.${COLOR_RESET}"
    sudo pacman -S --needed --noconfirm python python-gobject gtk4 libadwaita nftables curl git || true
elif command -v dnf >/dev/null 2>&1; then
    echo -e "${COLOR_CYAN}Fedora/RHEL обнаружен.${COLOR_RESET}"
    sudo dnf install -y python3 python3-gobject gtk4 libadwaita nftables curl git || true
fi

echo -e "${COLOR_GREEN}✓ Все системные зависимости установлены.${COLOR_RESET}"

# 3. Download / check nfqws and strategies
echo -e "\n${COLOR_BOLD}[2/4] Подготовка зависимостей ядра и стратегий Flowseal...${COLOR_RESET}"
./service.sh download-deps --default

# 4. Install Desktop entry and CLI launchers
echo -e "\n${COLOR_BOLD}[3/4] Установка интеграции с рабочим столом и CLI утилит...${COLOR_RESET}"
./src/desktop/install-desktop.sh --user

# 5. Summary and Next steps
echo -e "\n${COLOR_BOLD}[4/4] Завершение настройки...${COLOR_RESET}"
echo -e "${COLOR_GREEN}${COLOR_BOLD}=== ✨ Zapret успешно установлен и готов к работе! ===${COLOR_RESET}\n"
echo -e "Способы запуска:"
echo -e "  • ${COLOR_CYAN}zapret-gui${COLOR_RESET}     — открыть нативный графический интерфейс GTK4"
echo -e "  • ${COLOR_CYAN}zapret${COLOR_RESET}         — консольное интерактивное меню управления"
echo -e "  • Ярлык в меню:   поиск «Zapret» в меню приложений GNOME / KDE"
echo -e "  • Быстрые действия: правый клик по значку Zapret в доке (Запуск / Остановка / Тестер)\n"
