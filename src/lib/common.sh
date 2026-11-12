#!/usr/bin/env bash

# =============================================================================
# Общие функции для всех скриптов zapret-discord-youtube-linux
# =============================================================================

# Guard: проверяем что файл не был уже загружен
[[ -n "${_COMMON_SH_LOADED:-}" ]] && return 0
_COMMON_SH_LOADED=1

# Подключаем константы
source "$(dirname "${BASH_SOURCE[0]}")/constants.sh"

# Флаг отладки (можно переопределить в скрипте)
DEBUG=${DEBUG:-false}

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

debug_log() {
    if $DEBUG; then
        echo "[DEBUG] $1"
    fi
}

handle_error() {
    log "Ошибка: $1"
    exit 1
}

show_error() {
    echo -e "\e[31mОшибка: $1\e[0m"
    read -p "Нажмите Enter для продолжения..."
}

# -----------------------------------------------------------------------------
# Проверка зависимостей
# -----------------------------------------------------------------------------

check_dependencies() {
    export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
    local deps=("git" "grep" "sed" "curl")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            handle_error "Не установлена утилита $dep"
        fi
    done

    # Проверяем наличие хотя бы одного бэкенда файрвола
    if ! command -v nft &>/dev/null && ! command -v iptables &>/dev/null; then
        handle_error "Не установлен nftables или iptables. Установите один из них."
    fi
}

# -----------------------------------------------------------------------------
# Работа с конфигурацией
# game filter ranges v1
# ipset mode v1
# active fakes v1
# -----------------------------------------------------------------------------

# Конфигурация — данные key=value, не исполняемый shell-код.
valid_game_filter_ports() {
    local value="$1" item first last
    local -a items
    [[ ${#value} -gt 0 && ${#value} -le 512 ]] || return 1
    [[ "$value" =~ ^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?(,[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?)*$ ]] || return 1
    IFS=, read -r -a items <<< "$value"
    [[ ${#items[@]} -le 128 ]] || return 1
    for item in "${items[@]}"; do
        first="${item%%-*}"
        last="${item##*-}"
        (( 10#$first <= 65535 && 10#$last <= 65535 && 10#$first <= 10#$last )) || return 1
    done
}

read_config() {
    local conf_file="$1"
    local -n result="$2"
    local -A values=()
    local line key value backend_file backend_name found
    local backend_dir="$(dirname "${BASH_SOURCE[0]}")/../firewall-backends"

    [[ -f "$conf_file" && -r "$conf_file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" == *=* ]] || return 1
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            interface) [[ "$value" =~ ^[[:alnum:]_.:-]+$ ]] || return 1 ;;
            gamefiltertcp|gamefilterudp) [[ "$value" == true || "$value" == false ]] || return 1 ;;
            gamefiltertcp_ports|gamefilterudp_ports) valid_game_filter_ports "$value" || return 1 ;;
            ipset_mode) [[ "$value" == legacy || "$value" == loaded || "$value" == none || "$value" == any ]] || return 1 ;;
            fakediscord|fakegameudp) [[ -z "$value" || "$value" =~ ^[0-9a-f]{64}$ ]] || return 1 ;;
            strategy) [[ "$value" =~ ^[[:alnum:]_][[:alnum:]_.-]*\.bat$ ]] || return 1 ;;
            firewall_backend)
                [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
                if [[ "$value" != auto ]]; then
                    found=false
                    for backend_file in "$backend_dir"/*.sh; do
                        backend_name="${backend_file##*/}"
                        backend_name="${backend_name%.sh}"
                        [[ "$backend_name" =~ ^[0-9][0-9]-(.*)$ ]] && backend_name="${BASH_REMATCH[1]}"
                        [[ "$backend_name" == "$value" ]] && found=true
                    done
                    [[ "$found" == true ]] || return 1
                fi
                ;;
            *) return 1 ;;
        esac
        [[ -z "${values[$key]+present}" ]] || return 1
        values["$key"]="$value"
    done < "$conf_file"

    for key in interface gamefiltertcp gamefilterudp strategy; do
        [[ -n "${values[$key]:-}" ]] || return 1
    done
    result=()
    for key in "${!values[@]}"; do
        result["$key"]="${values[$key]}"
    done
    result[firewall_backend]="${values[firewall_backend]:-auto}"
    result[gamefiltertcp_ports]="${values[gamefiltertcp_ports]:-1024-65535}"
    result[gamefilterudp_ports]="${values[gamefilterudp_ports]:-1024-65535}"
    result[ipset_mode]="${values[ipset_mode]:-legacy}"
    result[fakediscord]="${values[fakediscord]:-}"
    result[fakegameudp]="${values[fakegameudp]:-}"
}

# Проверка существования conf.env и обязательных полей без изменения файла
# Использование: if check_conf_file "$CONF_FILE"; then ...
check_conf_file() {
    local conf_file="${1:-$CONF_FILE}"

    local -A config=()
    read_config "$conf_file" config
}

# Загрузка конфигурации из файла
load_config() {
    local conf_file="${1:-$CONF_FILE}"

    if [[ ! -f "$conf_file" ]]; then
        handle_error "Файл конфигурации $conf_file не найден"
    fi

    local -A config=()
    read_config "$conf_file" config || handle_error "Некорректная конфигурация: $conf_file (ожидается key=value, не shell-код)"
    interface="${config[interface]}"
    gamefiltertcp="${config[gamefiltertcp]}"
    gamefilterudp="${config[gamefilterudp]}"
    gamefiltertcp_ports="${config[gamefiltertcp_ports]}"
    gamefilterudp_ports="${config[gamefilterudp_ports]}"
    ipset_mode="${config[ipset_mode]}"
    fakediscord="${config[fakediscord]:-}"
    fakegameudp="${config[fakegameudp]:-}"
    strategy="${config[strategy]}"
    firewall_backend="${config[firewall_backend]}"
    FIREWALL_BACKEND="$firewall_backend"
}

# -----------------------------------------------------------------------------
# Управление nfqws
# -----------------------------------------------------------------------------

check_nfqws_status() {
    if [[ -n "$(get_nfqws_pids)" ]]; then
        echo "Демоны nfqws запущены."
    else
        echo "Демоны nfqws не запущены."
    fi
}

# Находим только процессы с нашим исполняемым файлом, а не совпадением argv.
get_nfqws_pids() {
    local expected pid executable
    expected=$(realpath -- "$NFQWS_PATH") || return 1
    while IFS= read -r pid; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        executable=$(elevate readlink -- "/proc/$pid/exe" 2>/dev/null) || continue
        # После обновления бинарника Linux добавляет суффикс (deleted).
        [[ "${executable% (deleted)}" == "$expected" ]] && printf '%s\n' "$pid"
    done < <(pgrep -x nfqws || true)
    return 0
}

# Не останавливаем другие установки nfqws.
stop_nfqws() {
    local pid
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        elevate kill -TERM -- "$pid" 2>/dev/null || true
    done < <(get_nfqws_pids)
}

# -----------------------------------------------------------------------------
# Работа со стратегиями
# -----------------------------------------------------------------------------

# Настройка репозитория со стратегиями
# Требует: REPO_DIR, REPO_URL, MAIN_REPO_REV, BASE_DIR, INTERACTIVE_MODE (опционально)
# Аргументы:
#   $1 - версия (коммит/тег/ветка), по умолчанию MAIN_REPO_REV
setup_repository() {
    local user_lists_dir="$BASE_DIR/user-lists"
    local version="${1:-$MAIN_REPO_REV}"

    if [ -d "$REPO_DIR" ]; then
        # В интерактивном режиме спрашиваем подтверждение
        if [[ "${INTERACTIVE_MODE:-false}" == "true" ]]; then
            log "Обнаружен существующий репозиторий стратегий."
            read -p "Удалить существующий репозиторий и загрузить заново? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log "Использование существующей версии репозитория."
                return 0
            fi
        fi

        if [[ -d "$REPO_DIR/lists" && -d "$user_lists_dir" ]]; then
            log "Копирование lists"
            rm -f "$user_lists_dir"/*
            cp "$REPO_DIR/lists"/* "$user_lists_dir/"  
        fi
        log "Удаление существующего репозитория..."
        rm -rf "$REPO_DIR"
    fi

    log "Клонирование репозитория (версия: $version)..."

    # Проверяем, является ли версия хешем коммита (40 символов hex)
    if [[ "$version" =~ ^[0-9a-f]{40}$ ]]; then
        # Для хеша коммита клонируем весь репозиторий и делаем checkout
        git clone "$REPO_URL" "$REPO_DIR" || \
            handle_error "Ошибка при клонировании репозитория"

        cd "$REPO_DIR" || handle_error "Не удалось перейти в директорию $REPO_DIR"
        git checkout "$version" || \
            handle_error "Ошибка при переключении на коммит '$version'. Проверьте, что коммит существует."
        cd - > /dev/null
    else
        # Для тега или ветки используем shallow clone
        git clone --branch "$version" --depth 1 "$REPO_URL" "$REPO_DIR" || \
            handle_error "Ошибка при клонировании репозитория. Проверьте, что версия '$version' существует."
    fi

    chmod +x "$BASE_DIR/src/rename_bat.sh"
    rm -rf "$REPO_DIR/.git"
    "$BASE_DIR/src/rename_bat.sh" || handle_error "Ошибка при переименовании файлов"

    # Создаём пользовательские списки (только если в стратегиях есть директория lists)
    if [[ -d "$REPO_DIR/lists" ]]; then
        local user_lists_dir="$BASE_DIR/user-lists"
        mkdir -p "$user_lists_dir"

        # Создаем lists (touch не перезаписывает файлы если они существовали)
        touch "$user_lists_dir/ipset-exclude-user.txt"
        touch "$user_lists_dir/list-general-user.txt"
        touch "$user_lists_dir/list-exclude-user.txt"

        # Делаем файлы читаемыми для всех (nfqws запускается под nobody)
        chmod 644 "$user_lists_dir/ipset-exclude-user.txt"
        chmod 644 "$user_lists_dir/list-general-user.txt"
        chmod 644 "$user_lists_dir/list-exclude-user.txt"

        # Создаём хардлинки (не симлинки!) чтобы обойти проблемы с доступом к /home/user
        for file in "$user_lists_dir"/*; do
            ln -f "$file" "$REPO_DIR/lists/" 2>/dev/null || true
        done
    fi
}

# Проверка и создание конфига (helper для install_service и desktop)
ensure_config_exists() {
    if ! check_conf_file; then
        read -p "Конфигурация отсутствует или неполная. Создать конфигурацию сейчас? (y/n): " answer
        if [[ $answer =~ ^[Yy]$ ]]; then
            create_conf_file
        else
            echo "Операция отменена."
            read -p "Нажмите Enter для продолжения..."
            return 1
        fi
        # Перепроверяем конфигурацию
        if ! check_conf_file; then
            show_error "Файл конфигурации всё ещё некорректен. Операция отменена."
            return 1
        fi
    fi
    return 0
}

# Получение списка доступных стратегий (имена файлов)
# Требует: REPO_DIR, CUSTOM_STRATEGIES_DIR
get_strategies() {
    {
        # Кастомные стратегии
        if [ -d "$CUSTOM_STRATEGIES_DIR" ]; then
            find "$CUSTOM_STRATEGIES_DIR" -maxdepth 1 -type f -name "*.bat" -printf "%f\n" 2>/dev/null
        fi
        # Стратегии из репозитория
        if [ -d "$REPO_DIR" ]; then
            find "$REPO_DIR" -maxdepth 1 -type f \( -name "general*.bat" -o -name "discord*.bat" \) -printf "%f\n" 2>/dev/null
        fi
    } | sort -u
}

# Вывод списка стратегий
show_strategies() {
    echo "Доступные стратегии:"
    echo
    get_strategies
}

# Валидация и нормализация названия стратегии
# Возвращает 0 и выводит нормализованное имя, или 1 при ошибке
normalize_strategy() {
    local s="$1"

    # Поиск точного совпадения
    local exact_match
    exact_match=$(get_strategies | grep -E "^(${s}|${s}\\.bat|general_${s}|general_${s}\\.bat)$" | head -n1)

    if [ -n "$exact_match" ]; then
        echo "$exact_match"
        return 0
    fi

    # Регистронезависимый поиск
    local case_insensitive_match
    case_insensitive_match=$(get_strategies | grep -i -E "^(${s}|${s}\\.bat|general_${s}|general_${s}\\.bat)$" | head -n1)

    if [ -n "$case_insensitive_match" ]; then
        echo "$case_insensitive_match"
        return 0
    fi

    return 1
}

# Интерактивный выбор стратегии
# Записывает результат в переменную $selected_strategy
select_strategy_interactive() {
    local strategies_list
    mapfile -t strategies_list < <(get_strategies)

    if [ ${#strategies_list[@]} -eq 0 ]; then
        handle_error "Не найдены файлы стратегий .bat"
    fi

    echo "Доступные стратегии:"
    select selected_strategy in "${strategies_list[@]}"; do
        if [ -n "$selected_strategy" ]; then
            log "Выбрана стратегия: $selected_strategy"
            return 0
        fi
        show_error "Неверный выбор. Попробуйте еще раз."
done
}

# Получение полного пути к файлу стратегии
# Возвращает путь к файлу или пустую строку если не найден
get_strategy_path() {
    local strategy="$1"

    if [ -f "$CUSTOM_STRATEGIES_DIR/$strategy" ]; then
        echo "$CUSTOM_STRATEGIES_DIR/$strategy"
    elif [ -f "$REPO_DIR/$strategy" ]; then
        echo "$REPO_DIR/$strategy"
    else
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# Парсинг .bat файлов стратегий
# -----------------------------------------------------------------------------

# Парсинг параметров из bat файла
# Устанавливает глобальные переменные: tcp_ports, udp_ports, nfqws_params[]
# Требует: USE_GAME_FILTER, GAME_FILTER_PORTS
parse_bat_file() {
    local file="$1"
    local tcp_range="${gamefiltertcp_ports:-1024-65535}" udp_range="${gamefilterudp_ports:-1024-65535}"
    valid_game_filter_ports "$tcp_range" && valid_game_filter_ports "$udp_range" || handle_error "Некорректные порты Game Filter"
    USE_SYNCED_STRATEGY=false
    nfqws_argv=()
    # active fakes v1: verify configured override files before use.
    local fake_dir="${FAKE_DIR:-$BASE_DIR/fakes}"
    local -a fake_args=()
    if [[ -n "${fakediscord:-}" ]]; then
        [[ "$(sha256sum -- "$fake_dir/ACTIVE_DISCORD_UDP.bin" 2>/dev/null | cut -d' ' -f1)" == "$fakediscord" ]] \
            || handle_error "Активный fake-файл Discord UDP изменился; выберите его заново в настройках GUI"
        fake_args+=(--fake-discord "$fake_dir/ACTIVE_DISCORD_UDP.bin")
    fi
    if [[ -n "${fakegameudp:-}" ]]; then
        [[ "$(sha256sum -- "$fake_dir/ACTIVE_GAME_UDP.bin" 2>/dev/null | cut -d' ' -f1)" == "$fakegameudp" ]] \
            || handle_error "Активный fake-файл GameFilter UDP изменился; выберите его заново в настройках GUI"
        fake_args+=(--fake-gameudp "$fake_dir/ACTIVE_GAME_UDP.bin")
    fi
    # synchronized profile runtime v1
    # Only upstream files use the compiled catalog; never shadow a custom file.
    if [[ "$(dirname -- "$file")" == "$REPO_DIR" && -f "$REPO_DIR/strategies.json" ]]; then
        local output
        output=$(python3 "$BASE_DIR/src/lib/strategy_sync.py" runtime \
            --repo "$REPO_DIR" --strategy "${file##*/}" --user-lists "$USER_LISTS_DIR" \
            --gamefiltertcp "${USE_GAME_FILTER_TCP:-false}" \
            --gamefilterudp "${USE_GAME_FILTER_UDP:-false}" \
            --gamefiltertcp-ports "$tcp_range" --gamefilterudp-ports "$udp_range" \
            --ipset-mode "${ipset_mode:-legacy}" "${fake_args[@]}") || handle_error "Не удалось прочитать синхронизированную стратегию"
        local -a fields
        mapfile -t fields <<< "$output"
        [[ ${#fields[@]} -gt 2 ]] || handle_error "Пустая синхронизированная стратегия"
        tcp_ports="${fields[0]}"
        udp_ports="${fields[1]}"
        nfqws_argv=("${fields[@]:2}")
        nfqws_params=()
        USE_SYNCED_STRATEGY=true
        return 0
    fi
    local bin_path="bin/"
    debug_log "Parsing .bat file: $file"

    # Читаем весь файл целиком
    local content=$(cat "$file" | tr -d '\r')

    debug_log "File content loaded"

    # Заменяем переменные
    content="${content//%BIN%/$bin_path}"
    content="${content//%LISTS%/lists/}"

    # В системной установке пользовательские списки живут вне версий кода.
    if [[ "${SYSTEM_INSTALL:-false}" == true ]]; then
        local list_path list_reference
        for list_path in "$USER_LISTS_DIR"/*.txt; do
            [[ -f "$list_path" ]] || continue
            list_reference="lists/${list_path##*/}"
            content="${content//"$list_reference"/$list_path}"
        done
    fi

    if [[ "${ipset_mode:-legacy}" != legacy ]]; then
        content=$(printf '%s' "$content" | python3 "$(dirname "${BASH_SOURCE[0]}")/ipset_mode.py" rewrite \
            --mode "$ipset_mode" --repo "$REPO_DIR" --user-lists "$USER_LISTS_DIR") || handle_error "Не удалось применить режим IPSet"
    fi

    if [[ -n "${fakediscord:-}" || -n "${fakegameudp:-}" ]]; then
        content=$(printf '%s' "$content" | python3 "$(dirname "${BASH_SOURCE[0]}")/fake_select.py" rewrite \
            --repo "$REPO_DIR" --data "$(dirname -- "$fake_dir")" --discord "${fakediscord:-}" --gameudp "${fakegameudp:-}") \
            || handle_error "Не удалось применить активные fakes"
    fi

    # Обрабатываем GameFilter
    if [ "$USE_GAME_FILTER" = true ]; then
        local generic_range="$udp_range"
        [[ "$USE_GAME_FILTER_TCP" == true ]] && generic_range="$tcp_range"
        content="${content//%GameFilter%/$generic_range}"
        #TCP and UDP
        if [ "$USE_GAME_FILTER_TCP" = true ]; then
            content="${content//%GameFilterTCP%/$tcp_range}"
        else
            content="${content//%GameFilterTCP%/$GAME_FILTER_OFF_PORTS}"
        fi

        if [ "$USE_GAME_FILTER_UDP" = true ]; then
            content="${content//%GameFilterUDP%/$udp_range}"
        else
            content="${content//%GameFilterUDP%/$GAME_FILTER_OFF_PORTS}"
        fi
    else
        content="${content//,%GameFilter%/}"
        content="${content//%GameFilter%,/}"
        #TCP and UDP
        content="${content//,%GameFilterTCP%/}"
        content="${content//%GameFilterTCP%,/}"
        content="${content//,%GameFilterUDP%/}"
        content="${content//%GameFilterUDP%,/}"
    fi

    # Ищем --wf-tcp и --wf-udp
    local wf_tcp_count=$(echo "$content" | grep -oP -- '--wf-tcp=' | wc -l)
    local wf_udp_count=$(echo "$content" | grep -oP -- '--wf-udp=' | wc -l)

    # Проверяем количество вхождений
    if [ "$wf_tcp_count" -eq 0 ] || [ "$wf_udp_count" -eq 0 ]; then
        echo "ERROR: --wf-tcp or --wf-udp not found in $file"
        exit 1
    fi

    if [ "$wf_tcp_count" -gt 1 ]; then
        echo "ERROR: Multiple --wf-tcp entries found in $file (found: $wf_tcp_count)"
        exit 1
    fi

    if [ "$wf_udp_count" -gt 1 ]; then
        echo "ERROR: Multiple --wf-udp entries found in $file (found: $wf_udp_count)"
        exit 1
    fi

    # Извлекаем порты
    tcp_ports=$(echo "$content" | grep -oP -- '--wf-tcp=\K[0-9,-]+' | head -n1)
    udp_ports=$(echo "$content" | grep -oP -- '--wf-udp=\K[0-9,-]+' | head -n1)

    debug_log "TCP ports: $tcp_ports"
    debug_log "UDP ports: $udp_ports"

    # Парсим с помощью grep -oP (Perl regex)
    nfqws_params=()
    while IFS= read -r match; do
        if [[ "$match" =~ --filter-(tcp|udp)=([0-9,%-]+)[[:space:]]+(.*) ]]; then
            local protocol="${BASH_REMATCH[1]}"
            local ports="${BASH_REMATCH[2]}"
            local nfqws_args="${BASH_REMATCH[3]}"

            # Очищаем лишние пробелы
            nfqws_args=$(echo "$match" | xargs)
            nfqws_args="${nfqws_args//=^!/=!}"

            nfqws_params+=("$nfqws_args")
            debug_log "Matched protocol: $protocol, ports: $ports"
            debug_log "NFQWS parameters: $nfqws_args"
        fi
    done < <(echo "$content" | grep -oP -- '--filter-(tcp|udp)=([0-9,-]+)\s+(?:[\s\S]*?--new|.*)')
}

# -----------------------------------------------------------------------------
# Запуск nfqws
# -----------------------------------------------------------------------------

# Запуск процесса nfqws
# Требует: NFQWS_PATH, REPO_DIR, NFT_MARK, NFT_QUEUE_NUM, nfqws_params[]
start_nfqws() {
    log "Запуск процесса nfqws..."
    stop_nfqws
    cd "$REPO_DIR" || handle_error "Не удалось перейти в директорию $REPO_DIR"

    local full_params=(
        "$NFQWS_PATH"
        --daemon
        --dpi-desync-fwmark="$NFT_MARK"
        --qnum="$NFT_QUEUE_NUM"
    )

    if [[ "${USE_SYNCED_STRATEGY:-false}" == true ]]; then
        full_params+=("${nfqws_argv[@]}")
    else
        for params in "${nfqws_params[@]}"; do
            full_params+=($params)
        done
    fi

    debug_log "Запуск NFQWS с параметрами: ${full_params[@]}"
    elevate "${full_params[@]}" ||
        handle_error "Ошибка при запуске nfqws"
}

# -----------------------------------------------------------------------------
# Основная функция запуска zapret
# -----------------------------------------------------------------------------

# Запуск zapret с указанной конфигурацией
# Использует глобальные переменные из conf.env: interface, gamefiltertcp, gamefilterudp, strategy
# Требует: REPO_DIR, NFQWS_PATH, STOP_SCRIPT
run_zapret() {
    # Остановка предыдущего экземпляра
    stop_nfqws
    firewall_clear
    sleep 1

    # Установка USE_GAME_FILTER
    if [ "$gamefiltertcp" == "true" -a "$gamefilterudp" == "true" ]; then
        USE_GAME_FILTER=true
        USE_GAME_FILTER_TCP=true
        USE_GAME_FILTER_UDP=true
        log "GameFilterTCP и GameFilterUDP включен"

    elif [ "$gamefiltertcp" == "true" ]; then
        USE_GAME_FILTER=true
        USE_GAME_FILTER_TCP=true
        USE_GAME_FILTER_UDP=false
        log "GameFilterTCP включен"

    elif [ "$gamefilterudp" == "true" ]; then
        USE_GAME_FILTER=true
        USE_GAME_FILTER_TCP=false
        USE_GAME_FILTER_UDP=true
        log "GameFilterUDP включен"

    else
        USE_GAME_FILTER=false
        USE_GAME_FILTER_TCP=false
        USE_GAME_FILTER_UDP=false
        log "GameFilter выключен"
    fi

    # Получаем путь к стратегии
    local strategy_path
    strategy_path=$(get_strategy_path "$strategy")
    if [ -z "$strategy_path" ]; then
        handle_error "Указанный .bat файл стратегии $strategy не найден"
    fi

    # Парсим стратегию
    parse_bat_file "$strategy_path"

    # Настройка файрвола
    local backend
    backend=$(detect_firewall_backend) || handle_error "Не удалось определить бэкенд файрвола"
    log "Настройка $backend..."
    firewall_setup "$tcp_ports" "$udp_ports" "$interface" ||
        handle_error "Ошибка при настройке $backend"

    # Запуск nfqws
    start_nfqws
    log "Настройка успешно завершена"
}
