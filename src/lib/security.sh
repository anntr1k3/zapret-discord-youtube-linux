#!/usr/bin/env bash

# Сервис не должен исполнять от root файлы из изменяемой пользователем папки.
# Это проверка перед установкой, а не автоматическое изменение владельцев.
_check_secure_path() {
    local path="$1" owner mode
    [[ ! -L "$path" ]] || return 1
    read -r owner mode < <(stat -c '%u %a' -- "$path")
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

assert_secure_service_tree() {
    local base="${1:-$HOME_DIR_PATH}" path
    # Пути попадают в шаблоны нескольких init-систем: запрещаем shell-метасимволы.
    if [[ ! "$base" =~ ^/[a-zA-Z0-9_./-]+$ || ! -d "$base" ]]; then
        echo "Ошибка: сервис требует абсолютный путь без пробелов и спецсимволов." >&2
        return 1
    fi

    path="$base"
    while :; do
        if ! _check_secure_path "$path"; then
            echo "Ошибка: $path должен принадлежать root, не быть ссылкой и не допускать запись группы/остальных." >&2
            return 1
        fi
        [[ "$path" == / ]] && break
        path=$(dirname -- "$path")
    done

    find "$base" -print >/dev/null || return 1
    while IFS= read -r -d '' path; do
        if ! _check_secure_path "$path"; then
            echo "Ошибка: небезопасный файл сервиса: $path. Используйте отдельную root-owned установку." >&2
            return 1
        fi
    done < <(find "$base" -print0)
}
