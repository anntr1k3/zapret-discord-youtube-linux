#!/usr/bin/env bash

SUDOERS_FILE="/etc/sudoers.d/zapret"
DOAS_CONF="/etc/doas.conf"

# Не выдаём NOPASSWD на изменяемый пользователем бинарник и произвольный firewall.
# status/remove сохранены для миграции существующих установок.
setup_permissions() {
    echo "Ошибка: автоматическая выдача NOPASSWD отключена как небезопасная." >&2
    echo "Используйте обычное подтверждение sudo/doas. Старые правила: setup-permissions remove." >&2
    return 1
}

remove_permissions() {
    local removed=false

    if [[ -f "$SUDOERS_FILE" ]]; then
        elevate rm -f "$SUDOERS_FILE" || return 1
        echo "Удалён $SUDOERS_FILE"
        removed=true
    fi

    if [[ -f "$DOAS_CONF" ]] && grep -q "# Zapret Discord YouTube" "$DOAS_CONF"; then
        # Общий файл может содержать правила администратора. Не удаляем
        # диапазон до пустой строки или похожие правила других приложений.
        echo "Требуется ручное удаление старого блока Zapret из $DOAS_CONF администратором." >&2
        return 1
    fi

    if ! $removed; then
        echo "Настройки не найдены"
    fi
}

show_permissions_status() {
    echo "Создание NOPASSWD отключено. Существующие правила не удаляются автоматически."
    if [[ -f "$SUDOERS_FILE" ]]; then
        echo "sudoers: $SUDOERS_FILE"
        cat "$SUDOERS_FILE" 2>/dev/null || elevate cat "$SUDOERS_FILE"
    else
        echo "sudoers: не настроен"
    fi

    if [[ -f "$DOAS_CONF" ]] && grep -q "# Zapret Discord YouTube" "$DOAS_CONF"; then
        echo "doas: найдены старые правила, проверьте $DOAS_CONF"
        grep -A5 "# Zapret Discord YouTube" "$DOAS_CONF"
    else
        echo "doas: не настроен"
    fi
}
