"""GTK-independent labels and selection rules for operation feedback."""


MESSAGES = {
    "refresh": ("Обновляем состояние…", None),
    "read-config": ("Читаем настройки · может потребоваться авторизация…", "Настройки прочитаны"),
    "read-status": ("Читаем расширенный статус · может потребоваться авторизация…", "Снимок расширенного статуса получен"),
    "diagnostics": ("Собираем локальную диагностику · без изменений системы…", "Отчёт диагностики собран"),
    "export-diagnostics": ("Сохраняем отчёт диагностики…", "Отчёт диагностики сохранён"),
    "scan-discord": ("Проверяем поддерживаемые профили Discord…", "Предпросмотр кэша Discord обновлён"),
    "clean-discord": ("Очищаем только подтверждённый кэш Discord…", "Подтверждённый кэш Discord очищен"),
    "read-tcp-timestamps": ("Читаем TCP timestamps · может потребоваться авторизация…", "TCP timestamps прочитаны"),
    "enable-tcp-timestamps": ("Включаем TCP timestamps · может потребоваться авторизация…", "TCP timestamps включены без постоянной настройки"),
    "start": ("Запускаем сервис · может потребоваться авторизация…", "Команда запуска выполнена"),
    "stop": ("Останавливаем сервис · может потребоваться авторизация…", "Команда остановки выполнена"),
    "restart": ("Перезапускаем сервис · может потребоваться авторизация…", "Команда перезапуска выполнена"),
    "select-profile": ("Применяем профиль · может потребоваться авторизация…", "Профиль применён"),
    "set-autostart": ("Меняем автозапуск · может потребоваться авторизация…", "Настройка автозапуска сохранена"),
    "set-game-filter": ("Применяем Game Filter · может потребоваться авторизация…", "Настройки Game Filter сохранены"),
    "set-ipset-mode": ("Применяем режим IPSet · может потребоваться авторизация…", "Режим IPSet сохранён"),
    "set-active-fakes": ("Применяем активные fakes · может потребоваться авторизация…", "Активные fakes сохранены"),
    "fetch-ipset": ("Скачиваем список IPSet с Flowseal…", "Список IPSet загружен"),
    "update-ipset": ("Применяем список IPSet · может потребоваться авторизация…", "Список IPSet обновлён"),
    "fetch-hosts": ("Скачиваем hosts с Flowseal…", "Список hosts загружен"),
    "update-hosts": ("Применяем hosts · может потребоваться авторизация…", "hosts обновлён"),
    "export-hosts": ("Экспортируем скачанный hosts…", "Скачанный hosts сохранён"),
    "check": ("Проверяем обновления Flowseal…", "Проверка Flowseal завершена"),
    "set-auto-check": ("Меняем автоматическую проверку обновлений…", "Настройка автоматической проверки сохранена"),
    "prepare": ("Скачиваем и проверяем стратегии · это может занять несколько минут…", "Подготовка завершена — результат на вкладке «Обновления»"),
    "apply": ("Применяем стратегии · не закрывайте окно…", "Подготовленный пакет применён"),
    "logs": ("Читаем журнал…", "Журнал загружен"),
}


def operation_messages(action):
    return MESSAGES[action]


def diagnostics_text(report):
    if not report:
        return "Диагностика ещё не выполнялась. Запускается только по нажатию, без root, сетевых проб и исправлений."
    labels = {"observed": "Наблюдение", "warning": "Внимание", "unknown": "Неизвестно",
              "not-applicable": "Неприменимо"}
    lines = ["Локальная диагностика · " + str(report.get("checked_at", "время неизвестно")),
             "Снимок не обновляется автоматически. Наблюдения не означают исправность или эффективность обхода DPI."]
    for item in report.get("checks", []):
        lines += ["", f"[{labels.get(item.get('state'), 'Неизвестно')}] {item.get('title', '')}",
                  str(item.get("summary", ""))]
        lines.extend("  · " + str(detail) for detail in item.get("details", []))
    lines += ["", "Ограничения и приватность:"]
    lines.extend("  · " + str(value) for value in report.get("limitations", []))
    return "\n".join(lines)


def service_state_title(state):
    if state.get("unit_error") or state.get("unit_present") is None:
        return "Состояние сервиса неизвестно"
    if not state.get("installed"):
        return "Обнаружен сторонний или неуправляемый юнит" if state.get("unit_present") else "Системный сервис не установлен"
    return {"active": "Сервис работает", "inactive": "Сервис остановлен", "failed": "Сервис завершился с ошибкой",
            "activating": "Сервис запускается", "deactivating": "Сервис останавливается",
            "reloading": "Сервис перечитывает настройки"}.get(state.get("state"), "Состояние сервиса неизвестно")


def service_status_text(report):
    if not report:
        return "Расширенный статус ещё не прочитан. Это отдельная проверка с авторизацией; изменений системы нет."
    labels = {"present": "обнаружено", "absent": "не обнаружено", "unknown": "неизвестно"}
    unit = report.get("unit", {})
    props = unit.get("properties", {})
    lines = ["Снимок на момент: " + str(report.get("checked_at", "неизвестно")),
             "Не обновляется автоматически; после изменений прочитайте статус заново."]
    if unit.get("state") == "known":
        lines += [f"systemd: {props.get('LoadState', '?')} / {props.get('ActiveState', '?')} / {props.get('SubState', '?')}",
                  f"MainPID: {props.get('MainPID', '?')} · Result: {props.get('Result', '?')} · ExecMainStatus: {props.get('ExecMainStatus', '?')}"]
    else:
        lines.append("systemd: неизвестно · " + str(unit.get("error")))
    config = report.get("config", {})
    lines += ["Профиль в конфиге: " + str(config.get("strategy") or "неизвестно"),
              "Backend в конфиге: " + str(config.get("firewall_backend") or "неизвестно")]
    if report.get("config_error"):
        lines.append("Ошибка чтения конфига: " + report["config_error"])
    engine = report.get("engine", {})
    lines += ["Движок: " + str(engine.get("path")), "SHA-256: " + str(engine.get("sha256") or "неизвестно"),
              "Версия движка не извлекалась: бинарник для диагностики не запускается."]
    if engine.get("error"):
        lines.append("Движок: " + engine["error"])
    process = report.get("process", {})
    lines += ["nfqws текущего релиза в cgroup сервиса: " + labels.get(process.get("state"), "неизвестно"),
              "PID nfqws: " + (", ".join(map(str, process.get("pids", []))) or "—"),
              "Очереди процесса: " + (", ".join(map(str, process.get("queues", []))) or "не определены"),
              "Ожидаемая очередь приложения: " + str(report.get("expected_queue", "неизвестно"))]
    if process.get("error"):
        lines.append(process["error"])
    for name, info in report.get("firewall", {}).items():
        lines.append(f"{name}: {labels.get(info.get('state'), 'неизвестно')} · распознано правил: {info.get('recognized_rules', 0)} · очереди: {info.get('queues', [])}")
        if info.get("error"):
            lines.append(info["error"])
    lines.extend("Внимание: " + warning for warning in report.get("warnings", []))
    lines.append("Это наблюдения, не доказательство обхода DPI или принадлежности всех одноимённых правил. Исправления не выполняются.")
    return "\n".join(lines)


def version_text(info):
    def app_text(app):
        if not app or not app.get("version"):
            return "версия неизвестна"
        return app["version"] + (" · релиз" if app.get("release") else " · разрабатываемая сборка, не релиз")
    def target_text(target):
        if not target or not target.get("revision"):
            return (target or {}).get("error") or "версия неизвестна"
        channel = "релиз" if target.get("channel") == "release" else "ветка main, не релиз"
        return f"{target.get('tag') or channel} · {channel}\nCommit: {target['revision']}"
    lines = ["Linux-приложение (открытое окно): " + app_text(info.get("running_app"))]
    lines.append("Установленная системная копия приложения: " + app_text(info["installed_app"])
                 if info.get("installed_app") is not None else "Системная копия приложения не обнаружена.")
    scope = "системная копия" if info.get("scope") == "installed" else "локальный checkout, не установленный сервис"
    lines += ["", "Локальный набор Flowseal (" + scope + "):", target_text(info.get("current")),
              "", "Flowseal по последней сохранённой проверке:", target_text(info.get("checked"))]
    if info.get("checked", {}).get("checked_at"):
        lines.append("Время проверки: " + str(info["checked"]["checked_at"]))
    relation = info.get("relation")
    lines.append("Ревизии данных совпадают." if relation == "same" else
                 "Ревизии данных различаются. Это не доказывает, какая из них новее." if relation == "different" else
                 "Сравнить ревизии данных пока нельзя.")
    lines += ["", "Проверка Flowseal относится к данным стратегий, а не к версии Linux-приложения.",
              "Обновление самого приложения здесь пока не проверяется и не устанавливается."]
    return "\n".join(lines)


def profile_index(profiles, config):
    if config is None:
        return None
    strategy = config["config"]["strategy"]
    return profiles.index(strategy) if strategy in profiles else None


def game_filter_values(config):
    tcp = config.get("gamefiltertcp") == "true"
    udp = config.get("gamefilterudp") == "true"
    mode = "all" if tcp and udp else "tcp" if tcp else "udp" if udp else "disabled"
    return mode, config.get("gamefiltertcp_ports", "1024-65535"), config.get("gamefilterudp_ports", "1024-65535")
