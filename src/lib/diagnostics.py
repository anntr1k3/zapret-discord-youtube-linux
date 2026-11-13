"""Unprivileged, read-only observations. No network probes or automatic fixes."""

import ast
import datetime
import ipaddress
import itertools
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from urllib.parse import urlsplit


PROXY_KEYS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
KNOWN_PROCESSES = {"openvpn", "tailscaled", "zerotier-one", "sing-box", "xray", "v2ray",
                   "clash", "mihomo", "warp-svc", "adguardhome", "nfqws", "tpws", "wg-quick"}
USER_LISTS = ("list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt")


def read_text(path, limit=65536):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Слишком большой диагностический файл")
    return data.decode("utf-8")


def proxy_address(value):
    """Only scheme/host/port survive. Never echo malformed input."""
    hidden = "некорректный или неподдерживаемый адрес (значение скрыто)"
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        return hidden
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https", "socks", "socks4", "socks5", "socks5h") or not parsed.hostname:
            return hidden
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
            host = f"[{address}]" if address.version == 6 else str(address)
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if len(host) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in host.rstrip(".").split(".")):
                return hidden
        port = f":{parsed.port}" if parsed.port is not None else ""
        suffix = " (учётные данные скрыты)" if parsed.username is not None or parsed.password is not None else ""
        return f"{parsed.scheme}://{host}{port}{suffix}"
    except (ValueError, UnicodeError):
        return hidden


def command(runner, argv):
    result = runner(argv, capture_output=True, text=True, check=False, timeout=6)
    if result.returncode or len(result.stdout) > 8192:
        # stderr may contain proxy credentials or other unexpected user data.
        raise ValueError("неизвестно: команда чтения недоступна или завершилась ошибкой")
    return result.stdout.strip()


def collect(base, data, managed=False, environ=None, proc=Path("/proc"), etc=Path("/etc"),
            runner=subprocess.run, which=shutil.which):
    base, data, proc, etc = map(Path, (base, data, proc, etc))
    environ = os.environ if environ is None else environ
    checks = []
    def add(key, title, state, summary, details=()):
        checks.append({"id": key, "title": title, "state": state, "summary": summary, "details": list(details)})

    deps = {name: bool(which(name)) for name in ("python3", "bash", "git", "grep", "sed", "curl", "nft", "iptables", "ip6tables", "systemctl", "pkexec")}
    required = all(deps[name] for name in ("python3", "bash", "git", "grep", "sed", "curl", "systemctl", "pkexec"))
    backend = deps["nft"] or (deps["iptables"] and deps["ip6tables"])
    add("dependencies", "Команды и backend", "observed" if required and backend else "warning",
        "Наличие команд не доказывает поддержку ядром NFQUEUE и работоспособность обхода.",
        [f"{name}: {'найдена в PATH' if found else 'не найдена'}" for name, found in deps.items()])

    paths, unsafe = [], False
    if managed:
        try:
            resolved = base.resolve(strict=True)
            for parent in (resolved, *resolved.parents):
                info = parent.stat()
                if info.st_uid != 0 or info.st_mode & 0o022:
                    unsafe = True
                    paths.append(f"{parent}: небезопасный владелец или права родительского каталога")
        except OSError:
            unsafe = True
            paths.append("Не удалось проверить каталоги системной копии")
    for relative in ("service.sh", "nfqws", "src/lib/common.sh", "src/lib/strategy_sync.py", "zapret-latest", "custom-strategies"):
        path = base / relative
        try:
            info = path.lstat()
            directory = relative in ("zapret-latest", "custom-strategies")
            regular = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            safe = regular and (not managed or (info.st_uid == 0 and not info.st_mode & 0o022))
            unsafe |= not safe
            paths.append(f"{path}: {'тип/права допустимы' if safe else 'небезопасный тип или права'}")
        except OSError:
            unsafe = True
            paths.append(f"{path}: отсутствует или недоступен")
    add("paths", "Файлы и пути", "warning" if unsafe else "observed",
        "Проверяется системная копия." if managed else "Проверяется checkout, не доверенная системная установка. Пробелы и Unicode допустимы.", paths)
    lists, missing = [], False
    for name in USER_LISTS:
        path = data / "user-lists" / name
        try:
            info = path.lstat()
            valid = stat.S_ISREG(info.st_mode)
            missing |= not valid
            lists.append(f"{path}: {'обычный файл' if valid else 'неподдерживаемый тип'}")
        except OSError:
            missing = True
            lists.append(f"{path}: отсутствует или недоступен")
    add("user-lists", "Пользовательские списки", "warning" if missing else "observed",
        "Содержимое не экспортируется; недостающие файлы диагностика не создаёт.", lists)

    proxies = [f"{key}: {proxy_address(environ[key])}" for key in PROXY_KEYS if environ.get(key)]
    if environ.get("no_proxy") or environ.get("NO_PROXY"):
        proxies.append("no_proxy/NO_PROXY: список исключений задан, содержимое скрыто")
    add("proxy-environment", "Прокси окружения GUI", "warning" if proxies else "observed",
        "Настройки этого процесса, не всех приложений. Пароли, имена пользователей, пути и query скрыты.",
        proxies or ["Переменные прокси в окружении не заданы."])
    gnome = []
    try:
        if not which("gsettings"):
            raise ValueError("неизвестно: gsettings не найден")
        mode = ast.literal_eval(command(runner, ["/usr/bin/gsettings", "get", "org.gnome.system.proxy", "mode"]))
        if mode not in ("none", "manual", "auto"):
            raise ValueError("неизвестно: неподдерживаемый режим GNOME proxy")
        gnome.append("Режим GNOME: " + mode)
        if mode == "auto":
            gnome.append("PAC-адрес и его содержимое не запрашиваются и не экспортируются.")
        if mode == "manual":
            for kind in ("http", "https", "socks"):
                host = ast.literal_eval(command(runner, ["/usr/bin/gsettings", "get", "org.gnome.system.proxy." + kind, "host"]))
                port = ast.literal_eval(command(runner, ["/usr/bin/gsettings", "get", "org.gnome.system.proxy." + kind, "port"]))
                if not isinstance(host, str) or type(port) is not int or not 0 <= port <= 65535:
                    raise ValueError("неизвестно: неподдерживаемые настройки GNOME proxy")
                if host:
                    address = f"[{host}]" if ":" in host and "@" not in host else host
                    gnome.append(kind + ": " + proxy_address(f"{kind}://{address}:{port}"))
        add("proxy-gnome", "Системный прокси GNOME", "warning" if mode != "none" else "observed",
            "Не описывает собственные настройки браузера, Flatpak и других приложений.", gnome)
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        add("proxy-gnome", "Системный прокси GNOME", "unknown", "неизвестно: настройки GNOME недоступны или не распознаны", gnome)

    dns, dns_errors = [], []
    try:
        for line in read_text(etc / "resolv.conf").splitlines():
            fields = line.split("#", 1)[0].split()
            if fields and fields[0] == "nameserver" and len(fields) == 2:
                try:
                    address = str(ipaddress.ip_address(fields[1]))
                    dns.append("resolv.conf nameserver: " + address)
                except ValueError:
                    dns_errors.append("Строка nameserver не распознана; значение скрыто")
        if not dns:
            dns_errors.append("IP-адреса nameserver не найдены; это не доказывает отсутствие DNS")
    except (OSError, ValueError):
        dns_errors.append("resolv.conf недоступен")
    for flag in ("dnsovertls", "dnssec"):
        try:
            if not which("resolvectl"):
                raise ValueError("resolvectl не найден")
            value = command(runner, ["/usr/bin/resolvectl", flag])
            # Export only recognized global modes, not per-link domains/IPs.
            match = re.search(r"^Global:\s*(yes|no|opportunistic|allow-downgrade)\s*$", value, re.M)
            dns.append(f"systemd-resolved {flag}: " + (match[1] if match else "глобальное значение неизвестно"))
        except (OSError, ValueError, subprocess.SubprocessError):
            dns_errors.append(f"systemd-resolved {flag}: неизвестно")
    add("dns", "Сведения о DNS", "observed" if dns and not dns_errors else "unknown",
        "Локальный stub в resolv.conf не раскрывает upstream DNS. Запросов DNS к целям нет.", dns + dns_errors)

    try:
        value = read_text(proc / "sys/net/ipv4/tcp_timestamps", 32).strip()
        if value not in ("0", "1", "2"):
            raise ValueError("неподдерживаемое значение")
        add("tcp-timestamps", "TCP timestamps", "observed", "Только чтение; sysctl не изменяется.",
            ["net.ipv4.tcp_timestamps=" + value, "Выключены" if value == "0" else "Включены"])
    except (OSError, ValueError):
        add("tcp-timestamps", "TCP timestamps", "unknown", "неизвестно: параметр недоступен")

    try:
        entries = list(itertools.islice((entry for entry in proc.iterdir() if entry.name.isdecimal()), 4097))
        candidates, errors = [], 0
        for entry in entries[:4096]:
            try:
                name = read_text(entry / "comm", 256).strip().lower()
                if name in KNOWN_PROCESSES:
                    candidates.append(f"{name}, PID {entry.name}")
            except (OSError, ValueError):
                errors += 1
        details = candidates[:30]
        if errors or len(entries) > 4096 or len(candidates) > 30:
            details.append("Наблюдения процессов неполные или ограничены; отсутствие совпадений не доказывает отсутствие VPN/обходов.")
        add("possible-conflicts", "Возможные параллельные VPN/обходы", "warning" if candidates else "unknown" if errors else "observed",
            "Наличие процесса не доказывает конфликт. Включая nfqws самого приложения; принадлежность проверяется в расширенном статусе.",
            details or ["Известных имён не обнаружено в доступной части procfs."])
    except OSError:
        add("possible-conflicts", "Возможные параллельные VPN/обходы", "unknown", "неизвестно: procfs недоступен")

    try:
        queues = []
        for line in read_text(proc / "net/netfilter/nfnetlink_queue").splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) < 3 or not all(field.isdecimal() for field in fields[:3]):
                raise ValueError("неподдерживаемый формат NFQUEUE")
            if int(fields[0]) == 220:
                queues.append(f"Очередь 220: зарегистрирован listener, ожидающих пакетов {fields[2]}")
        add("nfqueue", "NFQUEUE текущего network namespace", "observed",
            "Netlink port ID не является доказательством PID/владельца. Конфликт очереди не определяется только этим файлом.",
            queues or ["Listener очереди 220 не наблюдается; это не доказывает неподдерживаемость NFQUEUE."])
    except (OSError, ValueError):
        add("nfqueue", "NFQUEUE текущего network namespace", "unknown",
            "неизвестно: данные очереди недоступны; модуль может быть не загружен или встроен в ядро")

    try:
        found = 0
        for line in read_text(etc / "hosts", 1024 * 1024).splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) < 2:
                continue
            try:
                ipaddress.ip_address(fields[0])
            except ValueError:
                continue
            if any(name.lower() in ("youtube.com", "youtu.be") or name.lower().endswith(".youtube.com") for name in fields[1:]):
                found += 1
        add("hosts", "Записи YouTube в hosts", "warning" if found else "observed",
            f"Найдено строк с именами YouTube: {found}. Ничего не удаляется; остальные записи не экспортируются.")
    except (OSError, ValueError):
        add("hosts", "Записи YouTube в hosts", "unknown", "неизвестно: hosts недоступен или имеет неподдерживаемую кодировку")
    add("windows-only", "Платформенные проверки Windows", "not-applicable",
        "Windows-версии проверок BFE, WinDivert/SYS, Killer, Intel Connectivity, Check Point, SmartByte и OneDrive неприменимы. Возможные Linux-аналоги VPN рассматриваются отдельно.")
    return {"schema": 1, "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "checks": checks,
            "limitations": ["Браузерный DoH и Secure DNS не определяются по системному DNS.",
                "Прокси отражают окружение GUI и доступные GNOME-настройки, не все приложения.",
                "Имена процессов не доказывают конфликт, а отсутствие имён не исключает VPN или фильтрацию.",
                "Это локальные наблюдения, не сетевые пробы и не доказательство обхода DPI.",
                "Никакие исправления, очистка Discord, установки пакетов или изменения sysctl/firewall/hosts не выполняются.",
                "Отчёт может содержать локальные пути, DNS/proxy-хосты и PID. Просмотрите его перед передачей другим."]}
