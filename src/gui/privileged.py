#!/usr/bin/env python3
"""Small installed-only administrative protocol for the unprivileged GUI."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import uuid


SERVICE = "zapret_discord_youtube.service"
RELEASES = Path("/opt/zapret-discord-youtube/releases")
HOSTS = Path("/etc/hosts")
STREAM_ACTION = "test-session"
# strategy-tester-v1: installed-only streaming transport and unprivileged GUI runner supported.
# read-only-service-status-v1: safe for unprivileged capability detection.
# tcp-timestamps-enable-v1: fixed-key runtime-only action, independent of config.
# remove-service-v1: installed-only service removal supported.
ACTIONS = {"read-config": set(), "read-status": set(), "select-profile": {"strategy", "expected_sha256"},
           "read-tcp-timestamps": set(), "enable-tcp-timestamps": {"expected_value"},
           "set-game-filter": {"mode", "tcp_ports", "udp_ports", "expected_sha256"},
           "set-ipset-mode": {"mode", "expected_sha256", "expected_list_sha256"},
           "set-active-fakes": {"discord", "gameudp", "expected_sha256"},
           "update-ipset": {"stage", "sha256", "expected_sha256"},
           "update-hosts": {"stage", "sha256", "expected_hosts_sha256"},
           "set-autostart": {"enabled"}, "apply-strategies": {"stage", "digest"}, "rollback": set(),
           "remove-service": {"purge"}}


def validate_payload(action, payload):
    if action not in ACTIONS or not isinstance(payload, dict) or set(payload) != ACTIONS[action]:
        raise ValueError("Неизвестная операция или поля административного запроса")
    if action == "remove-service" and type(payload["purge"]) is not bool:
        raise ValueError("purge должен быть boolean")
    if action == "enable-tcp-timestamps":
        if not isinstance(payload["expected_value"], str) or payload["expected_value"] not in ("0", "1", "2"):
            raise ValueError("Требуется прочитанное значение TCP timestamps")
    if action == "select-profile":
        if not isinstance(payload["strategy"], str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bat", payload["strategy"]):
            raise ValueError("Некорректное имя стратегии")
    if action in ("select-profile", "set-game-filter", "set-ipset-mode", "set-active-fakes"):
        if not isinstance(payload["expected_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["expected_sha256"]):
            raise ValueError("Требуется версия прочитанной конфигурации")
    if action == "set-active-fakes":
        for field in ("discord", "gameudp"):
            value = payload[field]
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise ValueError("Выбор fake: SHA-256 файла из релиза или null для возврата по умолчанию")
    if action == "update-ipset":
        if (not isinstance(payload["stage"], str) or not Path(payload["stage"]).is_absolute()
                or "\x00" in payload["stage"] or len(payload["stage"]) > 4096
                or not isinstance(payload["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])):
            raise ValueError("Требуются абсолютный путь подготовленного IPSet и его SHA-256")
        if not isinstance(payload["expected_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["expected_sha256"]):
            raise ValueError("Требуется версия прочитанной конфигурации")
    if action == "update-hosts":
        if (not isinstance(payload["stage"], str) or not Path(payload["stage"]).is_absolute()
                or "\x00" in payload["stage"] or len(payload["stage"]) > 4096
                or not isinstance(payload["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])):
            raise ValueError("Требуются абсолютный путь подготовленного hosts и его SHA-256")
        if (not isinstance(payload["expected_hosts_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["expected_hosts_sha256"])):
            raise ValueError("Требуется SHA-256 текущего файла hosts")
    if action == "set-ipset-mode":
        if payload["mode"] not in ("loaded", "none", "any"):
            raise ValueError("Неизвестный режим IPSet")
        token = payload["expected_list_sha256"]
        if payload["mode"] == "loaded":
            if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
                raise ValueError("Требуется SHA-256 выбранного загруженного IPSet")
        elif token is not None:
            raise ValueError("Для этого режима IPSet не требуется токен списка")
    if action == "set-game-filter":
        if payload["mode"] not in ("disabled", "tcp", "udp", "all"):
            raise ValueError("Неизвестный режим Game Filter")
        for key in ("tcp_ports", "udp_ports"):
            if not isinstance(payload[key], str) or not re.fullmatch(r"[0-9,-]{1,512}", payload[key]):
                raise ValueError("Некорректные порты Game Filter")
    if action == "set-autostart" and type(payload["enabled"]) is not bool:
        raise ValueError("enabled должен быть boolean")
    if action == "apply-strategies":
        if (not isinstance(payload["stage"], str) or not Path(payload["stage"]).is_absolute()
                or "\x00" in payload["stage"] or not isinstance(payload["digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["digest"])):
            raise ValueError("Требуются абсолютный stage и его SHA-256 digest")


def load_fake_select():
    # Only this release's trusted copy of the selection logic.
    path = Path(__file__).resolve().parents[1] / "lib/fake_select.py"
    spec = importlib.util.spec_from_file_location("gui_fake_select", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_ipset_mode():
    # Only this release's trusted copy of the list inspection logic.
    path = Path(__file__).resolve().parents[1] / "lib/ipset_mode.py"
    spec = importlib.util.spec_from_file_location("gui_ipset_mode", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_hosts_file():
    # Only this release's trusted copy of the hosts parsing/merge logic.
    path = Path(__file__).resolve().parents[1] / "lib/hosts_file.py"
    spec = importlib.util.spec_from_file_location("gui_hosts_file", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_tcp_timestamps():
    path = Path(__file__).resolve().parents[1] / "lib/tcp_timestamps.py"
    spec = importlib.util.spec_from_file_location("installed_tcp_timestamps", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def config_result(installer):
    state = installer.state()
    if state is None:
        raise ValueError("Управляемая системная установка отсутствует")
    path = installer.data / "conf.env"
    data = path.read_bytes()
    if len(data) > 16384:
        raise ValueError("Конфигурация слишком велика для редактора GUI")
    release = installer.release(state["current"])
    # Allow reading a structurally valid config with unavailable IPSet data so
    # the user can explicitly recover by choosing none/any. Writes stay strict.
    values = installer.validate_config(path, release, validate_ipset=False, validate_fakes=False)
    capabilities = ["game-filter-ranges-v1"]
    if "# ipset mode v1" in (release / "src/lib/common.sh").read_text():
        capabilities.append("ipset-mode-v1")
    if "# active fakes v1" in (release / "src/lib/common.sh").read_text():
        capabilities.append("active-fakes-v1")
    if "update-ipset" in ACTIONS:
        capabilities.append("ipset-update-v1")
    if "update-hosts" in ACTIONS:
        capabilities.append("hosts-update-v1")
    if "read-status" in ACTIONS:
        capabilities.append("service-status-v1")
    if "enable-tcp-timestamps" in ACTIONS:
        capabilities.append("tcp-timestamps-enable-v1")
    if "remove-service" in ACTIONS:
        capabilities.append("remove-service-v1")
    fakes = installer.fake_state(values, release)
    strategy_name = values.get("strategy")
    usage = {"discord": 0, "gameudp": 0}
    try:
        catalog = None
        catalog_path = release / "zapret-latest" / "strategies.json"
        if catalog_path.is_file():
            catalog = json.loads(catalog_path.read_text())
            if not isinstance(catalog, dict) or catalog.get("schema") != 1 \
                    or not isinstance(catalog.get("strategies"), dict):
                catalog = None
        if strategy_name:
            # Custom strategies are plain .bat files. Synchronized strategies
            # keep only a placeholder .bat on disk, so tokens are counted from
            # the compiled catalog instead.
            custom = release / "custom-strategies" / strategy_name
            latest = release / "zapret-latest" / strategy_name
            entry = (catalog or {}).get("strategies", {}).get(strategy_name)
            if custom.is_file():
                usage = load_fake_select().strategy_usage(custom.read_bytes().decode("utf-8-sig"))
            elif entry is not None:
                tokens = [token for profile in entry.get("profiles") or [] for token in profile]
                usage = load_fake_select().strategy_usage("\n".join(tokens))
            elif latest.is_file():
                usage = load_fake_select().strategy_usage(latest.read_bytes().decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError):
        usage = {"discord": 0, "gameudp": 0}
    return {"config": values, "sha256": hashlib.sha256(data).hexdigest(),
            "capabilities": capabilities, "ipset": installer.ipset_state(values, release),
            "fakes": fakes, "fakes_usage": usage}


def updated_config(old, updates):
    newline = b"\r\n" if b"\r\n" in old else b"\n"
    new = old
    for key, value in updates.items():
        pattern = rb"(?m)^" + key.encode("ascii") + rb"=[^\r\n]*"
        replacement = key.encode("ascii") + b"=" + value.encode("ascii")
        new, count = re.subn(pattern, lambda _: replacement, new, count=1)
        if not count:
            if new and not new.endswith(b"\n"):
                new += newline
            new += replacement + newline
    return new


def write_config(path, data, info, prefix=".gui-config-"):
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_fake_file(target, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".fake-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def update_ipset_transaction(installer, release, current, payload):
    """Write the staged upstream IPSet into persistent user data.

    The config, the selected mode and user exclusions are never touched; the
    list lands in user-lists/ipset-all.txt, which legacy and loaded modes
    resolve first. Config is validated unchanged and the service restarts
    only when the bytes actually differ.
    """
    ipset = load_ipset_mode()
    stage = Path(payload["stage"])
    try:
        info = stage.lstat()
    except OSError as error:
        raise ValueError(f"Не удалось прочитать подготовленный IPSet: {error}") from error
    # The stage is produced by the unprivileged GUI; a root-owned regular file
    # here could smuggle privileged-only content into a world-readable list.
    if not stat.S_ISREG(info.st_mode) or (os.geteuid() == 0 and info.st_uid == 0):
        raise ValueError("Подготовленный IPSet должен быть обычным файлом вашего пользователя")
    inspected = ipset.inspect_list(stage)
    if inspected["sha256"] != payload["sha256"]:
        raise ValueError("Список IPSet изменился после проверки. Загрузите его заново.")
    if inspected["kind"] != "loaded":
        raise ValueError("Скачанный список пуст или является заглушкой; обновление отменено")
    wanted = stage.read_bytes()
    if hashlib.sha256(wanted).hexdigest() != payload["sha256"]:
        raise ValueError("Список IPSet изменился после проверки. Загрузите его заново.")
    lists = installer.data / "user-lists"
    installer.check_path(lists)
    target = lists / "ipset-all.txt"
    try:
        existing_mode = stat.S_IMODE(target.stat().st_mode)
        existing = target.read_bytes()
    except OSError:
        existing_mode, existing = 0o644, None
    if existing == wanted:
        return current
    path = installer.data / "conf.env"
    old = path.read_bytes()
    if hashlib.sha256(old).hexdigest() != current["sha256"]:
        raise ValueError("Конфигурация была изменена другим процессом")
    active = installer.systemd.is_active()
    wrote = False
    attempted_start = False
    installer.backup()

    def restore_file():
        if existing is None:
            target.unlink(missing_ok=True)
        else:
            write_fake_file(target, existing, existing_mode)

    try:
        if active:
            installer.systemd.run("stop", SERVICE)
        if path.read_bytes() != old:
            raise ValueError("Конфигурация была изменена другим процессом")
        write_fake_file(target, wanted, existing_mode)
        wrote = True
        if active:
            attempted_start = True
            try:
                installer.systemd.run("start", SERVICE)
            except Exception as error:
                raise RuntimeError("Сервис не запустился с обновлённым IPSet") from error
            if not installer.systemd.is_active():
                raise RuntimeError("Сервис не запустился с обновлённым IPSet")
    except BaseException as error:
        try:
            if wrote:
                if attempted_start:
                    installer.systemd.run("reset-failed", SERVICE)
                installer.systemd.run("stop", SERVICE)
                restore_file()
            if active:
                installer.systemd.run("start", SERVICE)
        except Exception as recovery:
            raise RuntimeError(f"Ошибка обновления IPSet; восстановление также не удалось: {recovery}") from error
        raise
    return config_result(installer)


def hosts_status():
    """Read-only summary used by the GUI and after a successful write."""
    try:
        data = HOSTS.read_bytes()
    except OSError as error:
        return {"readable": False, "present": False, "entries": 0, "sha256": None,
                "size": 0, "malformed": None, "error": f"Не удалось прочитать /etc/hosts: {error}"}
    result = load_hosts_file().status(data)
    result.update(readable=True, error=None)
    return result


def update_hosts_transaction(installer, payload):
    """Write only the marked managed block into /etc/hosts.

    The service is not restarted: hosts changes take effect for new lookups.
    A backup of the complete previous file is created before the atomic write.
    """
    hosts = load_hosts_file()
    stage = Path(payload["stage"])
    try:
        fd = os.open(stage, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError(f"Не удалось прочитать подготовленный hosts: {error}") from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or (os.geteuid() == 0 and info.st_uid == 0):
            raise ValueError("Подготовленный hosts должен быть обычным файлом вашего пользователя")
        raw = stream.read(hosts.MAX_BYTES + 1)
    if hashlib.sha256(raw).hexdigest() != payload["sha256"]:
        raise ValueError("Файл hosts изменился после проверки. Загрузите его заново.")
    inspected = hosts.validate(raw)
    if inspected["sha256"] != payload["sha256"]:
        raise ValueError("Файл hosts изменился после проверки. Загрузите его заново.")
    try:
        target_info = HOSTS.lstat()
    except OSError as error:
        raise ValueError(f"Не удалось прочитать /etc/hosts: {error}") from error
    if not stat.S_ISREG(target_info.st_mode):
        raise ValueError("/etc/hosts должен быть обычным файлом, не symlink или специальным файлом")
    if target_info.st_uid != 0 or target_info.st_mode & 0o022:
        raise ValueError("/etc/hosts должен принадлежать root и не быть доступным на запись группе/остальным")
    current = HOSTS.read_bytes()
    if hashlib.sha256(current).hexdigest() != payload["expected_hosts_sha256"]:
        raise ValueError("/etc/hosts изменился после просмотра. Проверьте изменения заново.")
    # Raises on malformed or duplicated markers before anything is written.
    new = hosts.merge(current, inspected["data"])
    if new == current:
        return {"hosts": hosts_status(), "changed": False, "backup": None}
    if hosts.merge(new, inspected["data"]) != new:
        raise RuntimeError("Не удалось безопасно сформировать управляемый блок hosts")
    directory = installer.state_dir / "hosts-backups"
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup = directory / ("hosts-" + uuid.uuid4().hex)
    write_fake_file(backup, current, 0o600)
    latest_info = HOSTS.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    if (any(getattr(latest_info, field) != getattr(target_info, field) for field in fields)
            or HOSTS.read_bytes() != current):
        raise ValueError("/etc/hosts изменился во время подготовки. Проверьте изменения заново.")
    try:
        write_config(HOSTS, new, target_info, prefix=".gui-hosts-")
        if HOSTS.read_bytes() != new:
            raise RuntimeError("Файл /etc/hosts не совпал после записи")
    except BaseException as error:
        try:
            if HOSTS.read_bytes() != current:
                write_config(HOSTS, current, target_info, prefix=".gui-hosts-")
        except Exception as recovery:
            raise RuntimeError(f"Ошибка записи hosts; восстановление также не удалось: {recovery}") from error
        raise
    return {"hosts": hosts_status(), "changed": True, "backup": str(backup)}


def active_fakes_transaction(installer, release, current, payload):
    fake = load_fake_select()
    sources = {}
    for kind in ("discord", "gameudp"):
        if payload[kind] is not None:
            # Resolve the vetted release bin before touching anything.
            sources[kind] = fake.select_source(release / "zapret-latest", payload[kind])
    path = installer.data / "conf.env"
    old = path.read_bytes()
    if hashlib.sha256(old).hexdigest() != current["sha256"]:
        raise ValueError("Конфигурация была изменена другим процессом")
    info = path.stat()
    new = updated_config(old, {"fakediscord": payload["discord"] or "",
                               "fakegameudp": payload["gameudp"] or ""})
    if len(new) > 16384:
        raise ValueError("Конфигурация слишком велика для редактора GUI")
    directory = installer.data / "fakes"
    files = []
    for kind in ("discord", "gameudp"):
        target = fake.active_path(installer.data, kind)
        wanted = sources[kind].read_bytes() if kind in sources else None
        try:
            existing = target.read_bytes()
        except OSError:
            existing = None
        files.append((target, existing, wanted))
    if new == old and all(existing == wanted for _, existing, wanted in files):
        return current
    # Overrides that are not being re-selected must still match their files;
    # reject drift before stopping the service.
    for kind, field in (("discord", "fakediscord"), ("gameudp", "fakegameudp")):
        if kind in sources:
            continue
        kept = payload[kind] if payload[kind] is not None else current["config"].get(field, "")
        if kept:
            fake.verify_active(installer.data, kind, kept)
    fd, candidate = tempfile.mkstemp(prefix=".gui-fakes-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(new)
        installer.validate_config(Path(candidate), release, validate_fakes=False)
    finally:
        Path(candidate).unlink(missing_ok=True)
    active = installer.systemd.is_active()
    wrote = False
    attempted_start = False
    installer.backup()

    def restore_files():
        for target, existing, _ in files:
            if existing is None:
                target.unlink(missing_ok=True)
            else:
                write_fake_file(target, existing)

    try:
        if active:
            installer.systemd.run("stop", SERVICE)
        if path.read_bytes() != old:
            raise ValueError("Конфигурация была изменена другим процессом")
        installer.check_path(directory)
        directory.mkdir(mode=0o700, exist_ok=True)
        for target, existing, wanted in files:
            if wanted == existing:
                continue
            if wanted is None:
                target.unlink(missing_ok=True)
            else:
                write_fake_file(target, wanted)
        wrote = True
        write_config(path, new, info)
        installer.validate_config(path, release)
        if active:
            attempted_start = True
            installer.systemd.run("start", SERVICE)
            if not installer.systemd.is_active():
                raise RuntimeError("Сервис не запустился с новыми настройками")
    except BaseException as error:
        try:
            if wrote:
                if path.read_bytes() != new:
                    raise RuntimeError("Конфигурация изменена другим процессом; автоматическое восстановление отменено")
                if attempted_start:
                    installer.systemd.run("reset-failed", SERVICE)
                installer.systemd.run("stop", SERVICE)
                write_config(path, old, info)
                restore_files()
            if active:
                installer.systemd.run("start", SERVICE)
        except Exception as recovery:
            raise RuntimeError(f"Ошибка настроек; восстановление также не удалось: {recovery}") from error
        raise
    return config_result(installer)


def dispatch(installer, action, payload):
    validate_payload(action, payload)
    if action == "apply-strategies":
        installer.apply_strategies(Path(payload["stage"]), payload["digest"], confirmed=True)
        return {"applied": True}
    if action == "rollback":
        installer.rollback()
        return {"rolled_back": True}
    if action == "remove-service":
        purge = payload["purge"]
        installer.remove(purge=purge)
        return {"removed": True, "purged": purge}
    with installer.operation():
        if action in ("read-tcp-timestamps", "enable-tcp-timestamps"):
            if installer.state() is None:
                raise ValueError("Управляемая системная установка отсутствует")
            runtime = load_tcp_timestamps()
            return runtime.status() if action == "read-tcp-timestamps" else runtime.enable(payload["expected_value"])
        if action == "read-status":
            state = installer.state()
            if state is None:
                raise ValueError("Управляемая системная установка отсутствует")
            release = installer.release(state["current"])
            path = Path(__file__).resolve().parents[1] / "lib/service_status.py"
            spec = importlib.util.spec_from_file_location("installed_service_status", path)
            module = importlib.util.module_from_spec(spec)
            exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
            values, error = None, None
            try:
                values = config_result(installer)["config"]
            except (OSError, ValueError, RuntimeError) as problem:
                error = str(problem)
            return module.collect(release, values, error)
        if action == "update-hosts":
            if installer.state() is None:
                raise ValueError("Управляемая системная установка отсутствует")
            return update_hosts_transaction(installer, payload)
        current = config_result(installer)
        if action == "read-config":
            return current
        if action == "set-autostart":
            old = installer.systemd.is_enabled()
            try:
                installer.systemd.run("enable" if payload["enabled"] else "disable", SERVICE)
            except Exception:
                installer.systemd.run("enable" if old else "disable", SERVICE)
                raise
            return {"enabled": installer.systemd.is_enabled()}
        if payload["expected_sha256"] != current["sha256"]:
            raise ValueError("Конфигурация изменилась. Сначала перечитайте настройки.")
        state = installer.state()
        release = installer.release(state["current"])
        if action == "set-active-fakes":
            return active_fakes_transaction(installer, release, current, payload)
        if action == "update-ipset":
            return update_ipset_transaction(installer, release, current, payload)
        if action == "select-profile":
            strategy = payload["strategy"]
            if not any((release / folder / strategy).is_file() for folder in ("custom-strategies", "zapret-latest")):
                raise ValueError("Стратегия отсутствует в установленной версии")
            updates = {"strategy": strategy}
        elif action == "set-game-filter":
            mode = payload["mode"]
            updates = {"gamefiltertcp": "true" if mode in ("tcp", "all") else "false",
                       "gamefilterudp": "true" if mode in ("udp", "all") else "false",
                       "gamefiltertcp_ports": payload["tcp_ports"], "gamefilterudp_ports": payload["udp_ports"]}
        else:
            updates = {"ipset_mode": payload["mode"]}
            if payload["mode"] == "loaded":
                ipset_info = installer.ipset_state(current["config"], release)
                if not ipset_info["loaded_available"] or ipset_info["loaded_sha256"] != payload["expected_list_sha256"]:
                    raise ValueError("Загруженный IPSet изменился или недоступен. Перечитайте настройки.")
        path = installer.data / "conf.env"
        old = path.read_bytes()
        if hashlib.sha256(old).hexdigest() != current["sha256"]:
            raise ValueError("Конфигурация была изменена другим процессом")
        info = path.stat()
        new = updated_config(old, updates)
        if new == old:
            return current
        if len(new) > 16384:
            raise ValueError("Конфигурация слишком велика для редактора GUI")
        # Validate every value before backup/stop, including new port ranges.
        fd, candidate = tempfile.mkstemp(prefix=".gui-validate-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(new)
            installer.validate_config(Path(candidate), release)
            if action == "set-ipset-mode" and payload["mode"] == "loaded":
                ipset_info = installer.ipset_state(current["config"], release)
                if ipset_info["loaded_sha256"] != payload["expected_list_sha256"]:
                    raise ValueError("IPSet изменился во время подготовки. Перечитайте настройки.")
        finally:
            Path(candidate).unlink(missing_ok=True)
        active = installer.systemd.is_active()
        wrote = False
        attempted_start = False
        installer.backup()
        try:
            if active:
                installer.systemd.run("stop", SERVICE)
            if path.read_bytes() != old:
                raise ValueError("Конфигурация была изменена другим процессом")
            write_config(path, new, info)
            wrote = True
            installer.validate_config(path, release)
            if active:
                attempted_start = True
                installer.systemd.run("start", SERVICE)
                if not installer.systemd.is_active():
                    raise RuntimeError("Сервис не запустился с новыми настройками")
        except BaseException as error:
            try:
                if wrote:
                    if path.read_bytes() != new:
                        raise RuntimeError("Конфигурация изменена другим процессом; автоматическое восстановление отменено")
                    if attempted_start:
                        # A failed start is still loaded (possibly queued for
                        # Restart=on-failure). Stop can unload it, making a later
                        # reset-failed fail with "unit not loaded".
                        installer.systemd.run("reset-failed", SERVICE)
                    installer.systemd.run("stop", SERVICE)
                    write_config(path, old, info)
                if active:
                    installer.systemd.run("start", SERVICE)
            except Exception as recovery:
                raise RuntimeError(f"Ошибка настроек; восстановление также не удалось: {recovery}") from error
            raise
        return config_result(installer)


def verify_release():
    release = Path(__file__).resolve().parents[2]
    if release.parent != RELEASES or not re.fullmatch(r"[0-9a-f]{32}", release.name):
        raise ValueError("Административный помощник разрешён только из root-owned системной установки")
    for path in (release, *release.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Небезопасный родительский каталог помощника")
    for parent, directories, files in os.walk(release, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            info = path.lstat()
            if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError("Небезопасные файлы системного помощника")
    return release


def make_installer(release):
    path = release / "install.py"
    module = types.ModuleType("gui_trusted_installer")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)

    class CapturedSystemd(module.Systemd):
        def run(self, *args):
            try:
                subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(error.stderr.strip() or str(error)) from error

    installer = module.Installer(systemd=CapturedSystemd())
    installer.validate_config = module.validate_config
    return installer


def load_test_session_modules(release):
    modules = []
    for name in ("strategy_test_session", "strategy_test_service"):
        path = release / "src/lib" / (name + ".py")
        module = types.ModuleType("installed_stream_" + name)
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        modules.append(module)
    return tuple(modules)


def run_test_session(release, *, read_fd=0, write_fd=1):
    """Only called after root/release verification; never use the EOF JSON path."""
    protocol, service = load_test_session_modules(release)
    with protocol.SessionSignals() as signals:
        channel = protocol.MessageChannel(read_fd, write_fd)
        try:
            request = channel.receive(30)
            protocol.validate_begin(request)
            runtime = service.InstalledSessionRuntime(make_installer(release))
            result = protocol.serve(runtime, request, channel.receive, channel.send, signals=signals)
            return 0 if result["ok"] else 1
        except Exception as error:
            # No change precedes begin validation. Exceptions from serve have
            # already passed through its recovery path while the lock was held.
            signals.recovering = True
            try:
                channel.send({"event": "closed", "ok": False, "error": str(error)})
            except (OSError, TimeoutError):
                pass
            return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(*ACTIONS, STREAM_ACTION))
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("Требуется авторизация администратора")
        os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
        release = verify_release()
        if args.action == STREAM_ACTION:
            return run_test_session(release)
        data = sys.stdin.buffer.read(16385)
        if len(data) > 16384:
            raise ValueError("Запрос слишком велик")
        payload = json.loads(data)
        validate_payload(args.action, payload)
        result = dispatch(make_installer(release), args.action, payload)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        print(json.dumps({"ok": False, "error": detail}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
