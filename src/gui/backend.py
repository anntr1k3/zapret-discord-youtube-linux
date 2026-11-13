"""Unprivileged GUI operations, independent of GTK for testing."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


SERVICE = "zapret_discord_youtube.service"
CURRENT = Path("/opt/zapret-discord-youtube/current")
HOSTS = Path("/etc/hosts")
MARKER = "zapret-system-installer-v1\n"


def load_hosts_module():
    path = Path(__file__).resolve().parents[1] / "lib/hosts_file.py"
    spec = importlib.util.spec_from_file_location("gui_hosts_file", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_version_module():
    path = Path(__file__).resolve().parents[1] / "lib/version_info.py"
    spec = importlib.util.spec_from_file_location("gui_version_info", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_diagnostics_module():
    path = Path(__file__).resolve().parents[1] / "lib/diagnostics.py"
    spec = importlib.util.spec_from_file_location("gui_diagnostics", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_discord_cache_module():
    path = Path(__file__).resolve().parents[1] / "lib/discord_cache.py"
    spec = importlib.util.spec_from_file_location("gui_discord_cache", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_diagnostics_report(report, target):
    if report is None:
        raise ValueError("Сначала выполните диагностику")
    target = Path(target)
    if not target.is_absolute() or target.is_dir():
        raise ValueError("Выберите абсолютный путь файла отчёта")
    if target.is_symlink():
        raise OSError("Экспорт в symlink не допускается")
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".diagnostics-export-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"target": str(target), "size": len(encoded)}


class Backend:
    demo = False

    def __init__(self, workspace, current=CURRENT, cache=None):
        self.workspace = Path(workspace).resolve()
        self.current = Path(current)
        self.cache = Path(cache or Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "zapret-strategy-sync")
        self.loaded_config = None
        self.status_report = None
        self.diagnostic_report = None
        self.discord_report = None
        self.tcp_state = None

    @staticmethod
    def command(argv, **kwargs):
        result = subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Команда завершилась с кодом {result.returncode}")
        return result.stdout

    def managed(self):
        try:
            return (self.current / ".system-install").read_text() == MARKER
        except OSError:
            return False

    def base(self):
        return self.current if self.managed() else self.workspace

    def profiles(self):
        base = self.base()
        names = set()
        for folder in (base / "zapret-latest", base / "custom-strategies"):
            if folder.is_dir():
                names.update(path.name for path in folder.glob("*.bat")
                             if path.is_file() and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bat", path.name))
        return sorted(names)

    def trusted_helper(self):
        helper = self.current / "src/gui/privileged.py"
        if not self.managed() or not helper.is_file():
            raise RuntimeError("Установите или обновите системную копию адаптера: GUI не запускает помощник из пользовательского checkout от root.")
        resolved = helper.resolve(strict=True)
        releases = self.current.parent / "releases"
        if not resolved.is_relative_to(releases) or not re.fullmatch(r"[0-9a-f]{32}", resolved.relative_to(releases).parts[0]):
            raise RuntimeError("Недоверенное расположение системного помощника")
        for path in (resolved, *resolved.parents):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Помощник и его каталоги должны принадлежать root без записи группы/остальных")
        return helper

    def helper_ready(self):
        try:
            self.trusted_helper()
            return True
        except (OSError, RuntimeError):
            return False

    def snapshot(self):
        unit_error = None
        try:
            text = self.command(["/usr/bin/systemctl", "show", SERVICE,
                                 "--property=LoadState,ActiveState,SubState,UnitFileState,StatusText"], timeout=12)
            props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
            if not props.get("LoadState") or not props.get("ActiveState"):
                unit_error = "systemd не вернул полное состояние сервиса"
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            props, unit_error = {}, str(error)
        installed = self.managed() and props.get("LoadState") == "loaded"
        pending, update_error = None, None
        try:
            updates = self.sync("status")
            pending = None if updates.get("pending_is_current") else updates.get("pending")
            revision = updates.get("current_revision")
        except (OSError, ValueError, RuntimeError) as error:
            update_error, revision = str(error), None
        auto_check = self.update_checker().status()
        versions = load_version_module().summary(self.workspace, self.current, self.base(), self.managed(),
                                                 auto_check.get("last_check"))
        return {"installed": installed, "unit_present": props.get("LoadState") != "not-found" if not unit_error else None,
                "active": props.get("ActiveState") == "active", "state": props.get("ActiveState", "unknown"),
                "enabled": props.get("UnitFileState") in ("enabled", "enabled-runtime"),
                "detail": props.get("StatusText") or props.get("SubState", ""),
                "helper_ready": self.helper_ready(), "profiles": self.profiles(),
                "config": self.loaded_config, "pending": pending, "revision": revision,
                "update_error": update_error, "hosts": self.hosts_status(),
                "auto_check": auto_check, "versions": versions,
                "status_supported": self.status_supported(), "service_report": self.status_report,
                "unit_error": unit_error, "diagnostics": self.diagnostic_report, "discord": self.discord_report,
                "tcp_timestamps_supported": self.tcp_timestamps_supported(), "tcp_timestamps": self.tcp_state}

    def tcp_timestamps_supported(self):
        try:
            return b"# tcp-timestamps-enable-v1:" in self.trusted_helper().read_bytes()
        except (OSError, RuntimeError):
            return False

    def read_tcp_timestamps(self):
        if not self.tcp_timestamps_supported():
            raise RuntimeError("Установленный помощник не поддерживает действие TCP timestamps. Автоматическое обновление не выполняется.")
        self.tcp_state = None
        self.tcp_state = self.call_helper("read-tcp-timestamps", {})
        return self.tcp_state

    def enable_tcp_timestamps(self, expected_value):
        if not self.tcp_timestamps_supported():
            raise RuntimeError("Установленный помощник не поддерживает действие TCP timestamps. Автоматическое обновление не выполняется.")
        self.tcp_state = None
        self.diagnostic_report = None
        result = self.call_helper("enable-tcp-timestamps", {"expected_value": expected_value})
        self.tcp_state = result["tcp_timestamps"]
        return result

    def discord_manager(self):
        return load_discord_cache_module().CacheManager(config=os.environ.get("XDG_CONFIG_HOME"))

    def scan_discord(self):
        self.discord_report = None
        self.discord_report = self.discord_manager().discover()
        return copy.deepcopy(self.discord_report)

    def clean_discord(self, instance, token):
        self.discord_report = None
        result = self.discord_manager().clean(instance, token)
        self.scan_discord()
        return result

    def diagnostics(self):
        self.diagnostic_report = None
        managed = self.managed()
        data = Path("/etc/zapret-discord-youtube") if managed else self.workspace
        self.diagnostic_report = load_diagnostics_module().collect(self.base(), data, managed=managed)
        return copy.deepcopy(self.diagnostic_report)

    def export_diagnostics(self, target):
        return write_diagnostics_report(self.diagnostic_report, target)

    def status_supported(self):
        try:
            # Read a marker in trusted, installed-only code; never execute a
            # checkout helper or send a new action to an older helper.
            return b"# read-only-service-status-v1:" in self.trusted_helper().read_bytes()
        except (OSError, RuntimeError):
            return False

    def read_status(self):
        if not self.status_supported():
            raise RuntimeError("Установленный помощник не поддерживает расширенный статус. Требуется согласованное обновление системной копии.")
        self.status_report = None
        self.status_report = self.call_helper("read-status", {})
        return self.status_report

    def update_checker(self):
        path = self.workspace / "src/lib/update_check.py"
        spec = importlib.util.spec_from_file_location("gui_update_check", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.UpdateCheck(self.base(), self.cache)

    def set_auto_check(self, enabled):
        return self.update_checker().set_enabled(enabled)

    def hosts_status(self):
        try:
            data = HOSTS.read_bytes()
        except OSError as error:
            return {"readable": False, "present": False, "entries": 0, "sha256": None,
                    "size": 0, "malformed": None, "error": f"Не удалось прочитать /etc/hosts: {error}"}
        result = load_hosts_module().status(data)
        result.update(readable=True, error=None)
        return result

    def service_action(self, action):
        if action not in ("start", "stop", "restart"):
            raise ValueError("Unsupported service action")
        if not self.managed():
            raise RuntimeError("Управляемый системный сервис не установлен")
        self.status_report = None
        self.command(["/usr/bin/systemctl", action, SERVICE])

    def call_helper(self, action, payload):
        helper = self.trusted_helper()
        if action not in ("read-config", "read-status", "read-tcp-timestamps"):
            self.status_report = None
        result = subprocess.run(["/usr/bin/pkexec", "/usr/bin/python3", "-I", str(helper), action],
                                input=json.dumps(payload), capture_output=True, text=True, check=False)
        if result.returncode in (126, 127):
            raise RuntimeError("Авторизация отменена или отклонена. Никакой успех не предполагается — обновите статус.")
        try:
            response = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError(result.stderr.strip() or "Помощник вернул некорректный ответ") from None
        if result.returncode or not response.get("ok"):
            raise RuntimeError(response.get("error") or result.stderr.strip() or "Административная операция не выполнена")
        return response["result"]

    def load_config(self):
        self.loaded_config = self.call_helper("read-config", {})
        return self.loaded_config

    def select_profile(self, strategy, expected_sha256):
        self.loaded_config = self.call_helper("select-profile", {"strategy": strategy, "expected_sha256": expected_sha256})
        return self.loaded_config

    def set_autostart(self, enabled):
        return self.call_helper("set-autostart", {"enabled": enabled})

    def set_game_filter(self, mode, tcp_ports, udp_ports, expected_sha256):
        self.loaded_config = self.call_helper("set-game-filter", {
            "mode": mode, "tcp_ports": tcp_ports, "udp_ports": udp_ports, "expected_sha256": expected_sha256})
        return self.loaded_config

    def set_ipset_mode(self, mode, expected_sha256, expected_list_sha256=None):
        self.loaded_config = self.call_helper("set-ipset-mode", {
            "mode": mode, "expected_sha256": expected_sha256, "expected_list_sha256": expected_list_sha256})
        return self.loaded_config

    def set_active_fakes(self, discord, gameudp, expected_sha256):
        self.loaded_config = self.call_helper("set-active-fakes", {
            "discord": discord, "gameudp": gameudp, "expected_sha256": expected_sha256})
        return self.loaded_config

    def fetch_ipset(self):
        output = self.command([sys.executable, str(self.workspace / "src/lib/strategy_sync.py"),
                               "fetch-ipset", "--cache", str(self.cache)])
        return json.loads(output)

    def update_ipset(self, staged, sha256, expected_sha256):
        self.loaded_config = self.call_helper("update-ipset", {
            "stage": staged, "sha256": sha256, "expected_sha256": expected_sha256})
        return self.loaded_config

    def fetch_hosts(self):
        output = self.command([sys.executable, str(self.workspace / "src/lib/strategy_sync.py"),
                               "fetch-hosts", "--cache", str(self.cache)])
        result = json.loads(output)
        result["preview"] = self.preview_hosts(result["staged"], result["sha256"])
        result["hosts"] = {"sha256": result["preview"]["expected_hosts_sha256"]}
        return result

    def preview_hosts(self, staged, sha256):
        module = load_hosts_module()
        data = Path(staged).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError("Скачанный hosts изменился после проверки")
        inspected = module.validate(data)
        current = HOSTS.read_bytes()
        preview = module.preview(current, inspected["data"])
        preview["expected_hosts_sha256"] = hashlib.sha256(current).hexdigest()
        return preview

    def update_hosts(self, staged, sha256, expected_hosts_sha256):
        return self.call_helper("update-hosts", {
            "stage": staged, "sha256": sha256, "expected_hosts_sha256": expected_hosts_sha256})

    @staticmethod
    def export_hosts(staged, sha256, target):
        data = Path(staged).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError("Скачанный hosts изменился после проверки")
        target = Path(target)
        if not target.is_absolute() or target.name in ("", ".", "..") or target.is_dir():
            raise ValueError("Выберите абсолютный путь файла для экспорта")
        if target.is_symlink():
            raise OSError("Экспорт в symlink не допускается")
        fd, temporary = tempfile.mkstemp(prefix=".hosts-export-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {"target": str(target), "size": len(data), "sha256": sha256}

    def sync(self, action):
        if action not in ("check", "prepare", "status"):
            raise ValueError("Unsupported sync action")
        output = self.command([sys.executable, str(self.workspace / "src/lib/strategy_sync.py"), action,
                               "--base", str(self.base()), "--cache", str(self.cache)])
        return json.loads(output)

    def check_update(self):
        return self.sync("check")

    def prepare_update(self):
        return self.sync("prepare")

    def apply_update(self, prepared):
        result = self.call_helper("apply-strategies", {"stage": prepared["stage"], "digest": prepared["digest"]})
        self.loaded_config = None
        return result

    def rollback(self):
        result = self.call_helper("rollback", {})
        self.loaded_config = None
        return result

    def logs(self):
        result = subprocess.run(["/usr/bin/journalctl", "-u", SERVICE, "-n", "100", "--no-pager", "-o", "short-iso"],
                                capture_output=True, text=True, check=False, timeout=15)
        return result.stdout + ("\n" + result.stderr if result.stderr else "")


class DemoBackend:
    """No subprocesses, filesystem access or privileged operations in this mode."""
    demo = True

    def __init__(self):
        self.active = False
        self.enabled = False
        self.strategy = "general.bat"
        self.revision = None
        self.pending = None
        self.auto_check_enabled = False
        self.last_update_check = None
        self.status_report = None
        self.diagnostic_report = None
        self.discord_report = None
        self.demo_discord_cleaned = False
        self.tcp_state = None
        self.demo_tcp_value = "0"
        self.hosts_data = b"127.0.0.1 localhost\n::1 localhost\n192.0.2.10 keep.example\n"
        self.demo_hosts_body = (b"203.0.113.10 github.com\n203.0.113.11 example.invalid\n"
                                b"2001:db8::10 example.invalid\n")
        self.demo_hosts_sha = hashlib.sha256(self.demo_hosts_body).hexdigest()
        self.loaded_config = {"config": {"strategy": self.strategy, "gamefiltertcp": "false", "gamefilterudp": "false"},
                              "sha256": "0" * 64, "capabilities": ["game-filter-ranges-v1", "ipset-mode-v1", "active-fakes-v1", "ipset-update-v1", "hosts-update-v1"],
                              "ipset": {"configured_mode": "legacy", "effective_mode": "loaded", "loaded_available": True,
                                        "loaded_source": "/demo-only/ipset-loaded.txt", "loaded_sha256": "c" * 64,
                                        "loaded_entries": 128, "warning": None},
                              "fakes_usage": {"discord": 3, "gameudp": 1},
                              "fakes": {"discord": self.demo_fakes("discord"), "gameudp": self.demo_fakes("gameudp")}}

    @staticmethod
    def demo_fakes(kind):
        available = [{"name": "stun.bin", "sha256": "a" * 64, "size": 100},
                     {"name": "quic_initial_dbankcloud_ru.bin", "sha256": "b" * 64, "size": 1357}]
        return {"configured": False, "override_sha256": None, "active_sha256": None,
                "matched_name": None, "warning": None, "available": available}

    def snapshot(self):
        return copy.deepcopy({"installed": True, "unit_present": True, "active": self.active,
                              "state": "active" if self.active else "inactive", "enabled": self.enabled,
                              "detail": "Симуляция — система не изменяется", "helper_ready": True,
                              "profiles": ["general.bat", "general_alt.bat", "general_fake_tls_auto.bat"],
                              "config": self.loaded_config,
                              "pending": self.pending if self.pending and self.pending["revision"] != self.revision else None,
                              "revision": self.revision,
                              "update_error": None, "hosts": self.hosts_status(),
                              "auto_check": {"enabled": self.auto_check_enabled,
                                             "active": self.auto_check_enabled,
                                             "next_check": "завтра, 00:15" if self.auto_check_enabled else None,
                                             "last_check": self.last_update_check,
                                             "preparation_enabled": False, "error": None},
                              "versions": self.versions(), "status_supported": True,
                              "service_report": self.status_report, "diagnostics": self.diagnostic_report,
                              "discord": self.discord_report, "tcp_timestamps_supported": True,
                              "tcp_timestamps": self.tcp_state})

    def read_tcp_timestamps(self):
        self.tcp_state = {"value": self.demo_tcp_value, "enabled": self.demo_tcp_value != "0",
                          "scope": "running-kernel", "checked_at": "демонстрация", "error": None}
        return copy.deepcopy(self.tcp_state)

    def enable_tcp_timestamps(self, expected_value):
        if expected_value != self.demo_tcp_value:
            raise ValueError("Изменился снимок TCP timestamps (демо)")
        changed = self.demo_tcp_value == "0"
        if changed:
            self.demo_tcp_value = "1"
        self.diagnostic_report = None
        return {"changed": changed, "tcp_timestamps": self.read_tcp_timestamps()}

    def scan_discord(self):
        self.discord_report = {"processes": {"state": "clear", "pids": []}, "instances": [
            {"id": "native-stable", "label": "Discord Stable · native (демо)", "path": "/demo-only/.config/discord",
             "files": 0 if self.demo_discord_cleaned else 12, "bytes": 0 if self.demo_discord_cleaned else 4096,
             "token": "e" * 64 if self.demo_discord_cleaned else "d" * 64, "error": None,
             "caches": [] if self.demo_discord_cleaned else [
                 {"path": "/demo-only/.config/discord/Cache", "files": 10, "bytes": 3072},
                 {"path": "/demo-only/.config/discord/GPUCache", "files": 2, "bytes": 1024}]}]}
        return copy.deepcopy(self.discord_report)

    def clean_discord(self, instance, token):
        item = self.scan_discord()["instances"][0]
        if instance != item["id"] or token != item["token"]:
            raise ValueError("Изменился подтверждённый демонстрационный кэш")
        self.demo_discord_cleaned = True
        self.scan_discord()
        return {"id": instance, "removed_files": item["files"], "removed_bytes": item["bytes"]}

    def diagnostics(self):
        self.diagnostic_report = {"schema": 1, "checked_at": "демонстрация", "checks": [
            {"id": "dependencies", "title": "Команды и backend", "state": "observed",
             "summary": "Демонстрация: зависимости не проверялись", "details": ["nft, curl, python3: имитация наличия"]},
            {"id": "proxy-environment", "title": "Прокси", "state": "warning",
             "summary": "Демонстрационный прокси; учётные данные скрыты", "details": ["https://proxy.example:8443"]},
            {"id": "nfqueue", "title": "NFQUEUE", "state": "unknown",
             "summary": "Имитация недоступных сведений", "details": []},
            {"id": "windows-only", "title": "Проверки Windows", "state": "not-applicable",
             "summary": "WinDivert/BFE не применяются в Linux", "details": []}],
            "limitations": ["Демонстрация: файлы и процессы системы не читались; исправления не выполнялись.",
                            "Системные настройки не определяют браузерный DoH."]}
        return copy.deepcopy(self.diagnostic_report)

    def export_diagnostics(self, target):
        return write_diagnostics_report(self.diagnostic_report, target)

    def read_status(self):
        state = "present" if self.active else "absent"
        rule = {"state": state, "recognized_rules": 3 if self.active else 0,
                "queues": [220] if self.active else [], "error": None}
        self.status_report = {
            "checked_at": "демонстрация", "expected_queue": 220,
            "unit": {"state": "known", "properties": {"LoadState": "loaded",
                "ActiveState": "active" if self.active else "inactive", "SubState": "running" if self.active else "dead",
                "MainPID": "1234" if self.active else "0", "Result": "success"}, "error": None},
            "process": {"state": state, "pids": [1235] if self.active else [],
                        "queues": [220] if self.active else [], "error": None},
            "engine": {"path": "/demo-only/nfqws", "sha256": "e" * 64, "size": 126976, "error": None},
            "config": {"strategy": self.strategy, "firewall_backend": "nftables"}, "config_error": None,
            "firewall": {"nftables": rule, "iptables": {"state": "absent", "recognized_rules": 0,
                         "queues": [], "error": None}}, "warnings": []}
        return copy.deepcopy(self.status_report)

    def versions(self):
        module = load_version_module()
        current = module.target_info({"revision": self.revision, "channel": "release", "tag": "1.10.4"})
        checked = module.target_info(self.last_update_check)
        app = {"version": "1.0.0-dev", "release": False, "error": None}
        relation = ("same" if current["revision"] == checked["revision"] else "different") if current["revision"] and checked["revision"] else "unknown"
        return {"running_app": app, "installed_app": app, "scope": "installed", "current": current,
                "checked": checked, "relation": relation, "source_url": module.SOURCE_URL}

    def set_auto_check(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("Нужно логическое значение переключателя")
        self.auto_check_enabled = enabled
        return self.snapshot()["auto_check"]

    def service_action(self, action):
        if action not in ("start", "stop", "restart"):
            raise ValueError("Unsupported service action")
        self.active = action != "stop"
        self.status_report = None

    def load_config(self):
        return copy.deepcopy(self.loaded_config)

    def select_profile(self, strategy, expected_sha256):
        if strategy not in self.snapshot()["profiles"]:
            raise ValueError("Unknown demo profile")
        self.strategy = strategy
        self.loaded_config["config"]["strategy"] = strategy
        return self.load_config()

    def set_autostart(self, enabled):
        self.enabled = enabled
        return {"enabled": enabled}

    def set_game_filter(self, mode, tcp_ports, udp_ports, expected_sha256):
        if mode not in ("disabled", "tcp", "udp", "all"):
            raise ValueError("Unknown demo game filter mode")
        self.loaded_config["config"].update({
            "gamefiltertcp": "true" if mode in ("tcp", "all") else "false",
            "gamefilterudp": "true" if mode in ("udp", "all") else "false",
            "gamefiltertcp_ports": tcp_ports, "gamefilterudp_ports": udp_ports})
        return self.load_config()

    def set_ipset_mode(self, mode, expected_sha256, expected_list_sha256=None):
        if mode not in ("loaded", "none", "any"):
            raise ValueError("Unknown demo IPSet mode")
        if mode == "loaded" and expected_list_sha256 != self.loaded_config["ipset"]["loaded_sha256"]:
            raise ValueError("Demo IPSet token changed")
        self.loaded_config["config"]["ipset_mode"] = mode
        self.loaded_config["ipset"].update(configured_mode=mode, effective_mode=mode)
        return self.load_config()

    def set_active_fakes(self, discord, gameudp, expected_sha256):
        for kind, value in (("discord", discord), ("gameudp", gameudp)):
            if value is not None and not (isinstance(value, str) and len(value) == 64):
                raise ValueError("Unknown demo fake token")
        names = {item["sha256"]: item["name"] for item in self.loaded_config["fakes"]["discord"]["available"]}
        for kind, value in (("discord", discord), ("gameudp", gameudp)):
            info = self.loaded_config["fakes"][kind]
            if value is None:
                info.update(configured=False, override_sha256=None, active_sha256=None, matched_name=None, warning=None)
            else:
                if value not in names:
                    raise ValueError("Demo fake token changed")
                info.update(configured=True, override_sha256=value, active_sha256=value,
                            matched_name=names[value], warning=None)
            self.loaded_config["config"]["fakediscord" if kind == "discord" else "fakegameudp"] = value or ""
        return self.load_config()

    def fetch_ipset(self):
        return {"staged": "/demo-only/ipset-service.txt", "sha256": "d" * 64, "entries": 5523,
                "size": 118542, "kind": "loaded",
                "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/…"}

    def hosts_status(self):
        result = load_hosts_module().status(self.hosts_data)
        result.update(readable=True, error=None)
        return result

    def fetch_hosts(self):
        module = load_hosts_module()
        return {"staged": "/demo-only/hosts-service.txt", "sha256": self.demo_hosts_sha,
                "entries": 3, "hostnames": 3, "size": len(self.demo_hosts_body), "kind": "hosts",
                "url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/…",
                "preview": module.preview(self.hosts_data, self.demo_hosts_body),
                "hosts": self.hosts_status()}

    def update_hosts(self, staged, sha256, expected_hosts_sha256):
        if sha256 != self.demo_hosts_sha:
            raise ValueError("Demo hosts token changed")
        if expected_hosts_sha256 != self.hosts_status()["sha256"]:
            raise ValueError("Demo hosts changed after preview")
        new = load_hosts_module().merge(self.hosts_data, self.demo_hosts_body)
        changed = new != self.hosts_data
        self.hosts_data = new
        return {"hosts": self.hosts_status(), "changed": changed, "backup": None}

    def export_hosts(self, staged, sha256, target):
        if sha256 != self.demo_hosts_sha:
            raise ValueError("Demo hosts token changed")
        target = Path(target)
        target.write_bytes(self.demo_hosts_body)
        return {"target": str(target), "size": len(self.demo_hosts_body), "sha256": sha256}

    def update_ipset(self, staged, sha256, expected_sha256):
        if sha256 != "d" * 64:
            raise ValueError("Demo IPSet token changed")
        ipset = self.loaded_config["ipset"]
        if ipset["loaded_sha256"] == sha256:
            return self.load_config()
        ipset.update(loaded_source="/demo-only/ipset-all.txt", loaded_sha256=sha256, loaded_entries=5523)
        return self.load_config()

    def check_update(self):
        self.last_update_check = {"status": "checked", "checked_at": "демонстрация",
                                  "tag": "1.10.4", "revision": "a" * 40, "channel": "release",
                                  "update_available": self.revision != "a" * 40}
        return copy.deepcopy(self.last_update_check)

    def prepare_update(self):
        self.pending = {"status": "prepared", "tag": "1.10.4 (демо)", "revision": "a" * 40,
                        "stage": "/demo-only/stage", "digest": "b" * 64, "strategies": 22}
        return copy.deepcopy(self.pending)

    def apply_update(self, prepared):
        self.revision = prepared["revision"]
        return {"applied": True}

    def rollback(self):
        self.revision = None
        return {"rolled_back": True}

    def logs(self):
        return "[ДЕМО] Интерфейс готов.\n[ДЕМО] Ни сервис, ни firewall, ни настройки не изменяются.\n"
