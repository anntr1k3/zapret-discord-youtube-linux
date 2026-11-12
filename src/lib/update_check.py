"""Unprivileged, check-only user timer. Never prepares or applies strategies."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


SERVICE = "zapret-update-check.service"
TIMER = "zapret-update-check.timer"
HEADER = "# zapret-update-check-v1\n"


def quote(value):
    value = str(value)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Управляющие символы в путях таймера запрещены")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def atomic_write(path, data):
    fd, temporary = tempfile.mkstemp(prefix=".update-check-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class UpdateCheck:
    def __init__(self, base, cache, config=None, runner=subprocess.run):
        self.base, self.cache = Path(base).absolute(), Path(cache).absolute()
        self.config = Path(config or Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd/user")
        self.runner = runner

    def systemctl(self, *args, allow_missing=False):
        result = self.runner(["/usr/bin/systemctl", "--user", *args],
                             capture_output=True, text=True, check=False, timeout=20)
        props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if result.returncode and not (allow_missing and props.get("LoadState") == "not-found"):
            raise RuntimeError(result.stderr.strip() or "Не удалось связаться с пользовательским systemd")
        return props

    def inspect(self, name):
        return self.systemctl("show", name,
            "--property=LoadState,ActiveState,UnitFileState,NextElapseUSecRealtime,FragmentPath,DropInPaths,Result",
            allow_missing=True)

    def status(self):
        result = {"enabled": None, "active": None, "next_check": None,
                  "last_check": None, "preparation_enabled": None, "error": None, "execution_error": None}
        try:
            props = self.inspect(TIMER)
            state = props.get("UnitFileState", "")
            if props.get("LoadState") not in ("loaded", "not-found"):
                raise RuntimeError("Неизвестное или повреждённое состояние таймера проверки")
            result.update(enabled=state in ("enabled", "enabled-runtime"),
                          active=props.get("ActiveState") == "active",
                          next_check=props.get("NextElapseUSecRealtime") or None)
            service = self.inspect(SERVICE)
            if service.get("Result") not in (None, "", "success"):
                result["execution_error"] = "Последний запуск проверки в systemd завершился ошибкой: " + service["Result"]
            legacy = self.inspect("zapret-strategy-sync.timer")
            result["preparation_enabled"] = legacy.get("UnitFileState") in ("enabled", "enabled-runtime")
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            result["error"] = str(error)
        try:
            path = self.cache / "last-update-check.json"
            if path.exists():
                record = json.loads(path.read_text())
                if not isinstance(record, dict) or record.get("status") not in ("checked", "error"):
                    raise ValueError("Некорректный результат последней проверки")
                result["last_check"] = record
        except (OSError, ValueError) as error:
            result["error"] = (result["error"] + "\n" if result["error"] else "") + str(error)
        return result

    def unit_bytes(self):
        arguments = (self.base / "src/lib/strategy_sync.py", "check", "--base", self.base,
                     "--cache", self.cache, "--channel", "release")
        service = (HEADER + "[Unit]\nDescription=Check Flowseal updates (never prepare or apply)\n\n"
                   "[Service]\nType=oneshot\nNoNewPrivileges=true\nTimeoutStartSec=120\n"
                   "ExecStart=/usr/bin/python3 " + " ".join(quote(value) for value in arguments) + "\n")
        timer = (HEADER + "[Unit]\nDescription=Daily Flowseal update check\n\n"
                 "[Timer]\nOnCalendar=daily\nRandomizedDelaySec=30m\nPersistent=true\n\n"
                 "[Install]\nWantedBy=timers.target\n")
        return {SERVICE: service.encode(), TIMER: timer.encode()}

    def set_enabled(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("Нужно логическое значение переключателя")
        units = self.unit_bytes()
        old = {}
        for name in units:
            path = self.config / name
            if path.is_symlink():
                raise ValueError(f"Отказ менять symlink пользовательского unit: {path}")
            data = path.read_bytes() if path.exists() else None
            if data is not None and not data.startswith(HEADER.encode()):
                raise ValueError(f"Отказ менять посторонний пользовательский unit: {path}")
            old[name] = data
        previous = self.inspect(TIMER)
        for name, props in ((TIMER, previous), (SERVICE, self.inspect(SERVICE))):
            fragment = props.get("FragmentPath")
            if fragment and Path(fragment) != self.config / name:
                raise ValueError("Unit загружен из другого расположения; автоматическая правка запрещена")
            if props.get("DropInPaths") or (self.config / (name + ".d")).exists():
                raise ValueError("У unit есть дополнительные настройки; автоматическая правка запрещена")
        if previous.get("LoadState") not in ("loaded", "not-found"):
            raise RuntimeError("Неизвестное состояние таймера; изменения отменены")
        was_enabled = previous.get("UnitFileState") in ("enabled", "enabled-runtime")
        was_active = previous.get("ActiveState") == "active"
        self.config.mkdir(parents=True, exist_ok=True)
        try:
            if enabled:
                for name, data in units.items():
                    atomic_write(self.config / name, data)
                self.systemctl("daemon-reload")
                self.systemctl("enable", "--now", TIMER)
            else:
                self.systemctl("disable", "--now", TIMER)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            try:
                self.systemctl("disable", "--now", TIMER)
                for name, data in old.items():
                    path = self.config / name
                    if data is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, data)
                self.systemctl("daemon-reload")
                if was_enabled:
                    self.systemctl("enable", TIMER)
                if was_active:
                    self.systemctl("start", TIMER)
            except (OSError, RuntimeError, subprocess.SubprocessError) as recovery:
                raise RuntimeError(f"Ошибка переключения; восстановление также не удалось: {recovery}") from error
            raise
        return self.status()
