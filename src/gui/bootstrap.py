#!/usr/bin/env python3
"""Permanent packaged entry point for installing/removing the service.

No caller-supplied code, engine, source directory or target root is accepted.
The application package, including runtime/nfqws, is the trust boundary.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


APPLICATION = Path("/usr/lib/zapret-discord-youtube")
DEFAULT_STRATEGY = "general_alt12.bat"
ACTIONS = {"install-service": {"strategy", "start"}, "remove-service": {"purge"}}


def validate_payload(action, payload):
    if action not in ACTIONS or not isinstance(payload, dict) or set(payload) != ACTIONS[action]:
        raise ValueError("Неизвестная операция или поля запроса bootstrap")
    if action == "install-service":
        name = payload["strategy"]
        if name is not None and (not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bat", name)):
            raise ValueError("Некорректное имя стратегии")
        if type(payload["start"]) is not bool:
            raise ValueError("start должен быть boolean")
    elif type(payload["purge"]) is not bool:
        raise ValueError("purge должен быть boolean")


def verify_application():
    # Check the lexical path first; resolving it would hide a symlink entry.
    if Path(__file__).absolute() != APPLICATION / "src/gui/bootstrap.py":
        raise ValueError("Bootstrap разрешён только из постоянного пакета приложения")
    pending = [APPLICATION, *APPLICATION.parents]
    while pending:
        path = pending.pop()
        info = path.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError(f"Недоверенный файл пакета: {path}")
        if path == APPLICATION or path.is_relative_to(APPLICATION):
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
    return APPLICATION


def load_installer(application):
    path = application / "install.py"
    spec = importlib.util.spec_from_file_location("packaged_zapret_installer", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def dispatch(installer, application, action, payload):
    """Internal API; main fixes application/root before invoking this function."""
    validate_payload(action, payload)
    if action == "install-service":
        runtime = application / "runtime"
        installer.check_tree(runtime)
        installer.deploy(runtime, start=payload["start"],
                         initial_strategy=payload["strategy"] or DEFAULT_STRATEGY)
        return {"installed": True, "started": payload["start"]}
    installer.remove(purge=payload["purge"])
    return {"removed": True, "purged": payload["purge"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=tuple(ACTIONS))
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("Bootstrap требует авторизации администратора")
        application = verify_application()
        raw = sys.stdin.read(4097)
        if len(raw) > 4096:
            raise ValueError("Запрос bootstrap слишком велик")
        payload = json.loads(raw)
        validate_payload(args.action, payload)
        module = load_installer(application)

        class QuietSystemd(module.Systemd):
            def run(self, *args):
                result = subprocess.run(["/usr/bin/systemctl", *args],
                                        capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                                       or f"systemctl: код {result.returncode}")

        result = dispatch(module.Installer(systemd=QuietSystemd()), application, args.action, payload)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
