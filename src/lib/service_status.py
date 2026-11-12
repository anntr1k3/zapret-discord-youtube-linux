"""Read-only observations of the managed systemd unit, its engine and rules.

No global process ownership guesses, engine execution, shell, or repairs.
All command arguments are fixed, regardless of the GUI request/config.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess


SERVICE = "zapret_discord_youtube.service"
QUEUE = 220
MAX_OUTPUT = 4 * 1024 * 1024


def read_limited(path, limit=65536):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Превышен лимит размера диагностических данных")
    return data


def command(runner, argv):
    result = runner(argv, capture_output=True, text=True, check=False, timeout=12,
                    env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        raise ValueError(result.stderr.strip()[:1000] or f"Код возврата: {result.returncode}")
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError("Слишком большой ответ диагностической команды")
    return result.stdout


def unit_status(runner):
    try:
        text = command(runner, ["/usr/bin/systemctl", "show", SERVICE,
            "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,Result,ExecMainStatus,UnitFileState"])
        props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        if props.get("LoadState") not in ("loaded", "not-found", "masked") or not props.get("ActiveState"):
            raise ValueError("Неполный ответ systemd")
        return {"state": "known", "properties": props, "error": None}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {"state": "unknown", "properties": {}, "error": str(error)}


def process_status(unit, release, proc, cgroup):
    result = {"state": "unknown", "pids": [], "queues": [], "error": None}
    if unit["state"] != "known":
        result["error"] = "Нет достоверных сведений systemd о cgroup сервиса"
        return result
    props = unit["properties"]
    group = props.get("ControlGroup", "")
    if not group and props.get("ActiveState") in ("inactive", "failed"):
        result["state"] = "absent"
        return result
    try:
        parts = PurePosixPath(group).parts
        if (not group.startswith("/") or len(parts) < 2 or ".." in parts
                or parts[-1] != SERVICE or any(ord(char) < 32 for char in group)):
            raise ValueError("Нельзя безопасно определить cgroup управляемого сервиса")
        pids = read_limited(Path(cgroup) / group.lstrip("/") / "cgroup.procs").decode("ascii").split()
        if len(pids) > 256 or any(not re.fullmatch(r"[1-9][0-9]{0,9}", pid) for pid in pids):
            raise ValueError("Некорректный или слишком большой список процессов cgroup")
        queues = set()
        errors = []
        for pid in sorted(set(pids), key=int):
            folder = Path(proc) / pid
            try:
                membership = read_limited(folder / "cgroup").decode("utf-8")
                if f"0::{group}" not in membership.splitlines():
                    raise ValueError(f"PID {pid}: принадлежность cgroup не подтверждена")
                executable = (folder / "exe").readlink()
                if executable != Path(release) / "nfqws":
                    if executable.name in ("nfqws", "nfqws (deleted)"):
                        raise ValueError(f"PID {pid}: движок не совпадает с текущим релизом")
                    continue
                args = read_limited(folder / "cmdline").split(b"\0")
                queue_args = [arg for arg in args if arg.startswith(b"--qnum=")]
                if len(queue_args) != 1 or not re.fullmatch(rb"--qnum=[0-9]{1,5}", queue_args[0]):
                    raise ValueError(f"PID {pid}: очередь nfqws не определена")
                queue = int(queue_args[0].split(b"=", 1)[1])
                if queue > 65535:
                    raise ValueError(f"PID {pid}: некорректная очередь nfqws")
                if ((folder / "exe").readlink() != executable
                        or read_limited(folder / "cgroup").decode("utf-8") != membership):
                    raise ValueError(f"PID {pid}: процесс изменился во время чтения")
                result["pids"].append(int(pid))
                queues.add(queue)
            except (OSError, ValueError) as error:
                errors.append(str(error))
        result.update(state="unknown" if errors else "present" if result["pids"] else "absent",
                      queues=sorted(queues), error="; ".join(errors) if errors else None)
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    return result


def nft_status(runner):
    result = {"state": "unknown", "recognized_rules": 0, "queues": [], "error": None}
    try:
        listing = json.loads(command(runner, ["/usr/sbin/nft", "-j", "list", "tables"]))
        entries = listing["nftables"]
        if not isinstance(entries, list):
            raise ValueError("Некорректный ответ nftables")
        if not any(entry.get("table", {}).get("family") == "inet" and
                   entry.get("table", {}).get("name") == "zapretunix" for entry in entries):
            result["state"] = "absent"
            return result
        table = json.loads(command(runner, ["/usr/sbin/nft", "-j", "list", "table", "inet", "zapretunix"]))
        queues = set()
        for entry in table["nftables"]:
            rule = entry.get("rule", {})
            if (rule.get("family") != "inet" or rule.get("table") != "zapretunix"
                    or rule.get("chain") not in ("pre", "post") or rule.get("comment") != "Added by zapret script"):
                continue
            found = [expr["queue"].get("num") for expr in rule.get("expr", []) if "queue" in expr]
            if found and all(type(number) is int and 0 <= number <= 65535 for number in found):
                queues.update(found)
                result["recognized_rules"] += 1
        result.update(state="present", queues=sorted(queues))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        result.update(state="unknown", error=str(error))
    return result


def iptables_status(runner):
    result = {"state": "unknown", "recognized_rules": 0, "queues": [], "error": None}
    try:
        present = False
        queues = set()
        for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
            text = command(runner, [binary, "-t", "mangle", "-S"])
            for line in text.splitlines():
                args = shlex.split(line)
                if args[:1] == ["-N"] and args[1:] in (["zapret"], ["reply"]):
                    present = True
                if (len(args) > 2 and args[:1] == ["-A"] and args[1] in ("zapret", "reply")
                        and "NFQUEUE" in args and "--queue-num" in args
                        and "connbytes" in args and "--queue-bypass" in args):
                    value = args[args.index("--queue-num") + 1]
                    if value.isdecimal() and 0 <= int(value) <= 65535:
                        queues.add(int(value))
                        result["recognized_rules"] += 1
        result.update(state="present" if present else "absent", queues=sorted(queues))
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
        result.update(state="unknown", error=str(error))
    return result


def collect(release, config=None, config_error=None, runner=subprocess.run,
            proc=Path("/proc"), cgroup=Path("/sys/fs/cgroup")):
    unit = unit_status(runner)
    process = process_status(unit, release, proc, cgroup)
    engine = {"path": str(Path(release) / "nfqws"), "sha256": None, "size": None, "error": None}
    try:
        data = read_limited(Path(release) / "nfqws", 16 * 1024 * 1024)
        engine.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    except (OSError, ValueError) as error:
        engine["error"] = str(error)
    firewall = {"nftables": nft_status(runner), "iptables": iptables_status(runner)}
    warnings = []
    if unit["properties"].get("ActiveState") == "active" and process["state"] != "present":
        warnings.append("systemd активен, но nfqws текущего релиза не подтверждён")
    if process["queues"] and process["queues"] != [QUEUE]:
        warnings.append("Очередь работающего nfqws отличается от ожидаемой 220")
    for name, info in firewall.items():
        if info["state"] == "present" and not info["recognized_rules"]:
            warnings.append(f"{name}: именованные ресурсы есть, но ожидаемые правила не распознаны")
        if info["queues"] and info["queues"] != [QUEUE]:
            warnings.append(f"{name}: очередь правил отличается от ожидаемой 220")
    if process["state"] == "present" and all(info["state"] == "absent" for info in firewall.values()):
        warnings.append("nfqws работает, но именованные правила обоих backend отсутствуют")
    if all(info["recognized_rules"] > 0 for info in firewall.values()):
        warnings.append("Обнаружены правила обоих backend; активный backend нельзя определить однозначно")
    return {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "unit": unit,
            "process": process, "engine": engine, "config": config or {}, "config_error": config_error,
            "expected_queue": QUEUE, "firewall": firewall, "warnings": warnings}
