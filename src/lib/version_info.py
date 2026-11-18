"""Read-only version metadata. No network, git commands or binary execution."""

import json
from pathlib import Path
import re
from urllib.parse import quote


SOURCE_URL = "https://github.com/Flowseal/zapret-discord-youtube"
MAX_METADATA = 4096


def read_metadata(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("Метаданные версии слишком велики")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Ожидается объект метаданных версии")
    return value


def application(base):
    result = {"version": None, "release": False, "error": None}
    try:
        data = read_metadata(Path(base) / "src/app-version.json")
        if (data.get("schema") != 1 or not isinstance(data.get("version"), str)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", data["version"])
                or type(data.get("release")) is not bool
                or (data["release"] and "-" in data["version"])):
            raise ValueError("Некорректные метаданные версии Linux-приложения")
        result.update(version=data["version"], release=data["release"])
    except (OSError, ValueError) as error:
        result["error"] = f"Версия Linux-приложения неизвестна: {error}"
    return result


def debian_version(base):
    metadata = application(base)
    if metadata["error"]:
        raise ValueError(metadata["error"])
    version = metadata["version"]
    if metadata["release"]:
        return version
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*", version):
        raise ValueError("Для Debian нужен стабильный номер версии или явный кандидат -rcN")
    return version.replace("-rc", "~rc", 1)


def unknown_target(error):
    return {"revision": None, "channel": None, "tag": None, "release_url": None,
            "commit_url": None, "source_url": SOURCE_URL, "error": error}


def target_info(data):
    if not isinstance(data, dict):
        return unknown_target("Нет метаданных набора Flowseal")
    revision, channel, tag = data.get("revision"), data.get("channel"), data.get("tag")
    if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or channel not in ("release", "main")
            or (channel == "main" and tag is not None)
            or (channel == "release" and (not isinstance(tag, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", tag) or tag in (".", "..")))):
        return unknown_target("Некорректные метаданные набора Flowseal")
    return {"revision": revision, "channel": channel, "tag": tag, "source_url": SOURCE_URL,
            "release_url": SOURCE_URL + "/releases/tag/" + quote(tag, safe="") if tag else None,
            "commit_url": SOURCE_URL + "/commit/" + revision, "error": None}


def flowseal(base):
    try:
        return target_info(read_metadata(Path(base) / "zapret-latest/.flowseal-sync.json"))
    except (OSError, ValueError) as error:
        return unknown_target(f"Версия набора Flowseal неизвестна: {error}")


def summary(workspace, current, base, managed, last_check, *, packaged=False):
    installed = flowseal(base)
    if isinstance(last_check, dict) and last_check.get("status") == "checked":
        checked = target_info(last_check)
    elif isinstance(last_check, dict) and last_check.get("status") == "error":
        checked = unknown_target("Проверка Flowseal не выполнена: " + str(last_check.get("message", "ошибка")))
    else:
        checked = unknown_target("Успешной проверки Flowseal пока нет")
    checked["checked_at"] = last_check.get("checked_at") if isinstance(last_check, dict) else None
    relation = "unknown"
    if installed["revision"] and checked["revision"]:
        relation = "same" if installed["revision"] == checked["revision"] else "different"
    return {"running_app": application(workspace), "installed_app": application(current) if managed else None,
            "scope": "installed" if managed else "package" if packaged else "checkout",
            "current": installed, "checked": checked,
            "relation": relation, "source_url": SOURCE_URL}
