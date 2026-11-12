#!/usr/bin/env python3
"""Read-only IPSet mode resolution. Never rewrite upstream or user lists."""

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import sys


MODES = ("legacy", "loaded", "none", "any")
MAX_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200000
DUMMY = ipaddress.ip_network("203.0.113.113/32")


def inspect_list(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError(f"Недопустимый тип или размер IPSet: {path}")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Превышен размер IPSet")
        count, only_dummy = 0, True
        for number, line in enumerate(data.decode("utf-8-sig").split("\n"), 1):
            value = line.split("#", 1)[0].strip(" \t\r")
            if not value:
                continue
            if count >= MAX_ENTRIES:
                raise ValueError("Слишком много записей IPSet")
            try:
                if "%" in value or ("/" in value and not re.fullmatch(r"[0-9]{1,3}", value.rsplit("/", 1)[1])):
                    raise ValueError("Only literal addresses and CIDR prefixes are supported")
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise ValueError(f"Некорректный IP/CIDR в {path}, строка {number}") from None
            only_dummy = only_dummy and network == DUMMY
            count += 1
        return {"path": path, "entries": count, "sha256": hashlib.sha256(data).hexdigest(),
                "kind": "any" if count == 0 else "none" if only_dummy else "loaded"}
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Не удалось безопасно прочитать IPSet: {path}: {error}") from error


def primary_list(repo, user_lists):
    override = Path(user_lists) / "ipset-all.txt"
    return override if os.path.lexists(override) else Path(repo) / "lists/ipset-all.txt"


def loaded_list(repo, user_lists, cache=None):
    cache = {} if cache is None else cache
    candidates = [Path(user_lists) / name for name in
                  ("ipset-all.txt", "ipset-loaded.txt", "ipset-all.txt.backup")]
    candidates += [Path(repo) / "lists" / name for name in ("ipset-all.txt", "ipset-all.txt.backup")]
    for path in candidates:
        if not os.path.lexists(path):
            continue
        if path not in cache:
            cache[path] = inspect_list(path)
        if cache[path]["kind"] == "loaded":
            return cache[path]
    raise ValueError("Загруженный IPSet не найден: пустой список и заглушка не считаются загруженным набором")


def resolve_list(mode, repo, user_lists):
    if mode not in MODES:
        raise ValueError("Неизвестный режим IPSet")
    if mode == "legacy":
        return primary_list(repo, user_lists)
    if mode == "loaded":
        return loaded_list(repo, user_lists)["path"]
    path = Path(repo).parent / "src/lib" / f"ipset-{mode}.txt"
    if inspect_list(path)["kind"] != mode:
        raise ValueError(f"Повреждён встроенный список режима IPSet {mode}")
    return path


def describe(mode, repo, user_lists):
    if mode not in MODES:
        raise ValueError("Неизвестный режим IPSet")
    info = {"configured_mode": mode, "effective_mode": mode, "loaded_available": False,
            "loaded_source": None, "loaded_sha256": None, "loaded_entries": 0, "warning": None}
    cache = {}
    if mode == "legacy":
        try:
            path = primary_list(repo, user_lists)
            cache[path] = inspect_list(path)
            info["effective_mode"] = cache[path]["kind"]
        except ValueError as error:
            info["effective_mode"], info["warning"] = "unknown", str(error)
    elif mode in ("none", "any"):
        try:
            resolve_list(mode, repo, user_lists)
        except ValueError as error:
            info["effective_mode"], info["warning"] = "unavailable", str(error)
    try:
        loaded = loaded_list(repo, user_lists, cache)
        info.update(loaded_available=True, loaded_source=str(loaded["path"]),
                    loaded_sha256=loaded["sha256"], loaded_entries=loaded["entries"])
    except ValueError as error:
        if mode == "loaded":
            info["effective_mode"] = "unavailable"
        info["warning"] = info["warning"] or str(error)
    return info


def rewrite_legacy(text, mode, repo, user_lists):
    if mode == "legacy":
        return text
    selected = str(resolve_list(mode, repo, user_lists))
    if any(char in selected for char in ('"', "\r", "\n", "\x00")):
        raise ValueError("Неподдерживаемый путь IPSet")
    allowed = {"lists/ipset-all.txt", str(Path(repo) / "lists/ipset-all.txt"),
               str(Path(user_lists) / "ipset-all.txt")}
    def replace(match):
        value = match[1] if match[1] is not None else match[2]
        return '--ipset="' + selected + '"' if value in allowed else match[0]
    return re.sub(r'(?<![\w-])--ipset=(?:"([^"\r\n]+)"|([^\s^"\r\n]+))', replace, text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("rewrite",))
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--user-lists", type=Path, required=True)
    args = parser.parse_args()
    try:
        text = sys.stdin.read(256 * 1024 + 1)
        if len(text) > 256 * 1024:
            raise ValueError("Слишком большой файл стратегии")
        print(rewrite_legacy(text, args.mode, args.repo, args.user_lists), end="")
        return 0
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
