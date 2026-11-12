#!/usr/bin/env python3
"""Read-only active fake resolution. Never rewrite upstream or release bins."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


TYPES = ("discord", "gameudp")
ACTIVE_NAMES = {"discord": "ACTIVE_DISCORD_UDP.bin", "gameudp": "ACTIVE_GAME_UDP.bin"}
OPTION_KEYS = {"discord": ("--dpi-desync-fake-discord", "--dpi-desync-fake-stun"),
               "gameudp": ("--dpi-desync-fake-unknown-udp",)}
MAX_BYTES = 8 * 1024 * 1024
FAKE_FILE = re.compile(r'"?%BIN%([A-Za-z0-9_][A-Za-z0-9_.-]*\.bin)"?')
_TOKEN = re.compile(r'(?<![\w-])(--[a-z][a-z0-9-]*)=(?:"([^"\r\n]+)"|([^\s^"\r\n]+))')


def inspect_bin(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError(f"Недопустимый тип или размер fake-файла: {path}")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Превышен размер fake-файла")
    except (OSError, ValueError) as error:
        raise ValueError(f"Не удалось безопасно прочитать fake-файл: {path}: {error}") from error
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def available(repo):
    listing = []
    for entry in sorted((Path(repo) / "bin").iterdir(), key=lambda path: path.name):
        if not entry.name.endswith(".bin"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bin", entry.name):
            raise ValueError(f"Недопустимое имя fake-файла: {entry.name}")
        listing.append({"name": entry.name, **inspect_bin(entry)})
    return listing


def select_source(repo, sha256):
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError("Требуется корректный SHA-256 выбранного fake-файла")
    for item in available(repo):
        if item["sha256"] == sha256:
            return Path(repo) / "bin" / item["name"]
    raise ValueError("Выбранный fake-файл не найден в текущем релизе. Перечитайте настройки.")


def active_path(data_dir, kind):
    if kind not in TYPES:
        raise ValueError("Неизвестный тип активного fake")
    return Path(data_dir) / "fakes" / ACTIVE_NAMES[kind]


def verify_active(data_dir, kind, sha256):
    path = active_path(data_dir, kind)
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError(f"Некорректный SHA-256 активного fake {kind}")
    info = inspect_bin(path)
    if info["sha256"] != sha256:
        raise ValueError(f"Активный fake-файл {kind} изменился; ожидается SHA-256 {sha256}. "
                         "Выберите fake заново или верните версию по умолчанию.")
    return path


def rewrite(text, repo, data_dir, fakediscord, fakegameudp):
    """Substitute active fake files for affected option keys in a .bat payload."""
    selected = {}
    for kind, value in (("discord", fakediscord), ("gameudp", fakegameudp)):
        if value:
            selected[kind] = str(verify_active(data_dir, kind, value))
    if not selected:
        return text

    def replace(match):
        key, quoted, bare = match.groups()
        value = quoted if quoted is not None else bare or ""
        if not re.fullmatch(r"(?:\+[0-9]+)?@?(?:bin/%BIN%)?(?:bin/|%BIN%)[A-Za-z0-9_][A-Za-z0-9_.-]*\.bin", value):
            return match[0]
        for kind, keys in OPTION_KEYS.items():
            if key in keys and kind in selected:
                target = selected[kind]
                if any(char in target for char in ('"', "\r", "\n", "\x00")):
                    raise ValueError("Неподдерживаемый путь активного fake")
                return key + '="' + target + '"'
        return match[0]

    return _TOKEN.sub(replace, text)


def strategy_usage(text):
    """Count affected bin-valued tokens per type in a strategy payload."""
    usage = {kind: 0 for kind in TYPES}
    for match in _TOKEN.finditer(text):
        key, quoted, bare = match.groups()
        value = quoted if quoted is not None else bare or ""
        if not re.fullmatch(r"(?:\+[0-9]+)?@?(?:bin/%BIN%)?(?:bin/|%BIN%)[A-Za-z0-9_][A-Za-z0-9_.-]*\.bin", value):
            continue
        for kind, keys in OPTION_KEYS.items():
            if key in keys:
                usage[kind] += 1
    return usage


def describe(repo, data_dir, config):
    config = config or {}
    listing = available(repo)
    result = {}
    for kind in TYPES:
        key = "fakediscord" if kind == "discord" else "fakegameudp"
        value = config.get(key) or ""
        info = {"configured": bool(value), "override_sha256": value or None,
                "active_sha256": None, "matched_name": None, "warning": None}
        if value:
            try:
                path = verify_active(data_dir, kind, value)
                info["active_sha256"] = value
                for item in listing:
                    if item["sha256"] == value:
                        info["matched_name"] = item["name"]
                        break
                if info["matched_name"] is None:
                    info["warning"] = ("Активный fake-файл не совпадает ни с одним .bin текущего релиза "
                                       f"(SHA-256: {value}). Выберите fake заново или верните версию по умолчанию.")
            except ValueError as error:
                info["warning"] = str(error)
        result[kind] = {**info, "available": listing}
    return result


def resolve(repo, data_dir, config):
    """Strict resolution for runtimes: verify overrides, return active paths."""
    config = config or {}
    return {"discord": verify_active(data_dir, "discord", config["fakediscord"]) if config.get("fakediscord") else None,
            "gameudp": verify_active(data_dir, "gameudp", config["fakegameudp"]) if config.get("fakegameudp") else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("rewrite",))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--discord", default="")
    parser.add_argument("--gameudp", default="")
    args = parser.parse_args()
    try:
        text = sys.stdin.read(256 * 1024 + 1)
        if len(text) > 256 * 1024:
            raise ValueError("Слишком большой файл стратегии")
        print(rewrite(text, args.repo, args.data, args.discord, args.gameudp), end="")
        return 0
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
