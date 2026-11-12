"""Strict parsing and safe merging for the managed /etc/hosts block.

The upstream service file is downloaded by the unprivileged GUI, but only the
privileged helper writes /etc/hosts.  This module has no side effects: both
sides use it to validate the same bytes.
"""

import difflib
import hashlib
import ipaddress
import re


BEGIN = b"# BEGIN zapret-discord-youtube managed hosts"
END = b"# END zapret-discord-youtube managed hosts"
MAX_BYTES = 1024 * 1024
MAX_LINES = 20000
MAX_HOSTNAMES = 50000
MAX_HOSTNAME = 253
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
PREVIEW_LINES = 400


def decode(data):
    if len(data) > MAX_BYTES:
        raise ValueError("Файл hosts слишком велик")
    if b"\x00" in data:
        raise ValueError("Файл hosts содержит NUL-байт")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("Файл hosts должен быть в UTF-8") from error
    for character in text:
        if ord(character) < 32 and character not in "\n\r\t":
            raise ValueError("Файл hosts содержит управляющие символы")
    return text


def normalize(data):
    """Return UTF-8 bytes with LF endings and exactly one final newline."""
    text = decode(data).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise ValueError("Слишком много строк в файле hosts")
    return ("\n".join(lines) + "\n").encode("utf-8") if lines else b""


def hostname_ok(name):
    if not name or len(name) > MAX_HOSTNAME or name.endswith("."):
        return False
    return all(LABEL.fullmatch(label) for label in name.split("."))


def mapping(line, number):
    """Parse one non-comment line, returning (address, hostnames) or None."""
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    parts = content.split()
    if len(parts) < 2:
        raise ValueError(f"Строка {number}: нужен IP-адрес и хотя бы одно имя")
    if len(parts) > 65:
        raise ValueError(f"Строка {number}: слишком много имён для одного адреса")
    try:
        address = ipaddress.ip_address(parts[0])
    except ValueError as error:
        raise ValueError(f"Строка {number}: некорректный IP-адрес {parts[0]!r}") from error
    names = parts[1:]
    for name in names:
        if not hostname_ok(name):
            raise ValueError(f"Строка {number}: некорректное имя {name!r}")
    return str(address), names


def validate(data):
    """Validate a downloaded hosts file and return normalized bytes and stats."""
    normalized = normalize(data)
    lines = normalized.decode("utf-8").splitlines() if normalized else []
    entries = hostnames = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped in (BEGIN.decode(), END.decode()):
            raise ValueError("Скачанный hosts содержит служебные маркеры")
        parsed = mapping(line, number)
        if parsed is not None:
            entries += 1
            hostnames += len(parsed[1])
    if not entries:
        raise ValueError("Скачанный hosts не содержит ни одной записи")
    if hostnames > MAX_HOSTNAMES:
        raise ValueError("Слишком много имён в скачанном hosts")
    return {"data": normalized, "sha256": hashlib.sha256(normalized).hexdigest(),
            "entries": entries, "hostnames": hostnames, "lines": len(lines),
            "size": len(normalized)}


def block_range(lines):
    """Return (start, end) indexes of the single managed block, or None."""
    starts = [index for index, line in enumerate(lines) if line.rstrip(b"\r\n").strip() == BEGIN]
    ends = [index for index, line in enumerate(lines) if line.rstrip(b"\r\n").strip() == END]
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] > ends[0]:
        raise ValueError("Маркеры управляемого блока hosts повреждены; автоматическая правка отменена")
    return starts[0], ends[0]


def block_body(data):
    """Return normalized body lines inside the managed block, or None."""
    lines = data.splitlines(keepends=True)
    span = block_range(lines)
    if span is None:
        return None
    body = b"".join(lines[span[0] + 1:span[1]])
    return normalize(body).decode("utf-8").splitlines() if body else []


def managed_entries(data):
    body = block_body(data)
    if body is None:
        return None
    count = 0
    for line in body:
        try:
            if mapping(line, 0) is not None:
                count += 1
        except ValueError:
            continue
    return count


def merge(current, body):
    """Replace or append the managed block, preserving all other bytes."""
    body = normalize(body)
    if not body:
        raise ValueError("Пустой управляемый блок hosts не допускается")
    block = BEGIN + b"\n" + body + END + b"\n"
    lines = current.splitlines(keepends=True)
    span = block_range(lines)
    if span is None:
        new = current
        if new and not new.endswith(b"\n"):
            new += b"\n"
        if new and not new.endswith(b"\n\n"):
            new += b"\n"
        return new + block
    return b"".join(lines[:span[0]]) + block + b"".join(lines[span[1] + 1:])


def status(data):
    """Lenient status for the GUI; malformed markers are reported, not raised."""
    result = {"present": False, "entries": 0, "sha256": hashlib.sha256(data).hexdigest(),
              "size": len(data), "malformed": None, "youtube": []}
    try:
        entries = managed_entries(data)
    except ValueError as error:
        result.update(present=True, malformed=str(error))
        return result
    if entries is not None:
        result.update(present=True, entries=entries)
    try:
        result["youtube"] = youtube_entries(data)
    except ValueError:
        pass
    return result


def external_conflicts(current, body):
    """Hostnames in the new block that already map elsewhere outside it."""
    lines = current.splitlines(keepends=True)
    span = block_range(lines)
    outside = (lines[:span[0]] + lines[span[1] + 1:]) if span else lines
    known = {}
    for number, line in enumerate(outside, 1):
        try:
            parsed = mapping(line.decode("utf-8", "replace"), number)
        except ValueError:
            continue
        if parsed is not None:
            address, names = parsed
            for name in names:
                known.setdefault(name.lower(), address)
    conflicts = []
    wanted = normalize(body).decode("utf-8").splitlines()
    for number, line in enumerate(wanted, 1):
        parsed = mapping(line, number)
        if parsed is None:
            continue
        address, names = parsed
        for name in names:
            other = known.get(name.lower())
            if other is not None and other != address:
                conflicts.append(f"{name}: сейчас {other}, в новом блоке {address}")
    return conflicts


def youtube_entries(data):
    found = []
    lines = data.splitlines(keepends=True)
    span = block_range(lines)
    outside = (lines[:span[0]] + lines[span[1] + 1:]) if span else lines
    for line in outside:
        try:
            parsed = mapping(line.decode("utf-8", "replace"), 0)
        except ValueError:
            continue
        if parsed is None:
            continue
        for name in parsed[1]:
            lowered = name.lower()
            if lowered in ("youtube.com", "youtu.be") or lowered.endswith(".youtube.com"):
                found.append(line.decode("utf-8", "replace").rstrip("\r\n"))
    return found


def _mapping_count(lines):
    count = 0
    for line in lines:
        try:
            if mapping(line, 0) is not None:
                count += 1
        except ValueError:
            continue
    return count


def preview(current, body):
    """Describe the exact change the helper would make."""
    body = normalize(body)
    old = block_body(current)
    lines = body.decode("utf-8").splitlines()
    old_lines = old or []
    diff = list(difflib.unified_diff(old_lines, lines, fromfile="текущий блок", tofile="новый блок", lineterm=""))
    if len(diff) > PREVIEW_LINES:
        diff = diff[:PREVIEW_LINES] + [f"… показаны первые {PREVIEW_LINES} строк различий"]
    new = merge(current, body)
    return {"present": old is not None, "changed": new != current,
            "current_entries": _mapping_count(old_lines),
            "entries": _mapping_count(lines),
            "added": sum(1 for line in diff if line.startswith("+") and not line.startswith("+++")),
            "removed": sum(1 for line in diff if line.startswith("-") and not line.startswith("---")),
            "diff": diff, "conflicts": external_conflicts(current, body),
            "youtube": youtube_entries(current), "sha256": hashlib.sha256(body).hexdigest()}
