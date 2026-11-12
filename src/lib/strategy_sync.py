#!/usr/bin/env python3
"""Flowseal data-only synchronization: check, prepare, approve separately."""

import argparse
import datetime
import email.utils
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile


REPOSITORY = "Flowseal/zapret-discord-youtube"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_FILES = 4096
TARGET_CACHE_TTL = 15 * 60
MAX_RATE_LIMIT_WAIT = 24 * 60 * 60
USER_LISTS = {"list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt"}
CATALOG = "strategies.json"
PROVENANCE = ".flowseal-sync.json"
TIMER_HEADER = "# Managed by zapret-strategy-sync-v1\n"
LIST_OPTIONS = {"--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude"}
FAKE_OPTIONS = {"--dpi-desync-fake-" + name for name in
                ("http", "tls", "unknown", "syndata", "quic", "wireguard", "dht", "discord", "stun", "unknown-udp")}
FAKE_OPTIONS |= {"--dpi-desync-split-seqovl-pattern", "--dpi-desync-fakedsplit-pattern", "--dpi-desync-udplen-pattern"}
DPI_OPTIONS = {"--dpi-desync"} | {"--dpi-desync-" + name for name in (
    "ttl", "ttl6", "autottl", "autottl6", "tcp-flags-set", "tcp-flags-unset", "fooling",
    "repeats", "skip-nosni", "split-pos", "split-seqovl", "fakedsplit-mod",
    "hostfakesplit-midhost", "hostfakesplit-mod", "ipfrag-pos-tcp", "ipfrag-pos-udp",
    "ts-increment", "badseq-increment", "badack-increment", "any-protocol", "fake-tcp-mod",
    "fake-tls-mod", "udplen-increment", "start", "cutoff")}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encode_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".sync-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encode_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_bytes(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".sync-", dir=Path(path).parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def valid_payload_name(name):
    if not isinstance(name, str) or "\\" in name or any(ord(c) < 32 for c in name):
        return False
    if "/" not in name:
        return bool(re.fullmatch(r"(?:general|discord)[A-Za-z0-9А-Яа-яЁё_. ()-]*\.bat", name, re.I))
    folder, separator, filename = name.partition("/")
    extension = "bin" if folder == "bin" else "txt"
    return (separator and folder in ("bin", "lists") and filename not in USER_LISTS
            and bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\." + extension, filename)))


def check_payload(files):
    if not files or len(files) > MAX_FILES or sum(len(data) for data in files.values()) > MAX_ARCHIVE:
        raise ValueError("Empty or oversized strategy payload")
    for name, data in files.items():
        if not valid_payload_name(name) or len(data) > MAX_FILE:
            raise ValueError(f"Unsupported or oversized data file: {name}")
        if name.startswith("lists/"):
            text = data.decode("utf-8-sig")
            if any(ord(c) < 32 and c not in "\r\n\t" for c in text):
                raise ValueError(f"List is not plain text: {name}")


def normalized_name(name):
    russian = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    latin = ("a b v g d e yo zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ya").split()
    name = "".join(dict(zip(russian, latin)).get(char, char) for char in name.lower())
    name = re.sub(r"[\s()]+", "_", name)
    name = re.sub(r"_+", "_", name).replace("_.bat", ".bat")
    if not re.fullmatch(r"[a-z0-9_][a-z0-9_.-]*\.bat", name):
        raise ValueError(f"Unsupported strategy filename: {name}")
    return name


def validate_ports(value):
    for item in value.split(","):
        if re.fullmatch(r"%(?:GameFilter|GameFilterTCP|GameFilterUDP)%", item):
            continue
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", item):
            raise ValueError(f"Unsupported ports: {value}")
        ends = [int(number) for number in item.split("-")]
        if not all(1 <= number <= 65535 for number in ends) or ends[-1] < ends[0]:
            raise ValueError(f"Invalid port range: {value}")


def validate_argument(token, files):
    key, separator, value = token.partition("=")
    if not separator or not value:
        raise ValueError(f"Unsupported argument: {token}")
    value = value.replace("%BIN%", "bin/").replace("%LISTS%", "lists/")
    if key in ("--filter-tcp", "--filter-udp"):
        validate_ports(value)
    elif key in LIST_OPTIONS:
        if not re.fullmatch(r"lists/[A-Za-z0-9_][A-Za-z0-9_.-]*\.txt", value):
            raise ValueError(f"List path is not allowed: {value}")
        if value not in files and value.split("/")[1] not in USER_LISTS:
            raise ValueError(f"Missing list: {value}")
    elif key in FAKE_OPTIONS:
        match = re.fullmatch(r"((?:\+[0-9]+)?@)?(bin/[A-Za-z0-9_][A-Za-z0-9_.-]*\.bin)", value)
        if match:
            if match[2] not in files:
                raise ValueError(f"Missing fake: {match[2]}")
        elif not re.fullmatch(r"0x[0-9a-fA-F]+|![+-]?[0-9]*", value):
            raise ValueError(f"Fake path/value is not allowed: {value}")
    elif (key in ("--filter-l3", "--filter-l7", "--ip-id", "--hostlist-domains", "--hostlist-exclude-domains")
          or key in DPI_OPTIONS):
        if not re.fullmatch(r"[A-Za-z0-9_.,:+!=~-]+", value):
            raise ValueError(f"Unsafe argument: {token}")
    else:
        raise ValueError(f"Unknown/global argument is not allowed: {token}")
    return key + "=" + value


def compile_payload(files):
    check_payload(files)
    result = {}
    for name, data in files.items():
        if not name.lower().endswith(".bat"):
            continue
        normalized = normalized_name(name)
        if normalized in result:
            raise ValueError(f"Strategy filename collision: {normalized}")
        text = data.decode("utf-8-sig").replace("\r", "")
        if len(data) > 256 * 1024:
            raise ValueError(f"Oversized strategy: {name}")
        starts = list(re.finditer(r"(?im)^\s*start\s+", text))
        if len(starts) != 1:
            raise ValueError(f"Expected exactly one winws start command: {name}")
        command = text[starts[0].start():].strip()
        match = re.match(r'start\s+"[^"\n]*"\s+/min\s+"%BIN%winws\.exe"\s+', command, re.I)
        if not match:
            raise ValueError(f"Unsupported Windows launch format: {name}")
        tail = re.sub(r"\^[ \t]*\n", " ", command[match.end():]).replace("^!", "!")
        if "^" in tail or "\x00" in tail:
            raise ValueError(f"Unsupported command escaping: {name}")
        tokens = shlex.split(tail, posix=True)
        if len(tokens) > 4096 or len(tokens) < 3:
            raise ValueError(f"Invalid argument count: {name}")
        tcp = tokens.pop(0)
        udp = tokens.pop(0)
        if not tcp.startswith("--wf-tcp=") or not udp.startswith("--wf-udp="):
            raise ValueError(f"Unsupported capture filters: {name}")
        tcp, udp = tcp.split("=", 1)[1], udp.split("=", 1)[1]
        validate_ports(tcp)
        validate_ports(udp)
        profiles, profile = [], []
        for token in tokens + ["--new"]:
            if token == "--new":
                if not profile or not any(arg.startswith("--filter-") for arg in profile):
                    raise ValueError(f"Empty or unfiltered profile: {name}")
                if sum(arg.startswith(("--filter-tcp=", "--filter-udp=")) for arg in profile) > 1:
                    raise ValueError(f"Multiple protocol filters are not supported: {name}")
                profiles.append(profile)
                profile = []
            else:
                profile.append(validate_argument(token, files))
        if len(profiles) > 64:
            raise ValueError(f"Too many profiles: {name}")
        result[normalized] = {"tcp_ports": tcp, "udp_ports": udp, "profiles": profiles}
    if not result:
        raise ValueError("No supported strategies found")
    return result


def validate_game_ports(value):
    if (not isinstance(value, str) or not 0 < len(value) <= 512
            or len(value.split(",")) > 128
            or not re.fullmatch(r"[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?(?:,[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?)*", value)):
        raise ValueError("Порты Game Filter: используйте числа 1–65535 и диапазоны через запятую, без пробелов")
    try:
        validate_ports(value)
    except ValueError:
        raise ValueError("Порты Game Filter должны быть в пределах 1–65535, начало диапазона не больше конца") from None


def expanded_ports(value, tcp, udp, tcp_range="1024-65535", udp_range="1024-65535"):
    mapping = {"GameFilter": tcp_range if tcp else udp_range if udp else None,
               "GameFilterTCP": tcp_range if tcp else None, "GameFilterUDP": udp_range if udp else None}
    parts = []
    for item in value.split(","):
        match = re.fullmatch(r"%([A-Za-z]+)%", item)
        if match:
            if mapping[match[1]]:
                parts.append(mapping[match[1]])
        else:
            parts.append(item)
    return ",".join(parts)


def load_ipset_mode():
    path = Path(__file__).with_name("ipset_mode.py")
    spec = importlib.util.spec_from_file_location("runtime_ipset_mode", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_hosts_file():
    path = Path(__file__).with_name("hosts_file.py")
    spec = importlib.util.spec_from_file_location("runtime_hosts_file", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def materialize(strategy, repo, user_lists, tcp, udp, tcp_range="1024-65535", udp_range="1024-65535",
                ipset_mode="legacy", fakes=None):
    validate_game_ports(tcp_range)
    validate_game_ports(udp_range)
    repo, user_lists = Path(repo).absolute(), Path(user_lists).absolute()
    if ipset_mode not in ("legacy", "loaded", "none", "any"):
        raise ValueError("Неизвестный режим IPSet")
    selected_ipset = load_ipset_mode().resolve_list(ipset_mode, repo, user_lists) if ipset_mode != "legacy" else None
    fakes = fakes or {}
    active_fakes = {"--dpi-desync-fake-discord": fakes.get("discord"),
                    "--dpi-desync-fake-stun": fakes.get("discord"),
                    "--dpi-desync-fake-unknown-udp": fakes.get("gameudp")}
    argv = []
    for profile in strategy["profiles"]:
        current = []
        for token in profile:
            key, value = token.split("=", 1)
            if key in ("--filter-tcp", "--filter-udp"):
                value = expanded_ports(value, tcp, udp, tcp_range, udp_range)
                if not value:
                    break  # Entire profile belongs to a disabled game filter.
            elif key in LIST_OPTIONS:
                filename = value.split("/")[1]
                if key == "--ipset" and filename == "ipset-all.txt" and selected_ipset is not None:
                    value = str(selected_ipset)
                else:
                    value = str(user_lists / filename) if (user_lists / filename).is_file() else str(repo / value)
            elif key in FAKE_OPTIONS:
                match = re.fullmatch(r"((?:\+[0-9]+)?@)?(bin/.+)", value)
                if match:
                    if key in active_fakes and active_fakes[key] is not None:
                        value = (match[1] or "") + str(active_fakes[key])
                    else:
                        value = (match[1] or "") + str(repo / match[2])
            current.append(key + "=" + value)
        else:
            if argv:
                argv.append("--new")
            argv.extend(current)
    if not argv:
        raise ValueError("No enabled profiles remain")
    return {"tcp_ports": expanded_ports(strategy["tcp_ports"], tcp, udp, tcp_range, udp_range),
            "udp_ports": expanded_ports(strategy["udp_ports"], tcp, udp, tcp_range, udp_range), "argv": argv}


def write_catalog(repo, files, compiled, provenance):
    repo.mkdir(parents=True)
    for name, data in files.items():
        if name.lower().endswith(".bat"):
            continue
        path = repo / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
    (repo / "lists").mkdir(exist_ok=True)
    for name in USER_LISTS:
        (repo / "lists" / name).write_bytes(b"")
    for name in compiled:
        (repo / name).write_text(":: Data-only synchronized strategy; parsed from strategies.json\n")
    atomic_json(repo / CATALOG, {"schema": 1, "strategies": compiled})
    atomic_json(repo / PROVENANCE, provenance)


def validate_catalog(binary, repo, compiled, user_lists=None, private=False,
                     tcp_range="1024-65535", udp_range="1024-65535", ipset_mode="legacy", fakes=None):
    with tempfile.TemporaryDirectory(prefix=".dry-run-", dir=repo.parent) as temporary:
        placeholders = Path(temporary)
        for name in USER_LISTS:
            (placeholders / name).write_bytes(b"")
        lists = user_lists or placeholders
        for name, strategy in compiled.items():
            for tcp, udp in ((False, False), (True, False), (False, True), (True, True)):
                arguments = materialize(strategy, repo, lists, tcp, udp, tcp_range, udp_range, ipset_mode, fakes)
                # Root's private snapshot must stay 0700. Public validation below
                # uses nfqws's normal UID behavior and is mandatory before activation.
                uid = ["--uid=0:0"] if private and os.geteuid() == 0 else []
                result = subprocess.run([str(binary), "--dry-run", "--qnum=220",
                                         "--dpi-desync-fwmark=0x40000000", *uid, *arguments["argv"]], cwd=repo,
                                        capture_output=True, text=True, timeout=20, check=False)
                if result.returncode:
                    detail = (result.stderr or result.stdout)[-2000:]
                    raise ValueError(f"nfqws rejected {name} (TCP={tcp}, UDP={udp}): {detail}")


def read_archive(data):
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Archive is too large")
    files, seen, root, total = {}, set(), None, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("Too many archive entries")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError("Unsafe archive path/type")
            if not path.parts:
                raise ValueError("Empty archive path")
            root = root or path.parts[0]
            canonical = str(path)
            if path.parts[0] != root or canonical in seen:
                raise ValueError("Duplicate path or multiple archive roots")
            seen.add(canonical)
            total += entry.file_size
            if entry.file_size > MAX_FILE or total > MAX_ARCHIVE:
                raise ValueError("Unpacked archive exceeds size limits")
            name = str(PurePosixPath(*path.parts[1:]))
            if not entry.is_dir() and valid_payload_name(name):
                files[name] = archive.read(entry)
    check_payload(files)
    return files


def allowed_url(url):
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme == "https" and parsed.hostname == "raw.githubusercontent.com"
            and parsed.port in (None, 443) and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and "/.." not in parsed.path):
        # Raw content is allowed only inside the fixed upstream repository.
        return parsed.path.startswith(f"/{REPOSITORY}/")
    return (parsed.scheme == "https" and parsed.hostname in {"api.github.com", "codeload.github.com"}
            and parsed.port in (None, 443) and parsed.username is None and parsed.password is None)


class UpstreamRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if not allowed_url(new_url):
            raise ValueError("Unexpected upstream redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


class GitHubRateLimitError(ValueError):
    def __init__(self, retry_at):
        self.retry_at = retry_at
        when = datetime.datetime.fromtimestamp(retry_at, datetime.timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")
        super().__init__(f"GitHub временно ограничил запросы: превышен лимит API. "
                         f"Повторите проверку не раньше {when}. Лимит может быть общим для вашего внешнего IP. "
                         "Работающий сервис не изменён; ранее подготовленный пакет сохранён.")


def rate_limit_error(error):
    if error.code not in (403, 429):
        return None
    headers = error.headers or {}
    body = error.read(8192).decode("utf-8", errors="replace") if error.fp is not None else ""
    if (error.code != 429 and headers.get("X-RateLimit-Remaining") != "0"
            and "rate limit" not in (str(error.reason) + body).lower()):
        return None
    now = time.time()
    deadlines = []
    try:
        deadlines.append(float(int(headers["X-RateLimit-Reset"])))
    except (KeyError, ValueError, TypeError, OverflowError):
        pass
    retry = headers.get("Retry-After")
    if retry:
        try:
            deadlines.append(now + int(retry))
        except (ValueError, TypeError, OverflowError):
            try:
                deadlines.append(email.utils.parsedate_to_datetime(retry).timestamp())
            except (ValueError, TypeError, OverflowError):
                pass
    future = [value for value in deadlines if value > now]
    deadline = min(max(future) if future else now + 60, now + MAX_RATE_LIMIT_WAIT)
    return GitHubRateLimitError(deadline)


def fetch_bytes(url, limit=MAX_ARCHIVE):
    if not allowed_url(url):
        raise ValueError("Only the fixed upstream HTTPS endpoints are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "zapret-linux-strategy-sync/1"})
    opener = urllib.request.build_opener(UpstreamRedirects())
    for attempt in range(3):
        try:
            with opener.open(request, timeout=40) as response:
                if not allowed_url(response.geturl()):
                    raise ValueError("Unexpected upstream redirect")
                data = response.read(limit + 1)
            break
        except (urllib.error.URLError, TimeoutError):
            error = sys.exc_info()[1]
            if isinstance(error, urllib.error.HTTPError):
                limited = rate_limit_error(error)
                if limited is not None:
                    raise limited from error
            if attempt == 2 or (isinstance(error, urllib.error.HTTPError) and error.code not in (500, 502, 503, 504)):
                raise
            time.sleep(0.5 * (attempt + 1))
    if len(data) > limit:
        raise ValueError("Upstream response exceeds size limit")
    return data


def fetch_json(url):
    return json.loads(fetch_bytes(url, MAX_MANIFEST))


IPSET_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt"
HOSTS_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"


def fetch_hosts(cache):
    """Download the upstream hosts list and stage normalized, validated bytes.

    Nothing is applied here; the privileged helper writes only its managed
    block into /etc/hosts after confirmation and a second validation.
    """
    hosts = load_hosts_file()
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = fetch_bytes(HOSTS_URL, limit=hosts.MAX_BYTES)
    inspected = hosts.validate(data)
    staged = cache / "hosts-service.txt"
    atomic_bytes(staged, inspected["data"])
    return {"staged": str(staged), "sha256": inspected["sha256"], "entries": inspected["entries"],
            "hostnames": inspected["hostnames"], "size": inspected["size"], "kind": "hosts",
            "url": HOSTS_URL}


def fetch_ipset(cache):
    """Download the upstream service IPSet and stage a validated copy.

    The list itself is never applied here; the privileged helper writes it
    only after the user confirms and re-validates the staged bytes.
    """
    ipset = load_ipset_mode()
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = fetch_bytes(IPSET_URL, limit=ipset.MAX_BYTES)
    fd, temporary = tempfile.mkstemp(prefix=".ipset-download-", dir=cache)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        inspected = ipset.inspect_list(Path(temporary))
        if inspected["kind"] != "loaded":
            raise ValueError("Скачанный список пуст или является заглушкой; обновление IPSet отменено")
    finally:
        Path(temporary).unlink(missing_ok=True)
    staged = cache / "ipset-service.txt"
    atomic_bytes(staged, data)
    return {"staged": str(staged), "sha256": inspected["sha256"], "entries": inspected["entries"],
            "size": len(data), "kind": inspected["kind"], "url": IPSET_URL}


def resolve_target(channel):
    if channel not in ("release", "main"):
        raise ValueError("Unknown channel")
    tag = None
    ref = "main"
    if channel == "release":
        tag = fetch_json(f"https://api.github.com/repos/{REPOSITORY}/releases/latest")["tag_name"]
        if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", tag):
            raise ValueError("Invalid upstream release tag")
        ref = tag
    revision = fetch_json(f"https://api.github.com/repos/{REPOSITORY}/commits/{ref}")["sha"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid upstream commit")
    return {"revision": revision, "channel": channel, "tag": tag}


def read_small_json(path):
    try:
        with path.open("rb") as stream:
            data = stream.read(4097)
        value = json.loads(data) if len(data) <= 4096 else None
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def valid_target(target, channel):
    return (isinstance(target, dict) and set(target) == {"revision", "channel", "tag"}
            and target["channel"] == channel and isinstance(target["revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", target["revision"])
            and ((channel == "main" and target["tag"] is None)
                 or (channel == "release" and isinstance(target["tag"], str)
                     and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", target["tag"]))))


def cached_target(channel, cache):
    """Share short-lived resolution between check/prepare; never serve stale data."""
    if channel not in ("release", "main"):
        raise ValueError("Unknown channel")
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (cache / ".target.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Проверка Flowseal уже выполняется в другом окне или таймере") from error
        now = time.time()
        path = cache / f"target-{channel}.json"
        cached = read_small_json(path)
        checked_at = cached.get("checked_at")
        if (cached.get("schema") == 1 and cached.get("repository") == REPOSITORY
                and type(checked_at) in (int, float) and 0 <= now - checked_at < TARGET_CACHE_TTL
                and valid_target(cached.get("target"), channel)):
            return cached["target"]
        limited = read_small_json(cache / "github-rate-limit.json")
        retry_at = limited.get("retry_at")
        if (limited.get("schema") == 1 and limited.get("repository") == REPOSITORY
                and type(retry_at) in (int, float) and now < retry_at <= now + MAX_RATE_LIMIT_WAIT):
            raise GitHubRateLimitError(retry_at)
        try:
            target = resolve_target(channel)
        except GitHubRateLimitError as error:
            atomic_json(cache / "github-rate-limit.json", {"schema": 1, "repository": REPOSITORY,
                        "retry_at": error.retry_at})
            raise
        if not valid_target(target, channel):
            raise ValueError("Invalid upstream target")
        atomic_json(path, {"schema": 1, "repository": REPOSITORY, "checked_at": now, "target": target})
        return target


def write_stage(directory, files, target):
    check_payload(files)
    directory.mkdir(parents=True)
    hashes = {}
    for name, data in files.items():
        path = directory / "payload" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        hashes[name] = sha256(data)
    manifest = {"schema": 1, "repository": REPOSITORY, **target, "files": hashes}
    encoded = encode_json(manifest)
    (directory / "manifest.json").write_bytes(encoded)
    return manifest, sha256(encoded)


def read_regular_at(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f"Invalid staged file: {name}")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Staged file grew beyond limit")
        return data
    finally:
        os.close(fd)


def load_stage(directory, digest):
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("An explicit SHA-256 stage digest is required")
    try:
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with os.scandir(root) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 2:
                        raise ValueError("Unexpected stage contents")
            if set(names) != {"manifest.json", "payload"}:
                raise ValueError("Unexpected stage contents")
            encoded = read_regular_at(root, "manifest.json", MAX_MANIFEST)
            if sha256(encoded) != digest:
                raise ValueError("Stage manifest changed after approval")
            manifest = json.loads(encoded)
            if (not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("repository") != REPOSITORY
                    or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("revision", "")))
                    or manifest.get("channel") not in ("release", "main")
                    or set(manifest) != {"schema", "repository", "revision", "channel", "tag", "files"}
                    or (manifest["tag"] is not None and (not isinstance(manifest["tag"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", manifest["tag"])))):
                raise ValueError("Invalid stage metadata")
            hashes = manifest.get("files")
            if (not isinstance(hashes, dict) or not 0 < len(hashes) <= MAX_FILES
                    or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values())):
                raise ValueError("Invalid stage inventory")
            files = {}
            payload_fd = os.open("payload", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                def collect(fd, prefix=""):
                    with os.scandir(fd) as entries:
                        names = []
                        for entry in entries:
                            names.append(entry.name)
                            if len(names) > MAX_FILES:
                                raise ValueError("Too many staged entries")
                    for name in names:
                        relative = prefix + name
                        if not prefix and name in ("bin", "lists"):
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            try:
                                collect(child, name + "/")
                            finally:
                                os.close(child)
                        else:
                            if relative not in hashes or not valid_payload_name(relative):
                                raise ValueError("Unexpected staged data file")
                            data = read_regular_at(fd, name, MAX_FILE)
                            if sha256(data) != hashes[relative]:
                                raise ValueError(f"Staged file changed: {relative}")
                            files[relative] = data
                            if sum(map(len, files.values())) > MAX_ARCHIVE:
                                raise ValueError("Stage exceeds size limit")
                collect(payload_fd)
            finally:
                os.close(payload_fd)
            if set(files) != set(hashes):
                raise ValueError("Incomplete stage")
            check_payload(files)
            return manifest, files
        finally:
            os.close(root)
    except OSError as error:
        raise ValueError(f"Cannot safely read stage: {error}") from error


def installed_revision(base):
    path = base / "zapret-latest" / PROVENANCE
    return json.loads(path.read_text()).get("revision") if path.is_file() else None


def prepare(base, cache, target=None, files=None):
    base, cache = Path(base).resolve(strict=True), Path(cache).absolute()
    binary = base / "nfqws"
    if not binary.is_file():
        raise ValueError("Prepare requires an existing trusted nfqws; it will not download/upgrade the engine")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (cache / ".prepare.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another preparation is in progress") from error
        target = target or cached_target("release", cache)
        binary_hash = sha256(binary.read_bytes())
        parser_hash = sha256(Path(__file__).read_bytes())
        if installed_revision(base) == target["revision"]:
            return {"status": "up-to-date", **target}
        pending = cache / "pending.json"
        if pending.is_file():
            try:
                previous = json.loads(pending.read_text())
                if (previous.get("revision") == target["revision"] and previous.get("binary_sha256") == binary_hash
                        and previous.get("parser_sha256") == parser_hash and previous.get("channel") == target["channel"]
                        and previous.get("tag") == target.get("tag")):
                    load_stage(Path(previous["stage"]), previous["digest"])
                    return previous
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                # Leave damaged stages available for inspection; publish a new one.
                pass
        files = files if files is not None else read_archive(fetch_bytes(f'https://codeload.github.com/{REPOSITORY}/zip/{target["revision"]}'))
        compiled = compile_payload(files)
        stages = cache / "stages"
        stages.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=cache) as temporary:
            work = Path(temporary)
            repo = work / "catalog"
            write_catalog(repo, files, compiled, target)
            validate_catalog(binary, repo, compiled)
            manifest, digest = write_stage(work / "stage", files, target)
            destination = stages / (target["revision"][:12] + "-" + uuid.uuid4().hex[:12])
            os.rename(work / "stage", destination)
        result = {"status": "prepared", **target, "binary_sha256": binary_hash, "parser_sha256": parser_hash,
                  "stage": str(destination), "digest": digest, "strategies": len(compiled),
                  "prepared_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        atomic_json(pending, result)
        return result


def unit_quote(value):
    value = str(value)
    if any(ord(c) < 32 for c in value):
        raise ValueError("Control characters are not allowed in timer paths")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def install_timer(base, cache, config, channel):
    module = Path(__file__).absolute()
    service = TIMER_HEADER + "[Unit]\nDescription=Prepare Flowseal strategy updates (never apply)\n\n[Service]\nType=oneshot\nNoNewPrivileges=true\nExecStart=/usr/bin/python3 "
    service += " ".join(unit_quote(value) for value in (module, "prepare", "--base", base, "--cache", cache, "--channel", channel)) + "\n"
    timer = TIMER_HEADER + "[Unit]\nDescription=Daily Flowseal strategy preparation\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=30m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    config.mkdir(parents=True, exist_ok=True)
    units = {"zapret-strategy-sync.service": service, "zapret-strategy-sync.timer": timer}
    for name in units:
        path = config / name
        if path.is_symlink() or (path.exists() and not path.read_text().startswith(TIMER_HEADER)):
            raise ValueError(f"Refusing to overwrite an unrelated user unit: {path}")
    for name, content in units.items():
        (config / name).write_text(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "prepare", "status", "timer-install", "runtime", "fetch-ipset", "fetch-hosts"))
    current = Path("/opt/zapret-discord-youtube/current")
    default_base = current if (current / ".system-install").is_file() else Path(__file__).resolve().parents[2]
    parser.add_argument("--base", type=Path, default=default_base)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "zapret-strategy-sync")
    parser.add_argument("--channel", choices=("release", "main"), default="release")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--strategy")
    parser.add_argument("--user-lists", type=Path)
    parser.add_argument("--gamefiltertcp", choices=("true", "false"), default="false")
    parser.add_argument("--gamefilterudp", choices=("true", "false"), default="false")
    parser.add_argument("--gamefiltertcp-ports", default="1024-65535")
    parser.add_argument("--gamefilterudp-ports", default="1024-65535")
    parser.add_argument("--ipset-mode", choices=("legacy", "loaded", "none", "any"), default="legacy")
    parser.add_argument("--fake-discord", default=None)
    parser.add_argument("--fake-gameudp", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "runtime":
            if args.repo is None or args.user_lists is None or args.strategy is None:
                raise ValueError("Runtime requires repo, strategy and user-lists")
            catalog = json.loads((args.repo / CATALOG).read_text())
            if catalog.get("schema") != 1:
                raise ValueError("Unknown strategy catalog schema")
            value = materialize(catalog["strategies"][args.strategy], args.repo, args.user_lists,
                                 args.gamefiltertcp == "true", args.gamefilterudp == "true",
                                 args.gamefiltertcp_ports, args.gamefilterudp_ports, args.ipset_mode,
                                 {"discord": args.fake_discord, "gameudp": args.fake_gameudp})
            for token in [value["tcp_ports"], value["udp_ports"], *value["argv"]]:
                if "\n" in token or "\r" in token:
                    raise ValueError("Line breaks in arguments are not supported")
                print(token)
            return 0
        if args.command in ("prepare", "timer-install") and os.geteuid() == 0:
            raise ValueError("Run preparation/timer setup as your ordinary desktop user, not sudo")
        if args.command == "fetch-ipset" and os.geteuid() == 0:
            raise ValueError("Run the IPSet download as your ordinary desktop user, not sudo")
        if args.command == "fetch-hosts" and os.geteuid() == 0:
            raise ValueError("Run the hosts download as your ordinary desktop user, not sudo")
        if args.command == "check":
            target = cached_target(args.channel, args.cache)
            result = {**target, "current_revision": installed_revision(args.base)}
            result["update_available"] = target["revision"] != result["current_revision"]
            result.update(status="checked", checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            args.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_json(args.cache / "last-update-check.json", result)
        elif args.command == "fetch-ipset":
            result = fetch_ipset(args.cache)
        elif args.command == "fetch-hosts":
            result = fetch_hosts(args.cache)
        elif args.command == "prepare":
            result = prepare(args.base, args.cache, cached_target(args.channel, args.cache))
            atomic_json(args.cache / "last-check.json", result)
        elif args.command == "status":
            path = args.cache / "pending.json"
            revision = installed_revision(args.base)
            pending = json.loads(path.read_text()) if path.is_file() else None
            result = {"current_revision": revision, "pending": pending,
                      "pending_is_current": bool(revision and pending and pending.get("revision") == revision),
                      "last_check": json.loads((args.cache / "last-check.json").read_text())
                      if (args.cache / "last-check.json").is_file() else None}
        else:
            config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd/user"
            install_timer(args.base, args.cache, config, args.channel)
            result = {"timer_files": str(config), "enabled": False,
                      "next": "systemctl --user daemon-reload; systemctl --user enable --now zapret-strategy-sync.timer"}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        if args.command in ("prepare", "check") and os.geteuid() != 0:
            try:
                args.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
                record = "last-check.json" if args.command == "prepare" else "last-update-check.json"
                atomic_json(args.cache / record, {"status": "error", "message": str(error),
                            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            except OSError:
                pass
        print(f"Синхронизация стратегий не выполнена: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
