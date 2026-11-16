"""Read-only NFQUEUE conflict detection for the installed tester.

Call under the installer operation lock and recheck immediately before binding.
A selected number is not a kernel reservation; foreground nfqws must still bind
it exclusively. Unknown/dynamic rules or unavailable inspectors fail closed.
"""

import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess


MAX_OUTPUT = 4 * 1024 * 1024
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/"}


def queue_number(value):
    if type(value) is not int or not 0 <= value <= 65535:
        raise ValueError("Invalid NFQUEUE number")
    return value


def queue_value(value):
    if type(value) is int:
        return {queue_number(value)}
    if isinstance(value, dict) and set(value) == {"range"}:
        ends = value["range"]
        if not isinstance(ends, list) or len(ends) != 2:
            raise ValueError("Invalid NFQUEUE range")
        first, last = (queue_number(item) for item in ends)
        if first > last:
            raise ValueError("Reversed NFQUEUE range")
        return set(range(first, last + 1))
    if isinstance(value, dict) and set(value) == {"set"}:
        entries = value["set"]
        if not isinstance(entries, list) or not entries:
            raise ValueError("Invalid NFQUEUE set")
        result = set()
        for entry in entries:
            result.update(queue_value(entry))
        return result
    raise ValueError("Dynamic/unknown NFQUEUE expression; cannot safely select a test queue")


def nft_queues(document):
    if (not isinstance(document, dict) or not isinstance(document.get("nftables"), list)
            or any(not isinstance(entry, dict) for entry in document["nftables"])):
        raise ValueError("Invalid nftables document")
    result = set()

    def visit(item):
        if isinstance(item, list):
            for entry in item:
                visit(entry)
        elif isinstance(item, dict):
            if "queue" in item:
                value = item["queue"]
                if not isinstance(value, dict) or "num" not in value:
                    raise ValueError("Unknown nft queue expression")
                result.update(queue_value(value["num"]))
            if isinstance(item.get("xt"), dict) and item["xt"].get("name", "").upper() == "NFQUEUE":
                raise ValueError("Opaque nft compatibility NFQUEUE target")
            for value in item.values():
                visit(value)

    try:
        visit(document["nftables"])
    except RecursionError as error:
        raise ValueError("Overly nested nftables document") from error
    return result


def legacy_queues(text):
    result = set()
    for line in text.splitlines():
        if not line.startswith("-A "):
            continue
        tokens = shlex.split(line)
        if not any(tokens[index] in ("-j", "-g") and tokens[index + 1] == "NFQUEUE"
                   for index in range(len(tokens) - 1)):
            continue
        values = []
        for index, token in enumerate(tokens):
            key, separator, value = token.partition("=")
            if key not in ("--queue-num", "--queue-balance"):
                continue
            if not separator:
                if index + 1 >= len(tokens):
                    raise ValueError("Missing legacy NFQUEUE value")
                value = tokens[index + 1]
            pattern = r"[0-9]{1,5}" if key == "--queue-num" else r"[0-9]{1,5}:[0-9]{1,5}"
            if not re.fullmatch(pattern, value):
                raise ValueError("Invalid legacy NFQUEUE value")
            numbers = [int(item) for item in value.split(":")]
            values.append(queue_value(numbers[0] if len(numbers) == 1 else {"range": numbers}))
        if len(values) > 1:
            raise ValueError("Ambiguous legacy NFQUEUE options")
        result.update(values[0] if values else {0})
    return result


def binding_queues(text):
    result = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or not re.fullmatch(r"[0-9]{1,5}", fields[0]) or not fields[1].isdigit():
            raise ValueError("Invalid NFQUEUE binding observation")
        result.add(queue_number(int(fields[0])))
    return result


def read_optional(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_OUTPUT + 1)
    except FileNotFoundError:
        return None  # Kernel interface absent because backend is not loaded.
    if len(data) > MAX_OUTPUT:
        raise ValueError("Oversized proc observation")
    return data.decode("ascii")


def observe(*, run=subprocess.run, read=read_optional):
    def command(argv):
        result = run(argv, capture_output=True, text=True, check=False, timeout=12, env=dict(ENV))
        if result.returncode or len(result.stdout) > MAX_OUTPUT:
            raise ValueError("Cannot inspect NFQUEUE rules: " + (result.stderr or "invalid output")[-1000:])
        return result.stdout

    bindings = read(Path("/proc/net/netfilter/nfnetlink_queue"))
    result = binding_queues(bindings) if bindings is not None else set()
    result.update(nft_queues(json.loads(command(["/usr/sbin/nft", "-j", "list", "ruleset"]))))
    for path, binary in (("/proc/net/ip_tables_names", "/usr/sbin/iptables-legacy-save"),
                         ("/proc/net/ip6_tables_names", "/usr/sbin/ip6tables-legacy-save")):
        names = read(Path(path))
        if names is None or not names.strip():
            continue
        if any(not re.fullmatch(r"[A-Za-z0-9_]+", name) for name in names.splitlines()):
            raise ValueError("Invalid legacy table names")
        # Explicit legacy binaries, never alternatives pointing back to nft.
        result.update(legacy_queues(command([binary])))
    return result


def select_queue(occupied, *, candidates=None):
    if candidates is None:
        start = secrets.randbelow(20000)
        candidates = [30000 + ((start + offset) % 20000) for offset in range(20000)]
    if not isinstance(candidates, (list, tuple)) or len(candidates) > 20000:
        raise ValueError("Invalid candidate queue list")
    for candidate in candidates:
        queue_number(candidate)
    for candidate in candidates:
        if candidate not in occupied and candidate not in (0, 220):
            return candidate
    raise ValueError("No conflict-free tester queue is available")
