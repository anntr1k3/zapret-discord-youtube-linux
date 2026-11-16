"""Installed tester preflight and isolated execution primitives.

Call prepare under Installer.operation from verified installed helper code only;
never pass a GUI-supplied release/path/argv. GUI activation is separately gated.
Persistent config/lists/fakes are not rewritten, even temporarily.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid


ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/"}


def load_sibling(name):
    if name not in ("strategy_sync", "strategy_test_session", "strategy_test_resources", "fake_select"):
        raise ValueError("Unknown trusted tester module")
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("installed_tester_" + name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Invalid tester input file type/size")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Tester input exceeds size limit")
    return data


def validate_compiled(compiler, entry, files):
    if not isinstance(entry, dict) or set(entry) != {"tcp_ports", "udp_ports", "profiles"}:
        raise ValueError("Invalid installed strategy catalog entry")
    for key in ("tcp_ports", "udp_ports"):
        if not isinstance(entry[key], str):
            raise ValueError("Invalid capture ports")
        compiler.validate_ports(entry[key])
    profiles = entry["profiles"]
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 64:
        raise ValueError("Invalid strategy profiles")
    count = 0
    for profile in profiles:
        if not isinstance(profile, list) or not profile:
            raise ValueError("Empty strategy profile")
        count += len(profile)
        if count > 4096:
            raise ValueError("Too many strategy arguments")
        for token in profile:
            if not isinstance(token, str) or compiler.validate_argument(token, files) != token:
                raise ValueError("Invalid/non-normalized installed strategy argument")
        if not any(token.startswith("--filter-") for token in profile):
            raise ValueError("Unfiltered strategy profile")
        if sum(token.startswith(("--filter-tcp=", "--filter-udp=")) for token in profile) > 1:
            raise ValueError("Multiple protocol filters in one profile")


def prepare(installer, request, *, run=subprocess.run):
    """Resolve/validate every selection, then dry-run all, before any service stop.

    Returns an internal plan, NOT a client-supplied or serializable root request.
    The future runtime must recheck config/release drift before enter/restore.
    """
    load_sibling("strategy_test_session").validate_begin(request)
    state = installer.state()
    if state is None:
        raise ValueError("Managed installation is required")
    release = installer.release(state["current"])
    config = installer.data / "conf.env"
    installer.check_path(config)
    original = read_regular(config, 16384)
    if hashlib.sha256(original).hexdigest() != request["expected_sha256"]:
        raise ValueError("Installed configuration changed; read it again")
    values = installer.validate_config(config, release)
    if values.get("firewall_backend", "auto") not in ("auto", "nftables"):
        raise ValueError("Isolated tester currently requires nftables; configuration was not changed")
    compiler = load_sibling("strategy_sync")
    repo = release / "zapret-latest"
    files = {}
    total = 0
    for folder, extension in (("bin", "bin"), ("lists", "txt")):
        for path in sorted((repo / folder).glob("*." + extension)):
            key = folder + "/" + path.name
            if path.name in compiler.USER_LISTS:
                continue
            if not compiler.valid_payload_name(key):
                raise ValueError("Unsupported installed resource name")
            data = read_regular(path, compiler.MAX_FILE)
            total += len(data)
            if total > compiler.MAX_ARCHIVE or len(files) >= compiler.MAX_FILES:
                raise ValueError("Installed resources exceed tester limits")
            files[key] = data
    catalog = None
    catalog_path = repo / compiler.CATALOG
    if catalog_path.exists():
        catalog = json.loads(read_regular(catalog_path, compiler.MAX_MANIFEST))
        if (not isinstance(catalog, dict) or catalog.get("schema") != 1
                or not isinstance(catalog.get("strategies"), dict)):
            raise ValueError("Invalid installed strategy catalog")
    fakes = load_sibling("fake_select").resolve(repo, installer.data, values)
    plans = {}
    # The original service profile must be parseable too: otherwise we cannot
    # verify its capture rules before stopping it or validate a later restore.
    names = list(dict.fromkeys([*request["strategies"], values["strategy"]]))
    for name in names:
        custom = release / "custom-strategies" / name
        upstream = repo / name
        # lstat rather than exists: a broken symlink must not change precedence.
        path = custom if os.path.lexists(custom) else upstream
        installer.check_path(path)
        if not path.is_file():
            raise ValueError("Selected strategy is absent from the installed release")
        if path == upstream and catalog is not None:
            entry = catalog["strategies"].get(name)
        else:
            # The same strict data-only compiler supports safe custom filenames
            # without executing the Windows preamble or invoking a shell parser.
            payload = {**files, "general_tester.bat": read_regular(path, 256 * 1024)}
            entry = compiler.compile_payload(payload)["general_tester.bat"]
        validate_compiled(compiler, entry, files)
        plans[name] = compiler.materialize(
            entry, repo, installer.data / "user-lists",
            values["gamefiltertcp"] == "true", values["gamefilterudp"] == "true",
            values.get("gamefiltertcp_ports", "1024-65535"), values.get("gamefilterudp_ports", "1024-65535"),
            ipset_mode="any", fakes=fakes)
    # Parsing every plan precedes the first engine invocation.
    binary = release / "nfqws"
    for name, plan in plans.items():
        result = run([str(binary), "--dry-run", "--qnum=220", "--dpi-desync-fwmark=0x40000000", *plan["argv"]],
                     cwd=repo, env=dict(ENV), capture_output=True, text=True, timeout=20, check=False)
        if result.returncode:
            raise ValueError(f"Installed engine rejected {name}: {(result.stderr or result.stdout)[-2000:]}")
    if read_regular(config, 16384) != original or installer.state()["current"] != state["current"]:
        raise ValueError("Installed configuration/release changed during tester preparation")
    return {"release": release, "config_bytes": original, "values": values,
            "baseline_plan": plans[values["strategy"]],
            "plans": {name: plans[name] for name in request["strategies"]}}


def bound_queues():
    path = Path("/proc/net/netfilter/nfnetlink_queue")
    try:
        data = read_regular(path, 1024 * 1024)
    except FileNotFoundError:
        return set()
    result = set()
    for line in data.decode("ascii").splitlines():
        fields = line.split()
        if not fields or not fields[0].isdigit():
            raise ValueError("Cannot inspect NFQUEUE bindings")
        result.add(int(fields[0]))
    return result


class IsolatedNftRun:
    """One foreground child and one exclusively created session table.

    Internal primitive, not a root entrypoint. The session owner must hold the
    installation lock throughout selection/binding/cleanup. Rules and bindings
    are rechecked immediately before spawning. Never use the legacy kill script.
    """

    def __init__(self, prepared, *, queue, run=subprocess.run, popen=subprocess.Popen,
                 queues=bound_queues, clock=time.monotonic, sleep=time.sleep, resources=None):
        if type(queue) is not int or not 1 <= queue <= 65535 or queue == 220:
            raise ValueError("An isolated test queue is required")
        self.prepared, self.queue = prepared, queue
        self.run, self.popen, self.queues = run, popen, queues
        self.resources = resources if resources is not None else (
            lambda: load_sibling("strategy_test_resources").observe(run=self.run))
        self.clock, self.sleep = clock, sleep
        token = uuid.uuid4().hex
        self.table = "zapret_test_" + token
        self.owner = "zapret-test:" + token
        self.process = None
        self.created = False
        self.fingerprint = None

    def command(self, args, **kwargs):
        result = self.run(["/usr/sbin/nft", *args], capture_output=True, text=True, timeout=12,
                          env=dict(ENV), check=False, **kwargs)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[-2000:] or "nft command failed")
        if len(result.stdout) > 4 * 1024 * 1024:
            raise RuntimeError("Session nft table is too large")
        return result.stdout

    def table_fingerprint(self):
        data = json.loads(self.command(["-j", "-s", "list", "table", "inet", self.table]))
        entries = data.get("nftables") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise RuntimeError("Cannot inspect session nft table")
        tables = [entry["table"] for entry in entries if isinstance(entry, dict) and "table" in entry]
        if len(tables) != 1 or any(tables[0].get(key) != value for key, value in
                                  (("family", "inet"), ("name", self.table), ("comment", self.owner))):
            raise RuntimeError("Session nft table ownership is unknown")
        return json.dumps([entry for entry in entries if "metainfo" not in entry], sort_keys=True)

    def script(self, plan):
        interface = self.prepared["values"]["interface"]
        if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
            raise ValueError("Invalid test interface")
        lines = [f'create table inet {self.table} {{ comment "{self.owner}"; }}',
                 f"add chain inet {self.table} post {{ type filter hook postrouting priority mangle; }}",
                 f"add chain inet {self.table} pre {{ type filter hook prerouting priority filter; }}"]
        out = "" if interface == "any" else f'oifname "{interface}" '
        inc = "" if interface == "any" else f'iifname "{interface}" '
        for protocol, key in (("tcp", "tcp_ports"), ("udp", "udp_ports")):
            ports = plan[key]
            if not isinstance(ports, str) or (ports and not re.fullmatch(r"[0-9,-]+", ports)):
                raise ValueError("Invalid test capture ports")
            if not ports:
                continue
            load_sibling("strategy_sync").validate_ports(ports)
            lines.append(f"add rule inet {self.table} post {out}meta mark & 0x40000000 == 0 "
                         f"{protocol} dport {{ {ports} }} ct original packets 1-6 "
                         f'queue num {self.queue} bypass comment "{self.owner}"')
            if protocol == "tcp":
                lines.append(f"add rule inet {self.table} pre {inc}tcp sport {{ {ports} }} "
                             f'ct reply packets 1-3 queue num {self.queue} bypass comment "{self.owner}"')
        if not plan["tcp_ports"] and not plan["udp_ports"]:
            raise ValueError("Test strategy has no capture ports")
        return "\n".join(lines) + "\n"

    def start(self, name):
        if self.process is not None or self.created:
            raise RuntimeError("Previous isolated test has not been cleaned up")
        if name not in self.prepared["plans"]:
            raise ValueError("Strategy was not approved/prepared")
        plan = self.prepared["plans"][name]
        script = self.script(plan)  # Validate interpolation before any side effect.
        release = self.prepared["release"]
        if self.queue in self.resources():
            raise RuntimeError("Test queue now conflicts with firewall rules or bindings")
        if self.queue in self.queues():
            raise RuntimeError("Test queue is already bound; refusing to share it")
        try:
            self.process = self.popen(
                [str(release / "nfqws"), f"--qnum={self.queue}", "--dpi-desync-fwmark=0x40000000", *plan["argv"]],
                cwd=release / "zapret-latest", env=dict(ENV), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
            deadline = self.clock() + 8
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError("Test engine exited before readiness")
                if self.queue in self.queues():
                    break
                if self.clock() >= deadline:
                    raise TimeoutError("Test engine did not bind its queue")
                self.sleep(0.05)
            # nft applies one transaction. 'create', unlike 'add', refuses an
            # existing table; failed creation must never grant cleanup ownership.
            self.command(["-f", "-"], input=script)
            self.created = True
            self.fingerprint = self.table_fingerprint()
        except BaseException as error:
            try:
                self.stop()
            except Exception as recovery:
                raise RuntimeError(f"Isolated start failed; cleanup also failed: {recovery}") from error
            raise

    def stop(self):
        errors = []
        if self.created:
            try:
                if self.fingerprint is None or self.table_fingerprint() != self.fingerprint:
                    raise RuntimeError("Session nft table changed; refusing to delete it")
                self.command(["delete", "table", "inet", self.table])
                self.created, self.fingerprint = False, None
            except Exception as error:
                errors.append(str(error))
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
                self.process = None
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("; ".join(errors))


def allocate(prepared, *, run=subprocess.run, **kwargs):
    """Select, not reserve, a conflict-free queue; start performs a fresh check."""
    resources = load_sibling("strategy_test_resources")
    queue = resources.select_queue(resources.observe(run=run))
    return IsolatedNftRun(prepared, queue=queue, run=run, **kwargs)
