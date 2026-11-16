#!/usr/bin/env python3
"""Real installed-helper pipes/signals ONLY in the marked disposable VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import types

from vm_ipset_update_smoke import sha, tree_hashes
from vm_smoke import APP, DATA, SERVICE, active, require, run, table_present


def load(path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or run("hostname").stdout.strip() != "zapret-integration"
            or not Path("/var/tmp/zapret-vm-provisioned").is_file()):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    require(not (APP / "current").exists() and not active() and not table_present(), "guest has no app installation")
    hosts_before = sha("/etc/hosts")
    timestamps_before = Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes()
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        release = (APP / "current").resolve()
        helper_path = release / "src/gui/privileged.py"
        helper = load(helper_path, "verified_stream_helper")
        require(helper.verify_release() == release, "installed root-owned helper verified")
        protocol = load(release / "src/lib/strategy_test_session.py", "vm_stream_protocol")
        primitive = load(release / "src/lib/strategy_test_runtime.py", "vm_stream_primitive")
        config = (DATA / "conf.env").read_bytes()
        request = {"strategies": ["general_alt12.bat", "general.bat"],
                   "expected_sha256": hashlib.sha256(config).hexdigest()}
        code_before, data_before = tree_hashes(release), tree_hashes(DATA)
        # Explicit guest fixture. The helper must leave this enabled even in
        # the initially inactive case; it never changes autostart itself.
        run("systemctl", "enable", SERVICE)
        cases = [("eof", False), ("eof", True), ("restore", True), ("sigterm", True),
                 ("sigint", True), ("invalid-command", True), ("truncated", True), ("broken-output", True)]
        for case, initial_active in cases:
            # Separate fixture cases, not one production session: rapid repeated
            # restore/start cycles otherwise hit systemd's start burst limit.
            # The production helper deliberately does NOT hide/reset this error.
            run("systemctl", "reset-failed", SERVICE)
            run("systemctl", "start" if initial_active else "stop", SERVICE)
            before_queues = primitive.bound_queues()
            process = subprocess.Popen(
                ["/usr/bin/python3", "-I", "-B", str(helper_path), "test-session"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
            try:
                channel = protocol.MessageChannel(process.stdout.fileno(), process.stdin.fileno())
                channel.send(request)
                ready = channel.receive(180)
                require(ready == {"event": "ready", "ok": True} and not active(),
                        f"{case}: ready after original service stop: {ready}")
                # A separate ordinary administrative operation must not enter
                # while this streaming helper owns the install transaction.
                other = run("/usr/bin/python3", "-I", "-B", str(helper_path), "read-config",
                            input="{}", check=False)
                require(other.returncode != 0 and not json.loads(other.stdout)["ok"], f"{case}: full-session lock held")
                channel.send({"command": "start", "strategy": "general_alt12.bat"})
                started = channel.receive(90)
                require(started == {"event": "started", "ok": True, "strategy": "general_alt12.bat"},
                        f"{case}: strategy started through actual pipe")
                if case == "eof":
                    process.stdin.close()
                elif case == "restore":
                    channel.send({"command": "restore"})
                elif case in ("sigterm", "sigint"):
                    process.send_signal(signal.SIGTERM if case == "sigterm" else signal.SIGINT)
                elif case == "invalid-command":
                    channel.send({"command": "exec", "argv": ["id"]})
                elif case == "broken-output":
                    # Simulate a dead GUI: no reader for the result and EOF on
                    # commands. Recovery must not depend on an acknowledgement.
                    process.stdout.close()
                    process.stdin.close()
                else:
                    os.write(process.stdin.fileno(), b'{"command":')
                    process.stdin.close()
                if case == "broken-output":
                    require(process.wait(timeout=180) == 1, "broken output is not reported as an acknowledged success")
                else:
                    final = channel.receive(180)
                    require(final["event"] == "restored" and final["restored"] and not final["restore_error"]
                            and not final["cleanup_error"], f"{case}: final response confirms recovery: {final}")
                    expected_success = case in ("eof", "restore")
                    require(final["ok"] == expected_success and process.wait(timeout=30) == (0 if expected_success else 1),
                            f"{case}: errors/signals are not reported as successful test runs")
                require(active() == initial_active and primitive.bound_queues() == before_queues,
                        f"{case}: original service and queues restored")
                require("zapret_test_" not in run("nft", "list", "tables").stdout, f"{case}: no session table left")
                require(run("systemctl", "is-enabled", SERVICE).stdout.strip() == "enabled",
                        f"{case}: autostart preserved")
            finally:
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=180)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                        raise RuntimeError("VM helper recovery timed out; success is not assumed")
                process.stdout.close()
        # Initial invalid JSON must not reach the transaction at all.
        before_pid = run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout
        rejected = run("/usr/bin/python3", "-I", "-B", str(helper_path), "test-session",
                       input='{"strategies":[],"strategies":["general.bat"],"expected_sha256":"' + "a" * 64 + '"}\n',
                       check=False)
        require(rejected.returncode != 0 and json.loads(rejected.stdout)["event"] == "closed",
                "duplicate initial keys rejected before session")
        require(run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout == before_pid,
                "invalid begin does not restart original service")
        require(tree_hashes(DATA) == data_before and tree_hashes(release) == code_before,
                "installed data and code unchanged by streaming sessions")
        evidence = {"status": "passed", "kernel": os.uname().release, "cases": cases,
                    "boundary": "real installed helper pipes and signals; pkexec dialog/GUI/DPI not tested",
                    "source_sha256": {name: sha(source / name) for name in (
                        "src/gui/privileged.py", "src/lib/strategy_test_session.py",
                        "src/lib/strategy_test_service.py", "ci/vm_strategy_stream_smoke.py")}}
    finally:
        if installed:
            run("python3", str(APP / "current/install.py"), "remove")
    require(sha("/etc/hosts") == hosts_before, "hosts unchanged")
    require(Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes() == timestamps_before, "timestamps unchanged")
    require(not active() and not table_present(), "guest app installation/service/rules removed")
    with Path("/var/tmp/zapret-strategy-stream-result.json").open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
