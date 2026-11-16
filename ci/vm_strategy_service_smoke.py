#!/usr/bin/env python3
"""Original-service transaction ONLY in an explicitly marked disposable guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
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
        parser.error("Only root inside the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    require(not (APP / "current").exists() and not active() and not table_present(), "guest has no app installation")
    hosts_before = sha("/etc/hosts")
    timestamps_before = Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes()
    installed = False
    sentinel = None
    runtimes = []
    legacy_chains = []
    nft_fixture = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        release = (APP / "current").resolve()
        helper = load(release / "src/gui/privileged.py", "service_vm_helper")
        require(helper.verify_release() == release, "root-owned installed helper verified")
        installer = helper.make_installer(release)
        service = load(release / "src/lib/strategy_test_service.py", "service_vm_runtime")
        protocol = load(release / "src/lib/strategy_test_session.py", "service_vm_protocol")
        resources = load(release / "src/lib/strategy_test_resources.py", "service_vm_resources")
        primitive = load(release / "src/lib/strategy_test_runtime.py", "service_vm_primitive")
        # Unreferenced chains deliberately have no effect on guest traffic.
        for binary, queue in (("iptables-legacy", 40010), ("ip6tables-legacy", 40011)):
            run(binary, "-t", "mangle", "-N", "zapret_test_queue_fixture")
            legacy_chains.append(binary)
            run(binary, "-t", "mangle", "-A", "zapret_test_queue_fixture", "-j", "NFQUEUE", "--queue-num", str(queue))
        run("nft", "-f", "-", input="create table inet zapret_queue_fixture\n"
            "add chain inet zapret_queue_fixture unused\n"
            "add rule inet zapret_queue_fixture unused queue num 40012 bypass\n")
        nft_fixture = True
        observed = resources.observe()
        require({40010, 40011, 40012} <= observed, "unbound nft and IPv4/IPv6 legacy rule queues are detected")
        require(not {40010, 40011, 40012} & primitive.bound_queues(), "fixture rule queues have no bound consumer")
        require(resources.select_queue(observed, candidates=[40010, 40011, 40012, 40013]) == 40013,
                "queue selection skips rule-only conflicts across backends")
        config_before = (DATA / "conf.env").read_bytes()
        request = {"strategies": ["general_alt12.bat", "general.bat"],
                   "expected_sha256": hashlib.sha256(config_before).hexdigest()}
        data_before, code_before = tree_hashes(DATA), tree_hashes(release)
        enabled_before = run("systemctl", "is-enabled", SERVICE, check=False).stdout
        for initial_active in (False, True):
            if initial_active:
                run("systemctl", "enable", SERVICE)  # Explicit guest fixture, not runtime behavior.
                enabled_before = run("systemctl", "is-enabled", SERVICE).stdout
                run("systemctl", "start", SERVICE)
            runtime = service.InstalledSessionRuntime(installer)
            runtimes.append(runtime)
            commands = iter([{"command": "start", "strategy": "general_alt12.bat"}, {"command": "stop"},
                             {"command": "start", "strategy": "general.bat"}])  # EOF with child running.
            responses = []
            result = protocol.serve(runtime, request, lambda timeout: next(commands, None), responses.append)
            require(result["ok"] and result["restored"] and result["reason"] == "eof",
                    f"EOF restores original service state (initial active={initial_active}): {result}")
            require(active() == initial_active, f"original active/inactive state preserved ({initial_active})")
            require(runtime.child.process is None and not runtime.child.created, "test process and table cleaned")
            require(runtime.child.queue not in resources.observe(), "test queue released with no remaining rules")
            require(run("systemctl", "is-enabled", SERVICE, check=False).stdout == enabled_before,
                    "autostart unchanged")
            require((DATA / "conf.env").read_bytes() == config_before, "working configuration unchanged")
        # A same-executable manual process is a conflict, not a cleanup target.
        sentinel_queue = resources.select_queue(resources.observe())
        sentinel = subprocess.Popen([str(release / "nfqws"), f"--qnum={sentinel_queue}", "--filter-tcp=9"],
            cwd=release / "zapret-latest", env=dict(primitive.ENV), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while sentinel_queue not in primitive.bound_queues():
            if sentinel.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Manual sentinel did not bind")
            time.sleep(0.05)
        runtime = service.InstalledSessionRuntime(installer)
        runtimes.append(runtime)
        result = protocol.serve(runtime, request, lambda timeout: None, lambda response: None)
        require(not result["ok"] and "outside" in result["error"], "manual same-executable engine blocks session before stop")
        require(active() and sentinel.poll() is None, "conflict preserves both managed service and manual engine")
        # Exercise the tightened systemd CLI cleanup itself, not just refusal.
        run("systemctl", "stop", SERVICE)
        require(sentinel.poll() is None, "systemd stop does not signal manual same-executable engine")
        run("systemctl", "start", SERVICE)
        require(sentinel.poll() is None, "systemd start does not signal manual same-executable engine")
        sentinel.terminate()
        sentinel.wait(timeout=8)
        sentinel = None
        # Drift after our stop must not restore a configuration changed externally.
        runtime = service.InstalledSessionRuntime(installer)
        runtimes.append(runtime)
        with runtime.operation():
            snapshot = runtime.snapshot(request)
            runtime.enter(snapshot)
            (DATA / "conf.env").write_bytes(config_before + b"# external VM fixture\n")
            try:
                runtime.restore(snapshot)
            except ValueError:
                require(not active(), "configuration drift blocks automatic service restart")
            else:
                raise AssertionError("Configuration drift was not detected")
            # The fixture, not runtime, reverts its exact injected bytes.
            (DATA / "conf.env").write_bytes(config_before)
            runtime.restore(snapshot)
            require(active(), "restore succeeds after fixture removes only its own injected drift")
        require(tree_hashes(DATA) == data_before and tree_hashes(release) == code_before,
                "code, config, lists and fakes preserved")
        evidence = {"status": "passed", "kernel": os.uname().release,
                    "boundary": "installed controller/service transaction; no GUI/polkit or DPI acceptance",
                    "source_sha256": {name: sha(source / name) for name in (
                        "src/lib/strategy_test_service.py", "src/lib/strategy_test_resources.py",
                        "src/lib/strategy_test_runtime.py", "src/lib/common.sh", "ci/vm_strategy_service_smoke.py")}}
    finally:
        errors = []
        for runtime in reversed(runtimes):
            try:
                runtime.stop()
            except Exception as error:
                errors.append(str(error))
        if nft_fixture:
            try:
                run("nft", "delete", "table", "inet", "zapret_queue_fixture")
            except Exception as error:
                errors.append(str(error))
        for binary in legacy_chains:
            try:
                run(binary, "-t", "mangle", "-F", "zapret_test_queue_fixture")
                run(binary, "-t", "mangle", "-X", "zapret_test_queue_fixture")
            except Exception as error:
                errors.append(str(error))
        if sentinel is not None:
            try:
                if sentinel.poll() is None:
                    sentinel.terminate()
                sentinel.wait(timeout=8)
            except Exception as error:
                errors.append(str(error))
        if installed:
            try:
                run("python3", str(APP / "current/install.py"), "remove")
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("VM cleanup failed: " + "; ".join(errors))
    require(sha("/etc/hosts") == hosts_before, "hosts unchanged")
    require(Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes() == timestamps_before, "timestamps unchanged")
    require(not active() and not table_present(), "VM test installation/service/rules removed")
    with Path("/var/tmp/zapret-strategy-service-result.json").open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
