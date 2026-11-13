#!/usr/bin/env python3
"""Real isolated engine/nftables primitives ONLY in the disposable marked VM."""

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


QUEUE = 41220
SENTINEL_QUEUE = 41221
SENTINEL_TABLE = "zapret_runtime_test_sentinel"


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
    require(not (APP / "current").exists() and not active() and not table_present(), "no existing app installation/service in VM")
    original_hosts = sha("/etc/hosts")
    original_timestamps = Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes()
    installed = False
    sentinel = None
    sentinel_table_created = False
    runners = []
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        release = (APP / "current").resolve()
        helper = load(release / "src/gui/privileged.py", "trusted_vm_helper")
        require(helper.verify_release() == release, "helper verifies root-owned installed release")
        installer = helper.make_installer(release)
        runtime = load(release / "src/lib/strategy_test_runtime.py", "trusted_vm_tester_runtime")
        require(not {QUEUE, SENTINEL_QUEUE} & runtime.bound_queues(), "fixture queues are not bound")
        data_before = tree_hashes(DATA)
        code_before = tree_hashes(release)
        config = (DATA / "conf.env").read_bytes()
        request = {"strategies": ["general_alt12.bat", "general.bat"],
                   "expected_sha256": hashlib.sha256(config).hexdigest()}
        with installer.operation():
            prepared = runtime.prepare(installer, request)
            require(len(prepared["plans"]) == 2, "real installed engine dry-runs both prepared strategies")
            require(not active() and not table_present(), "preparation starts no service or app rules")
            require((DATA / "conf.env").read_bytes() == config, "preparation does not rewrite working config")
            require(any(str(release / "src/lib/ipset-any.txt") in arg for arg in
                        prepared["plans"]["general_alt12.bat"]["argv"]), "IPSet any materialized without list replacement")
            # Deliberately use the SAME installed executable for an unrelated
            # foreground engine. Legacy stop_nfqws would kill it by exe match.
            sentinel = subprocess.Popen([str(release / "nfqws"), f"--qnum={SENTINEL_QUEUE}", "--filter-tcp=9"],
                cwd=release / "zapret-latest", env=dict(runtime.ENV), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 8
            while SENTINEL_QUEUE not in runtime.bound_queues():
                if sentinel.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Sentinel engine failed to bind")
                time.sleep(0.05)
            run("nft", "create", "table", "inet", SENTINEL_TABLE)
            sentinel_table_created = True
            run("nft", "add", "chain", "inet", SENTINEL_TABLE, "keep")
            sentinel_rules = run("nft", "-s", "list", "table", "inet", SENTINEL_TABLE).stdout
            for name in request["strategies"]:
                runner = runtime.IsolatedNftRun(prepared, queue=QUEUE)
                runners.append(runner)
                runner.start(name)
                require(runner.process.poll() is None and QUEUE in runtime.bound_queues(), f"foreground test engine ready: {name}")
                require(runner.owner in run("nft", "list", "table", "inet", runner.table).stdout,
                        f"exclusive session table carries ownership marker: {name}")
                require(sentinel.poll() is None and SENTINEL_QUEUE in runtime.bound_queues(), f"same-executable sentinel survives start: {name}")
                runner.stop()
                require(runner.process is None and QUEUE not in runtime.bound_queues(), f"only owned child stopped and queue released: {name}")
                require(run("nft", "list", "table", "inet", runner.table, check=False).returncode != 0,
                        f"session table removed: {name}")
                require(sentinel.poll() is None, f"same-executable sentinel survives stop: {name}")
            runner = runtime.IsolatedNftRun(prepared, queue=QUEUE)
            runners.append(runner)
            runner.start("general_alt12.bat")
            run("nft", "add", "chain", "inet", runner.table, "external_fixture")
            try:
                runner.stop()
            except RuntimeError as error:
                require("changed" in str(error), "external table drift explicitly reported")
            else:
                raise AssertionError("External table drift was not rejected")
            require(runner.process is None and QUEUE not in runtime.bound_queues(), "child stops even when table cleanup is refused")
            require(run("nft", "list", "chain", "inet", runner.table, "external_fixture").returncode == 0,
                    "foreign change preserved instead of broad deletion")
            # Fixture restores exactly its own injected change, then normal
            # cleanup must succeed; no blind override is added to runtime.
            run("nft", "delete", "chain", "inet", runner.table, "external_fixture")
            runner.stop()
            require(sentinel.poll() is None and run("nft", "-s", "list", "table", "inet", SENTINEL_TABLE).stdout == sentinel_rules,
                    "unrelated process and nft table preserved")
            require(not active() and not table_present(), "managed service/app table remain inactive throughout")
            require(tree_hashes(DATA) == data_before and tree_hashes(release) == code_before,
                    "installed code, config, lists and fakes unchanged")
        evidence = {"status": "passed", "kernel": os.uname().release,
            "boundary": "installed preflight and isolated engine/nft primitives only; no GUI/polkit/restore acceptance",
            "source_sha256": {name: sha(source / name) for name in (
                "src/lib/strategy_test_runtime.py", "src/lib/strategy_test_session.py", "ci/vm_strategy_runtime_smoke.py")}}
    finally:
        cleanup_errors = []
        for runner in reversed(runners):
            try:
                runner.stop()
            except Exception as error:
                cleanup_errors.append(str(error))
        if sentinel is not None:
            try:
                if sentinel.poll() is None:
                    sentinel.terminate()
                try:
                    sentinel.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    sentinel.kill()
                    sentinel.wait(timeout=5)
            except Exception as error:
                cleanup_errors.append(str(error))
        if sentinel_table_created:
            try:
                run("nft", "delete", "table", "inet", SENTINEL_TABLE)
            except Exception as error:
                cleanup_errors.append(str(error))
        if installed:
            try:
                run("python3", str(APP / "current/install.py"), "remove")
            except Exception as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise RuntimeError("VM fixture cleanup failed: " + "; ".join(cleanup_errors))
    require(sha("/etc/hosts") == original_hosts, "hosts unchanged")
    require(Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes() == original_timestamps, "runtime timestamps unchanged")
    require(not active() and not table_present(), "test installation removed and no app service/rules remain")
    with Path("/var/tmp/zapret-strategy-runtime-result.json").open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
