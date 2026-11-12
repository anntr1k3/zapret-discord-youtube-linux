#!/usr/bin/env python3
"""Real Game Filter transactions only inside the explicitly marked disposable VM."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile

from vm_gui_smoke import helper
from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, enabled, pids_for,
                      require, run, sentinels, table_present, verify_running, verify_sentinels)


def pid():
    return run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout.strip()


def payload(mode, token):
    return {"mode": mode, "tcp_ports": "2000-3000", "udp_ports": "4000,5000-6000", "expected_sha256": token}


def exercise(label, snapshot):
    for running in (False, True):
        run("systemctl", "start" if running else "stop", SERVICE)
        for mode in ("disabled", "tcp", "udp", "all"):
            before = helper("read-config", {})
            previous_pid = pid()
            result = helper("set-game-filter", payload(mode, before["sha256"]))
            config = result["config"]
            require(config["gamefiltertcp"] == ("true" if mode in ("tcp", "all") else "false")
                    and config["gamefilterudp"] == ("true" if mode in ("udp", "all") else "false"),
                    f"{label}: {mode} persists independent TCP/UDP flags")
            require(config["gamefiltertcp_ports"] == "2000-3000" and config["gamefilterudp_ports"] == "4000,5000-6000",
                    f"{label}: custom ranges survive config read")
            require(config["strategy"] == "general_alt12.bat" and not enabled(), "profile and autostart are unchanged")
            if running:
                verify_running()
                require(pid() != previous_pid, f"{label}: active edit restarts the actual service")
            else:
                require(not active() and not table_present(), f"{label}: inactive edit starts no service or firewall")
            previous_pid = pid()
            helper("set-game-filter", payload(mode, result["sha256"]))
            require(pid() == previous_pid, f"{label}: repeated identical edit is a no-op")
            verify_sentinels(snapshot)
    saved = (DATA / "conf.env").read_bytes()
    current = helper("read-config", {})
    previous_pid = pid()
    helper("set-game-filter", {**payload("tcp", current["sha256"]), "udp_ports": "65536"}, success=False)
    helper("set-game-filter", payload("udp", "0" * 64), success=False)
    require(pid() == previous_pid and (DATA / "conf.env").read_bytes() == saved,
            f"{label}: invalid range and stale token never stop or modify the working service")

    # A one-shot systemd pre-start failure exercises real recovery, not only mocks.
    dropdir = Path("/etc/systemd/system") / (SERVICE + ".d")
    dropdir.mkdir(exist_ok=False)
    dropin = dropdir / "game-filter-test.conf"
    flag = Path("/run/zapret-game-filter-fail-once")
    try:
        dropin.write_text("[Service]\nExecStartPre=/bin/sh -c 'if test -f /run/zapret-game-filter-fail-once; then rm /run/zapret-game-filter-fail-once; exit 1; fi'\n")
        run("systemctl", "daemon-reload")
        flag.touch(mode=0o600)
        helper("set-game-filter", payload("udp", current["sha256"]), success=False)
        require(not flag.exists(), "one-shot start failure actually occurred")
        require((DATA / "conf.env").read_bytes() == saved, f"{label}: failed start restores exact original config bytes")
        verify_running()
        verify_sentinels(snapshot)
    finally:
        flag.unlink(missing_ok=True)
        dropin.unlink(missing_ok=True)
        dropdir.rmdir()
        run("systemctl", "daemon-reload")
    run("systemctl", "stop", SERVICE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    require(not (APP / "current").exists(), "no pre-existing managed installation")
    source = args.source.resolve(strict=True)
    WORK.mkdir(exist_ok=True, mode=0o700)
    snapshot = sentinels(source)
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        exercise("legacy", snapshot)
        spec = importlib.util.spec_from_file_location("game_filter_vm_sync", source / "src/lib/strategy_sync.py")
        sync = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync)
        repo = source / "zapret-latest"
        files = {path.relative_to(repo).as_posix(): path.read_bytes() for path in repo.rglob("*")
                 if path.is_file() and sync.valid_payload_name(path.relative_to(repo).as_posix())}
        with tempfile.TemporaryDirectory(prefix="game-filter-stage-", dir="/var/tmp") as temporary:
            stage = Path(temporary) / "stage"
            # Explicit test-fixture provenance, not a claim about a fetched commit.
            _, digest = sync.write_stage(stage, files, {"revision": "a" * 40, "channel": "main", "tag": None})
            helper("apply-strategies", {"stage": str(stage), "digest": digest})
        exercise("compiled", snapshot)
    finally:
        if installed:
            run("python3", str(APP / "current/install.py"), "remove")
        verify_sentinels(snapshot)
        for process in pids_for(WORK / "unrelated-nfqws/nfqws"):
            os.kill(process, signal.SIGTERM)
        run("nft", "delete", "table", "inet", SENTINEL)
    require(not active() and not table_present(), "application service and rules cleaned up")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(),
                "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                                  for name in ("install.py", "src/gui/privileged.py", "src/lib/common.sh", "src/lib/strategy_sync.py")}}
    Path("/var/tmp/zapret-game-filter-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("GAME FILTER VM TEST PASSED (polkit dialog not tested)")


if __name__ == "__main__":
    main()
