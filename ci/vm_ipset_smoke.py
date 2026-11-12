#!/usr/bin/env python3
"""IPSet transactions with real systemd/nfqws in a marked disposable VM only."""

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


def request(mode, read):
    return {"mode": mode, "expected_sha256": read["sha256"],
            "expected_list_sha256": read["ipset"]["loaded_sha256"] if mode == "loaded" else None}


def file_hashes(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()}


def exercise(label, snapshot):
    lists = file_hashes(DATA / "user-lists")
    release = (APP / "current").resolve()
    code = file_hashes(release)
    for running in (False, True):
        run("systemctl", "start" if running else "stop", SERVICE)
        for mode in ("any", "none", "loaded"):
            read = helper("read-config", {})
            previous_pid = pid()
            result = helper("set-ipset-mode", request(mode, read))
            require(result["config"]["ipset_mode"] == mode and result["ipset"]["effective_mode"] == mode,
                    f"{label}: persisted mode {mode} agrees with effective mode")
            require(result["config"]["strategy"] == "general_alt12.bat" and not enabled(),
                    "profile and autostart are unchanged")
            if running:
                verify_running()
                require(pid() != previous_pid, f"{label}: active edit restarts service")
                command = Path(f"/proc/{pids_for(release / 'nfqws')[0]}/cmdline").read_bytes().split(b"\0")
                selected = result["ipset"]["loaded_source"] if mode == "loaded" else str(release / "src/lib" / f"ipset-{mode}.txt")
                require(("--ipset=" + selected).encode() in command, f"{label}: actual nfqws arguments use mode {mode}")
                require(("--ipset-exclude=" + str(DATA / "user-lists/ipset-exclude-user.txt")).encode() in command,
                        "actual nfqws keeps persistent user exclusions")
            else:
                require(not active() and not table_present(), f"{label}: inactive edit starts no service or rules")
            previous_pid = pid()
            helper("set-ipset-mode", request(mode, result))
            require(pid() == previous_pid, "identical mode is a no-op")
            require(file_hashes(DATA / "user-lists") == lists and file_hashes(release) == code,
                    "all list and release bytes remain unchanged")
            verify_sentinels(snapshot)
    saved = (DATA / "conf.env").read_bytes()
    read = helper("read-config", {})
    previous_pid = pid()
    helper("set-ipset-mode", {**request("none", read), "expected_sha256": "0" * 64}, success=False)
    helper("set-ipset-mode", {**request("none", read), "mode": "../path"}, success=False)
    loaded = Path(read["ipset"]["loaded_source"])
    require(loaded.is_relative_to(DATA / "user-lists"), "saved loaded dataset lives outside immutable releases")
    original = loaded.read_bytes()
    try:
        loaded.write_text("192.0.2.0/24\n")
        helper("set-ipset-mode", request("loaded", read), success=False)
        require(loaded.read_text() == "192.0.2.0/24\n", "helper does not undo another writer's list edit")
    finally:
        loaded.write_bytes(original)
    require(pid() == previous_pid and (DATA / "conf.env").read_bytes() == saved,
            "invalid mode and stale config/list tokens do not stop or change service")
    dropdir = Path("/etc/systemd/system") / (SERVICE + ".d")
    dropdir.mkdir(exist_ok=False)
    dropin = dropdir / "ipset-test.conf"
    flag = Path("/run/zapret-ipset-fail-once")
    try:
        dropin.write_text("[Service]\nExecStartPre=/bin/sh -c 'if test -f /run/zapret-ipset-fail-once; then rm /run/zapret-ipset-fail-once; exit 1; fi'\n")
        run("systemctl", "daemon-reload")
        flag.touch(mode=0o600)
        helper("set-ipset-mode", request("any", read), success=False)
        require(not flag.exists(), "one-shot start failure actually occurred")
        require((DATA / "conf.env").read_bytes() == saved, f"{label}: failed start restores exact config")
        verify_running()
        require(file_hashes(DATA / "user-lists") == lists, "recovery preserves all list bytes")
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
        read = helper("read-config", {})
        require("ipset-mode-v1" in read["capabilities"], "helper advertises IPSet mode support")
        require(read["ipset"]["effective_mode"] == "none" and read["ipset"]["loaded_available"],
                "legacy dummy is detected and saved loaded set remains available")
        require((DATA / "user-lists/ipset-loaded.txt").read_bytes() == (source / "user-lists/ipset-all.txt.backup").read_bytes(),
                "legacy backup migrates without loss into permanent data")
        exercise("legacy", snapshot)
        spec = importlib.util.spec_from_file_location("ipset_vm_sync", source / "src/lib/strategy_sync.py")
        sync = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync)
        repo = source / "zapret-latest"
        files = {path.relative_to(repo).as_posix(): path.read_bytes() for path in repo.rglob("*")
                 if path.is_file() and sync.valid_payload_name(path.relative_to(repo).as_posix())}
        with tempfile.TemporaryDirectory(prefix="ipset-stage-", dir="/var/tmp") as temporary:
            stage = Path(temporary) / "stage"
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
                                  for name in ("install.py", "src/gui/privileged.py", "src/lib/common.sh",
                                               "src/lib/strategy_sync.py", "src/lib/ipset_mode.py")}}
    Path("/var/tmp/zapret-ipset-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("IPSET VM TEST PASSED (polkit dialog not tested)")


if __name__ == "__main__":
    main()
