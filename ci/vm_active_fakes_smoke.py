#!/usr/bin/env python3
"""Active fake transactions with real systemd/nfqws in a marked disposable VM only."""

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


def file_hashes(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()}


def fake_load(source):
    spec = importlib.util.spec_from_file_location("vm_fake_select", source / "src/lib/fake_select.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def commandline(release):
    return Path(f"/proc/{pids_for(release / 'nfqws')[0]}/cmdline").read_bytes().split(b"\0")


def exercise(label, snapshot, source):
    fake = fake_load(source)
    release = (APP / "current").resolve()
    lists = file_hashes(DATA / "user-lists")
    bins = file_hashes(release / "zapret-latest/bin")
    read = helper("read-config", {})
    available = {item["name"]: item["sha256"] for item in read["fakes"]["discord"]["available"]}
    require(available.get("stun.bin") and available.get("quic_initial_dbankcloud_ru.bin"),
            f"{label}: vetted release bins are listed with hashes")
    for running in (False, True):
        run("systemctl", "start" if running else "stop", SERVICE)
        for payload in ({"discord": available["stun.bin"], "gameudp": available["quic_initial_dbankcloud_ru.bin"]},
                        {"discord": available["quic_initial_dbankcloud_ru.bin"], "gameudp": None}):
            read = helper("read-config", {})
            previous_pid = pid()
            result = helper("set-active-fakes", {**payload, "expected_sha256": read["sha256"]})
            for kind, field in (("discord", "fakediscord"), ("gameudp", "fakegameudp")):
                info = result["fakes"][kind]
                require(info["configured"] == (payload[kind] is not None)
                        and info.get("override_sha256") == payload[kind]
                        and result["config"].get(field) == (payload[kind] or ""),
                        f"{label}: {kind} selection is persisted coherently")
            require(result["config"]["strategy"] == "general_alt12.bat" and not enabled(),
                    "profile and autostart are unchanged")
            if running:
                verify_running()
                require(pid() != previous_pid, f"{label}: active fake edit restarts service")
                command = commandline(release)
                for kind in ("discord", "gameudp"):
                    target = fake.active_path(DATA, kind)
                    if payload[kind] is None:
                        continue
                    token = ("--dpi-desync-fake-" +
                             ("discord" if kind == "discord" else "unknown-udp") + "=").encode() + str(target).encode()
                    require(token in command, f"{label}: actual nfqws arguments use active {kind} fake")
                    if kind == "discord":
                        require(b"--dpi-desync-fake-stun=" + str(target).encode() in command,
                                f"{label}: fake-stun follows the active discord fake")
                tls = [line for line in command if line.startswith(b"--dpi-desync-fake-tls=")]
                require(tls, "strategy keeps fake-tls options")
                require(not any(b"ACTIVE_" in line for line in tls),
                        "tls fakes are never redirected")
                require(any(b"tls_clienthello" in line for line in tls),
                        "clienthello tls fakes are unchanged")
            else:
                require(not active() and not table_present(), f"{label}: inactive edit starts no service or rules")
            # clearing discord returns both config and files to upstream state
            read = helper("read-config", {})
            previous_pid = pid()
            result = helper("set-active-fakes", {"discord": None, "gameudp": payload["gameudp"],
                                                 "expected_sha256": read["sha256"]})
            if payload["discord"] is not None:
                require(not fake.active_path(DATA, "discord").exists()
                        and result["config"]["fakediscord"] == "",
                        f"{label}: clearing removes the override file and key")
                if running:
                    require(pid() != previous_pid, f"{label}: clearing a set fake restarts service")
            elif running:
                require(pid() == previous_pid, f"{label}: clearing an unset fake is a no-op")
            require(file_hashes(DATA / "user-lists") == lists and file_hashes(release / "zapret-latest/bin") == bins,
                    f"{label}: all list and release bin bytes remain unchanged")
            verify_sentinels(snapshot)


def negative_cases(snapshot, source):
    fake = fake_load(source)
    release = (APP / "current").resolve()
    saved = (DATA / "conf.env").read_bytes()
    read = helper("read-config", {})
    previous_pid = pid()
    available = {item["name"]: item["sha256"] for item in read["fakes"]["discord"]["available"]}
    helper("set-active-fakes", {"discord": "0" * 64, "gameudp": None, "expected_sha256": read["sha256"]}, success=False)
    helper("set-active-fakes", {"discord": "stun-bytes", "gameudp": None, "expected_sha256": read["sha256"]}, success=False)
    helper("set-active-fakes", {"discord": None, "gameudp": "0" * 64, "expected_sha256": read["sha256"]}, success=False)
    helper("set-active-fakes", {"discord": None, "gameudp": available["stun.bin"],
                                "expected_sha256": "0" * 64}, success=False)
    require(pid() == previous_pid and (DATA / "conf.env").read_bytes() == saved,
            "invalid and stale fake tokens do not stop or change service")
    require(not (DATA / "fakes").exists() or not any((DATA / "fakes").glob("*")),
            "rejected selections leave no active fake files")
    # A rotated release bin invalidates the previously shown hash.
    target = release / "zapret-latest/bin/stun.bin"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\x00")
        helper("set-active-fakes", {"discord": available["stun.bin"], "gameudp": None,
                                    "expected_sha256": helper("read-config", {})["sha256"]}, success=False)
        require(target.read_bytes() == original + b"\x00",
                "helper does not undo another writer's release edit")
    finally:
        target.write_bytes(original)
    require(pid() == previous_pid and (DATA / "conf.env").read_bytes() == saved,
            "rotated release bin is rejected before any change")
    # A drifted persistent override blocks other edits and recovers by re-selection.
    helper("set-active-fakes", {"discord": available["stun.bin"], "gameudp": available["quic_initial_dbankcloud_ru.bin"],
                                "expected_sha256": helper("read-config", {})["sha256"]})
    self_pid = pid()
    override = fake.active_path(DATA, "discord")
    keep = override.read_bytes()
    override.write_bytes(b"tampered")
    drifted = helper("read-config", {})
    require(drifted["fakes"]["discord"]["matched_name"] is None and drifted["fakes"]["discord"]["warning"],
            "drifted override is reported with a warning")
    before = (DATA / "conf.env").read_bytes()
    helper("set-active-fakes", {"discord": None, "gameudp": available["quic_initial_dbankcloud_ru.bin"],
                                "expected_sha256": drifted["sha256"]}, success=False)
    helper("set-active-fakes", {"discord": None, "gameudp": available["quic_initial_dbankcloud_ru.bin"],
                                "expected_sha256": drifted["sha256"]}, success=False)
    require(override.read_bytes() == b"tampered" and (DATA / "conf.env").read_bytes() == before
            and pid() == self_pid,
            "drifted override blocks other selections without service restart")
    result = helper("set-active-fakes", {"discord": available["stun.bin"], "gameudp": None,
                                         "expected_sha256": drifted["sha256"]})
    require(override.read_bytes() == keep and result["fakes"]["discord"]["matched_name"] == "stun.bin",
            "re-selection repairs the drifted override")
    read = helper("read-config", {})
    helper("set-active-fakes", {"discord": None, "gameudp": None, "expected_sha256": read["sha256"]})
    require(not any((DATA / "fakes").glob("*")), "final clearing removes all active fake files")
    # One-shot start failure: exact config and file recovery.
    dropdir = Path("/etc/systemd/system") / (SERVICE + ".d")
    dropdir.mkdir(exist_ok=False)
    dropin = dropdir / "fakes-test.conf"
    flag = Path("/run/zapret-fakes-fail-once")
    try:
        dropin.write_text("[Service]\nExecStartPre=/bin/sh -c 'if test -f /run/zapret-fakes-fail-once; then rm /run/zapret-fakes-fail-once; exit 1; fi'\n")
        run("systemctl", "daemon-reload")
        flag.touch(mode=0o600)
        read = helper("read-config", {})
        helper("set-active-fakes", {"discord": available["stun.bin"], "gameudp": available["quic_initial_dbankcloud_ru.bin"],
                                    "expected_sha256": read["sha256"]}, success=False)
        require(not flag.exists(), "one-shot start failure actually occurred")
        require((DATA / "conf.env").read_bytes() == saved and not any((DATA / "fakes").glob("*")),
                "failed start restores exact config and files")
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
        read = helper("read-config", {})
        require("active-fakes-v1" in read["capabilities"], "helper advertises active fake support")
        require(read["fakes"]["discord"]["configured"] is False and read["fakes"]["discord"]["available"],
                "fresh install has no overrides and lists vetted bins")
        require(all(item["size"] <= 8 * 1024 * 1024 for item in read["fakes"]["discord"]["available"]),
                "listed bins respect the size limit")
        exercise("legacy", snapshot, source)
        negative_cases(snapshot, source)
        spec = importlib.util.spec_from_file_location("fakes_vm_sync", source / "src/lib/strategy_sync.py")
        sync = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync)
        repo = source / "zapret-latest"
        files = {path.relative_to(repo).as_posix(): path.read_bytes() for path in repo.rglob("*")
                 if path.is_file() and sync.valid_payload_name(path.relative_to(repo).as_posix())}
        with tempfile.TemporaryDirectory(prefix="fakes-stage-", dir="/var/tmp") as temporary:
            stage = Path(temporary) / "stage"
            _, digest = sync.write_stage(stage, files, {"revision": "a" * 40, "channel": "main", "tag": None})
            helper("apply-strategies", {"stage": str(stage), "digest": digest})
        require("active-fakes-v1" in helper("read-config", {})["capabilities"],
                "capability survives a strategy sync")
        exercise("compiled", snapshot, source)
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
                                               "src/lib/strategy_sync.py", "src/lib/fake_select.py")}}
    Path("/var/tmp/zapret-fakes-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("ACTIVE FAKES VM TEST PASSED (polkit dialog not tested)")


if __name__ == "__main__":
    main()
