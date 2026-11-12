#!/usr/bin/env python3
"""IPSet list update with real network/systemd/nfqws in a marked disposable VM only."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal

from vm_gui_smoke import helper
from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, enabled, pids_for,
                      require, run, sentinels, table_present, verify_running, verify_sentinels)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_hashes(directory):
    return {str(path.relative_to(directory)): sha(path)
            for path in Path(directory).rglob("*") if path.is_file()}


def other_lists():
    target = DATA / "user-lists/ipset-all.txt"
    return {path.name: sha(path) for path in (DATA / "user-lists").iterdir()
            if path.is_file() and path != target}


def target():
    return DATA / "user-lists/ipset-all.txt"


def pid():
    return run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout.strip()


def commandline(release):
    return Path(f"/proc/{pids_for(release / 'nfqws')[0]}/cmdline").read_bytes().split(b"\0")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch(source, cache):
    """Run the real download as the ordinary user; return parsed result."""
    result = run("runuser", "-u", "vmtest", "--", "python3",
                 str(source / "src/lib/strategy_sync.py"), "fetch-ipset", "--cache", str(cache))
    return json.loads(result.stdout)


def write_as_user(path, data):
    run("runuser", "-u", "vmtest", "--", "tee", str(path), input=data.decode("utf-8"))


def payload(stage, digest, config):
    return {"stage": str(stage), "sha256": digest, "expected_sha256": config["sha256"]}


def helper_reply(action, request):
    result = run("/usr/bin/python3", "-I", str(APP / "current/src/gui/privileged.py"),
                 action, input=json.dumps(request), check=False)
    return result, json.loads(result.stdout)


def exercise_negative(stage, fetched, config, config_bytes, initial_list, initial_pid, cache):
    """Every rejected request leaves service, config and list untouched."""
    rejected = []
    rejected.append(("stale config token", payload(stage, fetched["sha256"], {**config, "sha256": "0" * 64})))
    rejected.append(("hash mismatch", payload(stage, "0" * 64, config)))

    dummy = cache / "ipset-dummy.txt"
    write_as_user(dummy, b"203.0.113.113/32\n")
    rejected.append(("dummy list", payload(dummy, sha(dummy), config)))

    empty = cache / "ipset-empty.txt"
    write_as_user(empty, b"")
    rejected.append(("empty list", payload(empty, sha(empty), config)))

    link = cache / "ipset-link.txt"
    link.symlink_to(stage)
    rejected.append(("symlink stage", payload(link, fetched["sha256"], config)))

    privileged = Path("/var/tmp/root-owned-ipset.txt")
    privileged.write_bytes(stage.read_bytes())
    rejected.append(("root-owned stage", payload(privileged, fetched["sha256"], config)))

    changed = cache / "ipset-changed.txt"
    write_as_user(changed, stage.read_bytes())
    request = payload(changed, sha(changed), config)
    write_as_user(changed, stage.read_bytes() + b"\n# changed after preview\n")
    rejected.append(("stage changed after preview", request))

    for label, request_payload in rejected:
        helper("update-ipset", request_payload, success=False)
        require(target().read_bytes() == initial_list and pid() == initial_pid,
                f"rejected {label} keeps list bytes and service process")
        require((DATA / "conf.env").read_bytes() == config_bytes,
                f"rejected {label} keeps configuration bytes")

    drift = config_bytes + b"# edited elsewhere\n"
    (DATA / "conf.env").write_bytes(drift)
    helper("update-ipset", payload(stage, fetched["sha256"], config), success=False)
    require(target().read_bytes() == initial_list and not enabled(),
            "changed configuration is rejected before any list write")
    require((DATA / "conf.env").read_bytes() == drift, "rejected write does not undo another editor")
    (DATA / "conf.env").write_bytes(config_bytes)
    privileged.unlink(missing_ok=True)
    for path in (dummy, empty, link, changed):
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    cache = Path("/home/vmtest/.cache/zapret-strategy-sync")
    require(not (APP / "current").exists() and not DATA.exists(), "VM has no previous installation")
    WORK.mkdir(exist_ok=True, mode=0o700)
    sentinel_snapshot = sentinels(source)
    installed = False

    # The downloaded data is produced by the unprivileged GUI; keep its
    # ownership and mode checks meaningful by never fetching as root.
    fetched = fetch(source, cache)
    staged = Path(fetched["staged"])
    inspected = load_module("vm_ipset_mode", source / "src/lib/ipset_mode.py").inspect_list(staged)
    require(fetched["url"] == "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt",
            "download uses the fixed upstream IPSet endpoint")
    require(inspected["kind"] == "loaded" and inspected["entries"] == fetched["entries"] > 0
            and inspected["sha256"] == fetched["sha256"],
            "downloaded list is re-validated and its entries/hash agree")
    require(staged.is_file() and staged.stat().st_uid == int(run("id", "-u", "vmtest").stdout)
            and staged.stat().st_mode & 0o777 == 0o600,
            "stage is an ordinary user-owned mode-0600 file")
    require(not (DATA / "user-lists").exists(), "download itself does not touch installed data")

    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        read = helper("read-config", {})
        config_bytes = (DATA / "conf.env").read_bytes()
        require("ipset-update-v1" in read["capabilities"], "installed helper advertises IPSet update")
        initial_list = target().read_bytes()
        require(sha(target()) == read["ipset"]["loaded_sha256"],
                "initial persistent list is the loaded set")
        lists_before = other_lists()
        release_before = tree_hashes((APP / "current").resolve())
        require(not active() and not table_present(), "default install is inactive")

        # Rejections happen before any write while the service is inactive.
        initial_pid = pid()
        exercise_negative(staged, fetched, read, config_bytes, initial_list, initial_pid, cache)
        require(not active() and not table_present(), "rejected updates start no service or rules")
        verify_sentinels(sentinel_snapshot)

        # Inactive apply: no start, exact bytes, config and exclusions preserved.
        result = helper("update-ipset", payload(staged, fetched["sha256"], read))
        require(target().read_bytes() == staged.read_bytes(), "inactive update writes exact downloaded bytes")
        require(result["ipset"]["loaded_sha256"] == fetched["sha256"]
                and result["ipset"]["loaded_entries"] == fetched["entries"],
                "helper reports the same loaded hash and entry count")
        require((DATA / "conf.env").read_bytes() == config_bytes and other_lists() == lists_before,
                "inactive update preserves config and every other list")
        require(tree_hashes((APP / "current").resolve()) == release_before,
                "inactive update never modifies the release tree")
        require(not active() and not table_present(), "inactive update does not start service or rules")
        stat_before = target().stat()
        read = helper("read-config", {})
        helper("update-ipset", payload(staged, fetched["sha256"], read))
        stat_after = target().stat()
        require((stat_before.st_ino, stat_before.st_mtime_ns) == (stat_after.st_ino, stat_after.st_mtime_ns),
                "identical bytes are a no-op without rewriting the file")

        # Start and prove the actual nfqws command line uses the updated user list.
        run("systemctl", "start", SERVICE)
        verify_running()
        release = (APP / "current").resolve()
        command = commandline(release)
        expected = ("--ipset=" + str(target())).encode()
        require(expected in command, "real nfqws uses the persistent user IPSet")
        require(any(line.startswith(b"--ipset-exclude=") and b"ipset-exclude-user.txt" in line for line in command),
                "runtime keeps the user exclusion list")
        previous_pid = pid()

        # A second, genuinely different list restarts the active service.
        second = cache / "ipset-service-second.txt"
        second_data = staged.read_bytes() + b"\n# VM test second list\n"
        write_as_user(second, second_data)
        read = helper("read-config", {})
        helper("update-ipset", payload(second, sha(second), read))
        require(target().read_bytes() == second_data, "active update writes the second list")
        require(pid() != previous_pid, "active update restarts the running service")
        verify_running()
        require((DATA / "conf.env").read_bytes() == config_bytes and other_lists() == lists_before,
                "active update preserves config and every other list")
        verify_sentinels(sentinel_snapshot)

        # One-shot start failure restores the exact previous list and service.
        dropdir = Path("/etc/systemd/system") / (SERVICE + ".d")
        dropdir.mkdir(exist_ok=False)
        dropin = dropdir / "ipset-test.conf"
        flag = Path("/run/zapret-ipset-fail-once")
        third = cache / "ipset-service-third.txt"
        third_data = second_data + b"# VM test third list\n"
        try:
            dropin.write_text("[Service]\nExecStartPre=/bin/sh -c 'if test -f /run/zapret-ipset-fail-once; then rm /run/zapret-ipset-fail-once; exit 1; fi'\n")
            run("systemctl", "daemon-reload")
            flag.touch(mode=0o600)
            write_as_user(third, third_data)
            read = helper("read-config", {})
            result, reply = helper_reply("update-ipset", payload(third, sha(third), read))
            require(result.returncode != 0 and reply["ok"] is False,
                    "one-shot start failure is rejected by the helper")
            require(not flag.exists(), "one-shot start failure actually occurred")
            require("не запустился" in reply["error"],
                    "start failure is reported as a service failure")
            require(target().read_bytes() == second_data, "failed start restores the previous list")
            require((DATA / "conf.env").read_bytes() == config_bytes and other_lists() == lists_before,
                    "failed start restores config and leaves other lists alone")
            verify_running()
            verify_sentinels(sentinel_snapshot)
        finally:
            flag.unlink(missing_ok=True)
            dropin.unlink(missing_ok=True)
            dropdir.rmdir()
            run("systemctl", "daemon-reload")

        # The restored stage still applies after the injected failure is gone.
        read = helper("read-config", {})
        helper("update-ipset", payload(third, sha(third), read))
        require(target().read_bytes() == third_data, "recovery leaves the installation usable")
        verify_running()

        # Removal keeps the updated data, as expected for managed uninstall.
        updated_sha = sha(target())
        run("systemctl", "stop", SERVICE)
        run("python3", str(APP / "current/install.py"), "remove")
        installed = False
        require(sha(target()) == updated_sha, "managed removal preserves the updated IPSet list")
        require(not active() and not table_present(), "removal clears application service and rules")
        verify_sentinels(sentinel_snapshot)
    finally:
        if installed:
            run("python3", str(APP / "current/install.py"), "remove")
        verify_sentinels(sentinel_snapshot)
        for process in pids_for(WORK / "unrelated-nfqws/nfqws"):
            os.kill(process, signal.SIGTERM)
        run("nft", "delete", "table", "inet", SENTINEL)

    require(not active() and not table_present(), "application service and rules cleaned up")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(),
                "url": fetched["url"], "entries": fetched["entries"], "size": fetched["size"],
                "sha256": fetched["sha256"],
                "source_sha256": {name: sha(source / name)
                                  for name in ("install.py", "src/gui/privileged.py", "src/lib/common.sh",
                                               "src/lib/strategy_sync.py", "src/lib/ipset_mode.py")}}
    Path("/var/tmp/zapret-ipset-update-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("IPSET UPDATE VM TEST PASSED (polkit dialog and real DPI bypass not tested)")


if __name__ == "__main__":
    main()
