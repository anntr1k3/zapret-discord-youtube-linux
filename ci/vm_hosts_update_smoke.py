#!/usr/bin/env python3
"""Hosts integration: root ONLY inside an explicitly marked disposable VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat

from vm_gui_smoke import helper
from vm_ipset_update_smoke import load_module, pid, sha, tree_hashes, write_as_user
from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, pids_for,
                      require, run, sentinels, table_present, verify_running, verify_sentinels)


HOSTS = Path("/etc/hosts")


def payload(stage):
    return {"stage": str(stage), "sha256": sha(stage), "expected_hosts_sha256": sha(HOSTS)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    require(not (APP / "current").exists() and not DATA.exists(), "no previous application installation")
    require(stat.S_ISREG(HOSTS.lstat().st_mode) and HOSTS.stat().st_uid == 0,
            "guest hosts is a regular root-owned file")
    original, original_info = HOSTS.read_bytes(), HOSTS.stat()
    hosts_module = load_module("vm_hosts", source / "src/lib/hosts_file.py")
    require(not hosts_module.status(original)["present"], "guest has no managed hosts block")
    cache = Path("/home/vmtest/.cache/zapret-strategy-sync")
    fetched = json.loads(run("runuser", "-u", "vmtest", "--", "python3",
                             str(source / "src/lib/strategy_sync.py"), "fetch-hosts",
                             "--cache", str(cache)).stdout)
    stage = Path(fetched["staged"])
    inspected = hosts_module.validate(stage.read_bytes())
    require(fetched["url"] == "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts",
            "download uses the fixed hosts URL")
    require(inspected["sha256"] == fetched["sha256"] and inspected["entries"] == fetched["entries"] > 0,
            "real downloaded hosts passes validation and agrees with reported hash/count")
    require(stage.stat().st_uid == int(run("id", "-u", "vmtest").stdout)
            and stat.S_IMODE(stage.stat().st_mode) == 0o600, "stage belongs to ordinary user with mode 0600")
    require(HOSTS.read_bytes() == original and not DATA.exists(), "download changes neither hosts nor installed data")
    WORK.mkdir(exist_ok=True, mode=0o700)
    sentinel_snapshot = sentinels(source)
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        require("hosts-update-v1" in helper("read-config", {})["capabilities"], "installed helper advertises hosts update")
        data_before = tree_hashes(DATA)
        release_before = tree_hashes((APP / "current").resolve())
        # Prefix/suffix sentinels and non-UTF8 comments must survive verbatim.
        baseline = original + b"\n# VM private comment \xff\r\n192.0.2.1 keep.example\r\n"
        HOSTS.write_bytes(baseline)
        HOSTS.chmod(0o640)
        request = payload(stage)
        helper("update-hosts", {**request, "expected_hosts_sha256": "0" * 64}, success=False)
        helper("update-hosts", {**request, "sha256": "0" * 64}, success=False)
        empty = cache / "hosts-empty"
        write_as_user(empty, b"# no mappings\n")
        helper("update-hosts", payload(empty), success=False)
        link = cache / "hosts-link"
        link.symlink_to(stage)
        helper("update-hosts", payload(link), success=False)
        root_stage = WORK / "hosts-root-stage"
        root_stage.write_bytes(stage.read_bytes())
        helper("update-hosts", payload(root_stage), success=False)
        require(HOSTS.read_bytes() == baseline and not active() and not table_present(),
                "invalid requests preserve hosts and start no service/rules")

        # Another editor's bytes must not be silently overwritten.
        HOSTS.write_bytes(baseline + b"# external edit\n")
        helper("update-hosts", request, success=False)
        require(HOSTS.read_bytes() == baseline + b"# external edit\n", "stale preview preserves external editor bytes")
        HOSTS.write_bytes(baseline)
        result = helper("update-hosts", payload(stage))
        expected = hosts_module.merge(baseline, stage.read_bytes())
        require(result["changed"] and HOSTS.read_bytes() == expected, "inactive apply writes exact managed merge")
        backup = Path(result["backup"])
        require(backup.read_bytes() == baseline and stat.S_IMODE(backup.stat().st_mode) == 0o600,
                "complete backup has exact previous bytes and private permissions")
        require(HOSTS.stat().st_uid == original_info.st_uid and HOSTS.stat().st_gid == original_info.st_gid
                and stat.S_IMODE(HOSTS.stat().st_mode) == 0o640, "atomic replace preserves owner/group/mode")
        require(not active() and not table_present(), "inactive hosts update starts no service/rules")
        before = HOSTS.stat()
        result = helper("update-hosts", payload(stage))
        require(not result["changed"] and result["backup"] is None
                and HOSTS.stat().st_ino == before.st_ino and HOSTS.stat().st_mtime_ns == before.st_mtime_ns,
                "identical apply is a no-op, no backup or inode/mtime change")

        run("systemctl", "start", SERVICE)
        verify_running()
        service_pid = pid()
        second = cache / "hosts-second"
        write_as_user(second, stage.read_bytes() + b"192.0.2.22 vm-test.invalid\n")
        result = helper("update-hosts", payload(second))
        second_bytes = hosts_module.merge(expected, second.read_bytes())
        require(result["changed"] and HOSTS.read_bytes() == second_bytes, "active apply replaces only managed block")
        require(pid() == service_pid and active(), "hosts update does not restart active systemd service")
        require(tree_hashes(DATA) == data_before and tree_hashes((APP / "current").resolve()) == release_before,
                "hosts update leaves configuration, lists and installed release unchanged")
        verify_sentinels(sentinel_snapshot)

        # Failure injection runs an isolated interpreter with the INSTALLED module.
        # No installed source files are edited. A real replace happens before the
        # injected error; the helper must perform its actual recovery write.
        failure_code = '''
import importlib.util, json, sys
from pathlib import Path
path = Path("/opt/zapret-discord-youtube/current/src/gui/privileged.py")
spec = importlib.util.spec_from_file_location("installed_hosts_failure", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
release = module.verify_release()
previous = module.HOSTS.read_bytes()
write = module.write_config
def fail_after_replace(path, data, info, **kwargs):
    write(path, data, info, **kwargs)
    if data != previous:
        raise OSError("VM injected post-replace failure")
module.write_config = fail_after_replace
try:
    module.dispatch(module.make_installer(release), "update-hosts", json.loads(sys.stdin.read()))
except OSError as error:
    assert str(error) == "VM injected post-replace failure", str(error)
else:
    raise AssertionError("injected error was not raised")
assert module.HOSTS.read_bytes() == previous, "recovery did not restore exact bytes"
print("POST_REPLACE_RECOVERY_OK")
'''
        injected = run("python3", "-I", "-c", failure_code, input=json.dumps(payload(stage)))
        require("POST_REPLACE_RECOVERY_OK" in injected.stdout and HOSTS.read_bytes() == second_bytes,
                "post-replace failure restores complete previous hosts bytes")
        require(pid() == service_pid and active(), "recovery does not restart or stop the service")
        helper("update-hosts", payload(stage))
        require(HOSTS.read_bytes() == expected, "helper remains usable after recovery")
        malformed = expected + hosts_module.BEGIN + b"\n"
        HOSTS.write_bytes(malformed)
        helper("update-hosts", payload(stage), success=False)
        require(HOSTS.read_bytes() == malformed, "duplicate/broken markers are rejected without changes")
        HOSTS.write_bytes(expected)
        HOSTS.chmod(0o666)
        helper("update-hosts", payload(stage), success=False)
        require(HOSTS.read_bytes() == expected, "world-writable target is rejected")
        HOSTS.chmod(0o640)
        run("systemctl", "stop", SERVICE)
        run("python3", str(APP / "current/install.py"), "remove")
        installed = False
        require(HOSTS.read_bytes() == expected and backup.read_bytes() == baseline,
                "managed removal preserves hosts and full backup")
        require(not active() and not table_present(), "removal clears application service and rules")
        verify_sentinels(sentinel_snapshot)
    finally:
        # Never leave the disposable guest resolving names through the test block.
        HOSTS.write_bytes(original)
        os.chown(HOSTS, original_info.st_uid, original_info.st_gid)
        HOSTS.chmod(stat.S_IMODE(original_info.st_mode))
        try:
            if installed:
                run("python3", str(APP / "current/install.py"), "remove")
        finally:
            for process in pids_for(WORK / "unrelated-nfqws/nfqws"):
                os.kill(process, signal.SIGTERM)
            run("nft", "delete", "table", "inet", SENTINEL)
    require(HOSTS.read_bytes() == original and stat.S_IMODE(HOSTS.stat().st_mode) == stat.S_IMODE(original_info.st_mode),
            "guest original hosts bytes and permissions restored")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(),
                "url": fetched["url"], "entries": fetched["entries"], "size": fetched["size"],
                "sha256": fetched["sha256"], "original_hosts_sha256": hashlib.sha256(original).hexdigest(),
                "source_sha256": {name: sha(source / name) for name in
                                  ("install.py", "src/gui/privileged.py", "src/gui/backend.py",
                                   "src/lib/hosts_file.py", "src/lib/strategy_sync.py", "ci/vm_hosts_update_smoke.py")}}
    Path("/var/tmp/zapret-hosts-update-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("HOSTS UPDATE VM TEST PASSED (polkit dialog and real DNS/DPI behavior not tested)")


if __name__ == "__main__":
    main()
