#!/usr/bin/env python3
"""Strategy-only integration tests: disposable marked VM, never the host."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys

from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, boot_id, enabled,
                      hashes, network_probe, pids_for, require, run, sentinels,
                      stop_and_check, table_present, verify_running, verify_sentinels)


RESULTS = Path("/var/tmp/zapret-sync-smoke")


def helper(source):
    spec = importlib.util.spec_from_file_location("sync_vm_test", source / "src/lib/strategy_sync.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def apply(source, stage, digest, check=True):
    return run("python3", str(APP / "current/install.py"), "apply-strategies",
               "--stage", str(stage), "--digest", digest, "--yes", check=check, timeout=240)


def install_phase(source, cache):
    require(not (APP / "current").exists(), "VM has no existing managed installation")
    sync = helper(source)
    pending = json.loads((cache / "pending.json").read_text())
    stage, digest = Path(pending["stage"]), pending["digest"]
    manifest, files = sync.load_stage(stage, digest)
    compiled = sync.compile_payload(files)
    snapshot = sentinels(source)
    run("python3", str(source / "install.py"), "install", "--source", str(source), "--start")
    verify_running()
    before = (APP / "current").resolve()
    data_hashes = hashes()
    code_hashes = {name: sync.sha256((before / name).read_bytes()) for name in
                   ("nfqws", "service.sh", "install.py", "src/lib/common.sh", "src/lib/strategy_sync.py")}

    apply(source, stage, digest)
    after = (APP / "current").resolve()
    require(after != before, "strategy-only update creates a separate managed release")
    verify_running()
    require(not pids_for(before / "nfqws"), "old application process exits")
    require(hashes() == data_hashes, "configuration and user lists are byte-for-byte unchanged")
    require(all(sync.sha256((after / name).read_bytes()) == value for name, value in code_hashes.items()),
            "strategy update leaves engine and adapter code unchanged")
    catalog = json.loads((after / "zapret-latest/strategies.json").read_text())
    require(len(catalog["strategies"]) == len(compiled), "all prepared strategies are installed")
    require(sync.installed_revision(after) == manifest["revision"], "upstream commit provenance is recorded")
    pid = pids_for(after / "nfqws")[0]
    command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    require(not any(b".package-" in token or b".dry-run-" in token for token in command),
            "running arguments contain no temporary validation paths")
    require(any(b"/etc/zapret-discord-youtube/user-lists/" in token for token in command),
            "running nfqws reads persistent user lists")
    verify_sentinels(snapshot)

    main_pid = run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout.strip()
    apply(source, stage, digest)
    require(run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout.strip() == main_pid,
            "applying the same digest is a no-op without a restart")
    bad_stage = RESULTS / "tampered-stage"
    shutil.copytree(stage, bad_stage)
    (bad_stage / "payload/general.bat").write_bytes(b"tampered")
    failed = apply(source, bad_stage, digest, check=False)
    require(failed.returncode != 0, "tampered stage is rejected")

    bad_files = dict(files)
    bad_files["general.bat"] = bad_files["general.bat"].replace(b"--dpi-desync=fake", b"--dpi-desync=invalid-vm-test-mode")
    _, bad_digest = sync.write_stage(RESULTS / "incompatible-stage", bad_files,
                                    {key: manifest[key] for key in ("revision", "channel", "tag")})
    failed = apply(source, RESULTS / "incompatible-stage", bad_digest, check=False)
    (RESULTS / "expected-incompatible.log").write_text(failed.stdout + failed.stderr)
    require(failed.returncode != 0 and "nfqws rejected" in failed.stderr,
            "engine-incompatible strategy is rejected by real nfqws dry-run")
    require(run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout.strip() == main_pid,
            "rejected updates never stop the working service")
    require((APP / "current").resolve() == after and hashes() == data_hashes,
            "rejected updates leave code selection and data unchanged")
    verify_sentinels(snapshot)
    network_probe("synchronized")
    record = {"boot_before": boot_id(), "before": str(before), "after": str(after),
              "data_hashes": data_hashes, "code_hashes": code_hashes, "revision": manifest["revision"],
              "digest": digest, "strategies": len(compiled)}
    (RESULTS / "record.json").write_text(json.dumps(record, indent=2))
    print("SYNC READY FOR REBOOT", flush=True)


def after_reboot(source, cache):
    sync = helper(source)
    record = json.loads((RESULTS / "record.json").read_text())
    pending = json.loads((cache / "pending.json").read_text())
    require(boot_id() != record["boot_before"], "real reboot occurred after synchronization")
    verify_running()
    require(enabled(), "synchronized service retains autostart")
    require(sync.installed_revision((APP / "current").resolve()) == record["revision"],
            "compiled catalog is used successfully after boot")
    require(hashes() == record["data_hashes"], "user data survives synchronization and reboot")
    snapshot = sentinels(source)
    run("python3", str(APP / "current/install.py"), "rollback")
    require(str((APP / "current").resolve()) == record["before"], "rollback restores the pre-sync release")
    require(not (APP / "current/zapret-latest/strategies.json").exists(), "rollback restores the legacy strategy representation")
    verify_running()
    stop_and_check(snapshot)
    apply(source, Path(pending["stage"]), pending["digest"])
    require(not active() and enabled(), "inactive strategy update does not start the service or disable autostart")
    require(not table_present(), "inactive synchronization creates no firewall rules")
    run("systemctl", "start", SERVICE)
    verify_running()
    require(hashes() == record["data_hashes"], "reapplication still preserves user data")
    verify_sentinels(snapshot)
    run("python3", str(APP / "current/install.py"), "remove")
    require(not active() and not table_present(), "synchronized service removes cleanly")
    require(hashes() == record["data_hashes"], "removal preserves persistent user data")
    verify_sentinels(snapshot)
    for pid in pids_for(WORK / "unrelated-nfqws/nfqws"):
        os.kill(pid, signal.SIGTERM)
    run("nft", "delete", "table", "inet", SENTINEL)
    record["boot_after"] = boot_id()
    record["status"] = "passed"
    (RESULTS / "result.json").write_text(json.dumps(record, indent=2))
    print("SYNC VM TEST PASSED", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("install", "after-reboot"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Run only as root inside the explicitly marked disposable VM")
    RESULTS.mkdir(exist_ok=True, mode=0o700)
    WORK.mkdir(exist_ok=True, mode=0o700)
    try:
        (install_phase if args.phase == "install" else after_reboot)(args.source.resolve(), args.cache.resolve())
    except BaseException:
        (RESULTS / "failure-journal.log").write_text(run("journalctl", "-u", SERVICE, "--no-pager", "-n", "150", check=False).stdout)
        raise


if __name__ == "__main__":
    main()
