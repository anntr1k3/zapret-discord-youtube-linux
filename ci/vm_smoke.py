#!/usr/bin/env python3
"""Destructive integration tests: run as root ONLY in the disposable test VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess


SERVICE = "zapret_discord_youtube.service"
APP = Path("/opt/zapret-discord-youtube")
DATA = Path("/etc/zapret-discord-youtube")
WORK = Path("/var/tmp/zapret-vm-smoke")
SENTINEL = "zapret_vm_sentinel"


def run(*args, check=True, input=None, timeout=120):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
    return result


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message, flush=True)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def current():
    return (APP / "current").resolve(strict=True)


def active():
    return run("systemctl", "is-active", "--quiet", SERVICE, check=False).returncode == 0


def enabled():
    return run("systemctl", "is-enabled", "--quiet", SERVICE, check=False).returncode == 0


def hashes():
    return {str(file.relative_to(DATA)): hashlib.sha256(file.read_bytes()).hexdigest()
            for file in DATA.rglob("*") if file.is_file()}


def pids_for(binary):
    result = []
    for pid in run("pgrep", "-x", "nfqws", check=False).stdout.split():
        try:
            if Path(f"/proc/{pid}/exe").readlink() == binary:
                result.append(int(pid))
        except FileNotFoundError:
            pass
    return result


def table_present():
    return run("nft", "list", "table", "inet", "zapretunix", check=False).returncode == 0


def verify_running():
    require(active(), "systemd service is active after READY notification")
    require(bool(pids_for(current() / "nfqws")), "real nfqws is running from the current release")
    require(table_present(), "application nftables table exists")


def sentinels(source):
    sentinel = WORK / "unrelated-nfqws"
    sentinel.mkdir(exist_ok=True)
    binary = sentinel / "nfqws"
    if not binary.exists():
        shutil.copyfile(source / "nfqws", binary)
        binary.chmod(0o755)
    if not pids_for(binary):
        run(str(binary), "--daemon", "--qnum=221")
    require(bool(pids_for(binary)), "unrelated nfqws process is running in a separate queue")
    if run("nft", "list", "table", "inet", SENTINEL, check=False).returncode:
        run("nft", "-f", "-", input=f'''table inet {SENTINEL} {{
chain output {{
type filter hook output priority 0; policy accept;
ip daddr 192.0.2.254 accept comment "unrelated VM test rule"
}}
}}
''')
    return run("nft", "list", "table", "inet", SENTINEL).stdout


def verify_sentinels(snapshot):
    require(run("nft", "list", "table", "inet", SENTINEL).stdout == snapshot,
            "unrelated nftables rules are unchanged")
    require(bool(pids_for(WORK / "unrelated-nfqws/nfqws")), "unrelated nfqws process survives")


def stop_and_check(snapshot):
    binary = current() / "nfqws"
    run("systemctl", "stop", SERVICE)
    require(not active(), "service stops")
    require(not pids_for(binary), "application nfqws exits on stop")
    require(not table_present(), "application firewall rules are removed on stop")
    verify_sentinels(snapshot)


def network_probe(label):
    # slirp reconstructs traffic: these probes do not prove DPI bypass works.
    probes = {}
    for url in ("https://www.youtube.com", "https://discord.com"):
        result = run("curl", "--silent", "--show-error", "--connect-timeout", "5",
                     "--max-time", "12", "--output", "/dev/null", "--write-out", "%{http_code}",
                     url, check=False, timeout=20)
        probes[url] = {"exit": result.returncode, "http": result.stdout,
                       "error": result.stderr.strip()}
    (WORK / f"network-{label}.json").write_text(json.dumps(probes, indent=2) + "\n")
    print("NETWORK", label, json.dumps(probes), flush=True)


def install_phase(source):
    require(not (APP / "current").exists() and not DATA.exists(), "VM has no previous app installation")
    network_probe("before")
    snapshot = sentinels(source)
    run("python3", str(source / "install.py"), "install", "--source", str(source))
    require(not active() and not enabled(), "default install neither starts nor enables the service")
    require((DATA / "conf.env").is_file(), "configuration is stored in /etc")
    protected = []
    for tree in (APP / "releases", DATA):
        for path in (tree, *tree.rglob("*")):
            info = path.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise AssertionError(f"Unprotected installed file: {path}")
            protected.append(path)
    require(bool(protected), f"all {len(protected)} installed files/directories are root-owned and protected")
    run("systemctl", "enable", "--now", SERVICE)
    verify_running()
    verify_sentinels(snapshot)
    network_probe("running")
    stop_and_check(snapshot)
    run("systemctl", "start", SERVICE)
    verify_running()
    record = {"boot_before": boot_id(), "release": str(current()), "hashes": hashes(),
              "os": Path("/etc/os-release").read_text(), "kernel": run("uname", "-r").stdout.strip()}
    (WORK / "boot-check.json").write_text(json.dumps(record, indent=2) + "\n")
    print("READY FOR REBOOT", flush=True)


def lifecycle_phase(source):
    record = json.loads((WORK / "boot-check.json").read_text())
    require(boot_id() != record["boot_before"], "real VM reboot occurred")
    require(enabled(), "autostart survives reboot")
    verify_running()
    require(str(current()) == record["release"], "same managed release starts after reboot")
    require(hashes() == record["hashes"], "configuration and lists survive reboot")
    snapshot = sentinels(source)

    with (DATA / "user-lists/list-general-user.txt").open("a") as stream:
        stream.write("\nvm-persist.example\n")
    expected_hashes = hashes()
    first_release = current()
    candidate = WORK / "candidate"
    shutil.copytree(source, candidate)
    (candidate / "src/vm-release-note.txt").write_text("VM candidate release\n")

    run("python3", str(source / "install.py"), "update", "--source", str(candidate))
    require(current() != first_release, "active update atomically changes the release")
    verify_running()
    require(not pids_for(first_release / "nfqws"), "old application process is gone after update")
    require(hashes() == expected_hashes, "active update preserves user data")
    verify_sentinels(snapshot)

    run("python3", str(source / "install.py"), "rollback")
    require(current() == first_release, "explicit rollback restores the previous code")
    verify_running()
    require(hashes() == expected_hashes, "rollback preserves current user data")
    verify_sentinels(snapshot)

    stop_and_check(snapshot)
    run("python3", str(source / "install.py"), "update", "--source", str(candidate))
    require(not active() and enabled(), "inactive update does not start the service and preserves autostart")
    require(not table_present(), "inactive update does not create firewall rules")
    run("python3", str(source / "install.py"), "rollback")
    require(not active() and current() == first_release, "inactive rollback does not start the service")

    run("systemctl", "start", SERVICE)
    old_release = current()
    bad = WORK / "bad-candidate"
    shutil.copytree(candidate, bad)
    (bad / "nfqws").write_text("#!/bin/sh\necho 'Intentional VM startup failure' >&2\nexit 42\n")
    failure = run("python3", str(source / "install.py"), "update", "--source", str(bad), check=False)
    (WORK / "expected-update-failure.log").write_text(failure.stdout + failure.stderr)
    require(failure.returncode != 0, "bad nfqws causes update failure instead of false READY")
    require("recovery also failed" not in failure.stderr, "update recovery finishes without a secondary error")
    require(current() == old_release, "failed update restores the previous release")
    verify_running()
    require(hashes() == expected_hashes, "failed update preserves user data")
    verify_sentinels(snapshot)

    run("python3", str(source / "install.py"), "remove")
    require(not active() and not enabled(), "removal stops and disables the service")
    require(not (APP / "current").exists(), "managed current link is removed")
    require(not Path(f"/etc/systemd/system/{SERVICE}").exists(), "managed unit file is removed")
    require(not table_present(), "removal clears only application rules")
    require(hashes() == expected_hashes, "removal preserves configuration and lists")
    require(bool(list(Path("/var/lib/zapret-discord-youtube/backups").glob("*/conf.env"))), "configuration backups remain")
    verify_sentinels(snapshot)

    run("systemctl", "reset-failed", SERVICE, check=False)
    failure = run("python3", str(source / "install.py"), "install", "--source", str(bad), "--start", check=False)
    (WORK / "expected-install-failure.log").write_text(failure.stdout + failure.stderr)
    require(failure.returncode != 0, "initial --start failure is reported")
    require("recovery also failed" not in failure.stderr, "initial install recovery finishes without a secondary error")
    require(not active() and not enabled() and not (APP / "current").exists(), "failed initial install leaves no active/enabled release")
    require(not Path(f"/etc/systemd/system/{SERVICE}").exists(), "failed initial install removes the candidate unit")
    autostart = Path(f"/etc/systemd/system/multi-user.target.wants/{SERVICE}")
    require(not os.path.lexists(autostart), "failed initial install removes the autostart symlink")
    require(hashes() == expected_hashes, "failed initial install keeps retained user data")
    verify_sentinels(snapshot)

    run("systemctl", "reset-failed", SERVICE, check=False)
    run("python3", str(source / "install.py"), "install", "--source", str(source))
    require(not active(), "reinstallation remains inactive by default")
    require(not enabled(), "reinstallation does not inherit a stale autostart link")
    require(hashes() == expected_hashes, "reinstallation reuses retained user data")
    run("python3", str(source / "install.py"), "remove")
    verify_sentinels(snapshot)
    network_probe("after-remove")
    for pid in pids_for(WORK / "unrelated-nfqws/nfqws"):
        os.kill(pid, signal.SIGTERM)
    run("nft", "delete", "table", "inet", SENTINEL)
    record["boot_after"] = boot_id()
    record["lifecycle"] = "passed"
    record["data_preserved"] = True
    record["network_limitation"] = "QEMU user-mode NAT; DPI bypass and Discord voice are not validated"
    (WORK / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print("VM LIFECYCLE PASSED", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("install", "lifecycle"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("This test may only run as root inside the marked disposable zapret-integration VM")
    WORK.mkdir(exist_ok=True, mode=0o700)
    source = args.source.resolve(strict=True)
    try:
        (install_phase if args.phase == "install" else lifecycle_phase)(source)
    except BaseException:
        (WORK / "failure-journal.log").write_text(run("journalctl", "-u", SERVICE, "--no-pager", "-n", "150", check=False).stdout)
        raise


if __name__ == "__main__":
    main()
