#!/usr/bin/env python3
"""Install and exercise the exact Debian artifact in a marked disposable VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from vm_smoke import APP, DATA, SERVICE, active, enabled, hashes, require, run, table_present, verify_running


PACKAGE = "zapret-discord-youtube"
APPLICATION = Path("/usr/lib") / PACKAGE
STATE = Path("/var/lib") / PACKAGE


def bootstrap(action, **payload):
    result = run("/usr/bin/python3", "-I", str(APPLICATION / "src/gui/bootstrap.py"),
                 action, input=json.dumps(payload))
    reply = json.loads(result.stdout)
    require(reply["ok"], f"packaged bootstrap: {action}")
    return reply["result"]


def tester_roundtrip(*, initially_active, lose_ack=False):
    # Root runs this harness, not the GUI. Keep test-created bytecode out of the
    # package tree so it cannot survive dpkg removal as an unmanaged file.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(APPLICATION / "src/lib"))
    try:
        from strategy_test_client import StreamingTesterRunner, load_message_channel
    finally:
        sys.path.pop(0)

    def direct_helper(argv):
        # Exercise the real pipe protocol, but not graphical authorization.
        return subprocess.Popen(argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class DelayedAck(load_message_channel()):
        def receive(self, timeout):
            if lose_ack and timeout == 30.0:
                raise TimeoutError("simulated late start acknowledgement")
            return super().receive(timeout)

    strategy = "general_alt12.bat"
    saved = hashes()
    original_autostart = enabled()
    runner = StreamingTesterRunner(APP / "current/src/gui/privileged.py", [strategy], saved["conf.env"],
                                   spawn=direct_helper, channel_cls=DelayedAck)
    snapshot = runner.snapshot()
    try:
        require(not active() and not table_present(), "snapshot leaves managed service inactive")
        if lose_ack:
            try:
                runner.start(strategy)
            except RuntimeError as error:
                require("simulated late start acknowledgement" in str(error), "client rejects the timed-out start")
            else:
                raise AssertionError("simulated timeout unexpectedly accepted")
        else:
            runner.start(strategy)
            tables = run("nft", "list", "tables").stdout
            require("zapret_test_" in tables, "isolated nft table exists during the test")
            runner.stop()
    finally:
        runner.restore(snapshot)
    require(runner.restored and not any("zapret_test_" in line for line in run("nft", "list", "tables").stdout.splitlines()),
            "tester protocol confirms restoration and isolated rules are gone")
    require(active() == initially_active and table_present() == initially_active
            and enabled() == original_autostart and hashes() == saved,
            "tester restores original service state, autostart and data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--legacy-artifact", type=Path, help="test upgrade from the published v1.0.0 .deb")
    parser.add_argument("--tester", action="store_true", help="also exercise the real tester pipe protocol")
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root inside the explicitly marked disposable VM")
    artifact = args.artifact.resolve(strict=True)
    legacy = args.legacy_artifact.resolve(strict=True) if args.legacy_artifact else None
    # Installed commands must never depend on the current working directory.
    os.chdir("/")
    require(run("dpkg-deb", "-f", artifact, "Package").stdout.strip() == PACKAGE, "expected package name")
    print("Artifact SHA-256:", hashlib.sha256(artifact.read_bytes()).hexdigest(), flush=True)
    require(not any(os.path.lexists(path) for path in (APP, DATA, STATE, APPLICATION)),
            "fresh guest: no application, service, or saved data")
    status = run("dpkg-query", "-W", "-f=${Status}", PACKAGE, check=False)
    require(status.returncode != 0 and not active() and not enabled() and not table_present(),
            "no old package or running service")
    require(run("systemctl", "show", "-p", "LoadState", "--value", SERVICE, check=False).stdout.strip()
            == "not-found", "no existing systemd unit")

    if legacy:
        require(run("dpkg-deb", "-f", legacy, "Package").stdout.strip() == PACKAGE
                and run("dpkg-deb", "-f", legacy, "Version").stdout.strip() == "1.0.0",
                "legacy package is v1.0.0")
        print("Legacy SHA-256:", hashlib.sha256(legacy.read_bytes()).hexdigest(), flush=True)
        run("apt-get", "-y", "install", legacy, timeout=600)
        require((APP / "current/gui.py").is_file() and not (APP / "current").is_symlink(),
                "legacy package created the old real current directory")

    run("apt-get", "-y", "install", artifact, timeout=600)
    require((APPLICATION / "gui.py").is_file()
            and not any(os.path.lexists(path) for path in (APP / "current", DATA, STATE)),
            "package installs only the permanent application")
    require(not active() and not enabled() and not table_present(), "package install leaves networking unchanged")

    require(bootstrap("install-service", strategy=None, start=True) == {"installed": True, "started": True},
            "default install starts and enables the service")
    verify_running()
    require(enabled(), "auto-start enabled")
    require("general_alt12.bat" in run("/usr/bin/zapret", "strategy", "list").stdout,
            "installed CLI resolves profiles from an unrelated CWD")
    run("/usr/bin/zapret", "service", "stop")
    require(not active() and not table_present(), "CLI stop cleans the active service")
    run("/usr/bin/zapret", "service", "start")
    require(active() and table_present(), "CLI start restores the service")
    config = DATA / "conf.env"
    require("strategy=general_alt12.bat" in config.read_text(), "bootstrap selected ALT12")
    (DATA / "user-lists/list-general-user.txt").write_text("example.org\n")
    saved = hashes()
    if args.tester:
        tester_roundtrip(initially_active=True)
        tester_roundtrip(initially_active=True, lose_ack=True)

    require(bootstrap("remove-service", purge=False) == {"removed": True, "purged": False},
            "service removal without purge")
    require(not active() and not enabled() and not table_present() and not (APP / "current").is_symlink(),
            "service is inactive, disabled and removed")
    require((APPLICATION / "gui.py").is_file() and hashes() == saved, "application and data preserved")

    bootstrap("install-service", strategy="general.bat", start=False)
    require(not active() and not enabled() and not table_present() and hashes() == saved,
            "reinstall respects start=false and saved ALT12 and user lists")
    if args.tester:
        tester_roundtrip(initially_active=False)
    run("apt-get", "-y", "remove", PACKAGE, timeout=300)
    require(not APPLICATION.exists() and (APP / "current").is_symlink() and hashes() == saved,
            "removing the application does not remove the independently managed service")
    run("apt-get", "-y", "install", artifact, timeout=600)

    lock = STATE / ".install.lock"
    inode = lock.stat().st_ino
    require(bootstrap("remove-service", purge=True) == {"removed": True, "purged": True},
            "service removal with purge")
    require(not DATA.exists() and not table_present() and {entry.name for entry in STATE.iterdir()}
            == {".managed", ".install.lock"}, "purge removes data and backups only")
    require(lock.stat().st_ino == inode and (APPLICATION / "src/gui/bootstrap.py").is_file(),
            "purge preserves the lock and packaged bootstrap")
    print("DEB VM SMOKE PASSED (direct root helper; interactive polkit not tested)")


if __name__ == "__main__":
    main()
