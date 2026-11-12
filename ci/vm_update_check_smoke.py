#!/usr/bin/env python3
"""Check-only user timer: run ONLY as root in the marked disposable guest."""

import argparse
import json
import os
from pathlib import Path

from vm_ipset_update_smoke import sha, tree_hashes
from vm_smoke import APP, DATA, SERVICE, active, require, run, table_present


TIMER = "zapret-update-check.timer"
CHECK_SERVICE = "zapret-update-check.service"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    uid = run("id", "-u", "vmtest").stdout.strip()
    def user(*command, **kwargs):
        return run("runuser", "-u", "vmtest", "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                   f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus", *command, **kwargs)
    config = Path("/home/vmtest/.config/systemd/user")
    cache = Path("/home/vmtest/.cache/zapret-check-vm")
    names = (TIMER, CHECK_SERVICE, "zapret-strategy-sync.timer", "zapret-strategy-sync.service")
    require(all(not (config / name).exists() and not (config / name).is_symlink() for name in names),
            "no previous user timer units to overwrite")
    require(not active() and not table_present(), "application service and rules are initially absent")
    data_before, app_before = tree_hashes(DATA), tree_hashes(APP)
    source_before = tree_hashes(source)
    invoke = '''
import importlib.util, json, sys
from pathlib import Path
source, cache, action = sys.argv[1:]
spec = importlib.util.spec_from_file_location("vm_update_check", Path(source) / "src/lib/update_check.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
timer = module.UpdateCheck(source, cache)
result = timer.status() if action == "status" else timer.set_enabled(action == "enable")
print(json.dumps(result))
'''
    def call(action):
        return json.loads(user("python3", "-B", "-c", invoke, str(source), str(cache), action).stdout)
    try:
        status = call("status")
        require(status["enabled"] is False and status["error"] is None, "missing timer reports disabled with working user bus")
        status = call("enable")
        require(status["enabled"] and status["active"], "timer enabled and active in real user systemd")
        require(bool(status["next_check"]), "next check is scheduled")
        service = (config / CHECK_SERVICE).read_text()
        require('"check"' in service and '"prepare"' not in service and "pkexec" not in service,
                "generated service runs check only, without privilege escalation")
        require((config / CHECK_SERVICE).stat().st_uid == int(uid), "units belong to desktop user")
        user("systemctl", "--user", "start", CHECK_SERVICE)
        status = call("status")
        record = status["last_check"]
        require(record and record["status"] == "checked" and record.get("revision"),
                "real systemd service retrieves Flowseal metadata and records result")
        require(record.get("checked_at") and type(record.get("update_available")) is bool,
                "last check includes timestamp and availability")
        require(not (cache / "pending.json").exists() and not (cache / "stages").exists(),
                "check creates no archive stage or prepared update")
        require(tree_hashes(DATA) == data_before and tree_hashes(APP) == app_before
                and tree_hashes(source) == source_before, "check leaves installed data, code and source unchanged")
        require(not active() and not table_present(), "check starts no application service/firewall")
        dropdir = config / (CHECK_SERVICE + ".d")
        dropdir.mkdir()
        dropin = dropdir / "vm-timeout.conf"
        try:
            dropin.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/sleep 5\nTimeoutStartSec=1\n")
            user("systemctl", "--user", "daemon-reload")
            failed = user("systemctl", "--user", "start", CHECK_SERVICE, check=False)
            require(failed.returncode != 0, "injected real user service timeout occurs")
            require("timeout" in (call("status")["execution_error"] or ""),
                    "systemd timeout is visible even with an older successful metadata check")
        finally:
            dropin.unlink(missing_ok=True)
            dropdir.rmdir()
            user("systemctl", "--user", "daemon-reload")
        user("systemctl", "--user", "start", CHECK_SERVICE)
        require(call("status")["execution_error"] is None, "successful retry clears service execution error")
        record = call("status")["last_check"]
        status = call("disable")
        require(status["enabled"] is False and status["active"] is False,
                "disable stops and disables only the check timer")
        require(status["last_check"] == record, "disable preserves last check result")
        # Existing CLI preparation timer is separate and must not be disabled.
        user("python3", str(source / "src/lib/strategy_sync.py"), "timer-install",
             "--base", str(source), "--cache", str(cache))
        user("systemctl", "--user", "daemon-reload")
        user("systemctl", "--user", "enable", "zapret-strategy-sync.timer")
        require(call("status")["preparation_enabled"] is True, "separate legacy preparation schedule is reported")
        call("enable")
        call("disable")
        require(call("status")["preparation_enabled"] is True, "check toggle does not change preparation schedule")
    finally:
        for timer in (TIMER, "zapret-strategy-sync.timer"):
            user("systemctl", "--user", "disable", "--now", timer, check=False)
        user("systemctl", "--user", "stop", CHECK_SERVICE, check=False)
        for name in names:
            (config / name).unlink(missing_ok=True)
        user("systemctl", "--user", "daemon-reload")
    require(not active() and not table_present(), "VM application service/firewall remains unchanged")
    evidence = {"status": "passed", "last_check": record,
                "kernel": run("uname", "-r").stdout.strip(),
                "source_sha256": {name: sha(source / name) for name in
                                  ("src/lib/update_check.py", "src/lib/strategy_sync.py", "ci/vm_update_check_smoke.py")}}
    Path("/var/tmp/zapret-update-check-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("UPDATE CHECK VM TEST PASSED (desktop GUI and reboot not tested)")


if __name__ == "__main__":
    main()
