#!/usr/bin/env python3
"""Installed GUI helper integration test; only in the marked disposable VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from vm_smoke import APP, DATA, SERVICE, active, enabled, require, run, table_present, verify_running


def helper(action, payload, success=True):
    result = run("/usr/bin/python3", "-I", str(APP / "current/src/gui/privileged.py"),
                 action, input=json.dumps(payload), check=False)
    reply = json.loads(result.stdout)
    require((result.returncode == 0 and reply["ok"]) if success else (result.returncode != 0 and not reply["ok"]),
            f"isolated installed helper: {action} ({'success' if success else 'rejected'}): {reply}")
    return reply.get("result")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root inside the explicitly marked disposable VM")
    require(not (APP / "current").exists(), "no existing managed installation")
    installed = False
    try:
        run("python3", str(args.source / "install.py"), "install", "--source", str(args.source))
        installed = True
        read = helper("read-config", {})
        original = (DATA / "conf.env").read_bytes()
        require(read["sha256"] == hashlib.sha256(original).hexdigest(), "config token matches actual bytes")
        # The public upstream snapshot has Windows filenames with spaces. The
        # existing synchronizer publishes the supported canonical Linux names.
        pending = json.loads((args.cache / "pending.json").read_text())
        helper("apply-strategies", {"stage": pending["stage"], "digest": pending["digest"]})
        helper("select-profile", {"strategy": "general_fake_tls_auto.bat", "expected_sha256": read["sha256"]})
        require(not active() and not table_present(), "inactive profile change does not start service or create firewall rules")
        run("systemctl", "start", SERVICE)
        verify_running()
        pid = run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout
        helper("set-autostart", {"enabled": False})
        require(active() and not enabled(), "autostart disable does not stop active service")
        helper("set-autostart", {"enabled": True})
        require(active() and enabled(), "autostart enable preserves active service")
        helper("select-profile", {"strategy": "../outside.bat", "expected_sha256": read["sha256"]}, success=False)
        helper("select-profile", {"strategy": "general.bat", "expected_sha256": read["sha256"]}, success=False)
        helper("set-autostart", {"enabled": True, "unit": "other.service"}, success=False)
        require(run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout == pid,
                "invalid requests never restart active service")
        read = helper("read-config", {})
        helper("select-profile", {"strategy": "general.bat", "expected_sha256": read["sha256"]})
        verify_running()
        require((DATA / "conf.env").read_bytes() == original, "profile round trip preserves config bytes")
        helper("apply-strategies", {"stage": pending["stage"], "digest": pending["digest"]})
        verify_running()
        helper("rollback", {})
        verify_running()
        require((DATA / "conf.env").read_bytes() == original, "helper apply and rollback preserve configuration")
        read = helper("read-config", {})
        require("game-filter-ranges-v1" in read["capabilities"], "installed helper advertises Game Filter ranges")
        game = {"mode": "all", "tcp_ports": "2000-3000", "udp_ports": "4000,5000-6000",
                "expected_sha256": read["sha256"]}
        updated = helper("set-game-filter", game)
        verify_running()
        require(updated["config"]["gamefiltertcp_ports"] == "2000-3000"
                and updated["config"]["gamefilterudp_ports"] == "4000,5000-6000",
                "custom TCP and UDP ranges survive authenticated config round trip")
        pid = run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout
        helper("set-game-filter", {**game, "tcp_ports": "65536", "expected_sha256": updated["sha256"]}, success=False)
        helper("set-game-filter", game, success=False)
        require(run("systemctl", "show", SERVICE, "--property=MainPID", "--value").stdout == pid,
                "invalid range and stale token do not restart active service")
        run("systemctl", "stop", SERVICE)
        helper("set-game-filter", {**game, "mode": "disabled", "expected_sha256": updated["sha256"]})
        require(not active() and not table_present(), "inactive Game Filter edit does not start service or create rules")
        # The marked disposable test VM restores its initial config after testing
        # appended optional fields, before the existing installer cleanup.
        (DATA / "conf.env").write_bytes(original)
    finally:
        if installed:
            run("python3", str(APP / "current/install.py"), "remove")
    require(not active() and not table_present(), "VM cleanup removes service and application firewall")
    print("GUI HELPER VM TEST PASSED (authorization UI not tested)")


if __name__ == "__main__":
    main()
