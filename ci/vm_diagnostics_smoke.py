#!/usr/bin/env python3
"""Unprivileged diagnostics integration, ONLY in an explicitly marked VM."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal

from vm_ipset_update_smoke import pid, sha, tree_hashes
from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, pids_for, require,
                      run, sentinels, table_present, verify_running, verify_sentinels)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    require(not (APP / "current").exists() and not DATA.exists(), "VM has no application installation")
    uid = run("id", "-u", "vmtest").stdout.strip()
    fixture = Path("/home/vmtest/diagnostics-keyfile-fixture")
    target = Path("/home/vmtest/diagnostics-export.json")
    require(not fixture.exists() and not target.exists(), "no preexisting diagnostic fixture or export")
    def user(*argv, **kwargs):
        return run("runuser", "-u", "vmtest", "--", "env", "PYTHONDONTWRITEBYTECODE=1",
                   f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                   "GSETTINGS_BACKEND=keyfile", f"XDG_CONFIG_HOME={fixture}",
                   "HTTPS_PROXY=https://diaguser:DiagSecret@proxy.example:8443/private?token=DiagToken",
                   "no_proxy=PrivateExclusion.internal", *argv, **kwargs)
    def setting(schema, key, value):
        user("gsettings", "set", schema, key, value)
    setting("org.gnome.system.proxy", "mode", "manual")
    setting("org.gnome.system.proxy.http", "host", "proxy.example")
    setting("org.gnome.system.proxy.http", "port", "8080")
    setting("org.gnome.system.proxy.http", "use-authentication", "true")
    setting("org.gnome.system.proxy.http", "authentication-user", "DummyGnomeUser")
    setting("org.gnome.system.proxy.http", "authentication-password", "DummyGnomePassword")
    require(user("gsettings", "get", "org.gnome.system.proxy", "mode").stdout.strip() == "'manual'",
            "real gsettings fixture uses isolated keyfile, not desktop settings")
    WORK.mkdir(exist_ok=True, mode=0o700)
    sentinel = sentinels(source)
    installed = False
    code = '''
import importlib.util, json, sys
from pathlib import Path
source, target = sys.argv[1:]
spec = importlib.util.spec_from_file_location("vm_diagnostics_backend", Path(source) / "src/gui/backend.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
backend = module.Backend(source)
report = backend.diagnostics()
backend.export_diagnostics(target)
print(json.dumps(report))
'''
    def diagnose():
        return json.loads(user("python3", "-B", "-c", code, str(source), str(target)).stdout)
    def check(report, key):
        return next(item for item in report["checks"] if item["id"] == key)
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        run("systemctl", "start", SERVICE)
        verify_running()
        process = pid()
        rules = run("nft", "--stateless", "list", "ruleset").stdout
        before_data, before_code = tree_hashes(DATA), tree_hashes((APP / "current").resolve())
        before_settings = tree_hashes(fixture)
        before_hosts = sha("/etc/hosts")
        timestamps = Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes()
        report = diagnose()
        require(report["schema"] == 1 and len(report["checks"]) >= 10, "ordinary-user backend produces structured diagnostics")
        serialized = json.dumps(report)
        for secret in ("DiagSecret", "DiagToken", "diaguser", "PrivateExclusion", "DummyGnomeUser", "DummyGnomePassword"):
            require(secret not in serialized and secret not in target.read_text(), f"dummy credential/exclusion redacted: {secret}")
        require("proxy.example" in serialized, "sanitized proxy host remains useful")
        require(check(report, "proxy-gnome")["state"] == "warning", "real GNOME manual proxy observed")
        require(check(report, "paths")["state"] == "observed", "installed paths and root protection verified without execution")
        require(check(report, "user-lists")["state"] == "observed", "user lists located without reading their contents")
        require(check(report, "possible-conflicts")["state"] == "warning"
                and "nfqws" in " ".join(check(report, "possible-conflicts")["details"]),
                "actual engine processes reported only as possible conflicts")
        require(check(report, "windows-only")["state"] == "not-applicable", "Windows checks explicitly not applicable")
        require(json.loads(target.read_text()) == report and target.stat().st_uid == int(uid)
                and target.stat().st_mode & 0o777 == 0o600, "export matches redacted report and is user-owned/private")
        require(tree_hashes(DATA) == before_data and tree_hashes((APP / "current").resolve()) == before_code,
                "diagnostics changes no application config, lists or code")
        require(tree_hashes(fixture) == before_settings and sha("/etc/hosts") == before_hosts
                and Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes() == timestamps,
                "GNOME settings, hosts and sysctl are unchanged")
        require(pid() == process and run("nft", "--stateless", "list", "ruleset").stdout == rules,
                "service PID and firewall structure unchanged")
        verify_sentinels(sentinel)
        setting("org.gnome.system.proxy", "mode", "auto")
        setting("org.gnome.system.proxy", "autoconfig-url", "https://proxy.example/PrivatePacToken?secret=PacSecret")
        pac = diagnose()
        require("PrivatePacToken" not in json.dumps(pac) and "PacSecret" not in target.read_text(),
                "real GNOME PAC URL is neither fetched nor exported")
        run("systemctl", "stop", SERVICE)
        stopped = diagnose()
        require(stopped["checks"] and not active() and not table_present(), "stopped diagnostic does not start service or rules")
        verify_sentinels(sentinel)
    finally:
        try:
            if installed:
                run("python3", str(APP / "current/install.py"), "remove")
        finally:
            for process_id in pids_for(WORK / "unrelated-nfqws/nfqws"):
                os.kill(process_id, signal.SIGTERM)
            run("nft", "delete", "table", "inet", SENTINEL)
            target.unlink(missing_ok=True)
            if fixture.exists():
                shutil.rmtree(fixture)
    require(not active() and not table_present(), "VM app service and firewall cleaned up")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(), "report": report,
                "source_sha256": {name: sha(source / name) for name in
                                  ("src/lib/diagnostics.py", "src/gui/backend.py", "src/gui/presentation.py",
                                   "src/gui/app.py", "ci/vm_diagnostics_smoke.py")}}
    Path("/var/tmp/zapret-diagnostics-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("DIAGNOSTICS VM TEST PASSED (desktop clipboard/file chooser and DPI bypass not tested)")


if __name__ == "__main__":
    main()
