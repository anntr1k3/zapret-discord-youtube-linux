#!/usr/bin/env python3
"""Version metadata across a real data update, ONLY in a marked disposable VM."""

import argparse
import json
import os
from pathlib import Path

from vm_gui_smoke import helper
from vm_ipset_update_smoke import sha, tree_hashes
from vm_smoke import APP, DATA, active, require, run, table_present


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--saved-check", type=Path,
                        help="Replay historical last_check evidence, preserving its time; pin archive preparation to it")
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    saved_check = json.loads(args.saved_check.read_text())["last_check"] if args.saved_check else None
    require(not (APP / "current").exists() and not active() and not table_present(),
            "VM has no active or installed application service")
    uid = run("id", "-u", "vmtest").stdout.strip()
    cache = Path("/home/vmtest/.cache/zapret-versions-vm")
    invoke = '''
import importlib.util, json, sys
from pathlib import Path
source, cache, action, saved = sys.argv[1:]
spec = importlib.util.spec_from_file_location("vm_version_backend", Path(source) / "src/gui/backend.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
backend = module.Backend(source, cache=cache)
record = json.loads(saved)
if record:
    spec = importlib.util.spec_from_file_location("vm_version_sync", Path(source) / "src/lib/strategy_sync.py")
    sync = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync)
    target = {key: record[key] for key in ("revision", "channel", "tag")}
    assert record["status"] == "checked" and record["checked_at"] and sync.valid_target(target, "release")
    if action == "check":
        Path(cache).mkdir(parents=True, exist_ok=True)
        sync.atomic_json(Path(cache) / "last-update-check.json", record)
        print(json.dumps(record))
        sys.exit(0)
    if action == "prepare":
        print(json.dumps(sync.prepare(backend.base(), Path(cache), target=target)))
        sys.exit(0)
actions = {"snapshot": backend.snapshot, "check": backend.check_update, "prepare": backend.prepare_update}
print(json.dumps(actions[action]()))
'''
    def user(action):
        result = run("runuser", "-u", "vmtest", "--", "env", "PYTHONDONTWRITEBYTECODE=1",
                     f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                     "python3", "-B", "-c", invoke, str(source), str(cache), action,
                     json.dumps(saved_check), timeout=240)
        return json.loads(result.stdout)
    checkout = user("snapshot")["versions"]
    require(checkout["scope"] == "checkout" and checkout["installed_app"] is None,
            "uninstalled source is labelled checkout, not a system installation")
    require(checkout["running_app"]["version"] == "1.0.0-dev" and not checkout["running_app"]["release"],
            "development application version is explicitly not a release")
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        before = tree_hashes(DATA)
        original_code = tree_hashes((APP / "current").resolve() / "src")
        initial = user("snapshot")["versions"]
        require(initial["scope"] == "installed" and initial["installed_app"]["version"] == "1.0.0-dev",
                "packaged src application metadata survives real install and is user-readable")
        require(initial["current"]["revision"] is None and initial["relation"] == "unknown",
                "legacy data without provenance remains unknown, not service.bat version")
        checked = user("check")
        after_check = user("snapshot")["versions"]
        require(after_check["checked"]["revision"] == checked["revision"]
                and after_check["checked"]["tag"] == checked["tag"],
                "backend shows saved historical Flowseal check separately from application" if saved_check else
                "backend shows actual checked Flowseal release separately from application")
        require(after_check["checked"]["release_url"].startswith(
                    "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/"),
                "checked release link is derived from fixed official repository")
        prepared = user("prepare")
        after_prepare = user("snapshot")["versions"]
        require(after_prepare["current"] == initial["current"] and after_prepare["running_app"] == initial["running_app"],
                "real preparation does not become installed data or application version")
        helper("apply-strategies", {"stage": prepared["stage"], "digest": prepared["digest"]})
        final_snapshot = user("snapshot")
        final = final_snapshot["versions"]
        require(final_snapshot["pending"] is None, "already applied pending is not offered again as unapplied")
        require(final["current"]["revision"] == checked["revision"] and final["relation"] == "same",
                "after real apply current provenance matches last checked revision")
        require(final["current"]["release_url"] == after_check["checked"]["release_url"],
                "installed provenance now links to the checked release")
        require(final["running_app"] == initial["running_app"] and final["installed_app"] == initial["installed_app"],
                "Flowseal update does not change application version")
        require(tree_hashes((APP / "current").resolve() / "src") == original_code,
                "data update preserves actual application source files including version metadata")
        require(tree_hashes(DATA) == before, "version read/check/prepare/apply preserves user config and lists")
        require(not active() and not table_present(), "stopped service remains stopped without firewall rules")
    finally:
        if installed:
            run("python3", str(APP / "current/install.py"), "remove")
    require(not active() and not table_present() and not (APP / "current").exists(), "VM managed installation cleaned up")
    evidence = {"status": "passed", "historical_check_replayed": bool(saved_check),
                "kernel": run("uname", "-r").stdout.strip(), "versions": final,
                "source_sha256": {name: sha(source / name) for name in
                                  ("src/app-version.json", "src/lib/version_info.py", "src/gui/backend.py",
                                   "src/gui/presentation.py", "src/gui/app.py", "ci/vm_versions_smoke.py")}}
    Path("/var/tmp/zapret-versions-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("VERSIONS VM TEST PASSED (desktop links, polkit dialog and real DPI bypass not tested)")


if __name__ == "__main__":
    main()
