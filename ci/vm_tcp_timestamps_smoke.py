#!/usr/bin/env python3
"""Actual kernel sysctl tests ONLY in a marked disposable integration guest."""

import argparse
import json
import os
from pathlib import Path
import signal

from vm_gui_smoke import helper
from vm_ipset_update_smoke import pid, sha, tree_hashes
from vm_smoke import (APP, DATA, SERVICE, SENTINEL, WORK, active, pids_for, require,
                      run, sentinels, table_present, verify_running, verify_sentinels)


TARGET = Path("/proc/sys/net/ipv4/tcp_timestamps")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    require(not (APP / "current").exists() and not active() and not table_present(), "no active app installation in VM")
    original = TARGET.read_text()
    require(original.strip() in ("0", "1", "2"), "guest timestamps has supported original value")
    persistent_before = {name: tree_hashes(Path(name)) for name in ("/etc/sysctl.d", "/usr/lib/sysctl.d", "/run/sysctl.d")}
    hosts_before = sha("/etc/hosts")
    WORK.mkdir(exist_ok=True, mode=0o700)
    sentinel = sentinels(source)
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        require("tcp-timestamps-enable-v1" in helper("read-config", {})["capabilities"], "installed helper advertises fixed-key runtime action")
        data_before = tree_hashes(DATA)
        code_before = tree_hashes((APP / "current").resolve())
        for value in ("1", "2"):
            TARGET.write_text(value + "\n")  # Test fixture, never production UI.
            observed = helper("read-tcp-timestamps", {})
            result = helper("enable-tcp-timestamps", {"expected_value": value})
            require(observed["enabled"] is True and not result["changed"] and TARGET.read_text().strip() == value,
                    f"already enabled mode {value} is preserved")
        TARGET.write_text("0\n")
        require(helper("read-tcp-timestamps", {})["enabled"] is False, "explicit root read observes disabled kernel value")
        helper("enable-tcp-timestamps", {"expected_value": "2"}, success=False)
        helper("enable-tcp-timestamps", {"expected_value": "0", "value": "0"}, success=False)
        helper("enable-tcp-timestamps", {"expected_value": "0", "path": "/etc/sysctl.conf"}, success=False)
        require(TARGET.read_text().strip() == "0", "stale token and extended payloads cause no write")
        result = helper("enable-tcp-timestamps", {"expected_value": "0"})
        require(result["changed"] and TARGET.read_text().strip() == "1", "real inactive enable writes kernel value 1")
        require(not active() and not table_present(), "inactive enable starts no service or rules")

        run("systemctl", "start", SERVICE)
        verify_running()
        before_pid = pid()
        before_rules = run("nft", "--stateless", "list", "ruleset").stdout
        TARGET.write_text("0\n")
        helper("enable-tcp-timestamps", {"expected_value": "0"})
        require(TARGET.read_text().strip() == "1" and pid() == before_pid, "active enable leaves running service PID unchanged")
        config = DATA / "conf.env"
        config_bytes = config.read_bytes()
        try:
            config.write_text("unsupported_setting=invalid\n")
            TARGET.write_text("0\n")
            helper("enable-tcp-timestamps", {"expected_value": "0"})
            require(TARGET.read_text().strip() == "1" and config.read_text() == "unsupported_setting=invalid\n",
                    "action works with invalid config without repairing or executing it")
        finally:
            config.write_bytes(config_bytes)

        # Isolated interpreter imports only the installed module; source files
        # stay immutable while real kernel writes exercise recovery.
        injected = r'''
import importlib.util, sys
from pathlib import Path
path = Path('/opt/zapret-discord-youtube/current/src/gui/privileged.py')
spec = importlib.util.spec_from_file_location('installed_timestamp_failure', path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
release = helper.verify_release()
runtime = helper.load_tcp_timestamps()
helper.load_tcp_timestamps = lambda: runtime
original_write = runtime.write_value
mode = sys.argv[1]
def write(value):
    original_write(value)
    if value == '1':
        if mode == 'external':
            runtime.TARGET.write_text('2\n')
        else:
            raise OSError('VM injected post-write failure')
runtime.write_value = write
try:
    helper.dispatch(helper.make_installer(release), 'enable-tcp-timestamps', {'expected_value': '0'})
except OSError as error:
    assert mode == 'recover' and str(error) == 'VM injected post-write failure', str(error)
    assert runtime.read_value() == '0'
except RuntimeError as error:
    assert mode == 'external' and 'параллель' in str(error), str(error)
    assert runtime.read_value() == '2'
else:
    raise AssertionError('expected injection failure was not reported')
print('INJECTION_OK')
'''
        for mode, expected in (("recover", "0"), ("external", "2")):
            TARGET.write_text("0\n")
            # -I ignores PYTHONDONTWRITEBYTECODE. Explicit -B prevents this
            # test-only import from creating .pyc inside the installed release.
            result = run("python3", "-I", "-B", "-c", injected, mode)
            require("INJECTION_OK" in result.stdout and TARGET.read_text().strip() == expected,
                    "post-write failure restores zero" if mode == "recover" else "different external value 2 is preserved without blind rollback")

        # Remount only a private child mount namespace, never the guest's
        # original /proc/sys. Production helper does not remount anything.
        TARGET.write_text("0\n")
        readonly_code = r'''
import json, subprocess
subprocess.run(['mount', '--bind', '/proc/sys', '/proc/sys'], check=True)
subprocess.run(['mount', '-o', 'remount,bind,ro', '/proc/sys'], check=True)
result = subprocess.run(['/usr/bin/python3', '-I', '/opt/zapret-discord-youtube/current/src/gui/privileged.py',
                         'enable-tcp-timestamps'], input='{"expected_value":"0"}', capture_output=True, text=True)
reply = json.loads(result.stdout)
assert result.returncode != 0 and reply['ok'] is False, reply
assert 'Read-only file system' in reply['error'], reply
print('READONLY_REFUSAL_OK')
'''
        result = run("unshare", "--mount", "--propagation", "private", "python3", "-I", "-c", readonly_code)
        require("READONLY_REFUSAL_OK" in result.stdout and TARGET.read_text().strip() == "0", "read-only procfs is rejected without repair or remount by helper")
        helper("enable-tcp-timestamps", {"expected_value": "0"})
        require(TARGET.read_text().strip() == "1", "helper remains usable after injected errors")
        require(pid() == before_pid and run("nft", "--stateless", "list", "ruleset").stdout == before_rules,
                "all timestamp actions preserve service PID and firewall structure")
        data_after = tree_hashes(DATA)
        code_after = tree_hashes((APP / "current").resolve())
        changed_data = sorted(name for name in data_before.keys() | data_after.keys() if data_before.get(name) != data_after.get(name))
        changed_code = sorted(name for name in code_before.keys() | code_after.keys() if code_before.get(name) != code_after.get(name))
        require(not changed_data and not changed_code,
                "timestamp actions preserve config, lists and immutable release"
                + (f"; changed data: {changed_data}; changed release: {changed_code}" if changed_data or changed_code else ""))
        require({name: tree_hashes(Path(name)) for name in persistent_before} == persistent_before and sha("/etc/hosts") == hosts_before,
                "no persistent sysctl files or hosts changed")
        verify_sentinels(sentinel)
    finally:
        TARGET.write_text(original)
        try:
            if installed:
                run("python3", str(APP / "current/install.py"), "remove")
        finally:
            for process in pids_for(WORK / "unrelated-nfqws/nfqws"):
                os.kill(process, signal.SIGTERM)
            run("nft", "delete", "table", "inet", SENTINEL)
    require(TARGET.read_text() == original, "original guest timestamps restored exactly")
    require(not active() and not table_present(), "VM app and firewall cleaned up")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(), "original_value": original.strip(),
                "source_sha256": {name: sha(source / name) for name in
                    ("src/lib/tcp_timestamps.py", "src/gui/privileged.py", "src/gui/backend.py",
                     "src/gui/presentation.py", "src/gui/app.py", "ci/vm_tcp_timestamps_smoke.py")}}
    Path("/var/tmp/zapret-tcp-timestamps-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("TCP TIMESTAMPS VM TEST PASSED (polkit dialog, reboot persistence and DPI bypass not tested)")


if __name__ == "__main__":
    main()
