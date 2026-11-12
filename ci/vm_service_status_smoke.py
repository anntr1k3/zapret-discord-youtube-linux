#!/usr/bin/env python3
"""Read-only status with real nfqws/firewall, ONLY in a marked disposable VM."""

import argparse
import json
import os
from pathlib import Path
import signal

from vm_gui_smoke import helper
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
    require(not (APP / "current").exists() and not active() and not table_present(),
            "VM has no managed service to overwrite")
    WORK.mkdir(exist_ok=True, mode=0o700)
    sentinel = sentinels(source)
    installed = False
    try:
        run("python3", str(source / "install.py"), "install", "--source", str(source))
        installed = True
        require("service-status-v1" in helper("read-config", {})["capabilities"],
                "installed helper advertises read-only service status")
        stopped = helper("read-status", {})
        require(stopped["process"]["state"] == "absent", "stopped service has no owned engine process")
        require(stopped["firewall"]["nftables"]["state"] == "absent", "stopped service has no named nftables table")
        release = (APP / "current").resolve()
        require(stopped["engine"]["sha256"] == sha(release / "nfqws"), "engine identity is the installed file hash")
        run("systemctl", "start", SERVICE)
        verify_running()
        before_data, before_code = tree_hashes(DATA), tree_hashes(release)
        # iptables-nft jump counters change under ordinary VM traffic. Compare
        # rule structure, not live packet/byte state (nft --stateless).
        before_rules = run("nft", "--stateless", "list", "ruleset").stdout
        before_pid = pid()
        report = helper("read-status", {})
        require(report["unit"]["properties"]["ActiveState"] == "active", "report observes active unit")
        require(report["process"]["state"] == "present"
                and report["process"]["pids"] == sorted(pids_for(release / "nfqws")),
                "only real nfqws from this unit and release is reported")
        require(report["process"]["queues"] == [220], "actual process queue is 220")
        require(report["firewall"]["nftables"]["recognized_rules"] > 0
                and report["firewall"]["nftables"]["queues"] == [220], "nftables rules signature and queue agree")
        require(report["config"]["strategy"] == "general_alt12.bat"
                and report["config"]["firewall_backend"] == "nftables", "fresh config profile and backend are reported")
        require(report["warnings"] == [], "consistent active installation has no detected warnings")

        # Same collector as an ordinary user must not claim rules absent when
        # the kernel refuses access. No pkexec or automatic elevation here.
        code = '''
import importlib.util, json
from pathlib import Path
release = Path("/opt/zapret-discord-youtube/current").resolve()
spec = importlib.util.spec_from_file_location("installed_status_probe", release / "src/lib/service_status.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.collect(release)))
'''
        unprivileged = json.loads(run("runuser", "-u", "vmtest", "--", "python3", "-B", "-c", code).stdout)
        require(unprivileged["firewall"]["nftables"]["state"] == "unknown"
                and unprivileged["firewall"]["nftables"]["error"], "unprivileged access denial is unknown, not no rules")

        config = DATA / "conf.env"
        original_config = config.read_bytes()
        try:
            config.write_bytes(b"unsupported_setting=invalid\n")
            invalid = helper("read-status", {})
            require(invalid["config_error"] and invalid["process"]["state"] == "present",
                    "invalid config does not block process/firewall observations")
            require(config.read_bytes() == b"unsupported_setting=invalid\n", "read-only status never repairs invalid config")
        finally:
            config.write_bytes(original_config)
        require(tree_hashes(DATA) == before_data and tree_hashes(release) == before_code,
                "status changes neither config/lists nor installed release bytes")
        require(pid() == before_pid and run("nft", "--stateless", "list", "ruleset").stdout == before_rules,
                "status does not restart service or alter any rules")
        verify_sentinels(sentinel)
        run("systemctl", "stop", SERVICE)
        final = helper("read-status", {})
        require(final["process"]["state"] == "absent" and final["firewall"]["nftables"]["state"] == "absent",
                "fresh stopped snapshot distinguishes absence from previous active observation")
        verify_sentinels(sentinel)
        # Exercise the second supported backend, including IPv4/IPv6 chains.
        config.write_bytes(original_config.replace(b"firewall_backend=nftables", b"firewall_backend=iptables"))
        try:
            run("systemctl", "start", SERVICE)
            require(active(), "real service starts with iptables backend")
            ipt_pid = pid()
            ipt_rules = run("nft", "--stateless", "list", "ruleset").stdout
            ipt_report = helper("read-status", {})
            require(ipt_report["process"]["state"] == "present" and ipt_report["process"]["queues"] == [220],
                    "iptables runtime still identifies owned process and queue")
            require(ipt_report["firewall"]["iptables"]["state"] == "present"
                    and ipt_report["firewall"]["iptables"]["recognized_rules"] > 0
                    and ipt_report["firewall"]["iptables"]["queues"] == [220],
                    "real IPv4/IPv6 iptables rules are recognized")
            require(ipt_report["firewall"]["nftables"]["state"] == "absent",
                    "iptables-nft compatibility tables are not mislabelled as own nftables backend")
            after_ipt_rules = run("nft", "--stateless", "list", "ruleset").stdout
            require(pid() == ipt_pid and after_ipt_rules == ipt_rules,
                    "iptables status changes neither service PID nor rules")
            verify_sentinels(sentinel)
        finally:
            run("systemctl", "stop", SERVICE)
            config.write_bytes(original_config)
    finally:
        try:
            if installed:
                run("python3", str(APP / "current/install.py"), "remove")
        finally:
            for process in pids_for(WORK / "unrelated-nfqws/nfqws"):
                os.kill(process, signal.SIGTERM)
            run("nft", "delete", "table", "inet", SENTINEL)
    require(not active() and not table_present(), "VM service/firewall cleaned up")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(),
                "active_report": report, "unprivileged_report": unprivileged, "iptables_report": ipt_report,
                "source_sha256": {name: sha(source / name) for name in
                                  ("src/lib/service_status.py", "src/gui/privileged.py", "src/gui/backend.py",
                                   "src/gui/presentation.py", "src/gui/app.py", "ci/vm_service_status_smoke.py")}}
    Path("/var/tmp/zapret-service-status-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("SERVICE STATUS VM TEST PASSED (polkit dialog and real DPI bypass not tested)")


if __name__ == "__main__":
    main()
