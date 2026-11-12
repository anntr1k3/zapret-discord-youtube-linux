"""Read-only status tests with fake proc/cgroup trees and command replies."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GROUP = "/system.slice/zapret_discord_youtube.service"


def load(relative):
    spec = importlib.util.spec_from_file_location("service_status_test", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/service_status.py")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret-status-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.release = self.base / "release"
        self.release.mkdir()
        (self.release / "nfqws").write_bytes(b"not executed")
        self.proc = self.base / "proc"
        self.cgroup = self.base / "cgroup"
        group = self.cgroup / GROUP.lstrip("/")
        group.mkdir(parents=True)
        (group / "cgroup.procs").write_text("10\n11\n")
        self.process(10, self.release / "nfqws", GROUP, ["--qnum=220"])
        self.process(11, Path("/bin/bash"), GROUP, [])
        self.calls = []
        self.unit = f"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=11\nControlGroup={GROUP}\nResult=success\n"
        self.table = {"nftables": [{"table": {"family": "inet", "name": "zapretunix"}},
            {"rule": {"family": "inet", "table": "zapretunix", "chain": "post",
                      "comment": "Added by zapret script", "expr": [{"queue": {"num": 220}}]}}]}
        def runner(argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == "/usr/bin/systemctl":
                return subprocess.CompletedProcess(argv, 0, self.unit, "")
            if argv[0] == "/usr/sbin/nft":
                value = {"nftables": [{"table": {"family": "inet", "name": "zapretunix"}}]} if argv[-1] == "tables" else self.table
                return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")
            return subprocess.CompletedProcess(argv, 0, "-P PREROUTING ACCEPT\n", "")
        self.runner = runner

    def process(self, pid, executable, group, args):
        folder = self.proc / str(pid)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "exe").symlink_to(executable)
        (folder / "cgroup").write_text("0::" + group + "\n")
        (folder / "cmdline").write_bytes(b"nfqws\0" + b"\0".join(arg.encode() for arg in args) + b"\0")

    def collect(self):
        return self.module.collect(self.release, {"strategy": "general_alt12.bat", "firewall_backend": "auto"},
                                   runner=self.runner, proc=self.proc, cgroup=self.cgroup)

    def test_active_process_belongs_to_unit_and_current_release(self):
        result = self.collect()
        self.assertEqual(result["process"]["state"], "present")
        self.assertEqual(result["process"]["pids"], [10])
        self.assertEqual(result["process"]["queues"], [220])
        self.assertEqual(result["config"]["strategy"], "general_alt12.bat")
        self.assertEqual(result["engine"]["size"], len(b"not executed"))

    def test_unrelated_process_is_not_claimed_as_our_engine(self):
        (self.cgroup / GROUP.lstrip("/") / "cgroup.procs").write_text("11\n")
        self.process(55, self.release / "nfqws", "/unrelated.service", ["--qnum=220"])
        result = self.collect()
        self.assertEqual(result["process"]["state"], "absent")
        self.assertEqual(result["process"]["pids"], [])
        self.assertTrue(result["warnings"])

    def test_different_cgroup_membership_is_unknown_not_owned(self):
        (self.proc / "10/cgroup").write_text("0::/other.service\n")
        result = self.collect()
        self.assertEqual(result["process"]["state"], "unknown")
        self.assertEqual(result["process"]["pids"], [])

    def test_read_failure_is_unknown_not_absent(self):
        (self.cgroup / GROUP.lstrip("/") / "cgroup.procs").unlink()
        self.assertEqual(self.collect()["process"]["state"], "unknown")

    def test_stopped_unit_needs_no_global_process_scan(self):
        self.unit = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlGroup=\nResult=success\n"
        result = self.collect()
        self.assertEqual(result["process"]["state"], "absent")

    def test_controlgroup_parent_traversal_is_rejected(self):
        self.unit = "LoadState=loaded\nActiveState=active\nControlGroup=/../../etc\n"
        self.assertEqual(self.collect()["process"]["state"], "unknown")

    def test_recognized_nft_rules_and_queues(self):
        result = self.collect()
        self.assertEqual(result["firewall"]["nftables"]["state"], "present")
        self.assertEqual(result["firewall"]["nftables"]["recognized_rules"], 1)
        self.assertEqual(result["firewall"]["nftables"]["queues"], [220])

    def test_table_name_alone_does_not_prove_our_rules(self):
        self.table["nftables"][1]["rule"]["comment"] = "unrelated"
        result = self.collect()
        self.assertEqual(result["firewall"]["nftables"]["recognized_rules"], 0)
        self.assertTrue(result["warnings"])

    def test_permission_failure_is_not_absent_firewall(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] != "/usr/bin/systemctl":
                return subprocess.CompletedProcess(argv, 1, "", "Operation not permitted")
            return old(argv, **kwargs)
        self.runner = runner
        result = self.collect()
        self.assertEqual(result["firewall"]["nftables"]["state"], "unknown")
        self.assertEqual(result["firewall"]["iptables"]["state"], "unknown")

    def test_missing_table_only_after_successful_enumeration(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] == "/usr/sbin/nft":
                return subprocess.CompletedProcess(argv, 0, '{"nftables":[]}', "")
            return old(argv, **kwargs)
        self.runner = runner
        self.assertEqual(self.collect()["firewall"]["nftables"]["state"], "absent")

    def test_missing_tools_are_unknown(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] != "/usr/bin/systemctl":
                raise FileNotFoundError("missing tool")
            return old(argv, **kwargs)
        self.runner = runner
        self.assertEqual(self.collect()["firewall"]["nftables"]["state"], "unknown")

    def test_queue_mismatch_is_a_warning(self):
        (self.proc / "10/cmdline").write_bytes(b"nfqws\0--qnum=221\0")
        self.assertTrue(any("очеред" in warning.lower() for warning in self.collect()["warnings"]))

    def test_status_executes_only_fixed_read_commands(self):
        self.collect()
        self.assertTrue(self.calls)
        for argv in self.calls:
            self.assertNotIn("nfqws", argv[0])
            self.assertFalse(any(token in argv for token in ("start", "stop", "flush", "delete", "add", "-F", "-D", "-X")))

    def test_systemd_failure_still_returns_unknown_report(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] == "/usr/bin/systemctl":
                raise subprocess.TimeoutExpired(argv, 10)
            return old(argv, **kwargs)
        self.runner = runner
        result = self.collect()
        self.assertEqual(result["unit"]["state"], "unknown")
        self.assertEqual(result["process"]["state"], "unknown")

    def test_iptables_ipv4_and_ipv6_are_read_and_recognized(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
                text = "-N zapret\n-A zapret -m connbytes -j NFQUEUE --queue-num 220 --queue-bypass\n"
                return subprocess.CompletedProcess(argv, 0, text, "")
            return old(argv, **kwargs)
        self.runner = runner
        report = self.collect()
        self.assertEqual(report["firewall"]["iptables"]["recognized_rules"], 2)
        self.assertTrue(any("обоих backend" in warning for warning in report["warnings"]))

    def test_bad_nft_json_is_unknown(self):
        old = self.runner
        def runner(argv, **kwargs):
            if argv[0] == "/usr/sbin/nft":
                return subprocess.CompletedProcess(argv, 0, "not json", "")
            return old(argv, **kwargs)
        self.runner = runner
        self.assertEqual(self.collect()["firewall"]["nftables"]["state"], "unknown")

    def test_text_keeps_denied_access_distinct_from_no_rules(self):
        presentation = load("src/gui/presentation.py")
        report = self.collect()
        report["firewall"]["nftables"].update(state="unknown", error="Permission denied")
        text = presentation.service_status_text(report)
        self.assertIn("nftables: неизвестно", text)
        self.assertIn("Permission denied", text)
        self.assertIn("не доказательство обхода DPI", text)

    def test_basic_titles_do_not_hide_unknown_transitions_or_foreign_units(self):
        presentation = load("src/gui/presentation.py")
        for state, expected in (({"installed": False, "unit_present": None, "unit_error": "denied"}, "неизвестно"),
                                ({"installed": False, "unit_present": True}, "неуправляемый"),
                                ({"installed": True, "unit_present": True, "state": "activating"}, "запускается"),
                                ({"installed": True, "unit_present": True, "state": "failed"}, "ошибкой")):
            with self.subTest(state=state):
                self.assertIn(expected, presentation.service_state_title(state))


class ProtocolTests(unittest.TestCase):
    def test_read_status_accepts_no_arbitrary_paths_or_commands(self):
        helper = load("src/gui/privileged.py")
        helper.validate_payload("read-status", {})
        for payload in ({"pid": 1}, {"path": "/etc/shadow"}, {"command": "flush"}):
            with self.assertRaises(ValueError):
                helper.validate_payload("read-status", payload)

    def test_demo_status_is_independent_of_subprocesses(self):
        backend = load("src/gui/backend.py").DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("real command")):
            self.assertEqual(backend.read_status()["process"]["state"], "absent")
            backend.service_action("start")
            self.assertEqual(backend.read_status()["process"]["state"], "present")

    def test_old_helper_does_not_receive_unsupported_action(self):
        module = load("src/gui/backend.py")
        with tempfile.TemporaryDirectory() as directory:
            old = Path(directory) / "old-helper.py"
            old.write_text("# previous installed protocol\n")
            backend = module.Backend(ROOT)
            backend.trusted_helper = mock.Mock(return_value=old)
            backend.call_helper = mock.Mock()
            with self.assertRaises(RuntimeError):
                backend.read_status()
            backend.call_helper.assert_not_called()

    def test_basic_systemd_error_is_unknown_not_not_installed(self):
        module = load("src/gui/backend.py")
        backend = module.Backend(ROOT)
        backend.command = mock.Mock(side_effect=PermissionError("Access denied"))
        backend.sync = mock.Mock(return_value={})
        backend.update_checker = mock.Mock()
        backend.update_checker.return_value.status.return_value = {}
        state = backend.snapshot()
        self.assertIsNone(state["unit_present"])
        self.assertIn("Access denied", state["unit_error"])


if __name__ == "__main__":
    unittest.main()
