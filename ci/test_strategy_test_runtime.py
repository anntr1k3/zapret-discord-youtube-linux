"""Installed tester planning/isolation: temporary offline root and fake kernel I/O."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import test_installer as fixtures


ROOT = Path(__file__).resolve().parents[1]
BAT = ('@echo off\nstart "zapret" /min "%BIN%winws.exe" --wf-tcp=443 --wf-udp=443 '
       '--filter-tcp=443 --ipset="%LISTS%ipset-all.txt" --dpi-desync=fake '
       '--dpi-desync-fake-tls="%BIN%tls.bin"\n')


def load():
    path = ROOT / "src/lib/strategy_test_runtime.py"
    spec = importlib.util.spec_from_file_location("strategy_test_runtime_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.fixture = fixtures.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installer = self.fixture.installer
        self.installer.validate_config = self.fixture.module.validate_config
        source = self.fixture.source
        (source / "src/lib/common.sh").write_text("# game filter ranges v1\n# ipset mode v1\n")
        (source / "src/lib/ipset-any.txt").write_bytes(b"")
        (source / "zapret-latest/general.bat").write_text(BAT)
        (source / "zapret-latest/general_alt12.bat").write_text(BAT)
        (source / "zapret-latest/lists/ipset-all.txt").write_text("203.0.113.113/32\n")
        (source / "zapret-latest/bin/tls.bin").write_bytes(b"fake")
        self.fixture.install()
        self.release = self.installer.current.resolve()
        self.original = (self.installer.data / "conf.env").read_bytes()
        self.request = {"strategies": ["general.bat", "general_alt12.bat"],
                        "expected_sha256": hashlib.sha256(self.original).hexdigest()}
        self.command = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))

    def prepare(self):
        with self.installer.operation():
            return self.module.prepare(self.installer, self.request, run=self.command)

    def test_prepares_all_selected_strategies_without_service_or_data_changes(self):
        before = {str(path): path.read_bytes() for path in self.installer.data.rglob("*") if path.is_file()}
        self.fixture.systemd.calls.clear()
        prepared = self.prepare()
        self.assertEqual(set(prepared["plans"]), set(self.request["strategies"]))
        self.assertEqual(prepared["config_bytes"], self.original)
        self.assertEqual(self.fixture.systemd.calls, [])
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.installer.data.rglob("*") if path.is_file()})

    def test_any_ipset_and_installed_fake_are_materialized_in_memory(self):
        plan = self.prepare()["plans"]["general.bat"]
        self.assertIn("--ipset=" + str(self.release / "src/lib/ipset-any.txt"), plan["argv"])
        self.assertIn("--dpi-desync-fake-tls=" + str(self.release / "zapret-latest/bin/tls.bin"), plan["argv"])
        self.assertEqual(plan["tcp_ports"], "443")
        self.assertNotIn("--daemon", plan["argv"])

    def test_original_profile_is_validated_even_when_not_selected(self):
        self.request["strategies"] = ["general_alt12.bat"]
        prepared = self.prepare()
        self.assertEqual(set(prepared["plans"]), {"general_alt12.bat"})
        self.assertEqual(prepared["baseline_plan"]["tcp_ports"], "443")
        self.assertEqual(self.command.call_count, 2)
        (self.release / "zapret-latest/general.bat").write_text("invalid original profile\n")
        self.command.reset_mock()
        with self.assertRaises(ValueError):
            self.prepare()
        self.command.assert_not_called()

    def test_dry_run_of_every_plan_has_fixed_globals_and_timeout(self):
        self.prepare()
        self.assertEqual(self.command.call_count, 2)
        for call in self.command.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[0], str(self.release / "nfqws"))
            self.assertIn("--dry-run", argv)
            self.assertEqual(call.kwargs["timeout"], 20)
            self.assertFalse(call.kwargs.get("shell", False))
            self.assertNotIn("LD_PRELOAD", call.kwargs["env"])

    def test_stale_revision_refused_before_engine_execution(self):
        self.request["expected_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "changed"):
            self.prepare()
        self.command.assert_not_called()

    def test_missing_strategy_refused_before_engine_execution(self):
        self.request["strategies"].append("missing.bat")
        with self.assertRaises(ValueError):
            self.prepare()
        self.command.assert_not_called()

    def test_custom_strategy_takes_precedence_over_upstream(self):
        (self.release / "custom-strategies/general.bat").write_text(BAT.replace("--wf-tcp=443", "--wf-tcp=8443"))
        self.assertEqual(self.prepare()["plans"]["general.bat"]["tcp_ports"], "8443")

    def test_custom_arbitrary_safe_name_uses_same_data_compiler(self):
        (self.release / "custom-strategies/minecraft.bat").write_text(BAT)
        self.request["strategies"] = ["minecraft.bat"]
        self.assertIn("minecraft.bat", self.prepare()["plans"])

    def test_global_daemon_option_in_strategy_is_rejected_before_dry_run(self):
        (self.release / "zapret-latest/general_alt12.bat").write_text(BAT.replace("--filter-tcp", "--daemon --filter-tcp"))
        with self.assertRaises(ValueError):
            self.prepare()
        self.command.assert_not_called()

    def test_symlink_strategy_is_not_followed(self):
        target = self.release / "zapret-latest/general_alt12.bat"
        target.unlink()
        target.symlink_to(self.fixture.source / "zapret-latest/general.bat")
        with self.assertRaises(ValueError):
            self.prepare()
        self.command.assert_not_called()

    def test_engine_rejection_or_timeout_never_changes_service(self):
        for failure in (subprocess.CompletedProcess([], 1, "", "unsupported option"),
                        subprocess.TimeoutExpired(["nfqws"], 20)):
            with self.subTest(failure=failure):
                self.command.side_effect = failure if isinstance(failure, Exception) else None
                self.command.return_value = failure
                self.fixture.systemd.calls.clear()
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    self.prepare()
                self.assertEqual(self.fixture.systemd.calls, [])

    def test_compiled_catalog_is_revalidated_and_cannot_add_global_arguments(self):
        compiler = self.module.load_sibling("strategy_sync")
        files = {"general.bat": BAT.encode(), "lists/ipset-all.txt": b"", "bin/tls.bin": b"fake"}
        entries = compiler.compile_payload(files)
        catalog = self.release / "zapret-latest/strategies.json"
        catalog.write_text(json.dumps({"schema": 1, "strategies": entries}))
        self.request["strategies"] = ["general.bat"]
        self.assertIn("general.bat", self.prepare()["plans"])
        entries["general.bat"]["profiles"][0].append("--daemon=yes")
        catalog.write_text(json.dumps({"schema": 1, "strategies": entries}))
        self.command.reset_mock()
        with self.assertRaises(ValueError):
            self.prepare()
        self.command.assert_not_called()


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.process = mock.Mock(pid=12345)
        self.process.poll.return_value = None
        self.process.wait.return_value = 0
        self.popen = mock.Mock(return_value=self.process)
        self.calls = []
        self.mutated = False
        self.runner = None

        def command(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if "list" in argv:
                data = {"nftables": [{"table": {"family": "inet", "name": self.runner.table,
                                              "comment": self.runner.owner}}]}
                if self.mutated:
                    data["nftables"].append({"rule": {"comment": "external change"}})
                return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        self.command = mock.Mock(side_effect=command)
        self.runner = self.module.IsolatedNftRun(
            {"release": Path("/opt/zapret-discord-youtube/releases") / ("a" * 32),
             "values": {"interface": "any"},
             "plans": {"general.bat": {"tcp_ports": "443", "udp_ports": "443", "argv": ["--filter-tcp=443"]}}},
            queue=41220, run=self.command, popen=self.popen,
            queues=mock.Mock(side_effect=[set(), {41220}]), resources=lambda: set())

    def test_foreground_process_and_exclusive_namespaced_nft_table(self):
        self.runner.start("general.bat")
        argv = self.popen.call_args.args[0]
        self.assertIn("--qnum=41220", argv)
        self.assertNotIn("--daemon", argv)
        self.assertNotIn("--dry-run", argv)
        script = next(kwargs["input"] for argv, kwargs in self.calls if "input" in kwargs)
        self.assertIn("create table inet zapret_test_", script)
        self.assertNotIn("zapretunix", script)
        self.assertIn("queue num 41220 bypass", script)
        self.assertFalse(self.popen.call_args.kwargs.get("shell", False))

    def test_cleanup_deletes_only_unchanged_own_table_and_terminates_child(self):
        self.runner.start("general.bat")
        self.runner.stop()
        deletes = [argv for argv, _ in self.calls if "delete" in argv]
        self.assertEqual(deletes, [["/usr/sbin/nft", "delete", "table", "inet", self.runner.table]])
        self.process.terminate.assert_called_once()
        self.process.wait.assert_called_once_with(timeout=5)

    def test_external_table_change_is_preserved_but_child_is_stopped(self):
        self.runner.start("general.bat")
        self.mutated = True
        with self.assertRaisesRegex(RuntimeError, "changed"):
            self.runner.stop()
        self.assertFalse(any("delete" in argv for argv, _ in self.calls))
        self.process.terminate.assert_called_once()

    def test_table_creation_failure_never_deletes_existing_table(self):
        original = self.command.side_effect
        def fail_create(argv, **kwargs):
            if "input" in kwargs:
                return subprocess.CompletedProcess(argv, 1, "", "File exists")
            return original(argv, **kwargs)
        self.command.side_effect = fail_create
        with self.assertRaisesRegex(RuntimeError, "File exists"):
            self.runner.start("general.bat")
        self.assertFalse(any("delete" in argv for argv, _ in self.calls))
        self.process.terminate.assert_called_once()

    def test_engine_exit_before_ready_never_adds_rules(self):
        self.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "exited"):
            self.runner.start("general.bat")
        self.command.assert_not_called()
        self.process.terminate.assert_not_called()

    def test_unresponsive_child_is_killed_only_through_owned_handle(self):
        self.runner.start("general.bat")
        self.process.wait.side_effect = [subprocess.TimeoutExpired("nfqws", 5), 0]
        self.runner.stop()
        self.process.terminate.assert_called_once()
        self.process.kill.assert_called_once()

    def test_unknown_strategy_is_refused_before_process_or_firewall(self):
        with self.assertRaises(ValueError):
            self.runner.start("other.bat")
        self.popen.assert_not_called()
        self.command.assert_not_called()

    def test_already_bound_queue_is_refused_before_process_or_firewall(self):
        self.runner.queues = lambda: {41220}
        with self.assertRaisesRegex(RuntimeError, "bound"):
            self.runner.start("general.bat")
        self.popen.assert_not_called()
        self.command.assert_not_called()

    def test_new_firewall_queue_conflict_is_rejected_before_process(self):
        self.runner.resources = lambda: {41220}
        with self.assertRaisesRegex(RuntimeError, "conflicts"):
            self.runner.start("general.bat")
        self.popen.assert_not_called()
        self.command.assert_not_called()

    def test_unreadable_resource_state_is_not_bypassed(self):
        self.runner.resources = mock.Mock(side_effect=ValueError("unknown rules"))
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.runner.start("general.bat")
        self.popen.assert_not_called()

    def test_interface_injection_is_refused_before_process_or_firewall(self):
        self.runner.prepared["values"]["interface"] = 'eth0"; flush ruleset; #'
        with self.assertRaises(ValueError):
            self.runner.start("general.bat")
        self.popen.assert_not_called()
        self.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
