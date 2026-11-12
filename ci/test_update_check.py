"""Automatic update checks: temporary user units, no host systemd changes."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckResultTests(unittest.TestCase):
    def setUp(self):
        self.sync = load("check_result_test", "src/lib/strategy_sync.py")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)

    def test_check_records_result_without_preparing(self):
        target = {"revision": "a" * 40, "channel": "release", "tag": "v1"}
        with mock.patch.object(self.sync, "cached_target", return_value=target), \
                mock.patch.object(self.sync, "installed_revision", return_value="b" * 40), \
                mock.patch.object(self.sync, "prepare", side_effect=AssertionError("must not prepare")):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(self.sync.main(["check", "--cache", str(self.cache)]), 0)
        record = json.loads((self.cache / "last-update-check.json").read_text())
        self.assertTrue(record["update_available"])
        self.assertEqual(record["status"], "checked")
        self.assertTrue(record["checked_at"])
        self.assertFalse((self.cache / "pending.json").exists())

    def test_failed_check_replaces_stale_success(self):
        (self.cache / "last-update-check.json").write_text('{"status":"checked"}')
        with mock.patch.object(self.sync, "cached_target", side_effect=OSError("offline")), \
                mock.patch.object(self.sync.os, "geteuid", return_value=1000):
            with mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(self.sync.main(["check", "--cache", str(self.cache)]), 1)
        record = json.loads((self.cache / "last-update-check.json").read_text())
        self.assertEqual(record["status"], "error")
        self.assertEqual(record["message"], "offline")


class TimerTests(unittest.TestCase):
    def setUp(self):
        self.module = load("update_check_test", "src/lib/update_check.py")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret check Юникод ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.enabled = False
        self.active = False
        self.fail_enable = False
        def runner(argv, **kwargs):
            self.calls.append(argv)
            command = argv[2]
            if command == "show":
                return subprocess.CompletedProcess(argv, 0,
                    f"LoadState=loaded\nActiveState={'active' if self.active else 'inactive'}\n"
                    f"UnitFileState={'enabled' if self.enabled else 'disabled'}\n"
                    "NextElapseUSecRealtime=Fri 2026-11-13 00:15:00 UTC\n", "")
            if command == "enable":
                if self.fail_enable:
                    self.fail_enable = False
                    return subprocess.CompletedProcess(argv, 1, "", "injected enable failure")
                self.enabled = True
                self.active = "--now" in argv or self.active
            if command == "disable":
                self.enabled = False
                self.active = False if "--now" in argv else self.active
            if command == "start":
                self.active = True
            return subprocess.CompletedProcess(argv, 0, "", "")
        self.timer = self.module.UpdateCheck(self.root / "base", self.root / "cache",
                                             self.root / "units", runner=runner)

    def test_unit_checks_only_no_prepare_apply_or_privileges(self):
        self.timer.set_enabled(True)
        service = (self.root / "units" / self.module.SERVICE).read_text()
        self.assertIn('"check"', service)
        self.assertNotIn('"prepare"', service)
        self.assertNotIn("pkexec", service)
        self.assertNotIn("User=root", service)
        self.assertTrue(self.enabled and self.active)
        self.assertTrue(all(call[:2] == ["/usr/bin/systemctl", "--user"] for call in self.calls))

    def test_disable_does_not_stop_running_check_or_old_preparation(self):
        self.timer.set_enabled(True)
        self.calls.clear()
        self.timer.set_enabled(False)
        self.assertFalse(self.enabled or self.active)
        self.assertFalse(any(self.module.SERVICE in call for call in self.calls if "show" not in call))
        self.assertFalse(any("zapret-strategy-sync.timer" in call for call in self.calls if "show" not in call))

    def test_refuses_foreign_unit_without_systemd_mutations(self):
        directory = self.root / "units"
        directory.mkdir()
        path = directory / self.module.SERVICE
        path.write_text("[Service]\nExecStart=/bin/true\n")
        with self.assertRaises(ValueError):
            self.timer.set_enabled(True)
        self.assertEqual(path.read_text(), "[Service]\nExecStart=/bin/true\n")
        self.assertFalse(any("enable" in call or "daemon-reload" in call for call in self.calls))

    def test_refuses_symlink_unit(self):
        directory = self.root / "units"
        directory.mkdir()
        target = self.root / "other"
        target.write_text("private")
        (directory / self.module.TIMER).symlink_to(target)
        with self.assertRaises(ValueError):
            self.timer.set_enabled(True)
        self.assertEqual(target.read_text(), "private")

    def test_enable_failure_restores_absent_units_and_disabled_state(self):
        self.fail_enable = True
        with self.assertRaisesRegex(RuntimeError, "injected enable failure"):
            self.timer.set_enabled(True)
        self.assertFalse((self.root / "units" / self.module.SERVICE).exists())
        self.assertFalse((self.root / "units" / self.module.TIMER).exists())
        self.assertFalse(self.enabled or self.active)

    def test_status_exposes_last_check_without_network(self):
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "last-update-check.json").write_text('{"status":"error","message":"offline"}')
        result = self.timer.status()
        self.assertEqual(result["last_check"]["message"], "offline")
        self.assertIn("2026", result["next_check"])
        self.assertTrue(all("show" in call for call in self.calls))

    def test_user_bus_failure_is_unknown_not_disabled(self):
        self.timer.runner = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "", "No user bus")
        result = self.timer.status()
        self.assertIsNone(result["enabled"])
        self.assertIn("No user bus", result["error"])
        with self.assertRaises(RuntimeError):
            self.timer.set_enabled(True)

    def test_quote_preserves_systemd_special_characters(self):
        self.assertEqual(self.module.quote('/home/a $USER 100%/"x"'), '"/home/a $$USER 100%%/\\"x\\""')
        with self.assertRaises(ValueError):
            self.module.quote("/path\nnewline")

    def test_masked_state_is_not_treated_as_disabled(self):
        self.timer.runner = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0,
            "LoadState=masked\nUnitFileState=masked\nActiveState=inactive\n", "")
        self.assertIsNone(self.timer.status()["enabled"])
        with self.assertRaises(RuntimeError):
            self.timer.set_enabled(True)

    def test_foreign_service_fragment_is_not_shadowed(self):
        self.timer.runner = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0,
            "LoadState=loaded\nUnitFileState=disabled\nFragmentPath=/usr/lib/systemd/user/foreign.service\n", "")
        with self.assertRaises(ValueError):
            self.timer.set_enabled(True)
        self.assertFalse((self.root / "units" / self.module.SERVICE).exists())

    def test_demo_toggle_never_calls_systemd(self):
        backend = load("auto_check_backend_test", "src/gui/backend.py").DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("systemd in demo")):
            self.assertTrue(backend.set_auto_check(True)["enabled"])
            backend.check_update()
            self.assertTrue(backend.snapshot()["auto_check"]["last_check"])
            self.assertFalse(backend.set_auto_check(False)["enabled"])

    def test_failed_systemd_execution_is_not_hidden_by_old_success(self):
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "last-update-check.json").write_text('{"status":"checked","update_available":false}')
        normal = self.timer.runner
        def runner(argv, **kwargs):
            if self.module.SERVICE in argv:
                return subprocess.CompletedProcess(argv, 0, "LoadState=loaded\nResult=timeout\n", "")
            return normal(argv, **kwargs)
        self.timer.runner = runner
        self.assertIn("timeout", self.timer.status()["execution_error"])


if __name__ == "__main__":
    unittest.main()
