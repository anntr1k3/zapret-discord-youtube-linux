"""Fixed-key TCP timestamps actions: fake I/O only, never host sysctl writes."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_installer as fixtures


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location("tcp_timestamps_test", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/tcp_timestamps.py")
        self.value = "0"
        self.writes = []
        def write(value):
            self.writes.append(value)
            self.value = value
        self.write = write

    def enable(self, expected="0"):
        return self.module.enable(expected, read=lambda: self.value, write=self.write)

    def test_enable_zero_is_exactly_one_runtime_write(self):
        result = self.enable()
        self.assertTrue(result["changed"])
        self.assertEqual(result["tcp_timestamps"]["value"], "1")
        self.assertEqual(self.writes, ["1"])

    def test_enabled_modes_one_and_two_are_preserved(self):
        for value in ("1", "2"):
            self.value = value
            result = self.enable(value)
            self.assertFalse(result["changed"])
            self.assertEqual(self.value, value)
        self.assertEqual(self.writes, [])

    def test_stale_confirmation_never_writes(self):
        self.value = "2"
        with self.assertRaises(ValueError):
            self.enable("0")
        self.assertEqual(self.writes, [])

    def test_invalid_confirmation_values_are_rejected(self):
        for value in (None, 0, True, "3", "0\n", {}, ["0"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.enable(value)
        self.assertEqual(self.writes, [])

    def test_drift_during_preparation_never_writes(self):
        with self.assertRaises(ValueError):
            self.module.enable("0", read=mock.Mock(side_effect=["0", "2"]), write=self.write)
        self.assertEqual(self.writes, [])

    def test_failure_after_write_restores_previous_zero(self):
        def fail(value):
            self.write(value)
            if value == "1":
                raise OSError("injected post-write error")
        with self.assertRaisesRegex(OSError, "injected"):
            self.module.enable("0", read=lambda: self.value, write=fail)
        self.assertEqual(self.writes, ["1", "0"])
        self.assertEqual(self.value, "0")

    def test_failure_before_write_does_not_attempt_rollback(self):
        writer = mock.Mock(side_effect=PermissionError("read-only procfs"))
        with self.assertRaises(PermissionError):
            self.module.enable("0", read=lambda: self.value, write=writer)
        writer.assert_called_once_with("1")

    def test_external_mode_two_is_preserved_on_readback_failure(self):
        def external(value):
            self.writes.append(value)
            self.value = "2"
        with self.assertRaisesRegex(RuntimeError, "параллель"):
            self.module.enable("0", read=lambda: self.value, write=external)
        self.assertEqual(self.value, "2")
        self.assertEqual(self.writes, ["1"])

    def test_rollback_failure_is_explicit(self):
        def fail(value):
            if value == "0":
                raise OSError("recovery failure")
            self.write(value)
            raise OSError("post-write failure")
        with self.assertRaisesRegex(RuntimeError, "восстановление"):
            self.module.enable("0", read=lambda: self.value, write=fail)

    def test_readback_unknown_does_not_blindly_write_zero(self):
        reader = mock.Mock(side_effect=["0", "0", OSError("readback failed"), OSError("still unreadable")])
        with self.assertRaisesRegex(RuntimeError, "неизвест"):
            self.module.enable("0", read=reader, write=self.write)
        self.assertEqual(self.writes, ["1"])

    def test_status_reports_unreadable_as_unknown_not_disabled(self):
        with mock.patch.object(self.module, "read_value", side_effect=PermissionError("denied")):
            result = self.module.status()
        self.assertIsNone(result["enabled"])
        self.assertIsNone(result["value"])
        self.assertTrue(result["error"])

    def test_status_distinguishes_zero_one_and_two(self):
        for value in ("0", "1", "2"):
            with mock.patch.object(self.module, "read_value", return_value=value):
                result = self.module.status()
            self.assertEqual(result["enabled"], value != "0")
            self.assertEqual(result["scope"], "running-kernel")

    def test_reader_rejects_invalid_content_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "timestamps"
            with mock.patch.object(self.module, "TARGET", target):
                for data in (b"3\n", b"", b"0\n1\n", b"1" * 100):
                    target.write_bytes(data)
                    with self.assertRaises(ValueError):
                        self.module.read_value()
                target.write_bytes(b"2\n")
                self.assertEqual(self.module.read_value(), "2")
                link = Path(directory) / "link"
                link.symlink_to(target)
                with mock.patch.object(self.module, "TARGET", link), self.assertRaises(OSError):
                    self.module.read_value()


class ProtocolTests(unittest.TestCase):
    def test_actions_accept_no_arbitrary_key_path_or_target_value(self):
        helper = load("src/gui/privileged.py")
        helper.validate_payload("read-tcp-timestamps", {})
        helper.validate_payload("enable-tcp-timestamps", {"expected_value": "0"})
        for request in ({"expected_value": "0", "path": "/etc/sysctl.conf"},
                        {"expected_value": "0", "value": "0"}, {"expected_value": 0}, {}):
            with self.assertRaises(ValueError):
                helper.validate_payload("enable-tcp-timestamps", request)

    def test_dispatch_does_not_depend_on_valid_config_or_restart_service(self):
        fixture = fixtures.InstallerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.install(start=True)
        fixture.systemd.calls.clear()
        helper = load("src/gui/privileged.py")
        runtime = mock.Mock()
        runtime.enable.return_value = {"changed": True, "tcp_timestamps": {"value": "1"}}
        (fixture.installer.data / "conf.env").write_text("invalid configuration\n")
        with mock.patch.object(helper, "load_tcp_timestamps", return_value=runtime), \
                mock.patch.object(helper, "config_result", side_effect=AssertionError("config must not be read")):
            result = helper.dispatch(fixture.installer, "enable-tcp-timestamps", {"expected_value": "0"})
        self.assertTrue(result["changed"])
        runtime.enable.assert_called_once_with("0")
        self.assertEqual(fixture.systemd.calls, [])

    def test_old_helper_receives_no_new_action(self):
        module = load("src/gui/backend.py")
        backend = module.Backend(ROOT)
        backend.tcp_timestamps_supported = mock.Mock(return_value=False)
        backend.call_helper = mock.Mock()
        with self.assertRaises(RuntimeError):
            backend.read_tcp_timestamps()
        with self.assertRaises(RuntimeError):
            backend.enable_tcp_timestamps("0")
        backend.call_helper.assert_not_called()

    def test_demo_actions_do_not_execute_any_commands(self):
        backend = load("src/gui/backend.py").DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("real command")):
            self.assertEqual(backend.read_tcp_timestamps()["value"], "0")
            result = backend.enable_tcp_timestamps("0")
            self.assertTrue(result["changed"])
            self.assertEqual(backend.snapshot()["tcp_timestamps"]["value"], "1")
            self.assertFalse(backend.enable_tcp_timestamps("1")["changed"])


if __name__ == "__main__":
    unittest.main()
