#!/usr/bin/env python3
"""No service operations: the shortcut's subprocesses are mocked."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class StopShortcutTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("stop_service", ROOT / "src/desktop/stop_service.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def invoke(self, result):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(self.module.subprocess, "run", return_value=result) as run:
                with mock.patch.object(self.module, "notify") as notify:
                    status = self.module.main([])
        return status, run, notify

    def test_stops_only_the_managed_unit_without_disabling_autostart(self):
        status, run, notify = self.invoke(subprocess.CompletedProcess([], 0, "", ""))
        self.assertEqual(status, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "stop", "zapret_discord_youtube.service"])
        self.assertIn("остановлен", notify.call_args.args[1])

    def test_denied_or_cancelled_authorization_is_not_reported_as_success(self):
        status, run, notify = self.invoke(subprocess.CompletedProcess([], 1, "", "Access denied"))
        self.assertEqual(status, 1)
        self.assertIn("Не удалось", notify.call_args.args[1])

    def test_dry_run_does_not_touch_systemd(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(self.module.subprocess, "run") as run:
                self.assertEqual(self.module.main(["--dry-run"]), 0)
        run.assert_not_called()

    def test_missing_systemctl_is_handled(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(self.module.subprocess, "run", side_effect=FileNotFoundError()):
                with mock.patch.object(self.module, "notify"):
                    self.assertEqual(self.module.main([]), 127)

    def test_notification_failure_does_not_change_stop_result(self):
        with mock.patch.object(self.module.subprocess, "run", side_effect=OSError("no notification service")):
            self.module.notify("title", "message")


if __name__ == "__main__":
    unittest.main()
