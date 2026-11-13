#!/usr/bin/env python3
"""GUI backend/helper tests: no GTK display, polkit or real service operations."""

import ast
import hashlib
import importlib.util
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


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.presentation = load("gui_presentation_test", "src/gui/presentation.py")

    def test_refresh_has_no_success_notification(self):
        busy, success = self.presentation.operation_messages("refresh")
        self.assertTrue(busy)
        self.assertIsNone(success)

    def test_user_actions_have_specific_feedback(self):
        for action in ("read-config", "start", "stop", "restart", "select-profile",
                       "set-autostart", "set-game-filter", "set-ipset-mode", "set-active-fakes",
                       "fetch-ipset", "update-ipset",
                       "check", "prepare", "apply", "logs",
                       "tester-run", "export-tester"):
            busy, success = self.presentation.operation_messages(action)
            self.assertTrue(busy.endswith("…"))
            self.assertTrue(success)
            self.assertNotEqual(success, "Готово")

    def test_tester_text_placeholder_and_report(self):
        placeholder = self.presentation.tester_text(None)
        self.assertIn("не выполнялось", placeholder)
        self.assertIn("Baseline", placeholder)
        report = {"type": "standard", "mode": "baseline", "started_at": "2026-11-13T10:00:00+00:00",
                  "finished_at": "2026-11-13T10:01:00+00:00", "cancelled": False, "restore_error": None,
                  "warnings": [], "dpi_license": None, "dpi_targets": [], "best": None,
                  "strategies": [{"name": "baseline", "error": None, "seconds": 1.0, "targets": [],
                                  "counts": {}}],
                  "analytics": {"strategies": {"baseline": {"OK": 0, "SSL": 0, "ERROR": 0, "UNSUP": 0,
                                                            "PingOK": 0, "PingFail": 0}}, "best": None}}
        text = self.presentation.tester_text(report)
        self.assertIn("Тест стратегий · тип standard · режим baseline", text)
        self.assertNotIn("Best strategy", text)

    def test_gui_has_no_manual_rollback_action(self):
        tree = ast.parse((ROOT / "src/gui/app.py").read_text())
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == "rollback"
                             for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                             and "Откатить версию" in node.value for node in ast.walk(tree)))

    def test_unread_config_never_selects_first_profile(self):
        self.assertIsNone(self.presentation.profile_index(["general.bat", "general_alt12.bat"], None))

    def test_only_saved_profile_is_shown_as_current(self):
        config = {"config": {"strategy": "general_alt12.bat"}}
        self.assertEqual(self.presentation.profile_index(["general.bat", "general_alt12.bat"], config), 1)
        self.assertIsNone(self.presentation.profile_index(["general.bat"], config))

    def test_game_filter_form_values_and_legacy_defaults(self):
        for tcp, udp, mode in (("false", "false", "disabled"), ("true", "false", "tcp"),
                               ("false", "true", "udp"), ("true", "true", "all")):
            self.assertEqual(self.presentation.game_filter_values({"gamefiltertcp": tcp, "gamefilterudp": udp}),
                             (mode, "1024-65535", "1024-65535"))
        self.assertEqual(self.presentation.game_filter_values({"gamefiltertcp": "true", "gamefilterudp": "true",
                          "gamefiltertcp_ports": "1000-2000", "gamefilterudp_ports": "3000,4000"}),
                         ("all", "1000-2000", "3000,4000"))


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.module = load("gui_backend_test", "src/gui/backend.py")
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-gui-test-")
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        self.backend = self.module.Backend(ROOT, current=self.tmp / "missing", cache=self.tmp / "cache")

    def test_demo_never_spawns_processes_or_writes_files(self):
        with mock.patch.object(self.module.subprocess, "run", side_effect=AssertionError("real command")), mock.patch.object(Path, "open", side_effect=AssertionError("filesystem access")), mock.patch.object(Path, "mkdir", side_effect=AssertionError("filesystem write")):
            demo = self.module.DemoBackend()
            self.assertFalse(demo.snapshot()["active"])
            demo.service_action("start")
            self.assertTrue(demo.snapshot()["active"])
            config = demo.load_config()
            demo.select_profile("general_alt.bat", config["sha256"])
            demo.set_autostart(True)
            demo.set_game_filter("all", "2000-3000", "4000-5000", "0" * 64)
            demo.set_ipset_mode("none", "0" * 64)
            demo.set_ipset_mode("any", "0" * 64)
            demo.set_ipset_mode("loaded", "0" * 64, "c" * 64)
            demo.set_active_fakes("a" * 64, None, "0" * 64)
            demo.set_active_fakes(None, "b" * 64, "0" * 64)
            demo.set_active_fakes(None, None, "0" * 64)
            fetched = demo.fetch_ipset()
            self.assertEqual(fetched["kind"], "loaded")
            demo.update_ipset(fetched["staged"], fetched["sha256"], "0" * 64)
            pending = demo.prepare_update()
            demo.apply_update(pending)
            demo.rollback()
            demo.service_action("stop")
            self.assertIn("демо", demo.logs().lower())
            self.assertFalse(demo.snapshot()["active"])

    def test_service_action_has_fixed_unit_and_no_shell(self):
        self.backend.managed = mock.Mock(return_value=True)
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.backend.service_action("stop")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "stop", "zapret_discord_youtube.service"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        with self.assertRaises(ValueError):
            self.backend.service_action("disable --now other.service")

    def test_gui_never_elevates_a_helper_from_the_checkout(self):
        with mock.patch.object(self.module.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                self.backend.load_config()
        run.assert_not_called()

    def test_helper_command_is_isolated_python_with_structured_input(self):
        self.backend.trusted_helper = mock.Mock(return_value=Path("/opt/zapret-discord-youtube/current/src/gui/privileged.py"))
        result = {"ok": True, "result": {"enabled": True}}
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(result), "")) as run:
            self.backend.set_autostart(True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/pkexec", "/usr/bin/python3", "-I", "/opt/zapret-discord-youtube/current/src/gui/privileged.py"])
        self.assertEqual(argv[-1], "set-autostart")
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"enabled": True})

    def test_cancelled_authorization_is_an_error(self):
        self.backend.trusted_helper = mock.Mock(return_value=Path("/trusted/helper.py"))
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 126, "", "")):
            with self.assertRaisesRegex(RuntimeError, "Авторизация"):
                self.backend.set_autostart(True)

    def test_initial_snapshot_does_not_load_config_or_check_network(self):
        self.backend.sync = mock.Mock(return_value={"pending": None, "current_revision": None})
        self.backend.call_helper = mock.Mock(side_effect=AssertionError("unexpected authorization"))
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "LoadState=not-found\nActiveState=inactive\n", "")):
            state = self.backend.snapshot()
        self.backend.sync.assert_called_once_with("status")
        self.backend.call_helper.assert_not_called()
        self.assertIsNone(state["config"])
        self.assertFalse(state["installed"])

    def test_game_filter_uses_fixed_helper_protocol(self):
        result = {"config": {"strategy": "general.bat"}, "sha256": "b" * 64}
        self.backend.call_helper = mock.Mock(return_value=result)
        self.assertEqual(self.backend.set_game_filter("tcp", "2000-3000", "4000,5000", "a" * 64), result)
        self.backend.call_helper.assert_called_once_with("set-game-filter", {
            "mode": "tcp", "tcp_ports": "2000-3000", "udp_ports": "4000,5000", "expected_sha256": "a" * 64})
        self.assertEqual(self.backend.loaded_config, result)

    def test_ipset_uses_fixed_helper_protocol(self):
        result = {"config": {"ipset_mode": "loaded"}, "sha256": "b" * 64}
        self.backend.call_helper = mock.Mock(return_value=result)
        self.assertEqual(self.backend.set_ipset_mode("loaded", "a" * 64, "c" * 64), result)
        self.backend.call_helper.assert_called_once_with("set-ipset-mode", {
            "mode": "loaded", "expected_sha256": "a" * 64, "expected_list_sha256": "c" * 64})

    def test_active_fakes_uses_fixed_helper_protocol(self):
        result = {"config": {"fakediscord": "c" * 64}, "sha256": "b" * 64}
        self.backend.call_helper = mock.Mock(return_value=result)
        self.assertEqual(self.backend.set_active_fakes("c" * 64, None, "a" * 64), result)
        self.backend.call_helper.assert_called_once_with("set-active-fakes", {
            "discord": "c" * 64, "gameudp": None, "expected_sha256": "a" * 64})
        self.assertEqual(self.backend.loaded_config, result)

    def test_ipset_update_uses_fixed_helper_protocol(self):
        result = {"config": {"ipset_mode": "loaded"}, "sha256": "b" * 64}
        self.backend.call_helper = mock.Mock(return_value=result)
        self.assertEqual(self.backend.update_ipset("/home/user/.cache/ipset-service.txt", "c" * 64, "a" * 64), result)
        self.backend.call_helper.assert_called_once_with("update-ipset", {
            "stage": "/home/user/.cache/ipset-service.txt", "sha256": "c" * 64, "expected_sha256": "a" * 64})
        self.assertEqual(self.backend.loaded_config, result)

    def test_fetch_ipset_runs_unprivileged_script_with_fixed_cache(self):
        result = {"staged": "/home/user/.cache/ipset-service.txt", "sha256": "c" * 64,
                  "entries": 2, "size": 40, "kind": "loaded", "url": "https://example.invalid/list"}
        with mock.patch.object(self.module.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, json.dumps(result), "")) as run:
            self.assertEqual(self.backend.fetch_ipset(), result)
        self.assertEqual(run.call_args.args[0], [self.module.sys.executable,
                                                 str(ROOT / "src/lib/strategy_sync.py"),
                                                 "fetch-ipset", "--cache", str(self.tmp / "cache")])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_demo_ipset_update_is_idempotent_and_validates_token(self):
        demo = self.module.DemoBackend()
        fetched = demo.fetch_ipset()
        first = demo.update_ipset(fetched["staged"], fetched["sha256"], "0" * 64)
        self.assertEqual(first["ipset"]["loaded_sha256"], "d" * 64)
        second = demo.update_ipset(fetched["staged"], fetched["sha256"], "0" * 64)
        self.assertEqual(second["ipset"]["loaded_sha256"], "d" * 64)
        with self.assertRaises(ValueError):
            demo.update_ipset(fetched["staged"], "e" * 64, "0" * 64)

    def test_demo_game_filter_preserves_strategy_and_service(self):
        demo = self.module.DemoBackend()
        demo.service_action("start")
        result = demo.set_game_filter("udp", "1000-2000", "3000,4000-5000", "0" * 64)
        self.assertEqual(result["config"]["strategy"], "general.bat")
        self.assertEqual(result["config"]["gamefiltertcp"], "false")
        self.assertEqual(result["config"]["gamefilterudp"], "true")
        self.assertEqual(result["config"]["gamefilterudp_ports"], "3000,4000-5000")
        self.assertTrue(demo.snapshot()["active"])


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = load("gui_helper_test", "src/gui/privileged.py")
        installer_tests = load("gui_installer_fixtures", "ci/test_installer.py")
        self.fixture = installer_tests.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installer = self.fixture.installer
        self.installer.validate_config = self.fixture.module.validate_config
        self.fixture.install(start=True)
        release = (self.installer.app / "current").resolve()
        (release / "zapret-latest/general_alt.bat").write_text("fixture alternative strategy\n")
        self.config = self.installer.data / "conf.env"
        self.original = self.config.read_bytes()
        self.digest = hashlib.sha256(self.original).hexdigest()
        self.installer.systemd.calls.clear()

    def test_read_config_returns_validated_fields_and_revision_token(self):
        result = self.helper.dispatch(self.installer, "read-config", {})
        self.assertEqual(result["config"]["strategy"], "general.bat")
        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_profile_change_preserves_other_settings_and_restarts_active_service(self):
        result = self.helper.dispatch(self.installer, "select-profile", {"strategy": "general_alt.bat", "expected_sha256": self.digest})
        self.assertEqual(result["config"]["strategy"], "general_alt.bat")
        self.assertEqual(self.config.read_bytes(), self.original.replace(b"strategy=general.bat", b"strategy=general_alt.bat"))
        self.assertTrue(self.installer.systemd.active)
        self.assertEqual(self.installer.systemd.calls, [("stop", "zapret_discord_youtube.service"), ("start", "zapret_discord_youtube.service")])

    def test_stale_or_invalid_profile_never_stops_service(self):
        for profile, digest in (("../outside.bat", self.digest), ("missing.bat", self.digest), ("general_alt.bat", "0" * 64)):
            with self.subTest(profile=profile, digest=digest):
                with self.assertRaises(ValueError):
                    self.helper.dispatch(self.installer, "select-profile", {"strategy": profile, "expected_sha256": digest})
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_failed_profile_start_restores_config_and_previous_service(self):
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "select-profile", {"strategy": "general_alt.bat", "expected_sha256": self.digest})
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue(self.installer.systemd.active)
        self.assertIn(("reset-failed", "zapret_discord_youtube.service"), self.installer.systemd.calls)

    def test_inactive_profile_change_does_not_start_service(self):
        self.installer.systemd.active = False
        self.helper.dispatch(self.installer, "select-profile", {"strategy": "general_alt.bat", "expected_sha256": self.digest})
        self.assertFalse(self.installer.systemd.active)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_autostart_does_not_change_active_state(self):
        self.helper.dispatch(self.installer, "set-autostart", {"enabled": False})
        self.assertFalse(self.installer.systemd.enabled)
        self.assertTrue(self.installer.systemd.active)

    def test_unknown_actions_extra_fields_and_non_boolean_are_rejected(self):
        for action, payload in (("install", {}), ("read-config", {"path": "/etc/shadow"}),
                                ("set-autostart", {"enabled": 1}), ("set-autostart", {"enabled": True, "unit": "other.service"})):
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, action, payload)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_helper_from_checkout_is_rejected(self):
        with self.assertRaises(ValueError):
            self.helper.verify_release()

    def test_profile_preserves_crlf_comments_and_permissions(self):
        original = b"# comment\r\n" + self.original.replace(b"\n", b"\r\n")
        self.config.write_bytes(original)
        self.config.chmod(0o640)
        self.helper.dispatch(self.installer, "select-profile", {
            "strategy": "general_alt.bat", "expected_sha256": hashlib.sha256(original).hexdigest()})
        self.assertEqual(self.config.read_bytes(), original.replace(b"general.bat", b"general_alt.bat"))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)

    def test_apply_only_passes_approved_data_to_existing_installer(self):
        self.installer.apply_strategies = mock.Mock()
        self.helper.dispatch(self.installer, "apply-strategies", {"stage": "/user/stage", "digest": "a" * 64})
        self.installer.apply_strategies.assert_called_once_with(Path("/user/stage"), "a" * 64, confirmed=True)
        for stage in ("relative", "/bad\x00path"):
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, "apply-strategies", {"stage": stage, "digest": "a" * 64})

    def game_payload(self, mode="all", tcp="2000-3000", udp="4000,5000-6000", digest=None):
        return {"mode": mode, "tcp_ports": tcp, "udp_ports": udp,
                "expected_sha256": digest or self.digest}

    def test_game_filter_modes_preserve_profile_and_restart_only_when_active(self):
        for mode, tcp, udp in (("disabled", "false", "false"), ("tcp", "true", "false"),
                               ("udp", "false", "true"), ("all", "true", "true")):
            with self.subTest(mode=mode):
                self.config.write_bytes(self.original)
                self.installer.systemd.calls.clear()
                result = self.helper.dispatch(self.installer, "set-game-filter", self.game_payload(mode))
                self.assertEqual(result["config"]["strategy"], "general.bat")
                self.assertEqual(result["config"]["gamefiltertcp"], tcp)
                self.assertEqual(result["config"]["gamefilterudp"], udp)
                self.assertEqual(result["config"]["gamefiltertcp_ports"], "2000-3000")
                self.assertEqual(result["config"]["gamefilterudp_ports"], "4000,5000-6000")
                self.assertTrue(self.installer.systemd.active)
                self.assertEqual(self.installer.systemd.calls, [("stop", "zapret_discord_youtube.service"),
                                                               ("start", "zapret_discord_youtube.service")])

    def test_game_filter_invalid_payload_never_changes_config_or_stops_service(self):
        payloads = [self.game_payload(mode="shell"), self.game_payload(tcp="0"), self.game_payload(udp="65536"),
                    self.game_payload(tcp="200-100"), self.game_payload(udp="1,,2"),
                    self.game_payload(tcp="01"), self.game_payload(udp="1;touch /tmp/NO"),
                    self.game_payload(tcp="9" * 513), self.game_payload(digest="0" * 64),
                    {**self.game_payload(), "unit": "other.service"}]
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.helper.dispatch(self.installer, "set-game-filter", payload)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_game_filter_failure_restores_all_config_bytes_and_active_service(self):
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "set-game-filter", self.game_payload())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue(self.installer.systemd.active)

    def test_recovery_resets_failed_unit_before_stop_can_unload_it(self):
        systemd = self.installer.systemd
        original_run = systemd.run
        loaded = True
        def run(*args):
            nonlocal loaded
            if args[0] == "start":
                loaded = True
            if args[0] == "reset-failed" and not loaded:
                raise RuntimeError("unit not loaded")
            original_run(*args)
            if args[0] == "stop":
                loaded = False
        systemd.run = run
        systemd.fail_start = True
        with self.assertRaisesRegex(RuntimeError, "simulated start failure"):
            self.helper.dispatch(self.installer, "set-game-filter", self.game_payload())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue(systemd.active)

    def test_game_filter_preserves_crlf_permissions_and_noop_does_not_restart(self):
        original = b"# retained\r\n" + self.original.replace(b"\n", b"\r\n").rstrip(b"\r\n")
        self.config.write_bytes(original)
        self.config.chmod(0o640)
        self.installer.systemd.active = False
        result = self.helper.dispatch(self.installer, "set-game-filter", self.game_payload(digest=hashlib.sha256(original).hexdigest()))
        content = self.config.read_bytes()
        self.assertIn(b"# retained\r\n", content)
        self.assertNotIn(b"\n", content.replace(b"\r\n", b""))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.installer.systemd.calls, [])
        self.installer.systemd.active = True
        self.helper.dispatch(self.installer, "set-game-filter", self.game_payload(digest=result["sha256"]))
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertEqual(self.config.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
