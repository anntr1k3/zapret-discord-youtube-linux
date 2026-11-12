#!/usr/bin/env python3
"""Exercise the installer in an offline root, never the host's /etc or systemd."""

import importlib.util
import contextlib
import io
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zapret_installer", REPO / "install.py")


class FakeSystemd:
    def __init__(self):
        self.active = False
        self.enabled = False
        self.fail_start = False
        self.calls = []
        self.existing_unit = False

    def unit_exists(self):
        return self.existing_unit

    def is_active(self):
        return self.active

    def is_enabled(self):
        return self.enabled

    def run(self, *args):
        self.calls.append(args)
        if args[0] == "start":
            if self.fail_start:
                self.fail_start = False
                raise RuntimeError("simulated start failure")
            self.active = True
        elif args[0] == "stop":
            self.active = False
        elif args[0] == "enable":
            self.enabled = True
        elif args[0] == "disable":
            self.enabled = False


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zapret-install-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.source = self.base / "source"
        self.source.mkdir()
        for name in ("src/lib", "src/firewall-backends", "custom-strategies",
                     "zapret-latest/lists", "zapret-latest/bin", "user-lists"):
            (self.source / name).mkdir(parents=True)
        (self.source / "service.sh").write_text("#!/bin/bash\n# release one\n")
        (self.source / "src/lib/common.sh").write_text("# fixture library\n# game filter ranges v1\n")
        (self.source / "src/lib/paths.sh").write_text("# fixture paths\n")
        (self.source / "src/firewall-backends/00-nftables.sh").write_text("# fixture\n")
        (self.source / "zapret-latest/general.bat").write_text("--filter-tcp=443\n")
        (self.source / "nfqws").write_text("fixture, must never be executed\n")
        (self.source / "user-lists/list-general-user.txt").write_text("example.org\n")
        (self.source / "conf.env").write_text(
            "interface=any\ngamefiltertcp=false\ngamefilterudp=false\n"
            "strategy=general.bat\nfirewall_backend=nftables\n"
        )
        self.systemd = FakeSystemd()
        self.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.module)
        self.installer = self.module.Installer(self.root, self.systemd)

    def install(self, **kwargs):
        self.installer.install(self.source, **kwargs)

    def test_install_separates_config_and_normalizes_permissions(self):
        (self.source / "service.sh").chmod(0o777)
        self.install()
        current = self.root / "opt/zapret-discord-youtube/current"
        self.assertTrue(current.is_symlink())
        self.assertIn("release one", (current / "service.sh").read_text())
        self.assertEqual((current / "service.sh").stat().st_mode & 0o777, 0o755)
        self.assertEqual((current / "nfqws").stat().st_mode & 0o777, 0o755)
        self.assertFalse((current / "conf.env").exists())
        self.assertTrue((current / ".system-install").is_file())
        self.assertEqual((self.root / "etc/zapret-discord-youtube/user-lists/list-general-user.txt").read_text(), "example.org\n")
        unit = self.root / "etc/systemd/system/zapret_discord_youtube.service"
        self.assertIn("/opt/zapret-discord-youtube/current/service.sh", unit.read_text())
        self.assertNotIn(str(self.source), unit.read_text())
        self.assertFalse(self.systemd.active)

    def test_install_leaves_legacy_list_backups_in_source_only(self):
        backup = self.source / "user-lists/ipset-all.txt.backup"
        backup.write_bytes(b"original backup\n")
        (self.source / "user-lists/ipset-all.txt").write_bytes(b"1.1.1.1\n")
        self.install()
        self.assertEqual(backup.read_bytes(), b"original backup\n")
        target = self.root / "etc/zapret-discord-youtube/user-lists"
        self.assertEqual((target / "ipset-all.txt").read_bytes(), b"1.1.1.1\n")
        self.assertFalse((target / backup.name).exists())
        self.assertFalse(any(self.installer.releases.rglob("*.backup")))

    def test_custom_game_filter_ranges_are_validated_and_installed(self):
        config = self.source / "conf.env"
        config.write_text(config.read_text() + "gamefiltertcp_ports=1,1000-2000,65535\ngamefilterudp_ports=3000-4000\n")
        self.install()
        self.assertEqual((self.installer.data / "conf.env").read_bytes(), config.read_bytes())

    def test_invalid_game_filter_ranges_are_rejected_before_install(self):
        config = self.source / "conf.env"
        original = config.read_text()
        for value in ("", "0", "65536", "2-1", "01", "1,,2", "1 2", "$(id)", "9" * 513):
            with self.subTest(value=value):
                config.write_text(original + "gamefiltertcp_ports=" + value + "\n")
                with self.assertRaises(ValueError):
                    self.module.validate_config(config, self.source)

    def test_custom_ranges_cannot_rollback_to_runtime_without_support(self):
        runtime = self.source / "src/lib/common.sh"
        runtime.write_text("# old runtime\n")
        self.install(start=True)
        runtime.write_text("# new runtime\n# game filter ranges v1\n")
        self.installer.update(self.source)
        config = self.installer.data / "conf.env"
        config.write_text(config.read_text() + "gamefiltertcp_ports=2000-3000\n")
        current = self.installer.current.resolve()
        self.systemd.calls.clear()
        with self.assertRaisesRegex(ValueError, "Game Filter"):
            self.installer.rollback()
        self.assertEqual(self.installer.current.resolve(), current)
        self.assertEqual(self.systemd.calls, [])

    def test_backup_exception_does_not_allow_other_files_or_symlinks(self):
        invalid = self.source / "user-lists/arbitrary.sh"
        invalid.write_text("must not be installed\n")
        with self.assertRaises(ValueError):
            self.install()
        invalid.unlink()
        (self.source / "user-lists/ipset-all.txt.backup").symlink_to(self.source / "conf.env")
        with self.assertRaises(ValueError):
            self.install()

    def test_update_and_rollback_preserve_data(self):
        self.install(start=True)
        config = self.root / "etc/zapret-discord-youtube/conf.env"
        config.write_text(config.read_text().replace("interface=any", "interface=eth0"))
        user_list = config.parent / "user-lists/list-general-user.txt"
        user_list.write_text("user-change.org\n")
        (self.source / "service.sh").write_text("#!/bin/bash\n# release two\n")
        (self.source / "conf.env").write_text("invalid source config is ignored on update\n")
        self.installer.update(self.source)
        current = self.root / "opt/zapret-discord-youtube/current"
        self.assertIn("release two", (current / "service.sh").read_text())
        self.assertTrue(self.systemd.active)
        self.installer.rollback()
        self.assertIn("release one", (current / "service.sh").read_text())
        self.assertIn("interface=eth0", config.read_text())
        self.assertEqual(user_list.read_text(), "user-change.org\n")
        backups = list((self.root / "var/lib/zapret-discord-youtube/backups").glob("*/conf.env"))
        self.assertTrue(backups)
        self.assertIn("interface=eth0", backups[0].read_text())

    def test_failed_update_restores_running_release(self):
        self.install(start=True)
        current = self.root / "opt/zapret-discord-youtube/current"
        original = current.readlink()
        self.systemd.fail_start = True
        (self.source / "service.sh").write_text("#!/bin/bash\n# bad update\n")
        with self.assertRaises(RuntimeError):
            self.installer.update(self.source)
        self.assertEqual(current.readlink(), original)
        self.assertTrue(self.systemd.active)

    def test_recovery_clears_start_limit_before_starting_previous_release(self):
        self.install(start=True)
        original = (self.root / "opt/zapret-discord-youtube/current").readlink()
        original_run = self.systemd.run
        failed_candidate = False
        rate_limited = False

        def rate_limit_after_failure(*args):
            nonlocal failed_candidate, rate_limited
            if args[0] == "start" and not failed_candidate:
                failed_candidate = True
                rate_limited = True
                raise RuntimeError("candidate startup failed")
            if args[0] == "start" and rate_limited:
                raise RuntimeError("Start request repeated too quickly")
            if args[0] == "reset-failed":
                rate_limited = False
            original_run(*args)

        self.systemd.run = rate_limit_after_failure
        with self.assertRaisesRegex(RuntimeError, "^candidate startup failed$"):
            self.installer.update(self.source)
        self.assertTrue(self.systemd.active)
        self.assertFalse(rate_limited)
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").readlink(), original)

    def test_remove_keeps_config_lists_and_backups(self):
        self.install(start=True)
        self.installer.remove()
        self.assertFalse((self.root / "opt/zapret-discord-youtube/current").exists())
        self.assertFalse((self.root / "etc/systemd/system/zapret_discord_youtube.service").exists())
        self.assertTrue((self.root / "etc/zapret-discord-youtube/conf.env").exists())
        self.assertFalse(self.systemd.active)
        self.assertFalse(self.systemd.enabled)
        # Reinstall must reuse rather than overwrite retained user data.
        (self.source / "user-lists/list-general-user.txt").write_text("replacement.org\n")
        self.install()
        self.assertEqual((self.root / "etc/zapret-discord-youtube/user-lists/list-general-user.txt").read_text(), "example.org\n")

    def test_unmanaged_unit_is_not_overwritten(self):
        unit = self.root / "etc/systemd/system/zapret_discord_youtube.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("# Someone else's unit\n")
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(unit.read_text(), "# Someone else's unit\n")
        self.assertEqual(self.systemd.calls, [])

    def test_vendor_or_transient_unit_is_not_shadowed(self):
        self.systemd.existing_unit = True
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.systemd.calls, [])
        self.assertFalse((self.root / "etc/systemd/system/zapret_discord_youtube.service").exists())

    def test_source_symlinks_are_rejected(self):
        (self.source / "src/link").symlink_to(self.base / "outside")
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.systemd.calls, [])

    def test_destination_symlinks_cannot_escape_offline_root(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.root / "etc").symlink_to(outside)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])

    def test_invalid_config_or_missing_binary_does_not_install(self):
        (self.source / "nfqws").unlink()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.systemd.calls, [])

    def test_rollback_without_previous_release_is_rejected(self):
        self.install()
        original = (self.root / "opt/zapret-discord-youtube/current").readlink()
        with self.assertRaises(ValueError):
            self.installer.rollback()
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").readlink(), original)

    def test_offline_root_must_not_resolve_to_host_root(self):
        with self.assertRaises(ValueError):
            self.module.Installer(pathlib.Path("/tmp/.."), self.systemd)

    def test_invalid_initial_config_is_not_executed_or_installed(self):
        marker = self.base / "executed"
        with (self.source / "conf.env").open("a") as stream:
            stream.write(f"$(touch {marker})\n")
        with self.assertRaises(ValueError):
            self.install()
        self.assertFalse(marker.exists())
        self.assertFalse((self.root / "opt/zapret-discord-youtube/current").exists())
        self.assertEqual(self.systemd.calls, [])

    def test_fifo_in_source_is_rejected_without_blocking(self):
        os.mkfifo(self.source / "src/fifo")
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.systemd.calls, [])

    def test_failed_initial_start_disables_and_removes_unit(self):
        self.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.install(start=True)
        self.assertFalse(self.systemd.active)
        self.assertFalse(self.systemd.enabled)
        self.assertFalse((self.root / "etc/systemd/system/zapret_discord_youtube.service").exists())
        self.assertFalse((self.root / "opt/zapret-discord-youtube/current").exists())

    def test_initial_start_failure_disables_before_removing_unit_file(self):
        self.systemd.fail_start = True
        original_run = self.systemd.run

        def disable_needs_unit(*args):
            if args[0] == "disable" and not self.installer.unit.is_file():
                raise RuntimeError("Failed to disable unit: unit file does not exist")
            original_run(*args)

        self.systemd.run = disable_needs_unit
        with self.assertRaisesRegex(RuntimeError, "^simulated start failure$"):
            self.install(start=True)
        self.assertFalse(self.systemd.enabled)
        self.assertFalse(self.installer.unit.exists())

    def test_second_operation_is_rejected_while_locked(self):
        with self.installer.operation():
            other = self.module.Installer(self.root, self.systemd)
            with self.assertRaises(ValueError):
                other.install(self.source)
        self.assertEqual(self.systemd.calls, [])

    def test_failed_remove_reload_restores_unit_and_running_service(self):
        self.install(start=True)
        original_run = self.systemd.run
        failed = False

        def fail_once(*args):
            nonlocal failed
            if args[0] == "daemon-reload" and not failed:
                failed = True
                raise RuntimeError("simulated daemon-reload failure")
            original_run(*args)

        self.systemd.run = fail_once
        with self.assertRaises(RuntimeError):
            self.installer.remove()
        self.assertTrue((self.root / "etc/systemd/system/zapret_discord_youtube.service").is_file())
        self.assertTrue(self.systemd.active)
        self.assertTrue(self.systemd.enabled)
        self.installer.state()

    def test_offline_cli_lifecycle_never_calls_systemctl(self):
        for command in ("install", "update", "rollback", "remove"):
            with self.subTest(command=command):
                with mock.patch.object(self.module.subprocess, "run", side_effect=AssertionError("real process launched")):
                    with mock.patch("sys.argv", ["install.py", command, "--root", str(self.root), "--source", str(self.source)]):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.module.main()

    def test_installed_runtime_uses_external_config_and_user_lists(self):
        # Real Bash libraries, but no daemon, network commands or binaries run.
        shutil.rmtree(self.source / "src")
        shutil.copytree(REPO / "src", self.source / "src")
        (self.source / "service.sh").write_bytes((REPO / "service.sh").read_bytes())
        self.install()
        release = (self.root / "opt/zapret-discord-youtube/current").resolve()
        strategy = release / "zapret-latest/general.bat"
        strategy.write_text('--wf-tcp=443 --wf-udp=443\n'
                            '--filter-tcp=443 --hostlist="%LISTS%list-general-user.txt"\n')
        script = '''
set -e
source "$1/src/lib/paths.sh"
configure_paths "$1"
source "$1/src/lib/common.sh"
load_config
[[ "$SYSTEM_INSTALL" == true && "$CONF_FILE" == "$2/etc/zapret-discord-youtube/conf.env" ]]
USE_GAME_FILTER=false
parse_bat_file "$REPO_DIR/general.bat"
[[ "${nfqws_params[*]}" == *"$2/etc/zapret-discord-youtube/user-lists/list-general-user.txt"* ]]
[[ "${nfqws_params[*]}" != *'lists/list-general-user.txt'* || "${nfqws_params[*]}" == *'/user-lists/'* ]]
'''
        result = subprocess.run(["bash", "-c", script, "test", str(release), str(self.root)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The real CLI must also use /etc, without invoking firewall tools.
        config = self.root / "etc/zapret-discord-youtube/conf.env"
        config.write_text(config.read_text().replace("interface=any", "interface=eth0"))
        fake_bin = self.base / "fake-bin"
        fake_bin.mkdir()
        (fake_bin / "nft").write_text("#!/bin/sh\nexit 99\n")
        (fake_bin / "nft").chmod(0o755)
        result = subprocess.run(["bash", str(release / "service.sh"), "config", "show"],
                                env={**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"},
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("interface=eth0", result.stdout)

    def test_created_directories_and_lock_are_safe_with_permissive_umask(self):
        old = os.umask(0)
        try:
            self.install()
        finally:
            os.umask(old)
        for name in ("var", "var/lib", "opt", "etc"):
            self.assertEqual((self.root / name).stat().st_mode & 0o022, 0)
        self.assertEqual((self.root / "var/lib/zapret-discord-youtube/.install.lock").stat().st_mode & 0o777, 0o600)

    def test_state_write_failure_restores_previous_release(self):
        self.install(start=True)
        original = (self.root / "opt/zapret-discord-youtube/current").readlink()
        old_atomic_write = self.module.atomic_write

        def fail_state_write(path, *args):
            if path == self.installer.state_file:
                raise OSError("simulated state write failure")
            return old_atomic_write(path, *args)

        with mock.patch.object(self.module, "atomic_write", side_effect=fail_state_write):
            with self.assertRaises(OSError):
                self.installer.update(self.source)
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").readlink(), original)
        self.assertTrue(self.systemd.active)
        self.installer.state()

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_generated_unit_passes_systemd_static_validation(self):
        unit = self.base / "zapret_discord_youtube.service"
        unit.write_bytes(self.installer.unit_content())
        result = subprocess.run(["systemd-analyze", "verify", "--man=no", str(unit)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_interrupted_update_recovers_previous_release(self):
        self.install(start=True)
        original = (self.root / "opt/zapret-discord-youtube/current").readlink()
        original_run = self.systemd.run
        interrupted = False

        def interrupt_once(*args):
            nonlocal interrupted
            if args[0] == "start" and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            original_run(*args)

        self.systemd.run = interrupt_once
        with self.assertRaises(KeyboardInterrupt):
            self.installer.update(self.source)
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").readlink(), original)
        self.assertTrue(self.systemd.active)
        self.installer.state()

    def test_offline_cli_cannot_start_host_service(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with mock.patch("sys.argv", ["install.py", "install", "--root", str(self.root), "--start"]):
                with self.assertRaises(SystemExit) as error:
                    self.module.main()
        self.assertEqual(error.exception.code, 2)

    def sync_fixture(self):
        shutil.rmtree(self.source / "src")
        shutil.copytree(REPO / "src", self.source / "src")
        self.install(start=True)
        spec = importlib.util.spec_from_file_location("installer_sync_fixture", REPO / "src/lib/strategy_sync.py")
        sync = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync)
        self.module.load_strategy_sync = lambda: sync
        files = {"general.bat": b'start "test" /min "%BIN%winws.exe" --wf-tcp=443 --wf-udp=443 ^\n--filter-tcp=443 --hostlist="%LISTS%list-general-user.txt" --dpi-desync=fake\n',
                 "lists/list-general.txt": b"upstream.example\n"}
        _, digest = sync.write_stage(self.base / "stage", files,
                                    {"revision": "a" * 40, "channel": "main", "tag": None})
        self.systemd.calls.clear()
        return sync, digest

    def test_trusted_sync_loader_does_not_create_bytecode_in_release(self):
        helper = self.source / "src/lib/strategy_sync.py"
        helper.write_text("VALUE = 123\n")
        self.module.__file__ = str(self.source / "install.py")
        with mock.patch.object(sys, "dont_write_bytecode", False):
            loaded = self.module.load_strategy_sync()
        self.assertEqual(loaded.VALUE, 123)
        self.assertFalse((helper.parent / "__pycache__").exists())

    def test_strategy_apply_changes_only_data_and_can_roll_back(self):
        sync, digest = self.sync_fixture()
        before = (self.root / "opt/zapret-discord-youtube/current").resolve()
        config = (self.root / "etc/zapret-discord-youtube/conf.env").read_bytes()
        hashes = {name: hashlib.sha256((before / name).read_bytes()).hexdigest()
                  for name in ("nfqws", "service.sh", "src/lib/common.sh", "install.py")}
        with mock.patch.object(sync, "validate_catalog") as validate, mock.patch.object(sync, "fetch_bytes", side_effect=AssertionError("privileged network access")):
            self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        after = (self.root / "opt/zapret-discord-youtube/current").resolve()
        self.assertNotEqual(before, after)
        self.assertTrue((after / "zapret-latest/strategies.json").is_file())
        for name, expected in hashes.items():
            self.assertEqual(hashlib.sha256((after / name).read_bytes()).hexdigest(), expected)
        self.assertEqual((self.root / "etc/zapret-discord-youtube/conf.env").read_bytes(), config)
        self.assertEqual((self.root / "etc/zapret-discord-youtube/user-lists/list-general-user.txt").read_text(), "example.org\n")
        self.assertTrue(self.systemd.active)
        self.assertEqual(validate.call_count, 2)
        self.assertTrue(validate.call_args_list[0].kwargs.get("private"))
        self.assertFalse(validate.call_args_list[1].kwargs.get("private", False))
        self.installer.rollback()
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").resolve(), before)

    def test_strategy_apply_validates_actual_custom_game_ranges(self):
        sync, digest = self.sync_fixture()
        config = self.installer.data / "conf.env"
        config.write_text(config.read_text() + "gamefiltertcp_ports=1000-2000\ngamefilterudp_ports=3000,4000\n")
        with mock.patch.object(sync, "validate_catalog") as validate:
            self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual(validate.call_count, 2)
        for call in validate.call_args_list:
            self.assertEqual(call.kwargs["tcp_range"], "1000-2000")
            self.assertEqual(call.kwargs["udp_range"], "3000,4000")

    def test_strategy_apply_requires_confirmation_and_checks_digest_before_stopping(self):
        sync, digest = self.sync_fixture()
        with self.assertRaises(ValueError):
            self.installer.apply_strategies(self.base / "stage", digest)
        (self.base / "stage/payload/general.bat").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual(self.systemd.calls, [])

    def test_incompatible_strategy_update_does_not_stop_service(self):
        sync, digest = self.sync_fixture()
        with mock.patch.object(sync, "validate_catalog", side_effect=ValueError("unsupported nfqws option")):
            with self.assertRaises(ValueError):
                self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual(self.systemd.calls, [])
        self.assertTrue(self.systemd.active)

    def test_public_access_validation_failure_never_switches_release(self):
        sync, digest = self.sync_fixture()
        before = (self.root / "opt/zapret-discord-youtube/current").resolve()
        releases = set(self.installer.releases.iterdir())
        with mock.patch.object(sync, "validate_catalog", side_effect=[None, ValueError("public file access denied")]):
            with self.assertRaisesRegex(ValueError, "public file access denied"):
                self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual(self.systemd.calls, [])
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").resolve(), before)
        self.assertEqual(set(self.installer.releases.iterdir()), releases)

    def test_failed_strategy_activation_restores_previous_release(self):
        sync, digest = self.sync_fixture()
        before = (self.root / "opt/zapret-discord-youtube/current").resolve()
        self.systemd.fail_start = True
        with mock.patch.object(sync, "validate_catalog"):
            with self.assertRaises(RuntimeError):
                self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual((self.root / "opt/zapret-discord-youtube/current").resolve(), before)
        self.assertTrue(self.systemd.active)

    def test_removed_selected_strategy_is_rejected_before_stopping(self):
        sync, digest = self.sync_fixture()
        manifest, files = sync.load_stage(self.base / "stage", digest)
        files["general (ALT).bat"] = files.pop("general.bat")
        _, other_digest = sync.write_stage(self.base / "other-stage", files,
                                          {key: manifest[key] for key in ("revision", "channel", "tag")})
        with self.assertRaisesRegex(ValueError, "Configured strategy is absent"):
            self.installer.apply_strategies(self.base / "other-stage", other_digest, confirmed=True)
        self.assertEqual(self.systemd.calls, [])

    def test_selected_custom_strategy_is_retained_but_not_blindly_updated(self):
        sync, digest = self.sync_fixture()
        current = (self.root / "opt/zapret-discord-youtube/current").resolve()
        custom = current / "custom-strategies/local.bat"
        custom.write_bytes(b"user-owned strategy data")
        config = self.root / "etc/zapret-discord-youtube/conf.env"
        config.write_text(config.read_text().replace("strategy=general.bat", "strategy=local.bat"))
        with self.assertRaisesRegex(ValueError, "Selected custom strategy"):
            self.installer.apply_strategies(self.base / "stage", digest, confirmed=True)
        self.assertEqual(custom.read_bytes(), b"user-owned strategy data")
        self.assertEqual(self.systemd.calls, [])


if __name__ == "__main__":
    unittest.main()
