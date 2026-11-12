#!/usr/bin/env python3
"""IPSet mode tests: offline roots and data-only runtimes, never host firewall."""

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_installer as fixtures


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.module = load("ipset_modes_test", ROOT / "src/lib/ipset_mode.py")
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-ipset-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.repo = self.base / "zapret-latest"
        self.lists = self.base / "user-lists"
        (self.repo / "lists").mkdir(parents=True)
        self.lists.mkdir()
        (self.base / "src/lib").mkdir(parents=True)
        (self.base / "src/lib/ipset-none.txt").write_text("203.0.113.113/32\n")
        (self.base / "src/lib/ipset-any.txt").write_text("\n")
        (self.repo / "lists/ipset-all.txt").write_text("198.51.100.0/24\n")

    def test_mode_classification_and_loaded_backup_without_mutation(self):
        main = self.lists / "ipset-all.txt"
        backup = self.lists / "ipset-all.txt.backup"
        main.write_text("203.0.113.113/32\n")
        backup.write_text("# retained\n192.0.2.0/24\n2001:db8::/32\n")
        before = {path: path.read_bytes() for path in (main, backup)}
        info = self.module.describe("legacy", self.repo, self.lists)
        self.assertEqual(info["effective_mode"], "none")
        self.assertTrue(info["loaded_available"])
        self.assertEqual(info["loaded_source"], str(backup))
        self.assertEqual(info["loaded_entries"], 2)
        for mode, expected in (("legacy", main), ("loaded", backup),
                               ("none", self.base / "src/lib/ipset-none.txt"),
                               ("any", self.base / "src/lib/ipset-any.txt")):
            self.assertEqual(self.module.resolve_list(mode, self.repo, self.lists), expected)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_empty_or_dummy_list_is_never_reported_as_loaded(self):
        source = self.repo / "lists/ipset-all.txt"
        for data, kind in (("", "any"), ("# comment\n\n", "any"), ("203.0.113.113/32\n", "none")):
            source.write_text(data)
            info = self.module.describe("legacy", self.repo, self.lists)
            self.assertEqual(info["effective_mode"], kind)
            self.assertFalse(info["loaded_available"])
            with self.assertRaises(ValueError):
                self.module.resolve_list("loaded", self.repo, self.lists)

    def test_invalid_inputs_symlinks_and_special_files_are_rejected(self):
        path = self.lists / "ipset-all.txt"
        for value in ("not an ip\n", "1.2.3.999\n", "192.0.2.0/99\n", "$(id)\n", "1.2.3.4\x00\n", "fe80::1%eth0\n", "192.0.2.0/255.255.255.0\n",
                      "192.0.2.1\u0085198.51.100.1\n", "192.0.2.1\u00a0\n"):
            path.write_text(value)
            with self.assertRaises(ValueError):
                self.module.inspect_list(path)
            with self.assertRaises(ValueError):
                self.module.resolve_list("loaded", self.repo, self.lists)
        path.unlink()
        path.symlink_to(self.repo / "lists/ipset-all.txt")
        with self.assertRaises(ValueError):
            self.module.inspect_list(path)
        path.unlink()
        with path.open("wb") as stream:
            stream.truncate(self.module.MAX_BYTES + 1)
        with self.assertRaises(ValueError):
            self.module.inspect_list(path)
        with self.assertRaises(ValueError):
            self.module.resolve_list("../other", self.repo, self.lists)

    def test_fifo_is_rejected_without_blocking(self):
        import os
        fifo = self.lists / "fifo.txt"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.module.inspect_list(fifo)

    def test_builtin_files_cannot_silently_change_mode(self):
        (self.base / "src/lib/ipset-any.txt").write_text("192.0.2.0/24\n")
        with self.assertRaises(ValueError):
            self.module.resolve_list("any", self.repo, self.lists)

    def test_rewrite_changes_only_main_inclusion_option(self):
        text = '--ipset="lists/ipset-all.txt" --ipset-exclude="lists/ipset-all.txt" --ipset=lists/other.txt'
        rewritten = self.module.rewrite_legacy(text, "none", self.repo, self.lists)
        self.assertIn('--ipset="' + str(self.base / "src/lib/ipset-none.txt") + '"', rewritten)
        self.assertIn('--ipset-exclude="lists/ipset-all.txt"', rewritten)
        self.assertIn('--ipset=lists/other.txt', rewritten)

    def test_compiled_runtime_preserves_exclusions_and_original_lists(self):
        sync = load("ipset_sync_test", ROOT / "src/lib/strategy_sync.py")
        exclude = self.lists / "ipset-exclude-user.txt"
        exclude.write_text("192.0.2.1\n")
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [[
            "--filter-tcp=443", "--ipset=lists/ipset-all.txt",
            "--ipset-exclude=lists/ipset-exclude-user.txt", "--dpi-desync=fake"]]}
        for mode in ("loaded", "none", "any"):
            result = sync.materialize(strategy, self.repo, self.lists, False, False, ipset_mode=mode)
            self.assertIn("--ipset=" + str(self.module.resolve_list(mode, self.repo, self.lists)), result["argv"])
            self.assertIn("--ipset-exclude=" + str(exclude), result["argv"])
        self.assertEqual(exclude.read_text(), "192.0.2.1\n")
        self.assertEqual((self.repo / "lists/ipset-all.txt").read_text(), "198.51.100.0/24\n")

    def test_legacy_bash_runtime_uses_mode_without_rewriting_source(self):
        bat = self.repo / "general.bat"
        content = 'start "test" /min "%BIN%winws.exe" --wf-tcp=443 --wf-udp=443 ^\n--filter-tcp=443 --ipset="%LISTS%ipset-all.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" --dpi-desync=fake\n'
        bat.write_text(content)
        script = '''
set -e
source "$1/src/lib/common.sh"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
SYSTEM_INSTALL=true
ipset_mode=none
USE_GAME_FILTER=false
parse_bat_file "$REPO_DIR/general.bat"
printf '%s\\n' "${nfqws_params[@]}"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.base)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.base / "src/lib/ipset-none.txt"), result.stdout)
        self.assertEqual(bat.read_text(), content)

    def test_compiled_bash_runtime_passes_ipset_mode(self):
        sync = load("ipset_bash_sync_test", ROOT / "src/lib/strategy_sync.py")
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [[
            "--filter-tcp=443", "--ipset=lists/ipset-all.txt", "--dpi-desync=fake"]]}
        sync.atomic_json(self.repo / "strategies.json", {"schema": 1, "strategies": {"general.bat": strategy}})
        script = '''
set -e
source "$1/src/lib/common.sh"
BASE_DIR="$1"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
ipset_mode=any
parse_bat_file "$REPO_DIR/general.bat"
printf '%s\\n' "${nfqws_argv[@]}"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.base)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--ipset=" + str(self.base / "src/lib/ipset-any.txt"), result.stdout.splitlines())


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        source = self.fixture.source
        common = source / "src/lib/common.sh"
        common.write_text(common.read_text() + "# ipset mode v1\n")
        for name in ("ipset-none.txt", "ipset-any.txt"):
            (source / "src/lib" / name).write_bytes((ROOT / "src/lib" / name).read_bytes())
        (source / "zapret-latest/lists/ipset-all.txt").write_text("198.51.100.0/24\n")
        self.fixture.install(start=True)
        self.installer = self.fixture.installer
        self.installer.validate_config = self.fixture.module.validate_config
        self.helper = load("ipset_helper_test", ROOT / "src/gui/privileged.py")
        self.config = self.installer.data / "conf.env"
        self.original = self.config.read_bytes()
        self.installer.systemd.calls.clear()

    def read(self):
        return self.helper.dispatch(self.installer, "read-config", {})

    def request(self, mode, config=None):
        config = config or self.read()
        return {"mode": mode, "expected_sha256": config["sha256"],
                "expected_list_sha256": config["ipset"]["loaded_sha256"] if mode == "loaded" else None}

    def test_modes_preserve_lists_code_profile_and_autostart(self):
        paths = [*self.installer.data.joinpath("user-lists").rglob("*"),
                 *self.installer.current.resolve().rglob("*")]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.is_file()}
        for mode in ("none", "any", "loaded"):
            result = self.helper.dispatch(self.installer, "set-ipset-mode", self.request(mode))
            self.assertEqual(result["config"]["ipset_mode"], mode)
            self.assertEqual(result["ipset"]["effective_mode"], mode)
            self.assertEqual(result["config"]["strategy"], "general.bat")
            self.assertTrue(self.installer.systemd.active)
            self.assertTrue(self.installer.systemd.enabled)
        self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before})

    def test_inactive_edit_and_identical_edit_do_not_start_or_restart(self):
        self.installer.systemd.active = False
        self.helper.dispatch(self.installer, "set-ipset-mode", self.request("any"))
        self.assertEqual(self.installer.systemd.calls, [])
        self.installer.systemd.active = True
        self.helper.dispatch(self.installer, "set-ipset-mode", self.request("any"))
        self.assertEqual(self.installer.systemd.calls, [])

    def test_invalid_modes_fields_and_stale_tokens_never_stop_service(self):
        read = self.read()
        payloads = [self.request("loaded", read), self.request("none", read), self.request("none", read), self.request("none", read)]
        payloads[0]["expected_list_sha256"] = "0" * 64
        payloads[1]["expected_sha256"] = "0" * 64
        payloads[2]["mode"] = "../path"
        payloads[3]["path"] = "/etc/shadow"
        for payload in payloads:
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, "set-ipset-mode", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_changed_list_is_not_silently_approved(self):
        approved = self.request("loaded")
        path = self.installer.data / "user-lists/ipset-all.txt"
        path.write_text("192.0.2.0/24\n")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-ipset-mode", approved)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertEqual(path.read_text(), "192.0.2.0/24\n")

    def test_failed_restart_restores_config_and_service(self):
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "set-ipset-mode", self.request("none"))
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue(self.installer.systemd.active)

    def test_initial_install_preserves_valid_legacy_backup_as_loaded_data(self):
        source = self.fixture.source
        (source / "user-lists/ipset-all.txt").write_text("203.0.113.113/32\n")
        backup = source / "user-lists/ipset-all.txt.backup"
        backup.write_text("192.0.2.0/24\n")
        with self.fixture.module.package_snapshot(source) as package:
            self.assertEqual((package / "user-lists/ipset-loaded.txt").read_text(), "192.0.2.0/24\n")
            self.assertFalse((package / "user-lists/ipset-all.txt.backup").exists())
        self.assertEqual(backup.read_text(), "192.0.2.0/24\n")

    def test_existing_saved_loaded_set_is_never_replaced_during_snapshot(self):
        lists = self.fixture.source / "user-lists"
        (lists / "ipset-loaded.txt").write_text("192.0.2.0/24\n")
        (lists / "ipset-all.txt.backup").write_text("198.51.100.0/24\n")
        with self.fixture.module.package_snapshot(self.fixture.source) as package:
            self.assertEqual((package / "user-lists/ipset-loaded.txt").read_text(), "192.0.2.0/24\n")

    def test_loaded_mode_without_valid_data_is_rejected_before_stop(self):
        (self.installer.data / "user-lists/ipset-all.txt").write_text("203.0.113.113/32\n")
        (self.installer.current.resolve() / "zapret-latest/lists/ipset-all.txt").write_text("\n")
        info = self.read()
        self.assertFalse(info["ipset"]["loaded_available"])
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-ipset-mode", {
                "mode": "loaded", "expected_sha256": info["sha256"], "expected_list_sha256": "a" * 64})
        self.assertEqual(self.installer.systemd.calls, [])

    def test_missing_loaded_data_can_be_recovered_by_selecting_none(self):
        self.helper.dispatch(self.installer, "set-ipset-mode", self.request("loaded"))
        (self.installer.data / "user-lists/ipset-all.txt").write_text("\n")
        (self.installer.current.resolve() / "zapret-latest/lists/ipset-all.txt").write_text("203.0.113.113/32\n")
        read = self.read()
        self.assertFalse(read["ipset"]["loaded_available"])
        self.assertEqual(read["ipset"]["effective_mode"], "unavailable")
        result = self.helper.dispatch(self.installer, "set-ipset-mode", self.request("none", read))
        self.assertEqual(result["ipset"]["effective_mode"], "none")
        self.assertTrue(self.installer.systemd.active)

    def test_config_compatibility_guard_and_bash_validation(self):
        common = self.installer.current.resolve() / "src/lib/common.sh"
        common.write_text("# old runtime\n")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-ipset-mode", self.request("none"))
        self.assertEqual(self.installer.systemd.calls, [])
        cfg = self.fixture.base / "test-config.env"
        for mode, valid in (("loaded", True), ("none", True), ("any", True), ("legacy", True), ("bad", False)):
            cfg.write_bytes(self.original + ("ipset_mode=" + mode + "\n").encode())
            result = subprocess.run(["bash", "-c", 'source "$1/src/lib/common.sh"; check_conf_file "$2"',
                                     "test", str(ROOT), str(cfg)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode == 0, valid)


if __name__ == "__main__":
    unittest.main()
