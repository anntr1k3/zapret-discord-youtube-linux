#!/usr/bin/env python3
"""Active fake selection tests: offline roots and data-only runtimes."""

import hashlib
import importlib.util
import os
from pathlib import Path
import re
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


BAT = (
    'start "test" /min "%BIN%winws.exe" --wf-tcp=443 --wf-udp=443 ^\n'
    "--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic=\"%BIN%quic_a.bin\" --new ^\n"
    "--filter-udp=19294 --filter-l7=discord --dpi-desync=fake "
    '--dpi-desync-fake-discord="%BIN%stun.bin" --dpi-desync-fake-discord="%BIN%quic_a.bin" '
    '--dpi-desync-fake-stun="%BIN%quic_a.bin" --new ^\n'
    "--filter-udp=50000 --ipset=lists/ipset-all.txt --dpi-desync=fake "
    '--dpi-desync-fake-unknown-udp="%BIN%quic_a.bin" --new ^\n'
    "--filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=\"%BIN%tls.bin\" "
    '--dpi-desync-fake-http=0x1603030001\n'
)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.module = load("active_fakes_test", ROOT / "src/lib/fake_select.py")
        self.sync = load("active_fakes_sync_test", ROOT / "src/lib/strategy_sync.py")
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-fakes-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.repo = self.base / "zapret-latest"
        self.data = self.base / "data"
        (self.repo / "bin").mkdir(parents=True)
        self.data.mkdir()
        self.bins = {"stun.bin": b"stun-bytes", "quic_a.bin": b"quic-a-bytes",
                     "tls.bin": b"tls-bytes"}
        for name, data in self.bins.items():
            (self.repo / "bin" / name).write_bytes(data)

    def hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def test_available_lists_regular_bins_with_hashes(self):
        (self.repo / "bin/nested.bin").write_bytes(b"x")
        listing = self.module.available(self.repo)
        self.assertEqual([item["name"] for item in listing], ["nested.bin", "quic_a.bin", "stun.bin", "tls.bin"])
        self.assertEqual(listing[0]["sha256"], self.hash(b"x"))
        self.assertEqual(listing[0]["size"], 1)
        os.mkfifo(self.repo / "bin/fifo.bin")
        with self.assertRaises(ValueError):
            self.module.available(self.repo)
        target = self.repo / "bin/stun.bin"
        link = self.repo / "bin/link.bin"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            self.module.available(self.repo)
        link.unlink()
        big = self.repo / "bin/big.bin"
        with big.open("wb") as stream:
            stream.truncate(self.module.MAX_BYTES + 1)
        with self.assertRaises(ValueError):
            self.module.available(self.repo)

    def test_selection_by_hash_and_unsupported_names(self):
        self.assertEqual(self.module.select_source(self.repo, self.hash(b"stun-bytes")),
                         self.repo / "bin/stun.bin")
        for sha in ("0" * 64, "not-a-hash"):
            with self.assertRaises(ValueError):
                self.module.select_source(self.repo, sha)

    def test_rewrite_replaces_only_affected_bin_values(self):
        discord = self.module.active_path(self.data, "discord")
        game = self.module.active_path(self.data, "gameudp")
        (self.data / "fakes").mkdir()
        discord.write_bytes(b"stun-bytes")
        game.write_bytes(b"quic-a-bytes")
        rewritten = self.module.rewrite(BAT, self.repo, self.data, self.hash(b"stun-bytes"), self.hash(b"quic-a-bytes"))
        self.assertEqual(rewritten.count("--dpi-desync-fake-discord=\"" + str(discord) + "\""), 2)
        self.assertIn('--dpi-desync-fake-stun="' + str(discord) + '"', rewritten)
        self.assertIn('--dpi-desync-fake-unknown-udp="' + str(game) + '"', rewritten)
        self.assertIn('--dpi-desync-fake-quic="%BIN%quic_a.bin"', rewritten)
        self.assertIn('--dpi-desync-fake-tls="%BIN%tls.bin"', rewritten)
        self.assertIn("--dpi-desync-fake-http=0x1603030001", rewritten)
        self.assertEqual(rewritten, self.module.rewrite(rewritten, self.repo, self.data,
                                                        self.hash(b"stun-bytes"), self.hash(b"quic-a-bytes")))
        self.assertEqual(self.module.rewrite(BAT, self.repo, self.data, "", ""), BAT)

    def test_rewrite_verifies_active_files_strictly(self):
        (self.data / "fakes").mkdir()
        discord = self.module.active_path(self.data, "discord")
        discord.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.module.rewrite(BAT, self.repo, self.data, self.hash(b"stun-bytes"), "")
        discord.unlink()
        with self.assertRaises(ValueError):
            self.module.rewrite(BAT, self.repo, self.data, self.hash(b"stun-bytes"), "")
        discord.write_bytes(b"stun-bytes")
        self.assertIn(str(discord), self.module.rewrite(BAT, self.repo, self.data, self.hash(b"stun-bytes"), ""))
        symlink = self.module.active_path(self.data, "gameudp")
        symlink.symlink_to(self.repo / "bin/stun.bin")
        with self.assertRaises(ValueError):
            self.module.rewrite(BAT, self.repo, self.data, self.hash(b"stun-bytes"), self.hash(b"stun-bytes"))

    def test_describe_reports_configured_and_matched_names(self):
        (self.data / "fakes").mkdir()
        self.module.active_path(self.data, "discord").write_bytes(b"stun-bytes")
        self.module.active_path(self.data, "gameudp").write_bytes(b"custom-bytes")
        info = self.module.describe(self.repo, self.data, {"fakediscord": self.hash(b"stun-bytes")})
        self.assertEqual(info["discord"]["configured"], True)
        self.assertEqual(info["discord"]["matched_name"], "stun.bin")
        self.assertEqual(info["discord"]["override_sha256"], self.hash(b"stun-bytes"))
        self.assertEqual(info["gameudp"]["configured"], False)
        self.assertEqual(info["gameudp"]["matched_name"], None)
        self.assertEqual([item["name"] for item in info["discord"]["available"]],
                         ["quic_a.bin", "stun.bin", "tls.bin"])
        info = self.module.describe(self.repo, self.data, {"fakediscord": self.hash(b"quic-a-bytes")})
        self.assertIsNone(info["discord"]["matched_name"])
        self.assertIn("SHA-256", info["discord"]["warning"])

    def test_usage_counts_only_affected_bin_tokens(self):
        usage = self.module.strategy_usage(BAT)
        self.assertEqual(usage["discord"], 3)
        self.assertEqual(usage["gameudp"], 1)
        no_discord = "\n".join(line for line in BAT.splitlines()
                               if "fake-discord" not in line and "fake-stun" not in line)
        self.assertEqual(self.module.strategy_usage(no_discord)["discord"], 0)
        self.assertEqual(self.module.strategy_usage(no_discord)["gameudp"], 1)

    def test_compiled_materialize_substitutes_fakes(self):
        (self.data / "fakes").mkdir()
        discord = self.module.active_path(self.data, "discord")
        game = self.module.active_path(self.data, "gameudp")
        discord.write_bytes(b"stun-bytes")
        game.write_bytes(b"quic-a-bytes")
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [
            ["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-fake-quic=bin/quic_a.bin"],
            ["--filter-udp=19294", "--filter-l7=discord", "--dpi-desync=fake",
             "--dpi-desync-fake-discord=bin/stun.bin", "--dpi-desync-fake-discord=bin/quic_a.bin",
             "--dpi-desync-fake-stun=bin/quic_a.bin"],
            ["--filter-udp=50000", "--ipset=lists/ipset-all.txt", "--dpi-desync=fake",
             "--dpi-desync-fake-unknown-udp=bin/quic_a.bin"],
            ["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fake-tls=bin/tls.bin",
             "--dpi-desync-fake-http=0x1603030001"]]}
        result = self.sync.materialize(strategy, self.repo, self.data, False, False,
                                       fakes={"discord": str(discord), "gameudp": str(game)})
        self.assertIn("--dpi-desync-fake-quic=" + str(self.repo / "bin/quic_a.bin"), result["argv"])
        self.assertEqual(result["argv"].count("--dpi-desync-fake-discord=" + str(discord)), 2)
        self.assertIn("--dpi-desync-fake-stun=" + str(discord), result["argv"])
        self.assertIn("--dpi-desync-fake-unknown-udp=" + str(game), result["argv"])
        self.assertIn("--dpi-desync-fake-tls=" + str(self.repo / "bin/tls.bin"), result["argv"])
        self.assertIn("--dpi-desync-fake-http=0x1603030001", result["argv"])
        self.assertIn("--new", result["argv"])
        untouched = self.sync.materialize(strategy, self.repo, self.data, False, False)
        for token in untouched["argv"]:
            if token.startswith("--dpi-desync-fake-discord="):
                self.assertNotIn(str(discord), token)
        self.assertEqual(self.sync.materialize(strategy, self.repo, self.data, False, False,
                                               fakes={"discord": None, "gameudp": None}), untouched)

    def test_legacy_bash_runtime_uses_fakes_without_rewriting_source(self):
        bat = self.repo / "general.bat"
        bat.write_text(BAT.replace('"%BIN%winws.exe"', '"%BIN%winws.exe"').replace(" --new ^", " --new ^"))
        (self.data / "fakes").mkdir()
        discord = self.module.active_path(self.data, "discord")
        game = self.module.active_path(self.data, "gameudp")
        discord.write_bytes(b"stun-bytes")
        game.write_bytes(b"quic-a-bytes")
        script = '''
set -e
source "$1/src/lib/common.sh"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
FAKE_DIR="$2/data/fakes"
SYSTEM_INSTALL=true
USE_GAME_FILTER=false
fakediscord="$3"
fakegameudp="$4"
parse_bat_file "$REPO_DIR/general.bat"
printf '%s\\n' "${nfqws_params[@]}"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.base),
                                 self.hash(b"stun-bytes"), self.hash(b"quic-a-bytes")],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count(str(discord)), 3)
        self.assertEqual(result.stdout.count(str(game)), 1)
        self.assertIn("bin/tls.bin", result.stdout)
        self.assertEqual(bat.read_text(), BAT.replace(' --new ^', ' --new ^'))

    def test_compiled_bash_runtime_passes_fake_paths(self):
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [
            ["--filter-udp=19294", "--filter-l7=discord", "--dpi-desync=fake",
             "--dpi-desync-fake-discord=bin/stun.bin"]]}
        self.sync.atomic_json(self.repo / "strategies.json", {"schema": 1, "strategies": {"general.bat": strategy}})
        (self.data / "fakes").mkdir()
        discord = self.module.active_path(self.data, "discord")
        discord.write_bytes(b"stun-bytes")
        script = '''
set -e
source "$1/src/lib/common.sh"
BASE_DIR="$1"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
FAKE_DIR="$2/data/fakes"
USE_GAME_FILTER=false
fakediscord="$3"
fakegameudp=""
parse_bat_file "$REPO_DIR/general.bat"
printf '%s\\n' "${nfqws_argv[@]}"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.base),
                                 self.hash(b"stun-bytes")], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(discord), result.stdout)

    def test_compiled_bash_runtime_rejects_drifted_fake_file(self):
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [
            ["--filter-udp=19294", "--filter-l7=discord", "--dpi-desync=fake",
             "--dpi-desync-fake-discord=bin/stun.bin"]]}
        self.sync.atomic_json(self.repo / "strategies.json", {"schema": 1, "strategies": {"general.bat": strategy}})
        (self.data / "fakes").mkdir()
        self.module.active_path(self.data, "discord").write_bytes(b"tampered")
        script = '''
set -e
source "$1/src/lib/common.sh"
BASE_DIR="$1"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
FAKE_DIR="$2/data/fakes"
USE_GAME_FILTER=false
fakediscord="$3"
parse_bat_file "$REPO_DIR/general.bat"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.base),
                                 self.hash(b"stun-bytes")], capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        source = self.fixture.source
        common = source / "src/lib/common.sh"
        common.write_text(common.read_text() + "# ipset mode v1\n# active fakes v1\n")
        for name in ("ipset-none.txt", "ipset-any.txt"):
            (source / "src/lib" / name).write_bytes((ROOT / "src/lib" / name).read_bytes())
        bins = {"stun.bin": b"stun-bytes", "quic_a.bin": b"quic-a-bytes", "tls.bin": b"tls-bytes"}
        for name, data in bins.items():
            (source / "zapret-latest/bin" / name).write_bytes(data)
        bat = source / "zapret-latest/general.bat"
        bat.write_text(BAT.replace("--wf-udp=443 ^", "--wf-udp=443 ^").replace("\n", " \n"))
        (source / "src/lib/fake_select.py").write_bytes((ROOT / "src/lib/fake_select.py").read_bytes())
        self.sync = load("fakes_helper_sync_test", ROOT / "src/lib/strategy_sync.py")
        self.bins = {name: hashlib.sha256(data).hexdigest() for name, data in bins.items()}
        self.fixture.install(start=True)
        self.installer = self.fixture.installer
        self.installer.validate_config = self.fixture.module.validate_config
        self.helper = load("fakes_helper_test", ROOT / "src/gui/privileged.py")
        self.config = self.installer.data / "conf.env"
        self.original = self.config.read_bytes()
        self.installer.systemd.calls.clear()

    def read(self):
        return self.helper.dispatch(self.installer, "read-config", {})

    def request(self, discord=None, gameudp=None, config=None):
        config = config or self.read()
        return {"discord": discord, "gameudp": gameudp, "expected_sha256": config["sha256"]}

    def data_tree(self):
        return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.installer.data.rglob("*")
                if path.is_file()}

    def test_read_config_reports_fakes_and_capability(self):
        result = self.read()
        self.assertIn("active-fakes-v1", result["capabilities"])
        fakes = result["fakes"]
        self.assertEqual(fakes["discord"]["configured"], False)
        self.assertEqual(fakes["discord"]["matched_name"], None)
        self.assertEqual([item["name"] for item in fakes["discord"]["available"]],
                         ["quic_a.bin", "stun.bin", "tls.bin"])
        self.assertEqual(fakes["gameudp"]["available"], fakes["discord"]["available"])

    def test_read_config_counts_usage_from_compiled_catalog(self):
        current = self.installer.current.resolve()
        strategy = {"tcp_ports": "443", "udp_ports": "443", "profiles": [
            ["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-fake-quic=bin/quic_a.bin"],
            ["--filter-udp=19294", "--filter-l7=discord", "--dpi-desync=fake",
             "--dpi-desync-fake-discord=bin/stun.bin", "--dpi-desync-fake-discord=bin/quic_a.bin",
             "--dpi-desync-fake-stun=bin/quic_a.bin"],
            ["--filter-udp=50000", "--ipset=lists/ipset-all.txt", "--dpi-desync=fake",
             "--dpi-desync-fake-unknown-udp=bin/quic_a.bin"],
            ["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fake-tls=bin/tls.bin",
             "--dpi-desync-fake-http=0x1603030001"]]}
        (current / "zapret-latest/general.bat").write_text(
            ":: Data-only synchronized strategy; parsed from strategies.json\n")
        self.sync.atomic_json(current / "zapret-latest/strategies.json",
                              {"schema": 1, "strategies": {"general.bat": strategy}})
        result = self.read()
        self.assertEqual(result["fakes_usage"], {"discord": 3, "gameudp": 1})

    def test_custom_strategy_usage_ignores_catalog(self):
        current = self.installer.current.resolve()
        custom = current / "custom-strategies"
        custom.mkdir(exist_ok=True)
        (custom / "general.bat").write_text(BAT.replace("\n", " \n"))
        self.sync.atomic_json(current / "zapret-latest/strategies.json",
                              {"schema": 1, "strategies": {"general.bat": {"tcp_ports": "443",
                                                                           "udp_ports": "443", "profiles": []}}})
        result = self.read()
        self.assertEqual(result["fakes_usage"], {"discord": 3, "gameudp": 1})

    def test_usage_falls_back_to_bat_without_valid_catalog(self):
        current = self.installer.current.resolve()
        self.sync.atomic_json(current / "zapret-latest/strategies.json", {"schema": 2, "strategies": {}})
        result = self.read()
        self.assertEqual(result["fakes_usage"], {"discord": 3, "gameudp": 1})

    def test_selecting_and_clearing_updates_files_config_and_service(self):
        discord = self.installer.data / "fakes/ACTIVE_DISCORD_UDP.bin"
        result = self.helper.dispatch(self.installer, "set-active-fakes",
                                      self.request(discord=self.bins["stun.bin"]))
        self.assertEqual(result["config"]["fakediscord"], self.bins["stun.bin"])
        self.assertEqual(result["fakes"]["discord"]["matched_name"], "stun.bin")
        self.assertEqual(discord.read_bytes(), b"stun-bytes")
        self.assertTrue(self.installer.systemd.active)
        result = self.helper.dispatch(self.installer, "set-active-fakes",
                                      self.request(discord=self.bins["quic_a.bin"]))
        self.assertEqual(discord.read_bytes(), b"quic-a-bytes")
        self.assertEqual(result["config"]["fakediscord"], self.bins["quic_a.bin"])
        result = self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=None))
        self.assertEqual(result["config"]["fakediscord"], "")
        self.assertFalse(discord.exists())
        self.assertTrue(self.installer.systemd.active)

    def test_noop_and_inactive_edits_do_not_restart(self):
        self.installer.systemd.active = False
        self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        self.assertEqual(self.installer.systemd.calls, [])
        self.installer.systemd.active = True
        calls = len(self.installer.systemd.calls)
        self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        self.assertEqual(len(self.installer.systemd.calls), calls)
        self.installer.systemd.active = False
        self.helper.dispatch(self.installer, "set-active-fakes", self.request(gameudp=self.bins["quic_a.bin"]))
        self.assertEqual(len(self.installer.systemd.calls), calls)

    def test_invalid_selections_never_stop_service(self):
        before = self.data_tree()
        payloads = [self.request(discord="0" * 64), self.request(discord="stun-bytes"),
                    self.request(gameudp="0" * 64), self.request(gameudp="b" * 64)]
        read = self.read()
        payloads.append({**self.request(discord=self.bins["stun.bin"], config=read), "expected_sha256": "0" * 64})
        for payload in payloads:
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, "set-active-fakes", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertEqual(self.data_tree(), before)

    def test_changed_bin_is_not_silently_approved(self):
        approved = self.request(discord=self.bins["stun.bin"])
        (self.installer.current.resolve() / "zapret-latest/bin/stun.bin").write_bytes(b"rotated")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-active-fakes", approved)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse((self.installer.data / "fakes/ACTIVE_DISCORD_UDP.bin").exists())

    def test_failed_restart_restores_config_files_and_service(self):
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(any((self.installer.data / "fakes").glob("*")))
        self.assertTrue(self.installer.systemd.active)

    def test_failed_restart_after_previous_override_restores_both_states(self):
        self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        original = self.config.read_bytes()
        discord = self.installer.data / "fakes/ACTIVE_DISCORD_UDP.bin"
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["quic_a.bin"]))
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(discord.read_bytes(), b"stun-bytes")
        self.assertTrue(self.installer.systemd.active)

    def test_drifted_active_file_blocks_apply_but_allows_recovery(self):
        self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        self.installer.systemd.calls.clear()
        discord = self.installer.data / "fakes/ACTIVE_DISCORD_UDP.bin"
        discord.write_bytes(b"tampered")
        read = self.read()
        self.assertIsNone(read["fakes"]["discord"]["matched_name"])
        self.assertIn("SHA-256", read["fakes"]["discord"]["warning"])
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-active-fakes",
                                 self.request(gameudp=self.bins["quic_a.bin"], config=read))
        self.assertEqual(self.installer.systemd.calls, [])
        result = self.helper.dispatch(self.installer, "set-active-fakes",
                                      self.request(discord=self.bins["quic_a.bin"], config=read))
        self.assertEqual(discord.read_bytes(), b"quic-a-bytes")

    def test_old_runtime_without_marker_is_rejected(self):
        common = self.installer.current.resolve() / "src/lib/common.sh"
        common.write_text("# old runtime\n")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "set-active-fakes", self.request(discord=self.bins["stun.bin"]))
        self.assertEqual(self.installer.systemd.calls, [])


if __name__ == "__main__":
    unittest.main()
