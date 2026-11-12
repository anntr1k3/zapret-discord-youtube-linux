#!/usr/bin/env python3
"""Offline strategy synchronization tests; never execute a downloaded program."""

import hashlib
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("strategy_sync", ROOT / "src/lib/strategy_sync.py")
REVISION = "a" * 40
BAT = '''@echo off
call service.bat check_updates
start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^
--filter-tcp=443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --dpi-desync=fake --dpi-desync-fake-tls="%BIN%tls.bin" --new ^
--filter-udp=%GameFilterUDP% --dpi-desync=fake --dpi-desync-fake-unknown-udp=0x0000
'''


def payload():
    return {"general.bat": BAT.encode(), "general (ALT).bat": BAT.replace("--dpi-desync=fake", "--dpi-desync=multisplit").encode(),
            "lists/list-general.txt": b"example.org\n", "bin/tls.bin": b"fake TLS bytes"}


class StrategySyncTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-sync-test-")
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        self.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.module)

    def stage(self, files=None):
        return self.module.write_stage(self.tmp / "stage", files or payload(),
                                       {"revision": REVISION, "channel": "main", "tag": None})

    def test_compiler_normalizes_names_and_preserves_all_profiles(self):
        compiled = self.module.compile_payload(payload())
        self.assertEqual(set(compiled), {"general.bat", "general_alt.bat"})
        self.assertEqual(len(compiled["general.bat"]["profiles"]), 2)

    def test_materialization_respects_independent_game_filters(self):
        strategy = self.module.compile_payload(payload())["general.bat"]
        lists = self.tmp / "user-lists"
        lists.mkdir()
        (lists / "list-general-user.txt").write_text("local.example\n")
        off = self.module.materialize(strategy, self.tmp, lists, False, False)
        on = self.module.materialize(strategy, self.tmp, lists, False, True)
        self.assertEqual(off["tcp_ports"], "80,443")
        self.assertEqual(off["udp_ports"], "443")
        self.assertNotIn("--new", off["argv"])
        self.assertIn("--new", on["argv"])
        self.assertIn("--filter-udp=1024-65535", on["argv"])
        self.assertIn("--hostlist=" + str(lists / "list-general-user.txt"), on["argv"])

    def test_l3_filter_before_protocol_filter_is_preserved(self):
        files = payload()
        files["general.bat"] = BAT.replace("--filter-tcp=443", "--filter-l3=ipv4 --filter-tcp=443").encode()
        strategy = self.module.compile_payload(files)["general.bat"]
        arguments = self.module.materialize(strategy, self.tmp, self.tmp, False, False)
        self.assertEqual(arguments["argv"][:2], ["--filter-l3=ipv4", "--filter-tcp=443"])

    def test_custom_game_filter_ranges_are_independent(self):
        strategy = self.module.compile_payload(payload())["general.bat"]
        result = self.module.materialize(strategy, self.tmp, self.tmp, True, True,
                                         tcp_range="1000-2000", udp_range="3000,4000-5000")
        self.assertEqual(result["tcp_ports"], "80,443,1000-2000")
        self.assertEqual(result["udp_ports"], "443,3000,4000-5000")
        self.assertIn("--filter-udp=3000,4000-5000", result["argv"])
        self.assertEqual(self.module.expanded_ports("%GameFilter%", True, True, "1000-2000", "3000"), "1000-2000")
        self.assertEqual(self.module.expanded_ports("%GameFilter%", False, True, "1000-2000", "3000"), "3000")

    def test_runtime_rejects_invalid_custom_ranges_even_when_disabled(self):
        strategy = self.module.compile_payload(payload())["general.bat"]
        for value in ("", "0", "65536", "2-1", "01", "1,,2", "1 2", "%GameFilter%", "1;id", "9" * 513):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.module.materialize(strategy, self.tmp, self.tmp, False, False, tcp_range=value)

    def test_l7_only_profile_is_not_silently_dropped(self):
        files = payload()
        files["general.bat"] = BAT.replace("--filter-tcp=443", "--filter-l7=quic").encode()
        strategy = self.module.compile_payload(files)["general.bat"]
        arguments = self.module.materialize(strategy, self.tmp, self.tmp, False, False)
        self.assertEqual(arguments["argv"][0], "--filter-l7=quic")

    def test_unknown_global_flags_shell_tokens_and_paths_are_rejected(self):
        for injection in ("--daemon", "--user=root", "--qnum=1", "--dpi-desync-fwmark=0",
                          "--hostlist-auto=/etc/shadow", "--hostlist=/etc/shadow",
                          "--dpi-desync-fake-tls=bin/../secret.bin", "& touch /tmp/NO",
                          "--filter-tcp=%Unknown%", "--new-feature=1", "--dpi-desync-new-unknown=1"):
            with self.subTest(injection=injection):
                files = payload()
                files["general.bat"] = (BAT + " " + injection).encode()
                with self.assertRaises(ValueError):
                    self.module.compile_payload(files)

    def test_missing_fake_and_normalization_collision_are_rejected(self):
        files = payload()
        del files["bin/tls.bin"]
        with self.assertRaises(ValueError):
            self.module.compile_payload(files)
        files = payload()
        files["general_ALT.bat"] = BAT.encode()
        with self.assertRaises(ValueError):
            self.module.compile_payload(files)

    def test_stage_digest_and_each_file_are_verified(self):
        manifest, digest = self.stage()
        loaded, files = self.module.load_stage(self.tmp / "stage", digest)
        self.assertEqual(loaded["revision"], REVISION)
        self.assertEqual(files, payload())
        (self.tmp / "stage/payload/bin/tls.bin").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.module.load_stage(self.tmp / "stage", digest)

    def test_rewritten_manifest_symlink_and_extra_file_are_rejected(self):
        _, digest = self.stage()
        manifest_path = self.tmp / "stage/manifest.json"
        original = manifest_path.read_bytes()
        manifest_path.write_bytes(original + b" ")
        with self.assertRaises(ValueError):
            self.module.load_stage(self.tmp / "stage", digest)
        manifest_path.write_bytes(original)
        target = self.tmp / "stage/payload/bin/tls.bin"
        target.unlink()
        target.symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            self.module.load_stage(self.tmp / "stage", digest)

    def test_zip_ignores_windows_executables_but_rejects_traversal(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in payload().items():
                archive.writestr("upstream-commit/" + name, data)
            archive.writestr("upstream-commit/bin/winws.exe", b"must not install")
            archive.writestr("upstream-commit/service.bat", b"must not execute")
        self.assertEqual(self.module.read_archive(buffer.getvalue()), payload())
        with zipfile.ZipFile(buffer, "a") as archive:
            archive.writestr("upstream-commit/../../escape", b"evil")
        with self.assertRaises(ValueError):
            self.module.read_archive(buffer.getvalue())

    def test_dry_run_checks_four_game_filter_modes_without_daemon_or_shell(self):
        compiled = self.module.compile_payload(payload())
        repo = self.tmp / "repo"
        self.module.write_catalog(repo, payload(), compiled, {"revision": REVISION})
        binary = self.tmp / "trusted-nfqws"
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.module.validate_catalog(binary, repo, compiled)
        self.assertEqual(run.call_count, 8)
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[:2], [str(binary), "--dry-run"])
            self.assertIn("--qnum=220", argv)
            self.assertNotIn("--daemon", argv)
            self.assertFalse(call.kwargs.get("shell", False))

    def test_private_root_validation_does_not_loosen_staging_permissions(self):
        compiled = self.module.compile_payload(payload())
        repo = self.tmp / "private" / "repo"
        self.module.write_catalog(repo, payload(), compiled, {"revision": REVISION})
        repo.parent.chmod(0o700)
        def dry_run(argv, **kwargs):
            allowed = "--uid=0:0" in argv
            return subprocess.CompletedProcess(argv, 0 if allowed else 1, "", "" if allowed else "Permission denied")
        with mock.patch.object(self.module.os, "geteuid", return_value=0), mock.patch.object(self.module.subprocess, "run", side_effect=dry_run):
            self.module.validate_catalog(self.tmp / "nfqws", repo, compiled, private=True)
        self.assertEqual(repo.parent.stat().st_mode & 0o777, 0o700)
        with mock.patch.object(self.module.os, "geteuid", return_value=0), mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.module.validate_catalog(self.tmp / "nfqws", repo, compiled)
        self.assertNotIn("--uid=0:0", run.call_args.args[0])

    def test_incompatible_engine_does_not_publish_stage(self):
        base = self.tmp / "base"
        base.mkdir()
        (base / "nfqws").write_bytes(b"not executed by this test")
        target = {"revision": REVISION, "channel": "main", "tag": None}
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "unknown option")):
            with self.assertRaises(ValueError):
                self.module.prepare(base, self.tmp / "cache", target=target, files=payload())
        self.assertFalse((self.tmp / "cache/pending.json").exists())

    def test_prepare_is_cached_and_never_updates_base_or_user_lists(self):
        base = self.tmp / "base"
        base.mkdir()
        (base / "nfqws").write_bytes(b"trusted fixture")
        (base / "user-lists").mkdir()
        user = base / "user-lists/list-general-user.txt"
        user.write_text("keep.example\n")
        target = {"revision": REVISION, "channel": "main", "tag": None}
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            first = self.module.prepare(base, self.tmp / "cache", target=target, files=payload())
            second = self.module.prepare(base, self.tmp / "cache", target=target, files=payload())
        self.assertEqual(first["stage"], second["stage"])
        self.assertEqual(user.read_text(), "keep.example\n")
        self.assertFalse((base / "zapret-latest").exists())

    def test_missing_cached_stage_is_reprepared_without_losing_old_files(self):
        base = self.tmp / "base"
        base.mkdir()
        (base / "nfqws").write_bytes(b"trusted fixture")
        cache = self.tmp / "cache"
        target = {"revision": REVISION, "channel": "main", "tag": None}
        with mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            first = self.module.prepare(base, cache, target=target, files=payload())
            Path(first["stage"], "payload/bin/tls.bin").unlink()
            second = self.module.prepare(base, cache, target=target, files=payload())
        self.assertNotEqual(first["stage"], second["stage"])
        self.assertTrue(Path(first["stage"]).is_dir())
        self.module.load_stage(Path(second["stage"]), second["digest"])

    def test_manifest_metadata_is_validated_even_when_digest_is_known(self):
        self.stage()
        path = self.tmp / "stage/manifest.json"
        manifest = json.loads(path.read_text())
        manifest["tag"] = {"unexpected": "object"}
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.module.load_stage(self.tmp / "stage", hashlib.sha256(path.read_bytes()).hexdigest())

    def test_network_resolution_pins_release_to_commit_and_handles_errors(self):
        with mock.patch.object(self.module, "fetch_json", side_effect=[{"tag_name": "v1.2.3"}, {"sha": REVISION}]) as fetch:
            result = self.module.resolve_target("release")
        self.assertEqual(result["revision"], REVISION)
        self.assertEqual(result["tag"], "v1.2.3")
        self.assertIn("commits/v1.2.3", fetch.call_args.args[0])
        with mock.patch.object(self.module, "fetch_json", return_value={"sha": "not-a-sha"}):
            with self.assertRaises(ValueError):
                self.module.resolve_target("main")

    def test_rate_limit_is_localized_and_never_retried_immediately(self):
        error = urllib.error.HTTPError("https://api.github.com/test", 403, "rate limit exceeded",
                                       {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1600"}, io.BytesIO(b"{}"))
        self.addCleanup(error.close)
        opener = mock.Mock()
        opener.open.side_effect = error
        with mock.patch.object(self.module.urllib.request, "build_opener", return_value=opener), mock.patch.object(self.module.time, "time", return_value=1000), mock.patch.object(self.module.time, "sleep") as sleep:
            with self.assertRaises(self.module.GitHubRateLimitError) as raised:
                self.module.fetch_bytes("https://api.github.com/test")
        self.assertEqual(raised.exception.retry_at, 1600)
        self.assertIn("лимит", str(raised.exception))
        self.assertIn("UTC", str(raised.exception))
        opener.open.assert_called_once()
        sleep.assert_not_called()

    def test_secondary_rate_limit_and_retry_after_are_recognized(self):
        for code, headers, body in ((429, {"Retry-After": "120"}, b"{}"),
                                    (403, {}, b'{"message":"You have exceeded a secondary rate limit"}')):
            with self.subTest(code=code):
                opener = mock.Mock()
                error = urllib.error.HTTPError("https://api.github.com/test", code, "Forbidden", headers, io.BytesIO(body))
                self.addCleanup(error.close)
                opener.open.side_effect = error
                with mock.patch.object(self.module.urllib.request, "build_opener", return_value=opener), mock.patch.object(self.module.time, "time", return_value=1000):
                    with self.assertRaises(self.module.GitHubRateLimitError) as raised:
                        self.module.fetch_bytes("https://api.github.com/test")
                self.assertEqual(raised.exception.retry_at, 1120 if code == 429 else 1060)

    def test_other_forbidden_response_is_not_misreported_as_rate_limit(self):
        opener = mock.Mock()
        error = urllib.error.HTTPError("https://api.github.com/test", 403, "Forbidden", {}, io.BytesIO(b"{}"))
        self.addCleanup(error.close)
        opener.open.side_effect = error
        with mock.patch.object(self.module.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(urllib.error.HTTPError):
                self.module.fetch_bytes("https://api.github.com/test")
        opener.open.assert_called_once()

    def test_target_cache_is_shared_by_check_and_prepare_and_expires(self):
        cache = self.tmp / "cache"
        target = {"revision": REVISION, "channel": "release", "tag": "1.2.3"}
        with mock.patch.object(self.module, "resolve_target", return_value=target) as resolve, mock.patch.object(self.module.time, "time", return_value=1000):
            self.assertEqual(self.module.cached_target("release", cache), target)
            self.assertEqual(self.module.cached_target("release", cache), target)
        resolve.assert_called_once_with("release")
        with mock.patch.object(self.module, "resolve_target", return_value=target) as resolve, mock.patch.object(self.module.time, "time", return_value=1000 + self.module.TARGET_CACHE_TTL):
            self.module.cached_target("release", cache)
        resolve.assert_called_once()

    def test_cached_release_is_not_used_for_main(self):
        cache = self.tmp / "cache"
        with mock.patch.object(self.module, "resolve_target", side_effect=[
            {"revision": REVISION, "channel": "release", "tag": "v1"},
            {"revision": "b" * 40, "channel": "main", "tag": None}]) as resolve:
            self.module.cached_target("release", cache)
            result = self.module.cached_target("main", cache)
        self.assertEqual(result["revision"], "b" * 40)
        self.assertEqual(resolve.call_count, 2)

    def test_rate_limit_cooldown_avoids_requests_and_keeps_pending(self):
        cache = self.tmp / "cache"
        cache.mkdir()
        pending = cache / "pending.json"
        pending.write_text('{"fixture":"preserved"}')
        with mock.patch.object(self.module.time, "time", return_value=1000), mock.patch.object(self.module, "resolve_target", side_effect=self.module.GitHubRateLimitError(1600)) as resolve:
            for channel in ("release", "main"):
                with self.assertRaises(self.module.GitHubRateLimitError):
                    self.module.cached_target(channel, cache)
        resolve.assert_called_once()
        self.assertEqual(pending.read_text(), '{"fixture":"preserved"}')
        with mock.patch.object(self.module.time, "time", return_value=1601), mock.patch.object(self.module, "resolve_target", return_value={"revision": REVISION, "channel": "release", "tag": "v1"}) as resolve:
            self.module.cached_target("release", cache)
        resolve.assert_called_once()

    def test_invalid_or_future_target_cache_is_not_trusted(self):
        cache = self.tmp / "cache"
        cache.mkdir()
        valid = {"revision": REVISION, "channel": "release", "tag": "v1"}
        for value in ("{bad json", json.dumps({"schema": 1, "repository": self.module.REPOSITORY,
                        "checked_at": 2000, "target": valid}),
                      json.dumps({"schema": 1, "repository": self.module.REPOSITORY,
                        "checked_at": 999, "target": {**valid, "revision": "bad"}})):
            (cache / "target-release.json").write_text(value)
            with mock.patch.object(self.module.time, "time", return_value=1000), mock.patch.object(self.module, "resolve_target", return_value=valid) as resolve:
                self.module.cached_target("release", cache)
            resolve.assert_called_once()

    def test_expired_target_does_not_hide_failed_fresh_check(self):
        cache = self.tmp / "cache"
        target = {"revision": REVISION, "channel": "release", "tag": "v1"}
        with mock.patch.object(self.module.time, "time", return_value=1000), mock.patch.object(self.module, "resolve_target", return_value=target):
            self.module.cached_target("release", cache)
        with mock.patch.object(self.module.time, "time", return_value=2000), mock.patch.object(self.module, "resolve_target", side_effect=self.module.GitHubRateLimitError(2600)):
            with self.assertRaises(self.module.GitHubRateLimitError):
                self.module.cached_target("release", cache)

    def test_cli_check_then_prepare_resolves_once_and_keeps_manifest_protocol(self):
        base, cache = self.tmp / "base", self.tmp / "cache"
        base.mkdir()
        (base / "nfqws").write_bytes(b"trusted fixture")
        target = {"revision": REVISION, "channel": "release", "tag": "v1"}
        with mock.patch.object(self.module.os, "geteuid", return_value=1000), mock.patch.object(self.module, "resolve_target", return_value=target) as resolve, mock.patch.object(self.module, "fetch_bytes", return_value=b"fixture"), mock.patch.object(self.module, "read_archive", return_value=payload()), mock.patch.object(self.module, "validate_catalog"), contextlib.redirect_stdout(io.StringIO()):
            for action in ("check", "prepare"):
                self.assertEqual(self.module.main([action, "--base", str(base), "--cache", str(cache)]), 0)
        resolve.assert_called_once()
        pending = json.loads((cache / "pending.json").read_text())
        manifest, files = self.module.load_stage(Path(pending["stage"]), pending["digest"])
        self.assertEqual(files, payload())
        self.assertEqual(set(manifest), {"schema", "repository", "revision", "channel", "tag", "files"})

    def test_timer_only_prepares_and_refuses_to_overwrite_user_units(self):
        config = self.tmp / "systemd/user"
        self.module.install_timer(self.tmp / "base", self.tmp / "cache", config, "release")
        unit = config / "zapret-strategy-sync.service"
        content = unit.read_text()
        self.assertIn("prepare", content)
        self.assertNotIn("apply-strategies", content)
        self.assertNotIn("sudo", content)
        unit.write_text("# a user's own unit\n")
        with self.assertRaises(ValueError):
            self.module.install_timer(self.tmp / "base", self.tmp / "cache", config, "release")

    def test_download_retries_transient_tls_failures_but_keeps_https_checks(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = "https://api.github.com/test"
        response.read.return_value = b"{}"
        opener = mock.Mock()
        opener.open.side_effect = [urllib.error.URLError("temporary TLS EOF"), response]
        with mock.patch.object(self.module.urllib.request, "build_opener", return_value=opener), mock.patch.object(self.module.time, "sleep"):
            self.assertEqual(self.module.fetch_bytes("https://api.github.com/test"), b"{}")
        self.assertEqual(opener.open.call_count, 2)
        redirects = self.module.UpstreamRedirects()
        with self.assertRaises(ValueError):
            redirects.redirect_request(None, None, 302, "", {}, "http://127.0.0.1/private")

    def test_generated_catalog_is_used_by_bash_without_splitting_argv(self):
        files = payload()
        compiled = self.module.compile_payload(files)
        base = self.tmp / "base with spaces"
        repo = base / "zapret-latest"
        self.module.write_catalog(repo, files, compiled, {"revision": REVISION})
        lists = base / "user-lists"
        lists.mkdir()
        (lists / "list-general-user.txt").write_text("keep.example\n")
        script = '''
set -e
source "$1/src/lib/common.sh"
BASE_DIR="$1"
REPO_DIR="$2/zapret-latest"
USER_LISTS_DIR="$2/user-lists"
USE_GAME_FILTER_TCP=false
USE_GAME_FILTER_UDP=true
parse_bat_file "$REPO_DIR/general.bat"
[[ "$USE_SYNCED_STRATEGY" == true && "$udp_ports" == 443,1024-65535 ]]
NFQWS_PATH=/trusted/nfqws
stop_nfqws() { :; }
elevate() { printf '%s\\0' "$@"; }
log() { :; }
start_nfqws
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(base)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        tokens = result.stdout.decode().split("\0")
        self.assertIn("--hostlist=" + str(lists / "list-general-user.txt"), tokens)
        self.assertIn("--filter-udp=1024-65535", tokens)
        self.assertNotIn("--uid=0:0", tokens)

    def test_compiled_catalog_bash_runtime_gets_custom_ranges(self):
        self.module.write_catalog(self.tmp / "catalog", payload(), self.module.compile_payload(payload()), {"revision": REVISION})
        script = '''
set -e
source "$1/src/lib/common.sh"
BASE_DIR="$1"
REPO_DIR="$2/catalog"
USER_LISTS_DIR="$2/lists"
USE_GAME_FILTER_TCP=true
USE_GAME_FILTER_UDP=true
gamefiltertcp_ports=1000-2000
gamefilterudp_ports=3000,4000-5000
parse_bat_file "$REPO_DIR/general.bat"
[[ "$tcp_ports" == 80,443,1000-2000 && "$udp_ports" == 443,3000,4000-5000 ]]
printf '%s\\n' "${nfqws_argv[@]}"
'''
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT), str(self.tmp)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--filter-udp=3000,4000-5000", result.stdout.splitlines())


if __name__ == "__main__":
    unittest.main()
