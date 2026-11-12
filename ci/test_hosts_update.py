#!/usr/bin/env python3
"""Hosts tests use temporary files only, never the host /etc/hosts."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import test_installer as fixtures


ROOT = Path(__file__).resolve().parents[1]
BODY = b"# upstream\n203.0.113.10 github.com\n2001:db8::1 example.invalid\n"
ORIGINAL = b"127.0.0.1 localhost\r\n# private\xff\n192.0.2.1 keep.example"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.hosts = load("hosts_test", "src/lib/hosts_file.py")

    def test_normalizes_download_and_counts_mappings_not_comments(self):
        result = self.hosts.validate(b"\xef\xbb\xbf# comment\r\n1.2.3.4 a.example b.example \r\n")
        self.assertEqual(result["data"], b"# comment\n1.2.3.4 a.example b.example\n")
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["hostnames"], 2)
        self.assertEqual(result["sha256"], digest(result["data"]))

    def test_rejects_invalid_and_empty_downloads(self):
        for data in (b"", b"# only comment\n", b"<html>error</html>",
                     b"1.2.3.4 bad_name\n", b"1.2.3.4 a..example\n",
                     b"1.2.3.4 a.example\x00\n", b"1.2.3.4 a.example\x1b\n",
                     b"\xff", b"1.2.3.4\n", self.hosts.BEGIN + b"\n" + BODY):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.hosts.validate(data)

    def test_limits(self):
        with mock.patch.object(self.hosts, "MAX_BYTES", 8), self.assertRaises(ValueError):
            self.hosts.validate(BODY)
        with mock.patch.object(self.hosts, "MAX_LINES", 1), self.assertRaises(ValueError):
            self.hosts.validate(BODY)
        with mock.patch.object(self.hosts, "MAX_HOSTNAMES", 1), self.assertRaises(ValueError):
            self.hosts.validate(BODY)

    def test_append_preserves_all_original_bytes_and_is_idempotent(self):
        merged = self.hosts.merge(ORIGINAL, BODY)
        self.assertTrue(merged.startswith(ORIGINAL + b"\n\n"))
        self.assertEqual(self.hosts.merge(merged, BODY), merged)
        self.assertEqual(self.hosts.status(merged)["entries"], 2)

    def test_replace_preserves_prefix_and_suffix_byte_for_byte(self):
        prefix, suffix = b"# private\xff\r\n", b"192.0.2.9 tail.example\r\n"
        current = prefix + self.hosts.BEGIN + b"\r\n1.2.3.4 old.example\r\n" + self.hosts.END + b"\r\n" + suffix
        merged = self.hosts.merge(current, BODY)
        self.assertEqual(merged, prefix + self.hosts.BEGIN + b"\n" + BODY + self.hosts.END + b"\n" + suffix)

    def test_malformed_or_duplicate_markers_refuse_write(self):
        for data in (self.hosts.BEGIN, self.hosts.END,
                     self.hosts.END + b"\n" + self.hosts.BEGIN,
                     self.hosts.merge(b"", BODY) * 2):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.hosts.merge(data, BODY)
            self.assertTrue(self.hosts.status(data)["malformed"])

    def test_preview_counts_actual_entries(self):
        current = self.hosts.merge(b"", BODY)
        preview = self.hosts.preview(current, BODY)
        self.assertEqual(preview["current_entries"], 2)
        self.assertEqual(preview["entries"], 2)
        self.assertFalse(preview["changed"])
        self.assertEqual(preview["diff"], [])

    def test_conflicts_and_youtube_are_reported_without_changing_outside(self):
        outside = b"192.0.2.2 GitHub.com\n127.0.0.1 www.youtube.com youtu.be\n"
        preview = self.hosts.preview(outside, BODY)
        self.assertEqual(len(preview["conflicts"]), 1)
        self.assertTrue(preview["youtube"])
        self.assertTrue(self.hosts.merge(outside, BODY).startswith(outside))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.sync = load("hosts_sync_test", "src/lib/strategy_sync.py")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret-hosts-fetch-")
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)

    def test_fixed_url_and_private_normalized_stage(self):
        self.assertTrue(self.sync.allowed_url(self.sync.HOSTS_URL))
        with mock.patch.object(self.sync, "fetch_bytes", return_value=BODY.replace(b"\n", b"\r\n")) as fetch:
            result = self.sync.fetch_hosts(self.cache)
        fetch.assert_called_once_with(self.sync.HOSTS_URL, limit=self.sync.load_hosts_file().MAX_BYTES)
        stage = Path(result["staged"])
        self.assertEqual(stage.read_bytes(), BODY)
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
        self.assertEqual(result["sha256"], digest(BODY))

    def test_invalid_download_preserves_previous_stage(self):
        with mock.patch.object(self.sync, "fetch_bytes", return_value=BODY):
            result = self.sync.fetch_hosts(self.cache)
        with mock.patch.object(self.sync, "fetch_bytes", return_value=b"html error"):
            with self.assertRaises(ValueError):
                self.sync.fetch_hosts(self.cache)
        self.assertEqual(Path(result["staged"]).read_bytes(), BODY)


class HelperTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.InstallerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.install(start=True)
        self.installer = fixture.installer
        self.helper = load("hosts_helper_test", "src/gui/privileged.py")
        self.hosts = fixture.root / "etc/hosts"
        self.hosts.write_bytes(ORIGINAL)
        self.hosts.chmod(0o640)
        self.stage = fixture.base / "hosts-stage"
        self.stage.write_bytes(BODY)
        self.stage.chmod(0o600)
        self.helper.HOSTS = self.hosts
        # Emulate the required root owner only for the temporary target file.
        real_lstat = Path.lstat
        def lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if path == self.hosts:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info
        patch = mock.patch.object(Path, "lstat", lstat)
        patch.start()
        self.addCleanup(patch.stop)
        self.installer.systemd.calls.clear()

    def request(self):
        return {"stage": str(self.stage), "sha256": digest(BODY),
                "expected_hosts_sha256": digest(self.hosts.read_bytes())}

    def apply(self, payload=None):
        return self.helper.dispatch(self.installer, "update-hosts", payload or self.request())

    def test_backup_permissions_and_no_service_or_config_changes(self):
        config = self.installer.data / "conf.env"
        original_config = config.read_bytes()
        result = self.apply()
        self.assertTrue(result["changed"])
        self.assertTrue(self.hosts.read_bytes().startswith(ORIGINAL))
        backup = Path(result["backup"])
        self.assertEqual(backup.read_bytes(), ORIGINAL)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.hosts.stat().st_mode), 0o640)
        self.assertEqual(config.read_bytes(), original_config)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_identical_update_keeps_inode_and_creates_no_backup(self):
        self.apply()
        inode = self.hosts.stat().st_ino
        result = self.apply()
        self.assertFalse(result["changed"])
        self.assertIsNone(result["backup"])
        self.assertEqual(self.hosts.stat().st_ino, inode)

    def test_independent_of_config_reading(self):
        (self.installer.data / "conf.env").write_text("invalid config\n")
        with mock.patch.object(self.helper, "config_result", side_effect=AssertionError("must not read config")):
            self.assertTrue(self.apply()["changed"])

    def test_stale_hosts_token_preserves_external_changes(self):
        payload = self.request()
        self.hosts.write_bytes(ORIGINAL + b"\n# external edit\n")
        before = self.hosts.read_bytes()
        with self.assertRaises(ValueError):
            self.apply(payload)
        self.assertEqual(self.hosts.read_bytes(), before)
        self.assertFalse((self.installer.state_dir / "hosts-backups").exists())

    def test_stage_hash_drift_and_invalid_payload_are_rejected(self):
        payload = self.request()
        self.stage.write_bytes(b"1.2.3.4 changed.example\n")
        with self.assertRaises(ValueError):
            self.apply(payload)
        for key, value in (("stage", "relative/path"), ("sha256", "bad"),
                           ("expected_hosts_sha256", "bad"), ("stage", "/" + "x" * 5000)):
            invalid = dict(payload, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.apply(invalid)
        self.assertEqual(self.hosts.read_bytes(), ORIGINAL)

    def test_symlink_stage_and_target_are_rejected(self):
        real_stage = self.stage.with_name("real-stage")
        self.stage.rename(real_stage)
        self.stage.symlink_to(real_stage)
        with self.assertRaises(ValueError):
            self.apply()
        self.stage.unlink()
        real_stage.rename(self.stage)
        real_hosts = self.hosts.with_name("real-hosts")
        self.hosts.rename(real_hosts)
        self.hosts.symlink_to(real_hosts)
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(real_hosts.read_bytes(), ORIGINAL)

    def test_partial_write_failure_recovers_original(self):
        write = self.helper.write_config
        def fail_after_write(path, data, info, **kwargs):
            write(path, data, info, **kwargs)
            if data != ORIGINAL:
                raise OSError("injected failure after replace")
        with mock.patch.object(self.helper, "write_config", side_effect=fail_after_write):
            with self.assertRaisesRegex(OSError, "injected failure"):
                self.apply()
        self.assertEqual(self.hosts.read_bytes(), ORIGINAL)
        self.assertEqual(self.installer.systemd.calls, [])

    def test_unsafe_target_owner_and_permissions_are_rejected(self):
        original_lstat = Path.lstat
        for uid, mode in ((1000, 0o100644), (0, 0o100664), (0, 0o100646)):
            def unsafe(path, *args, **kwargs):
                info = original_lstat(path, *args, **kwargs)
                if path == self.hosts:
                    fields = list(info)
                    fields[4], fields[0] = uid, mode
                    return os.stat_result(fields)
                return info
            with self.subTest(uid=uid, mode=mode), mock.patch.object(Path, "lstat", unsafe):
                with self.assertRaises(ValueError):
                    self.apply()
            self.assertEqual(self.hosts.read_bytes(), ORIGINAL)

    def test_root_owned_stage_is_rejected_when_privileged(self):
        original_fstat = os.fstat
        inode = self.stage.stat().st_ino
        def root_owned(fd):
            info = original_fstat(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info
        with mock.patch.object(self.helper.os, "fstat", root_owned), mock.patch.object(self.helper.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                self.apply()

    def test_malformed_target_is_not_backed_up_or_written(self):
        data = ORIGINAL + b"\n# BEGIN zapret-discord-youtube managed hosts\n"
        self.hosts.write_bytes(data)
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(self.hosts.read_bytes(), data)
        self.assertFalse((self.installer.state_dir / "hosts-backups").exists())


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.backend = load("hosts_backend_test", "src/gui/backend.py")

    def test_preview_token_is_for_exact_previewed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hosts"
            stage = Path(directory) / "stage"
            target.write_bytes(ORIGINAL)
            stage.write_bytes(BODY)
            backend = self.backend.Backend(ROOT)
            with mock.patch.object(self.backend, "HOSTS", target):
                preview = backend.preview_hosts(stage, digest(BODY))
            self.assertEqual(preview["expected_hosts_sha256"], digest(ORIGINAL))

    def test_export_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            stage, target = Path(directory) / "stage", Path(directory) / "export"
            stage.write_bytes(BODY)
            self.backend.Backend.export_hosts(stage, digest(BODY), target)
            self.assertEqual(target.read_bytes(), BODY)
            link = target.with_name("link")
            link.symlink_to(target)
            with self.assertRaises(OSError):
                self.backend.Backend.export_hosts(stage, digest(BODY), link)
            self.assertEqual(target.read_bytes(), BODY)

    def test_failed_export_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            stage, target = Path(directory) / "stage", Path(directory) / "export"
            stage.write_bytes(BODY)
            target.write_bytes(b"existing user data")
            with mock.patch.object(self.backend.os, "fsync", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    self.backend.Backend.export_hosts(stage, digest(BODY), target)
            self.assertEqual(target.read_bytes(), b"existing user data")

    def test_demo_apply_and_noop_preserve_original(self):
        backend = self.backend.DemoBackend()
        original = backend.hosts_data
        fetched = backend.fetch_hosts()
        result = backend.update_hosts(fetched["staged"], fetched["sha256"], fetched["hosts"]["sha256"])
        self.assertTrue(result["changed"])
        self.assertTrue(backend.hosts_data.startswith(original))
        result = backend.update_hosts(fetched["staged"], fetched["sha256"], backend.hosts_status()["sha256"])
        self.assertFalse(result["changed"])


if __name__ == "__main__":
    unittest.main()
