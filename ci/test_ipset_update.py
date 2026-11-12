#!/usr/bin/env python3
"""IPSet list update tests: offline staging, helper transaction, no host writes."""

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
LIST_DATA = b"203.0.113.10/32\n198.51.100.0/24\n"
DUMMY_DATA = b"203.0.113.113/32\n"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UrlTests(unittest.TestCase):
    def setUp(self):
        self.sync = load("ipset_sync_url_test", ROOT / "src/lib/strategy_sync.py")

    def test_fixed_upstream_ipset_url_is_allowed(self):
        self.assertTrue(self.sync.allowed_url(self.sync.IPSET_URL))

    def test_other_raw_paths_and_schemes_are_rejected(self):
        rejected = ["https://raw.githubusercontent.com/Other/repo/main/.service/ipset-service.txt",
                    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/../../etc/passwd",
                    "http://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/ipset-service.txt",
                    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/ipset-service.txt?x=1"]
        # The query variant is rejected because urlparse().path excludes it.
        self.assertFalse(self.sync.allowed_url(rejected[0]))
        self.assertFalse(self.sync.allowed_url(rejected[1]))
        self.assertFalse(self.sync.allowed_url(rejected[2]))
        self.assertFalse(self.sync.allowed_url(rejected[3]))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.sync = load("ipset_fetch_test", ROOT / "src/lib/strategy_sync.py")
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-ipset-fetch-")
        self.addCleanup(self.directory.cleanup)
        self.cache = Path(self.directory.name) / "cache"

    def test_fetch_stages_validated_list(self):
        with mock.patch.object(self.sync, "fetch_bytes", return_value=LIST_DATA) as fetch:
            result = self.sync.fetch_ipset(self.cache)
        fetch.assert_called_once_with(self.sync.IPSET_URL, limit=self.sync.load_ipset_mode().MAX_BYTES)
        staged = Path(result["staged"])
        self.assertEqual(staged.read_bytes(), LIST_DATA)
        self.assertEqual(result["sha256"], hashlib.sha256(LIST_DATA).hexdigest())
        self.assertEqual(result["entries"], 2)
        self.assertEqual(result["kind"], "loaded")
        self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)
        self.assertEqual(staged.parent, self.cache)

    def test_fetch_rejects_dummy_and_empty_lists(self):
        for data in (DUMMY_DATA, b"", b"# comment\n"):
            with mock.patch.object(self.sync, "fetch_bytes", return_value=data):
                with self.assertRaises(ValueError):
                    self.sync.fetch_ipset(self.cache)
            self.assertFalse((self.cache / "ipset-service.txt").exists())

    def test_fetch_rejects_oversized_and_invalid_content(self):
        with mock.patch.object(self.sync, "fetch_bytes", return_value=b"1.2.3.4\nnot-an-ip\n"):
            with self.assertRaises(ValueError):
                self.sync.fetch_ipset(self.cache)
        with mock.patch.object(self.sync, "fetch_bytes",
                               side_effect=ValueError("Upstream response exceeds size limit")):
            with self.assertRaises(ValueError):
                self.sync.fetch_ipset(self.cache)
        self.assertFalse((self.cache / "ipset-service.txt").exists())


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.InstallerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        common = self.fixture.source / "src/lib/common.sh"
        common.write_text(common.read_text() + "# ipset mode v1\n")
        self.fixture.install(start=True)
        self.installer = self.fixture.installer
        self.installer.validate_config = self.fixture.module.validate_config
        self.helper = load("ipset_update_helper_test", ROOT / "src/gui/privileged.py")
        self.config = self.installer.data / "conf.env"
        self.original = self.config.read_bytes()
        self.installer.systemd.calls.clear()
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-ipset-stage-")
        self.addCleanup(self.directory.cleanup)
        self.stage_dir = Path(self.directory.name)

    def stage(self, data=LIST_DATA, name="ipset-service.txt"):
        path = self.stage_dir / name
        path.write_bytes(data)
        return path

    def read(self):
        return self.helper.dispatch(self.installer, "read-config", {})

    def request(self, stage, data=LIST_DATA, config=None):
        config = config or self.read()
        return {"stage": str(stage), "sha256": hashlib.sha256(data).hexdigest(),
                "expected_sha256": config["sha256"]}

    def target(self):
        return self.installer.data / "user-lists/ipset-all.txt"

    def test_capability_is_advertised(self):
        self.assertIn("ipset-update-v1", self.read()["capabilities"])

    def test_update_writes_list_restarts_and_preserves_mode(self):
        # Select a mode explicitly: the update must keep it and only replace the list.
        self.config.write_bytes(self.original + b"ipset_mode=loaded\n")
        self.original = self.config.read_bytes()
        self.target().write_bytes(b"192.0.2.0/24\n")
        stage = self.stage()
        before = self.read()
        self.assertEqual(before["config"]["ipset_mode"], "loaded")
        result = self.helper.dispatch(self.installer, "update-ipset", self.request(stage))
        self.assertEqual(self.target().read_bytes(), LIST_DATA)
        self.assertEqual(result["config"], before["config"])
        self.assertEqual(result["ipset"]["effective_mode"], "loaded")
        self.assertTrue(self.installer.systemd.active)
        # Service was restarted because the list changed.
        self.assertIn(("stop", self.helper.SERVICE), self.installer.systemd.calls)
        self.assertIn(("start", self.helper.SERVICE), self.installer.systemd.calls)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_creates_missing_list(self):
        self.assertFalse(self.target().exists())
        self.helper.dispatch(self.installer, "update-ipset", self.request(self.stage()))
        self.assertEqual(self.target().read_bytes(), LIST_DATA)
        self.assertEqual(stat.S_IMODE(self.target().stat().st_mode), 0o644)

    def test_identical_list_never_restarts(self):
        self.stage()
        self.helper.dispatch(self.installer, "update-ipset", self.request(self.stage()))
        calls = len(self.installer.systemd.calls)
        self.helper.dispatch(self.installer, "update-ipset", self.request(self.stage()))
        self.assertEqual(len(self.installer.systemd.calls), calls)

    def test_stale_tokens_and_hash_drift_never_stop_service(self):
        stage = self.stage()
        read = self.read()
        payloads = [self.request(stage, config=read), self.request(stage, config=read)]
        payloads[0]["sha256"] = "0" * 64
        payloads[1]["expected_sha256"] = "0" * 64
        for payload in payloads:
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, "update-ipset", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse(self.target().exists())

    def test_modified_stage_is_rejected(self):
        stage = self.stage()
        payload = self.request(stage)
        stage.write_bytes(b"203.0.113.99/32\n")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "update-ipset", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse(self.target().exists())

    def test_dummy_or_empty_download_is_rejected(self):
        for data in (DUMMY_DATA, b""):
            with self.assertRaises(ValueError):
                self.helper.dispatch(self.installer, "update-ipset", self.request(self.stage(data), data=data))
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse(self.target().exists())

    def test_symlink_and_relative_stages_are_rejected(self):
        real = self.stage()
        link = self.stage_dir / "link.txt"
        link.symlink_to(real)
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "update-ipset", self.request(link))
        payload = self.request(real)
        payload["stage"] = "relative/ipset-service.txt"
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "update-ipset", payload)
        payload["stage"] = "a" * 5000
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "update-ipset", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse(self.target().exists())

    def test_failed_start_restores_list_and_service(self):
        stage = self.stage()
        self.helper.dispatch(self.installer, "update-ipset", self.request(stage))
        original_list = self.target().read_bytes()
        second = self.stage_dir / "second.txt"
        second.write_bytes(b"192.0.2.0/24\n")
        self.installer.systemd.calls.clear()
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "update-ipset", self.request(second, data=b"192.0.2.0/24\n"))
        self.assertEqual(self.target().read_bytes(), original_list)
        self.assertTrue(self.installer.systemd.active)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_failed_start_restores_absent_list(self):
        stage = self.stage()
        self.installer.systemd.fail_start = True
        with self.assertRaises(RuntimeError):
            self.helper.dispatch(self.installer, "update-ipset", self.request(stage))
        self.assertFalse(self.target().exists())
        self.assertTrue(self.installer.systemd.active)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_changed_config_is_rejected_before_stop(self):
        stage = self.stage()
        payload = self.request(stage)
        self.config.write_bytes(self.original + b"# edited elsewhere\n")
        with self.assertRaises(ValueError):
            self.helper.dispatch(self.installer, "update-ipset", payload)
        self.assertEqual(self.installer.systemd.calls, [])
        self.assertFalse(self.target().exists())


import unittest.mock  # noqa: E402  (used by FetchTests)


if __name__ == "__main__":
    unittest.main()
