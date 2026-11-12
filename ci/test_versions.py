"""Version presentation reads metadata only; never runs checkout binaries or git."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location("version_test_module", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/version_info.py")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret versions Юникод ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def write(self, relative, data):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        return path

    def target(self, revision="a" * 40, channel="release", tag="1.10.4"):
        return {"revision": revision, "channel": channel, "tag": tag}

    def test_application_version_is_explicitly_prerelease(self):
        app = self.module.application(ROOT)
        self.assertEqual(app["version"], "1.0.0-dev")
        self.assertFalse(app["release"])
        self.assertIsNone(app["error"])

    def test_missing_old_application_metadata_is_unknown(self):
        app = self.module.application(self.base)
        self.assertIsNone(app["version"])
        self.assertTrue(app["error"])

    def test_invalid_application_schema_is_not_a_release(self):
        for data in ({"schema": 99, "version": "1.0", "release": True},
                     {"schema": 1, "version": "bad\nversion", "release": False},
                     {"schema": 1, "version": "1.0.0", "release": "true"}):
            self.write("src/app-version.json", data)
            self.assertIsNone(self.module.application(self.base)["version"])

    def test_valid_installed_provenance_has_fixed_release_and_commit_links(self):
        self.write("zapret-latest/.flowseal-sync.json", self.target())
        result = self.module.flowseal(self.base)
        self.assertEqual(result["revision"], "a" * 40)
        self.assertEqual(result["release_url"], "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.4")
        self.assertTrue(result["commit_url"].endswith("/commit/" + "a" * 40))

    def test_legacy_service_bat_version_is_not_provenance(self):
        folder = self.base / "zapret-latest"
        folder.mkdir()
        (folder / "service.bat").write_text('set "LOCAL_VERSION=1.9.9a"')
        result = self.module.flowseal(self.base)
        self.assertIsNone(result["revision"])
        self.assertIsNone(result["tag"])
        self.assertTrue(result["error"])

    def test_main_is_a_commit_not_a_release(self):
        result = self.module.target_info(self.target(channel="main", tag=None))
        self.assertIsNone(result["release_url"])
        self.assertTrue(result["commit_url"])
        self.assertEqual(result["channel"], "main")

    def test_untrusted_urls_are_never_used(self):
        data = {**self.target(), "html_url": "file:///etc/passwd", "release_url": "https://evil.invalid"}
        result = self.module.target_info(data)
        self.assertEqual(result["release_url"], "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.4")

    def test_invalid_tags_revisions_and_channel_are_not_clickable(self):
        for data in (self.target(tag="../../etc/passwd"), self.target(revision="bad"),
                     self.target(channel="unknown"), self.target(channel="main", tag="v1")):
            result = self.module.target_info(data)
            self.assertIsNone(result["release_url"])
            self.assertIsNone(result["commit_url"])
            self.assertTrue(result["error"])

    def test_oversized_or_corrupt_metadata_is_unknown(self):
        path = self.write("zapret-latest/.flowseal-sync.json", self.target())
        for text in ("{" * 100, " " * 20000, "[]"):
            path.write_text(text)
            self.assertIsNone(self.module.flowseal(self.base)["revision"])

    def test_comparison_uses_current_bytes_not_old_check_current_revision(self):
        self.write("zapret-latest/.flowseal-sync.json", self.target())
        checked = {"status": "checked", "current_revision": "b" * 40, "checked_at": "yesterday", **self.target()}
        result = self.module.summary(ROOT, self.base, self.base, True, checked)
        self.assertEqual(result["relation"], "same")
        self.write("zapret-latest/.flowseal-sync.json", self.target("c" * 40))
        self.assertEqual(self.module.summary(ROOT, self.base, self.base, True, checked)["relation"], "different")

    def test_no_check_is_not_up_to_date(self):
        result = self.module.summary(ROOT, self.base, self.base, False, None)
        self.assertEqual(result["relation"], "unknown")
        self.assertEqual(result["scope"], "checkout")

    def test_failed_check_does_not_claim_latest_version(self):
        checked = {"status": "error", "message": "offline", **self.target()}
        result = self.module.summary(ROOT, self.base, self.base, True, checked)
        self.assertIsNone(result["checked"]["revision"])
        self.assertEqual(result["relation"], "unknown")
        self.assertIn("offline", result["checked"]["error"])

    def test_version_reading_uses_no_processes(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("version command")):
            self.module.summary(ROOT, self.base, self.base, True, None)

    def test_demo_versions_track_applied_data_separately_from_app(self):
        backend = load("src/gui/backend.py").DemoBackend()
        before = backend.snapshot()["versions"]
        backend.check_update()
        pending = backend.prepare_update()
        self.assertEqual(backend.snapshot()["versions"]["current"], before["current"])
        backend.apply_update(pending)
        after = backend.snapshot()["versions"]
        self.assertEqual(after["relation"], "same")
        self.assertEqual(after["running_app"], before["running_app"])

    def test_labels_separate_application_data_and_checkout(self):
        presentation = load("src/gui/presentation.py")
        info = self.module.summary(ROOT, self.base, self.base, False, None)
        text = presentation.version_text(info)
        self.assertIn("1.0.0-dev", text)
        self.assertIn("не релиз", text)
        self.assertIn("checkout", text)
        self.assertIn("Сравнить ревизии данных пока нельзя", text)

    def test_different_commit_is_not_claimed_to_be_newer(self):
        presentation = load("src/gui/presentation.py")
        self.write("zapret-latest/.flowseal-sync.json", self.target())
        checked = {"status": "checked", **self.target("b" * 40)}
        text = presentation.version_text(self.module.summary(ROOT, self.base, self.base, True, checked))
        self.assertIn("не доказывает", text)
        self.assertNotIn("доступна новая версия", text.lower())

    def test_old_installed_app_does_not_inherit_checkout_version(self):
        info = self.module.summary(ROOT, self.base, self.base, True, None)
        self.assertEqual(info["running_app"]["version"], "1.0.0-dev")
        self.assertIsNone(info["installed_app"]["version"])

    def test_already_applied_pending_is_not_offered_as_unapplied(self):
        module = load("src/gui/backend.py")
        backend = module.Backend(ROOT, current=self.base / "missing")
        backend.sync = mock.Mock(return_value={"pending": {"revision": "a" * 40},
                                              "pending_is_current": True, "current_revision": "a" * 40})
        backend.command = mock.Mock(return_value="LoadState=not-found\n")
        backend.update_checker = mock.Mock()
        backend.update_checker.return_value.status.return_value = {}
        self.assertIsNone(backend.snapshot()["pending"])
        demo = module.DemoBackend()
        demo.apply_update(demo.prepare_update())
        self.assertIsNone(demo.snapshot()["pending"])


if __name__ == "__main__":
    unittest.main()
