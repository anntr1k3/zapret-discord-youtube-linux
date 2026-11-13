"""Discord cache operations use only freshly created temporary profiles."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location("discord_cache_test", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/discord_cache.py")
        previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(prefix="zapret Discord Юникод ")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.profile = self.home / ".config/discord"
        for name in ("Cache", "Code Cache", "GPUCache"):
            folder = self.profile / name / "nested"
            folder.mkdir(parents=True)
            (folder / "entry").write_bytes(b"cache payload")
        for name in ("Local Storage/leveldb/token", "settings.json", "Cookies", "Session Storage/keep"):
            path = self.profile / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"must survive")
        self.manager = self.module.CacheManager(self.home, mounts=set(),
            process_probe=lambda: {"state": "clear", "pids": []})

    def preview(self, instance="native-stable"):
        return self.manager.preview(instance)

    def clean(self, preview=None, instance="native-stable"):
        return self.manager.clean(instance, (preview or self.preview(instance))["token"])

    def test_discovery_is_read_only_and_shows_exact_caches(self):
        report = self.manager.discover()
        item = next(item for item in report["instances"] if item["id"] == "native-stable")
        self.assertEqual(item["files"], 3)
        self.assertEqual({Path(item["path"]).name for item in item["caches"]}, {"Cache", "Code Cache", "GPUCache"})
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_clean_preserves_every_non_cache_file(self):
        result = self.clean()
        self.assertEqual(result["removed_files"], 3)
        for name in ("Cache", "Code Cache", "GPUCache"):
            self.assertFalse((self.profile / name).exists())
        for name in ("Local Storage/leveldb/token", "settings.json", "Cookies", "Session Storage/keep"):
            self.assertEqual((self.profile / name).read_bytes(), b"must survive")

    def test_noop_for_missing_caches_creates_nothing(self):
        self.clean()
        result = self.clean()
        self.assertEqual(result["removed_files"], 0)
        self.assertFalse(any(path.name.startswith(".zapret-discord-cache-") for path in self.profile.iterdir()))

    def test_modified_cache_invalidates_confirmation(self):
        preview = self.preview()
        (self.profile / "Cache/new").write_bytes(b"new")
        with self.assertRaises(ValueError):
            self.clean(preview)
        self.assertTrue((self.profile / "Cache/new").exists())

    def test_invalid_instance_and_token_never_delete(self):
        for instance in ("../../.ssh", "/etc", "native-stable/Cache"):
            with self.assertRaises(ValueError):
                self.manager.clean(instance, "a" * 64)
        with self.assertRaises(ValueError):
            self.manager.clean("native-stable", "bad")
        self.assertTrue((self.profile / "GPUCache/nested/entry").exists())

    def test_running_or_unknown_process_check_blocks_every_write(self):
        preview = self.preview()
        for state in ("running", "unknown"):
            self.manager.process_probe = lambda: {"state": state, "pids": [123]}
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.clean(preview)
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_root_cleanup_is_refused(self):
        with mock.patch.object(self.module.os, "geteuid", return_value=0), self.assertRaises(ValueError):
            self.clean()

    def test_symlink_inside_cache_is_rejected_without_following(self):
        outside = self.home / "keep"
        outside.write_bytes(b"external")
        (self.profile / "Cache/link").symlink_to(outside)
        with self.assertRaises(ValueError):
            self.preview()
        self.assertEqual(outside.read_bytes(), b"external")

    def test_symlink_profile_or_cache_is_not_followed(self):
        cache = self.profile / "Cache"
        cache.rename(self.profile / "old-cache")
        cache.symlink_to(self.profile / "old-cache")
        with self.assertRaises(ValueError):
            self.preview()
        cache.unlink()
        (self.profile / "old-cache").rename(cache)
        real = self.profile.with_name("discord-real")
        self.profile.rename(real)
        self.profile.symlink_to(real)
        with self.assertRaises(ValueError):
            self.preview()

    def test_hardlink_and_mountpoint_are_rejected(self):
        outside = self.home / "outside"
        outside.write_bytes(b"external")
        link = self.profile / "Cache/hardlink"
        os.link(outside, link)
        with self.assertRaises(ValueError):
            self.preview()
        link.unlink()
        self.manager.mounts = {str(self.profile / "Cache/nested")}
        with self.assertRaises(ValueError):
            self.preview()
        self.assertEqual(outside.read_bytes(), b"external")

    def test_entry_limit_refuses_whole_operation(self):
        with mock.patch.object(self.module, "MAX_ENTRIES", 1), self.assertRaises(ValueError):
            self.preview()
        self.assertTrue((self.profile / "Code Cache/nested/entry").exists())

    def test_flatpak_and_native_variants_are_independent(self):
        flatpak = self.home / ".var/app/com.discordapp.Discord/config/discord"
        (flatpak / "Cache").mkdir(parents=True)
        (flatpak / "Cache/entry").write_bytes(b"flatpak")
        ptb = self.home / ".config/discordptb"
        (ptb / "GPUCache").mkdir(parents=True)
        (ptb / "GPUCache/entry").write_bytes(b"ptb")
        self.clean(instance="flatpak-stable")
        self.assertTrue((ptb / "GPUCache/entry").exists())
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_snap_current_is_resolved_only_to_an_allowed_revision(self):
        snap = self.home / "snap/discord"
        profile = snap / "123/.config/discord"
        (profile / "Cache").mkdir(parents=True)
        (profile / "Cache/entry").write_bytes(b"snap")
        (snap / "current").symlink_to("123")
        preview = self.preview("snap-stable")
        self.assertIn("/123/", preview["path"])
        (snap / "current").unlink()
        (snap / "current").symlink_to("../../.config")
        with self.assertRaises(ValueError):
            self.manager.clean("snap-stable", preview["token"])
        self.assertTrue((profile / "Cache/entry").exists())

    def test_discovery_keeps_unsafe_instance_visible_but_disabled(self):
        (self.profile / "GPUCache/link").symlink_to(self.home)
        item = next(item for item in self.manager.discover()["instances"] if item["id"] == "native-stable")
        self.assertTrue(item["error"])
        self.assertIsNone(item["token"])

    def test_selected_native_variant_only(self):
        for folder, instance in (("discordptb", "native-ptb"), ("discordcanary", "native-canary"),
                                 ("discorddevelopment", "native-development")):
            path = self.home / ".config" / folder / "Cache"
            path.mkdir(parents=True)
            (path / "entry").write_text("variant")
            self.clean(instance=instance)
            self.assertFalse(path.exists())
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_partial_failure_is_honest_and_restores_remaining_directories(self):
        original = self.manager.delete_tree
        def fail(parent, name, node, counts):
            original(parent, name, node, counts)
            if counts["removed_files"]:
                raise OSError("injected deletion failure")
        with mock.patch.object(self.manager, "delete_tree", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "удалено файлов: 1"):
                self.clean()
        self.assertTrue((self.profile / "Code Cache/nested/entry").exists())
        self.assertTrue((self.profile / "GPUCache/nested/entry").exists())
        self.assertEqual((self.profile / "Local Storage/leveldb/token").read_bytes(), b"must survive")

    def test_cache_recreated_during_abort_is_never_overwritten(self):
        preview = self.preview()
        calls = 0
        def probe():
            nonlocal calls
            calls += 1
            if calls == 3:
                (self.profile / "Cache").mkdir()
                (self.profile / "Cache/new").write_bytes(b"new client cache")
                return {"state": "running", "pids": [123]}
            return {"state": "clear", "pids": []}
        self.manager.process_probe = probe
        with self.assertRaisesRegex(RuntimeError, "Остаток сохранён"):
            self.clean(preview)
        self.assertEqual((self.profile / "Cache/new").read_bytes(), b"new client cache")
        stages = list(self.profile.glob(".zapret-discord-cache-*"))
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0] / "Cache/nested/entry").exists())

    def test_unsafe_permissions_and_special_files_block_whole_preview(self):
        cache = self.profile / "Cache"
        cache.chmod(0o777)
        with self.assertRaises(ValueError):
            self.preview()
        cache.chmod(0o755)
        os.mkfifo(cache / "fifo")
        with self.assertRaises(ValueError):
            self.preview()
        self.assertTrue((self.profile / "Code Cache/nested/entry").exists())

    def test_config_outside_home_is_not_accepted(self):
        with self.assertRaises(ValueError):
            self.module.CacheManager(self.home, config=self.home.parent, mounts=set())

    def test_native_xdg_path_inside_home_is_supported(self):
        config = self.home / "custom config"
        path = config / "discord/Cache"
        path.mkdir(parents=True)
        (path / "entry").write_text("custom")
        manager = self.module.CacheManager(self.home, config=config, mounts=set(),
            process_probe=lambda: {"state": "clear", "pids": []})
        preview = manager.preview("native-stable")
        manager.clean("native-stable", preview["token"])
        self.assertFalse(path.exists())
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_swapped_root_is_not_deleted_after_staging(self):
        preview = self.preview()
        rename = self.module.os.rename
        injected = False
        def swap(source, destination, **kwargs):
            nonlocal injected
            if source == "Cache" and not injected:
                injected = True
                rename("Cache", "original-cache", src_dir_fd=kwargs["src_dir_fd"], dst_dir_fd=kwargs["src_dir_fd"])
                rename("Local Storage", "Cache", src_dir_fd=kwargs["src_dir_fd"], dst_dir_fd=kwargs["src_dir_fd"])
            return rename(source, destination, **kwargs)
        with mock.patch.object(self.module.os, "rename", side_effect=swap), self.assertRaises(RuntimeError):
            self.clean(preview)
        self.assertTrue((self.profile / "original-cache/nested/entry").exists())
        self.assertEqual((self.profile / "Cache/leveldb/token").read_bytes(), b"must survive")

    def test_unknown_process_probe_prevents_clean_when_procfs_unavailable(self):
        self.manager.process_probe = self.module.CacheManager(self.home, proc=self.home / "missing-proc", mounts=set()).processes
        with self.assertRaises(ValueError):
            self.clean()
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_staging_open_failure_leaves_no_empty_temporary_directory(self):
        preview = self.preview()
        original = self.module.os.open
        def fail(path, *args, **kwargs):
            if str(path).startswith(".zapret-discord-cache-"):
                raise PermissionError("injected staging failure")
            return original(path, *args, **kwargs)
        with mock.patch.object(self.module.os, "open", side_effect=fail), self.assertRaises(ValueError):
            self.clean(preview)
        self.assertFalse(list(self.profile.glob(".zapret-discord-cache-*")))
        self.assertTrue((self.profile / "Cache/nested/entry").exists())

    def test_real_probe_recognizes_discord_and_electron_names(self):
        proc = self.home / "fake-proc"
        for pid, name in ((111, "Discord"), (112, "electron"), (113, "unrelated")):
            folder = proc / str(pid)
            folder.mkdir(parents=True)
            (folder / "comm").write_text(name + "\n")
        manager = self.module.CacheManager(self.home, proc=proc, mounts=set())
        self.assertEqual(manager.processes(), {"state": "running", "pids": [111, 112]})

    def test_missing_mount_information_disables_preview(self):
        manager = self.module.CacheManager(self.home, proc=self.home / "missing-proc")
        item = next(item for item in manager.discover()["instances"] if item["id"] == "native-stable")
        self.assertIsNone(item["token"])
        self.assertIn("монтирован", item["error"])


class BackendTests(unittest.TestCase):
    def test_demo_scan_and_clean_never_touch_files_or_processes(self):
        backend = load("src/gui/backend.py").DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("process")), \
                mock.patch.object(Path, "open", side_effect=AssertionError("filesystem")):
            report = backend.scan_discord()
            item = report["instances"][0]
            result = backend.clean_discord(item["id"], item["token"])
        self.assertTrue(result["removed_files"])
        self.assertEqual(backend.snapshot()["discord"]["instances"][0]["files"], 0)


if __name__ == "__main__":
    unittest.main()
