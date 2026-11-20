"""Bootstrap trust checks without root, polkit, or host filesystem changes."""

import importlib.util
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class BootstrapTrustTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("bootstrap_trust_test", ROOT / "src/gui/bootstrap.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        temporary = tempfile.TemporaryDirectory(prefix="zapret-bootstrap-test-")
        self.addCleanup(temporary.cleanup)
        self.application = Path(temporary.name) / "usr/lib/zapret-discord-youtube"
        self.helper = self.application / "src/gui/bootstrap.py"
        self.helper.parent.mkdir(parents=True)
        self.helper.write_text("# fixture only\n")
        self.engine = self.application / "runtime/nfqws"
        self.engine.parent.mkdir()
        self.engine.write_text("never executed\n")
        self.real_lstat = Path.lstat

    def verify(self, bad_path=None, bad_uid=0, bad_mode=None):
        def lstat(path, *args, **kwargs):
            original = self.real_lstat(path, *args, **kwargs)
            # Model a package-manager-created root-owned hierarchy. No chown.
            mode = original.st_mode & ~0o022
            uid = 0
            if path == bad_path:
                uid = bad_uid
                if bad_mode is not None:
                    mode = bad_mode
            return types.SimpleNamespace(st_uid=uid, st_mode=mode)

        with mock.patch.object(self.module, "APPLICATION", self.application), \
                mock.patch.object(self.module, "__file__", str(self.helper)), \
                mock.patch.object(Path, "lstat", lstat):
            return self.module.verify_application()

    def test_accepts_only_root_owned_package_tree(self):
        self.assertEqual(self.verify(), self.application)

    def test_rejects_user_owned_engine_or_ancestor(self):
        for path in (self.engine, self.helper, self.application.parent):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "Недоверенный"):
                self.verify(path, bad_uid=1000)

    def test_rejects_writable_files_directories_symlinks_and_special_files(self):
        for path, mode in (
            (self.engine, stat.S_IFREG | 0o664),
            (self.engine.parent, stat.S_IFDIR | 0o775),
            (self.engine, stat.S_IFLNK | 0o777),
            (self.engine, stat.S_IFIFO | 0o644),
            (self.application, stat.S_IFLNK | 0o777),
        ):
            with self.subTest(path=path, mode=oct(mode)), \
                    self.assertRaisesRegex(ValueError, "Недоверенный"):
                self.verify(path, bad_mode=mode)


if __name__ == "__main__":
    unittest.main()
