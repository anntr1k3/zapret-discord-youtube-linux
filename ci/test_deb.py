"""Offline package regression tests; never install an artifact."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("dpkg-deb") and os.geteuid() != 0, "requires unprivileged Debian build tools")
class DebTests(unittest.TestCase):
    def test_rejects_unverified_archives_without_building_a_package(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            # Do not allow the old builder to write into the real workspace.
            checkout = base / "checkout"
            shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(
                ".git", "dist", "conf.env", "nfqws", "zapret-latest", "user-lists", "__pycache__"))
            inputs = base / "inputs"
            inputs.mkdir()
            (inputs / "zapret-v72.9.tar.gz").write_bytes(b"untrusted engine")
            (inputs / "flowseal.zip").write_bytes(b"untrusted catalog")
            output = base / "output"
            result = subprocess.run(
                ["/bin/bash", str(checkout / "scripts/build-deb.sh"), "--inputs", str(inputs),
                 "--output", str(output)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("SHA-256", result.stderr)
            self.assertFalse(list(base.rglob("*.deb")))

    @unittest.skipUnless(os.environ.get("ZAPRET_TEST_DEB"), "pass an actual built artifact via ZAPRET_TEST_DEB")
    def test_artifact_contents(self):
        artifact = Path(os.environ["ZAPRET_TEST_DEB"]).resolve(strict=True)
        app = "usr/lib/zapret-discord-youtube"
        runtime = app + "/runtime"
        data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", artifact], timeout=15)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            entries = {entry.name.removeprefix("./").rstrip("/"): entry for entry in archive}
            for name, entry in entries.items():
                with self.subTest(name=name):
                    self.assertTrue(entry.isfile() or entry.isdir())
                    self.assertEqual((entry.uid, entry.gid), (0, 0))
                    self.assertEqual(entry.mode & 0o7022, 0)
                    self.assertNotIn(name.split("/")[0], ("opt", "etc", "var"))
                    self.assertNotIn(Path(name).name, ("conf.env", "user-lists", "__pycache__"))
            for relative in ("gui.py", "sync.py", "install.py", "src/gui/bootstrap.py",
                             "runtime/src/gui/privileged.py", "runtime/src/lib/ipset-none.txt",
                             "runtime/zapret-latest/utils/targets.txt"):
                self.assertEqual(entries[f"{app}/{relative}"].mode, 0o644)
            for name in (f"{runtime}/nfqws", f"{runtime}/service.sh", "usr/bin/zapret", "usr/bin/zapret-gui"):
                self.assertEqual(entries[name].mode, 0o755)
            self.assertIn(f"/{app}/gui.py".encode(), archive.extractfile(entries["usr/bin/zapret-gui"]).read())
            metadata = json.load(archive.extractfile(entries[f"{app}/src/app-version.json"]))
            self.assertEqual(metadata, json.load(archive.extractfile(entries[f"{runtime}/src/app-version.json"])))
            self.assertEqual(metadata["version"], "1.0.1-rc1")
            self.assertIs(metadata["release"], False)
            engine = archive.extractfile(entries[f"{runtime}/nfqws"]).read()
            self.assertEqual(hashlib.sha256(engine).hexdigest(),
                             "e57db44af46835f68a8cacbf98267c694ee863e27622a8c3a3609eb14ebad11c")
            catalog = json.load(archive.extractfile(entries[f"{runtime}/zapret-latest/strategies.json"]))
            self.assertIn("general_alt12.bat", catalog["strategies"])
            self.assertEqual(len(catalog["strategies"]), 22)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["dpkg-deb", "--control", artifact, directory], check=True, timeout=15)
            self.assertEqual({path.name for path in Path(directory).iterdir()}, {"control"})
            control = (Path(directory) / "control").read_text()
            self.assertIn(f"\nVersion: {metadata['version'].replace('-rc', '~rc')}\n", control)
            self.assertIn("gir1.2-adw-1 (>= 1.5)", control)
            self.assertIn("pkexec", control)
