"""Offline path, launcher and stop-lock regressions; no host service actions."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CliPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="zapret-cli-")
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)

    def run_command(self, *args, **kwargs):
        return subprocess.run(args, cwd=self.tmp, text=True, capture_output=True, timeout=10, **kwargs)

    def test_rename_uses_explicit_strategy_directory_not_cwd(self):
        target = self.tmp / "another directory"
        target.mkdir()
        decoy = self.tmp / "zapret-latest"
        decoy.mkdir()
        (target / "general (ALT12).bat").write_text("real")
        (decoy / "general (ALT12).bat").write_text("decoy")
        result = self.run_command("bash", str(ROOT / "src/rename_bat.sh"), str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((decoy / "general (ALT12).bat").is_file())
        self.assertEqual((target / "general_alt12.bat").read_text(), "real")

    def test_missing_strategy_directory_fails(self):
        result = self.run_command("bash", str(ROOT / "src/rename_bat.sh"), str(self.tmp / "missing"))
        self.assertNotEqual(result.returncode, 0)

    def test_home_and_symlinked_launchers_forward_arguments_from_other_cwd(self):
        for name, source_name, source in (
            ("zapret", "service.sh", "#!/bin/sh\nprintf '%s\\n' \"$1\"\n"),
            ("zapret-gui", "gui.py", "import sys\nprint(sys.argv[1])\n"),
        ):
            for use_symlink in (False, True):
                with self.subTest(name=name, use_symlink=use_symlink):
                    home = self.tmp / (name + str(use_symlink))
                    project = home / ("Другой каталог" if use_symlink else "zapret-discord-youtube-linux")
                    (project / "bin").mkdir(parents=True)
                    (project / source_name).write_text(source)
                    (project / source_name).chmod(0o755)
                    destination = home / ".local/bin" / name
                    destination.parent.mkdir(parents=True)
                    # Keep this independent of services/packages on the test machine.
                    launcher = (ROOT / "bin" / name).read_text().replace("/opt/", "/nonexistent/opt/").replace(
                        "/usr/lib/zapret-discord-youtube", "/nonexistent/usr/lib/zapret-discord-youtube")
                    if use_symlink:
                        target = project / "bin" / name
                        target.write_text(launcher)
                        target.chmod(0o755)
                        destination.symlink_to(target)
                    else:
                        destination.write_text(launcher)
                        destination.chmod(0o755)
                    result = self.run_command(str(destination), "one argument", env={**os.environ, "HOME": str(home)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "one argument")

    def test_desktop_tester_selects_real_tester_page(self):
        desktop = (ROOT / "src/desktop/zapret-gui.desktop").read_text()
        action = desktop.split("[Desktop Action RunTester]\n", 1)[1]
        self.assertIn("Exec=zapret-gui --tester\n", action)
        result = self.run_command("/usr/bin/python3", str(ROOT / "gui.py"), "--help")
        self.assertIn("--tester", result.stdout)

    @unittest.skipUnless(shutil.which("flock"), "requires Linux flock")
    def test_parallel_stop_serializes_and_never_unlinks_the_lock(self):
        # Stub both privileged calls and supply an entirely private runtime dir.
        script = r'''
set -e
source "$1/src/cli/run.sh"
testdir=$2
_stop_lock_parent() { printf '%s\n' "$testdir"; }
log() { :; }
stop_nfqws() {
    mkdir "$testdir/in-progress" || exit 99
    echo begin
    sleep 0.15
}
firewall_clear() {
    rmdir "$testdir/in-progress"
    echo end
}
stop_zapret & first=$!
stop_zapret & second=$!
wait "$first"
wait "$second"
'''
        # Fail before invoking older implementations with a hardcoded /tmp lock.
        self.assertIn("_stop_lock_parent()", (ROOT / "src/cli/run.sh").read_text())
        result = self.run_command("bash", "-c", script, "test", str(ROOT), str(self.tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["begin", "end", "begin", "end"])
        self.assertTrue((self.tmp / "zapret-stop").is_dir())

    def test_stop_refuses_a_symlink_lock_without_doing_cleanup(self):
        target = self.tmp / "untouched"
        target.mkdir()
        link = self.tmp / "zapret-stop"
        link.symlink_to(target, target_is_directory=True)
        script = r'''
set -e
source "$1/src/cli/run.sh"
testdir=$2
_stop_lock_parent() { printf '%s\n' "$testdir"; }
log() { :; }
stop_nfqws() { echo 'unexpected cleanup'; }
firewall_clear() { echo 'unexpected cleanup'; }
stop_zapret
'''
        self.assertIn("_stop_lock_parent()", (ROOT / "src/cli/run.sh").read_text())
        result = self.run_command("bash", "-c", script, "test", str(ROOT), str(self.tmp))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Небезопасная блокировка", result.stderr)
        self.assertNotIn("unexpected cleanup", result.stdout)
        self.assertTrue(link.is_symlink())

    @unittest.skipIf(os.geteuid() == 0, "user desktop install is unprivileged")
    def test_desktop_install_uses_symlinks_and_keeps_unrelated_launchers(self):
        home = self.tmp / "home"
        bin_dir = home / ".local/bin"
        bin_dir.mkdir(parents=True)
        data = self.tmp / "data"
        env = {**os.environ, "HOME": str(home), "XDG_DATA_HOME": str(data)}
        installer = str(ROOT / "src/desktop/install-desktop.sh")
        foreign = bin_dir / "zapret-gui"
        foreign.write_text("custom user command")
        result = self.run_command("bash", installer, "--user", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_text(), "custom user command")
        self.assertFalse(data.exists())
        foreign.unlink()
        for _ in range(2):
            result = self.run_command("bash", installer, "--user", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("zapret", "zapret-gui"):
            launcher = bin_dir / name
            self.assertTrue(launcher.is_symlink())
            self.assertEqual(launcher.resolve(), ROOT / "bin" / name)


if __name__ == "__main__":
    unittest.main()
