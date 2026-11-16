"""Run shell ownership filtering with fake systemctl/proc/kill, never signal PIDs."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ServiceCgroupStopTests(unittest.TestCase):
    def run_stop(self, *, invocation=True, group="/system.slice/zapret_discord_youtube.service"):
        script = r'''
source "$1/src/lib/common.sh"
SYSTEM_INSTALL=true
INVOCATION_ID="$2"
get_nfqws_pids() { printf '%s\n' 100 101 102; }
elevate() {
    case "$1" in
        systemctl) printf '%s\n' "$EXPECTED_GROUP" ;;
        cat)
            case "${@: -1}" in
                /proc/100/cgroup) printf '0::/system.slice/zapret_discord_youtube.service\n' ;;
                /proc/101/cgroup) printf '0::/user.slice/manual\n' ;;
                /proc/102/cgroup) printf '0::/system.slice/zapret_discord_youtube.service/control\n' ;;
            esac ;;
        kill) printf 'SIGNAL %s\n' "${@: -1}" ;;
        *) return 99 ;;
    esac
}
EXPECTED_GROUP="$3"
stop_nfqws
'''
        return subprocess.run(["/bin/bash", "-c", script, "test", str(ROOT), "a" * 32 if invocation else "", group],
                              capture_output=True, text=True, timeout=5)

    def test_systemd_stop_only_signals_owned_cgroup(self):
        result = self.run_stop()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["SIGNAL 100", "SIGNAL 102"])

    def test_unknown_systemd_cgroup_fails_without_signals(self):
        for group in ("", "/", "/user.slice/manual", "/a/../zapret_discord_youtube.service"):
            with self.subTest(group=group):
                result = self.run_stop(group=group)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SIGNAL", result.stdout)

    def test_existing_non_systemd_cli_behavior_is_unchanged(self):
        result = self.run_stop(invocation=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["SIGNAL 100", "SIGNAL 101", "SIGNAL 102"])


if __name__ == "__main__":
    unittest.main()
