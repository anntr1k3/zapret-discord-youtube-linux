#!/usr/bin/env python3
"""Offline regression tests: no sudo, firewall changes or downloaded binaries."""

import pathlib
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class Regressions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="zapret-tests-")
        self.addCleanup(self.directory.cleanup)
        self.tmp = pathlib.Path(self.directory.name)

    def bash(self, script):
        result = subprocess.run(
            ["bash", "-c", 'TEST_TMP="$2"\nsource "$1/src/lib/common.sh"\n' + script,
            "test", str(ROOT), str(self.tmp)],
            text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_config_is_data_not_shell(self):
        (self.tmp / "conf.env").write_text(
            'interface=any\ngamefiltertcp=false\ngamefilterudp=true\n'
            'strategy=general.bat\n$(touch '
            + shlex.quote(str(self.tmp / "executed")) + ')\n'
        )
        self.bash('! (load_config "$2/conf.env")')
        self.assertFalse((self.tmp / "executed").exists())

    def test_config_validation_has_no_side_effects(self):
        config = self.tmp / "conf.env"
        content = ('interface=any\ngamefiltertcp=false\ngamefilterudp=true\n'
                   'strategy=general.bat\n')
        config.write_text(content)
        self.bash('check_conf_file "$2/conf.env"')
        self.assertEqual(config.read_text(), content)

    def test_config_defaults_crlf_and_no_final_newline(self):
        (self.tmp / "conf.env").write_bytes(
            b'# comment\r\ninterface=any\r\ngamefiltertcp=false\r\n'
            b'gamefilterudp=true\r\nstrategy=general.bat'
        )
        self.bash('load_config "$2/conf.env"\n'
                  '[[ "$interface" == any && "$gamefilterudp" == true '
                           '&& "$FIREWALL_BACKEND" == auto ]]')

    def test_game_filter_ports_config_defaults_and_validation(self):
        config = self.tmp / "conf.env"
        base = 'interface=any\ngamefiltertcp=true\ngamefilterudp=true\nstrategy=general.bat\n'
        config.write_text(base)
        self.bash('load_config "$2/conf.env"\n[[ "$gamefiltertcp_ports" == 1024-65535 && "$gamefilterudp_ports" == 1024-65535 ]]')
        config.write_text(base + 'gamefiltertcp_ports=1,1000-2000,65535\ngamefilterudp_ports=3000-4000\n')
        self.bash('load_config "$2/conf.env"\n[[ "$gamefiltertcp_ports" == 1,1000-2000,65535 && "$gamefilterudp_ports" == 3000-4000 ]]')
        for value in ("", "0", "65536", "2-1", "01", "1,,2", "1 2", "$(id)", "9" * 513):
            config.write_text(base + 'gamefiltertcp_ports=' + value + '\n')
            self.bash('! check_conf_file "$2/conf.env"')

    def test_legacy_strategy_uses_separate_game_port_ranges(self):
        (self.tmp / 'general.bat').write_text('start "test" /min "%BIN%winws.exe" --wf-tcp=443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^\n'
                                             '--filter-tcp=%GameFilterTCP% --dpi-desync=fake --new ^\n'
                                             '--filter-udp=%GameFilterUDP% --dpi-desync=fake\n')
        self.bash('''
REPO_DIR="$2"
USE_GAME_FILTER=true
USE_GAME_FILTER_TCP=true
USE_GAME_FILTER_UDP=true
gamefiltertcp_ports=1000-2000
gamefilterudp_ports=3000,4000-5000
parse_bat_file "$2/general.bat"
[[ "$tcp_ports" == 443,1000-2000 && "$udp_ports" == 443,3000,4000-5000 ]] || exit 1
[[ "${nfqws_params[*]}" == *--filter-tcp=1000-2000* ]] || exit 1
[[ "${nfqws_params[*]}" == *--filter-udp=3000,4000-5000* ]]
''')

    def test_config_rejects_bad_values_and_duplicates(self):
        base = ('interface=any\ngamefiltertcp=false\ngamefilterudp=true\n'
                'strategy=general.bat\n')
        for suffix in ['interface=eth0\n', 'firewall_backend=invalid\n',
                       'unknown=value\n', '=empty-key\n',
                       'strategy=../outside.bat\n']:
            with self.subTest(suffix=suffix):
                (self.tmp / "conf.env").write_text(base + suffix)
                self.bash('! check_conf_file "$2/conf.env"')
        (self.tmp / "conf.env").write_text(base.replace('false', 'yes'))
        self.bash('! check_conf_file "$2/conf.env"')

    def test_failed_config_load_does_not_use_previous_values(self):
        (self.tmp / "conf.env").write_text('interface=any\nstrategy=general.bat\n')
        self.bash('gamefiltertcp=true; gamefilterudp=true\n'
                  '! (load_config "$2/conf.env")')

    def test_available_firewall_backends_load(self):
        for backend in ['auto', 'nftables', 'iptables']:
            with self.subTest(backend=backend):
                (self.tmp / "conf.env").write_text(
                    'interface=any\ngamefiltertcp=false\ngamefilterudp=true\n'
                    f'strategy=general.bat\nfirewall_backend={backend}\n'
                )
                self.bash('load_config "$2/conf.env"\n'
                          f'[[ "$FIREWALL_BACKEND" == {backend} ]]')

    def test_auto_tune_saves_current_schema_and_backup(self):
        # Only load the function under test; never run auto-tune's network loop.
        text = (ROOT / "auto_tune_youtube.sh").read_text()
        start = text.index('save_strategy() {')
        function = text[start:text.index('\n}', start) + 2]
        old = 'original configuration\n'
        (self.tmp / "conf.env").write_text(old)
        self.bash(function + '\nSCRIPT_DIR="$1"\nCONF_FILE="$2/conf.env"\n'
                  'save_strategy general.bat\ncheck_conf_file "$CONF_FILE"')
        self.assertEqual((self.tmp / "conf.env.backup").read_text(), old)

    def test_auto_tune_rejects_invalid_strategy_without_replacing_config(self):
        text = (ROOT / "auto_tune_youtube.sh").read_text()
        start = text.index('save_strategy() {')
        function = text[start:text.index('\n}', start) + 2]
        (self.tmp / "conf.env").write_text('keep this\n')
        self.bash(function + '\nSCRIPT_DIR="$1"\nCONF_FILE="$2/conf.env"\n'
                  'if save_strategy ../outside.bat; then exit 1; fi')
        self.assertEqual((self.tmp / "conf.env").read_text(), 'keep this\n')
        self.assertEqual(list(self.tmp.iterdir()), [self.tmp / "conf.env"])

    def test_stop_matches_executable_not_command_line(self):
        output = self.bash('''
NFQWS_PATH="$2/nfqws"
touch "$NFQWS_PATH"
pgrep() { printf '101\n202\n'; }
elevate() {
    case "$1" in
        readlink)
            if [[ "$3" == /proc/101/exe ]]; then
                printf '%s (deleted)\n' "$NFQWS_PATH"
            else
                printf '/some/other/nfqws\n'
            fi ;;
        kill) printf 'SIGNAL %s\n' "${@:2}" ;;
        *) echo "Unexpected privileged command: $*" >&2; return 1 ;;
    esac
}
stop_nfqws
''')
        self.assertIn('101', output)
        self.assertNotIn('202', output)

    def test_no_passwordless_rules_are_created(self):
        self.bash('''
source "$1/src/lib/permissions.sh"
get_elevate_cmd() { echo sudo; }
elevate() { touch "$TEST_TMP/unexpected"; return 99; }
if setup_permissions testuser; then exit 1; fi
''')
        self.assertFalse((self.tmp / "unexpected").exists())

    def test_doas_migration_leaves_shared_rules_untouched(self):
        content = ('# Zapret Discord YouTube - nopass testuser\n'
                   'permit nopass testuser as root cmd /usr/bin/nft\n'
                   'permit otheruser as root\n')
        (self.tmp / "doas.conf").write_text(content)
        self.bash('''
source "$1/src/lib/permissions.sh"
SUDOERS_FILE="$TEST_TMP/missing-sudoers"
DOAS_CONF="$TEST_TMP/doas.conf"
elevate() { touch "$TEST_TMP/unexpected"; return 99; }
if remove_permissions; then exit 1; fi
''')
        self.assertEqual((self.tmp / "doas.conf").read_text(), content)
        self.assertFalse((self.tmp / "unexpected").exists())

    def test_each_init_backend_refuses_unsafe_install_before_side_effects(self):
        for backend in ['systemd', 'openrc', 'runit', 's6', 'dinit']:
            with self.subTest(backend=backend):
                self.bash('''
HOME_DIR_PATH="$TEST_TMP/app"
assert_secure_service_tree() { return 1; }
elevate() { touch "$TEST_TMP/unexpected"; return 99; }
''' + f'source "$1/src/init-backends/{backend}.sh"\n'
                    'if install_service; then exit 1; fi')
                self.assertFalse((self.tmp / "unexpected").exists())

    def test_config_creation_cancellation_aborts_install(self):
        self.bash('''
CONF_FILE="$TEST_TMP/missing.env"
read() { answer=n; }
if ensure_config_exists; then exit 1; fi
''')

    def test_service_tree_rejects_writable_or_non_root_paths(self):
        self.bash('''
source "$1/src/lib/security.sh"
declare -F assert_secure_service_tree >/dev/null || exit 1
mkdir "$2/app"
touch "$2/app/service.sh"
stat() {
    case "${@: -1}" in
        */app/service.sh) printf '%s\n' "$UNSAFE_METADATA" ;;
        *) printf '0 755\n' ;;
    esac
}
for UNSAFE_METADATA in '1000 755' '0 775' '0 777'; do
    if assert_secure_service_tree "$2/app"; then exit 1; fi
done
UNSAFE_METADATA='0 644'
assert_secure_service_tree "$2/app"
ln -s service.sh "$2/app/link"
if assert_secure_service_tree "$2/app"; then exit 1; fi
''')

    def test_service_tree_rejects_writable_parent(self):
        self.bash('''
source "$1/src/lib/security.sh"
mkdir "$TEST_TMP/app"
stat() {
    if [[ "${@: -1}" == "$TEST_TMP" ]]; then
        printf '0 777\n'
    else
        printf '0 755\n'
    fi
}
if assert_secure_service_tree "$TEST_TMP/app"; then exit 1; fi
''')

    def test_systemd_readiness_follows_initialization(self):
        (self.tmp / "conf.env").write_text(
            'interface=any\ngamefiltertcp=false\ngamefilterudp=false\nstrategy=general.bat\n')
        output = self.bash('''
source "$1/src/cli/run.sh"
REPO_DIR="$TEST_TMP"
SYSTEM_INSTALL=true
NOTIFY_SOCKET=mock
run_zapret() { echo INITIALIZED; }
systemd-notify() { echo READY; }
sleep() { :; }
run_zapret_command --config "$TEST_TMP/conf.env"
''')
        self.assertLess(output.index('INITIALIZED'), output.index('READY'))

    def test_failed_readiness_notification_cleans_up(self):
        (self.tmp / "conf.env").write_text(
            'interface=any\ngamefiltertcp=false\ngamefilterudp=false\nstrategy=general.bat\n')
        output = self.bash('''
source "$1/src/cli/run.sh"
REPO_DIR="$TEST_TMP"
SYSTEM_INSTALL=true
NOTIFY_SOCKET=mock
run_zapret() { :; }
systemd-notify() { return 1; }
stop_zapret() { echo CLEANED; }
if run_zapret_command --config "$TEST_TMP/conf.env"; then exit 1; fi
''')
        self.assertIn('CLEANED', output)

    def test_installed_copy_rejects_legacy_mutating_commands(self):
        self.bash('''
source "$1/src/cli/download.sh"
source "$1/src/init-backends/systemd.sh"
SYSTEM_INSTALL=true
elevate() { touch "$TEST_TMP/unexpected"; return 99; }
if handle_download_deps_command --default; then exit 1; fi
if install_service; then exit 1; fi
if remove_service; then exit 1; fi
''')
        self.assertFalse((self.tmp / "unexpected").exists())


if __name__ == '__main__':
    unittest.main()
