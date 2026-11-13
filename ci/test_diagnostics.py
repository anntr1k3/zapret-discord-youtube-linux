"""Unprivileged diagnostics: fake files/commands, no host changes or network."""

import importlib.util
import json
from pathlib import Path
import subprocess
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location("diagnostics_test", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/diagnostics.py")

    def test_credentials_path_query_and_fragment_are_not_reported(self):
        text = self.module.proxy_address("https://user:secret@proxy.example:8443/token?key=topsecret#private")
        self.assertEqual(text, "https://proxy.example:8443 (учётные данные скрыты)")
        for value in ("user", "secret", "token", "topsecret", "private"):
            self.assertNotIn(value, text)

    def test_encoded_credentials_ipv6_and_socks(self):
        text = self.module.proxy_address("socks5h://alice:p%40ss@[::1]:1080/path")
        self.assertIn("socks5h://[::1]:1080", text)
        self.assertNotIn("alice", text)
        self.assertNotIn("p%40ss", text)

    def test_invalid_proxy_value_is_hidden_not_echoed(self):
        for value in ("password=secret", "http://user:secret@host:bad", "file:///secret",
                      "https://proxy.example\nsecret", "https://bad_host/secret"):
            text = self.module.proxy_address(value)
            self.assertIn("скрыто", text)
            self.assertNotIn("secret", text)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/diagnostics.py")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret диагностика ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base, self.data = self.root / "base", self.root / "data"
        self.proc, self.etc = self.root / "proc", self.root / "etc"
        for relative in ("base/service.sh", "base/nfqws", "base/src/lib/common.sh", "base/src/lib/strategy_sync.py",
                         "data/user-lists/list-general-user.txt", "data/user-lists/list-exclude-user.txt",
                         "data/user-lists/ipset-exclude-user.txt", "etc/hosts"):
            self.write(relative, "fixture\n")
        (self.base / "zapret-latest").mkdir()
        (self.base / "custom-strategies").mkdir()
        self.write("proc/sys/net/ipv4/tcp_timestamps", "1\n")
        self.write("proc/net/netfilter/nfnetlink_queue", "220 123 0 2 65535 0 0 10 1\n221 456 0 2 65535 0 0 20 1\n")
        self.write("etc/resolv.conf", "# comment\nnameserver 127.0.0.53\nsearch private.example\n")
        self.write("proc/100/comm", "openvpn\n")
        self.write("proc/101/comm", "unrelated\n")
        self.calls = []
        def runner(argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == "/usr/bin/gsettings":
                value = "'none'\n" if argv[-1] == "mode" else "''\n"
            else:
                value = "Global: no\n"
            return subprocess.CompletedProcess(argv, 0, value, "")
        self.runner = runner
        self.env = {}
        self.which = lambda name: "/usr/bin/" + name

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def report(self):
        return self.module.collect(self.base, self.data, environ=self.env, proc=self.proc, etc=self.etc,
                                   runner=self.runner, which=self.which)

    def check(self, report, key):
        return next(check for check in report["checks"] if check["id"] == key)

    def test_unicode_paths_and_lists_are_read_without_execution(self):
        report = self.report()
        self.assertEqual(self.check(report, "paths")["state"], "observed")
        self.assertEqual(self.check(report, "user-lists")["state"], "observed")
        self.assertTrue(report["checked_at"])

    def test_missing_files_are_reported_but_not_created(self):
        missing = self.data / "user-lists/list-general-user.txt"
        missing.unlink()
        self.assertEqual(self.check(self.report(), "user-lists")["state"], "warning")
        self.assertFalse(missing.exists())

    def test_missing_dependencies_are_not_installed(self):
        self.which = lambda name: None
        report = self.report()
        self.assertEqual(self.check(report, "dependencies")["state"], "warning")
        self.assertFalse(self.calls)

    def test_proxy_report_redacts_environment_and_no_proxy(self):
        self.env = {"HTTPS_PROXY": "https://user:secret@proxy.example:443/key?token=hidden",
                    "no_proxy": "secret.internal,token.internal"}
        text = json.dumps(self.report(), ensure_ascii=False)
        self.assertIn("proxy.example", text)
        for value in ("secret", "hidden", "token.internal"):
            self.assertNotIn(value, text)

    def test_gnome_manual_proxy_never_reads_authentication_secrets(self):
        def runner(argv, **kwargs):
            self.calls.append(argv)
            values = {"mode": "'manual'", "host": "'proxy.example'", "port": "8080"}
            return subprocess.CompletedProcess(argv, 0, values.get(argv[-1], "Global: no"), "")
        self.runner = runner
        text = json.dumps(self.report(), ensure_ascii=False)
        self.assertIn("proxy.example", text)
        self.assertFalse(any("authentication-password" in call or "authentication-user" in call for call in self.calls))

    def test_command_failure_does_not_leak_stderr(self):
        self.runner = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "", "user:secret@proxy.example/token")
        text = json.dumps(self.report(), ensure_ascii=False)
        self.assertNotIn("secret", text)
        self.assertIn("неизвестно", text.lower())

    def test_dns_is_observation_not_browser_doh_verdict(self):
        report = self.report()
        dns = self.check(report, "dns")
        self.assertIn("127.0.0.53", " ".join(dns["details"]))
        self.assertTrue(any("DoH" in limitation for limitation in report["limitations"]))
        self.assertNotIn("private.example", json.dumps(dns))

    def test_tcp_timestamps_are_read_without_setting(self):
        self.write("proc/sys/net/ipv4/tcp_timestamps", "0\n")
        report = self.report()
        self.assertIn("0", " ".join(self.check(report, "tcp-timestamps")["details"]))
        self.assertEqual((self.proc / "sys/net/ipv4/tcp_timestamps").read_text(), "0\n")

    def test_known_process_is_only_a_possible_conflict(self):
        item = self.check(self.report(), "possible-conflicts")
        self.assertEqual(item["state"], "warning")
        self.assertIn("openvpn", " ".join(item["details"]))
        self.assertIn("не доказывает", item["summary"])
        self.assertNotIn("unrelated", " ".join(item["details"]))

    def test_nfqueue_listener_is_not_interpreted_as_pid_ownership(self):
        item = self.check(self.report(), "nfqueue")
        self.assertIn("220", " ".join(item["details"]))
        self.assertNotIn("PID 123", json.dumps(item, ensure_ascii=False))

    def test_unavailable_nfqueue_is_unknown_not_unsupported(self):
        (self.proc / "net/netfilter/nfnetlink_queue").unlink()
        self.assertEqual(self.check(self.report(), "nfqueue")["state"], "unknown")

    def test_youtube_hosts_detection_does_not_export_other_hosts(self):
        self.write("etc/hosts", "127.0.0.1 youtube.com\n192.0.2.10 private.internal\n")
        item = self.check(self.report(), "hosts")
        self.assertEqual(item["state"], "warning")
        self.assertNotIn("private.internal", json.dumps(item))

    def test_windows_checks_are_explicitly_not_applicable(self):
        self.assertEqual(self.check(self.report(), "windows-only")["state"], "not-applicable")

    def test_commands_are_fixed_reads_without_network_or_root(self):
        self.report()
        self.assertTrue(self.calls)
        for call in self.calls:
            self.assertIn(call[0], ("/usr/bin/gsettings", "/usr/bin/resolvectl"))
            if call[0].endswith("gsettings"):
                self.assertEqual(call[1], "get")
            self.assertNotIn("sudo", call)
            self.assertNotIn("set", call)

    def test_timeout_is_an_unknown_check_not_report_failure(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 6)
        self.runner = runner
        report = self.report()
        self.assertEqual(self.check(report, "proxy-gnome")["state"], "unknown")
        self.assertTrue(self.check(report, "paths")["details"])

    def test_pac_address_is_never_requested_or_exported(self):
        def runner(argv, **kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "'auto'" if argv[-1] == "mode" else "Global: no", "")
        self.runner = runner
        self.report()
        self.assertFalse(any("autoconfig-url" in call for call in self.calls))


class BackendTests(unittest.TestCase):
    def test_demo_diagnostics_never_uses_subprocesses(self):
        backend = load("src/gui/backend.py").DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("real command")):
            report = backend.diagnostics()
        self.assertTrue(report["checks"])
        self.assertEqual(backend.snapshot()["diagnostics"], report)

    def test_export_is_atomic_and_refuses_symlinks(self):
        module = load("src/gui/backend.py")
        backend = module.DemoBackend()
        backend.diagnostics()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            backend.export_diagnostics(target)
            self.assertEqual(json.loads(target.read_text()), backend.snapshot()["diagnostics"])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                backend.export_diagnostics(link)
            original = target.read_bytes()
            with mock.patch("os.fsync", side_effect=OSError("disk full")), self.assertRaises(OSError):
                backend.export_diagnostics(target)
            self.assertEqual(target.read_bytes(), original)

    def test_export_requires_existing_report(self):
        backend = load("src/gui/backend.py").DemoBackend()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            with self.assertRaises(ValueError):
                backend.export_diagnostics(target)
            self.assertFalse(target.exists())

    def test_presentation_keeps_unknown_and_not_applicable_distinct(self):
        backend = load("src/gui/backend.py").DemoBackend()
        presentation = load("src/gui/presentation.py")
        text = presentation.diagnostics_text(backend.diagnostics())
        self.assertIn("[Неизвестно]", text)
        self.assertIn("[Неприменимо]", text)
        self.assertIn("не означают исправность", text)


if __name__ == "__main__":
    unittest.main()
