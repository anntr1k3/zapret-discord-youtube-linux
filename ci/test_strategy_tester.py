"""Strategy tester engine: fake I/O only, no real network, root or runner calls."""

import datetime
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    import importlib.util
    spec = importlib.util.spec_from_file_location("strategy_tester_test", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_strategy(folder, name, content="--filter-tcp=443\n"):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(content)
    return path


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")

    def test_merges_folders_sorts_and_excludes_service_and_odd_names(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            write_strategy(base / "zapret-latest", "general (10).bat")  # пробел: как в профильном переключателе
            write_strategy(base / "zapret-latest", "general.bat")
            write_strategy(base / "zapret-latest", "service.bat")
            write_strategy(base / "zapret-latest", "service2.bat")
            write_strategy(base / "zapret-latest", "bad name!.bat")
            write_strategy(base / "custom-strategies", "general.bat")
            write_strategy(base / "custom-strategies", "minecraft.bat")
            self.assertEqual(self.module.discover_strategies(base),
                             ["general.bat", "minecraft.bat"])

    def test_missing_folders_are_not_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.module.discover_strategies(Path(directory)), [])


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")

    def test_parses_keys_values_and_last_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(
                "# comment\n"
                "Alpha = \"https://example.org\"\n"
                "  Beta  = \"PING:192.0.2.1\"  \n"
                "Alpha = \"https://example.net\"\n"
                "garbage line\n"
                "Broken = \"https://\"\n", encoding="utf-8")
            targets, problems = self.module.load_targets(path)
            self.assertEqual(len(targets), 2, "duplicate target keys must not schedule extra probes")
            by_name = {target["name"]: target for target in targets}
            self.assertEqual(by_name["Alpha"]["url"], "https://example.net")
            self.assertEqual(by_name["Beta"]["ping"], "192.0.2.1")
            self.assertIsNone(by_name["Beta"]["url"])
            self.assertTrue(any("Broken" in problem for problem in problems))

    def test_missing_file_uses_defaults_with_problem_note(self):
        targets, problems = self.module.load_targets(None)
        names = [target["name"] for target in targets]
        self.assertIn("YouTubeWeb", names)
        self.assertIn("Quad9DNS9999", names)
        self.assertTrue(problems)

    def test_empty_file_uses_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text("", encoding="utf-8")
            targets, _ = self.module.load_targets(path)
            self.assertTrue(targets)

    def test_target_file_is_capped_and_ping_options_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text("\n".join(f'T{i} = "PING:example.org"' for i in range(100)))
            targets, problems = self.module.load_targets(path)
            self.assertEqual(len(targets), self.module.MAX_TARGETS)
            self.assertTrue(problems)
        with self.assertRaises(ValueError):
            self.module.parse_target_value("PING:--help")

    def test_untrusted_target_values_are_rejected_with_problem(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(
                "WithUser = \"https://user:pass@example.org\"\n"
                "Ftp = \"ftp://example.org\"\n"
                "BadPing = \"PING:1.1.1.1;rm\"\n"
                "Space = \"PING:1.1.1.1 1.1.1.2\"\n"
                "Weird = \"PING:ч1\"\n"
                "LongPing = \"PING:" + "a" * 300 + "\"\n"
                "LongUrl = \"https://" + "a" * 3000 + "\"\n", encoding="utf-8")
            targets, problems = self.module.load_targets(path)
            self.assertEqual(targets, [])
            self.assertEqual(len(problems), 7)


class PlanTests(unittest.TestCase):
    def test_public_suite_probe_pins_only_global_address_and_bypasses_proxy(self):
        module = load("src/lib/strategy_tester.py")
        argv = module.dpi_probe_plan("curl", "example.org", Path("payload"))[0][1]
        resolved = [(2, 1, 6, "", ("93.184.215.14", 443))]
        with mock.patch.object(module.socket, "getaddrinfo", return_value=resolved), \
                mock.patch.object(module, "default_execute", return_value=(0, "200 1 1 0.1", "")) as execute:
            module.public_suite_execute(argv, 5)
        sent = execute.call_args.args[0]
        self.assertIn("example.org:443:93.184.215.14", sent)
        self.assertIn("--resolve", sent)
        self.assertIn("--noproxy", sent)
        self.assertEqual(sent[-1], "https://example.org")

    def test_public_suite_probe_rejects_private_and_mixed_dns_answers(self):
        module = load("src/lib/strategy_tester.py")
        argv = module.dpi_probe_plan("curl", "example.org", Path("payload"))[0][1]
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"):
            with self.subTest(address=address), \
                    mock.patch.object(module.socket, "getaddrinfo", return_value=[
                        (2, 1, 6, "", ("93.184.215.14", 443)), (2, 1, 6, "", (address, 443))]), \
                    mock.patch.object(module, "default_execute") as execute:
                with self.assertRaisesRegex(ValueError, "публичн"):
                    module.public_suite_execute(argv, 5)
                execute.assert_not_called()

    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")

    def test_http_probe_plan_has_three_fixed_commands_without_tls_disable(self):
        plan = self.module.http_probe_plan("/usr/bin/curl", "https://example.org", timeout=5)
        self.assertEqual([label for label, _ in plan], ["HTTP", "TLS1.2", "TLS1.3"])
        for label, argv in plan:
            self.assertEqual(argv[0], "/usr/bin/curl")
            self.assertEqual(argv[1], "-q", "ignore ~/.curlrc, including insecure options")
            self.assertNotIn("-k", argv)
            self.assertNotIn("--insecure", argv)
            self.assertEqual(argv[-1], "https://example.org")
        tls_args = {label: tuple(argv) for label, argv in plan}
        self.assertIn("--http1.1", tls_args["HTTP"])
        self.assertIn("--tlsv1.2", tls_args["TLS1.2"])
        self.assertIn("--tlsv1.3", tls_args["TLS1.3"])
        self.assertIn("--tls-max", tls_args["TLS1.2"])
        self.assertNotIn("--tls-max", tls_args["HTTP"])

    def test_ping_probe_plan_is_fixed_argv(self):
        argv, timeout = self.module.ping_probe_plan("/usr/bin/ping", "1.1.1.1")
        self.assertEqual(argv, ["/usr/bin/ping", "-c", "3", "-w", "10", "1.1.1.1"])
        self.assertEqual(timeout, 15)

    def test_dpi_probe_plan_posts_range_for_three_labels(self):
        payload = Path("/tmp/opencode/payload.bin")
        plan = self.module.dpi_probe_plan("/usr/bin/curl", "example.org", payload,
                                          range_bytes=65536, timeout=5)
        self.assertEqual([label for label, _ in plan], ["HTTP", "TLS1.2", "TLS1.3"])
        for label, argv in plan:
            self.assertEqual(argv[1], "-q")
            self.assertIn("--data-binary", argv)
            self.assertIn("@/tmp/opencode/payload.bin", argv)
            self.assertIn("--range", argv)
            self.assertIn("0-65535", argv)
            self.assertIn("-X", argv)
            self.assertNotIn("-k", argv)
            self.assertEqual(argv[-1], "https://example.org")

    def test_dpi_suite_targets_validates_and_caps_entries(self):
        entries = [{"id": "a", "provider": "P", "country": "RU", "host": "example.org"},
                   {"id": "b", "provider": "P", "country": "RU", "host": "bad host"},
                   {"id": "c", "provider": "P", "country": "RU", "host": "not_a-host!"},
                   {"host": "example.net"},
                   {"id": "d", "provider": "P", "country": "RU", "host": "example.net"}]
        targets = self.module.dpi_suite_targets(entries)
        self.assertEqual([target["id"] for target in targets], ["a", "d"])

    def test_custom_host_overrides_suite_and_is_validated(self):
        custom = self.module.dpi_suite_targets([], custom_host="example.org")
        self.assertEqual(len(custom), 1)
        self.assertEqual(custom[0]["host"], "example.org")
        with self.assertRaises(ValueError):
            self.module.dpi_suite_targets([], custom_host="bad host")

    def test_suite_entries_are_capped(self):
        entries = [{"id": str(i), "provider": "P", "country": "RU", "host": f"h{i}.example.org"}
                   for i in range(200)]
        self.assertEqual(len(self.module.dpi_suite_targets(entries)),
                         self.module.MAX_TARGETS)


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")

    def test_success_and_code_are_recorded(self):
        result = self.module.classify_http("HTTP", 0, "200", "")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["code"], "200")

    def test_exit_zero_with_unparsable_output_is_still_ok(self):
        result = self.module.classify_http("TLS1.2", 0, "", "")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["code"], "NA")

    def test_dns_and_certificate_stderr_match_upstream_ssl_label(self):
        for stderr in ("curl: (6) Could not resolve host: example.org",
                       "SSL certificate problem: self-signed certificate",
                       "certificate verify failed", "unable to get local issuer certificate"):
            result = self.module.classify_http("HTTP", 6, "000", stderr)
            self.assertEqual(result["status"], "SSL", stderr)
            self.assertIn(result["reason"], ("dns", "certificate"))

    def test_exit_35_and_unsupported_patterns(self):
        result = self.module.classify_http("TLS1.3", 35, "000", "error:0A00010B:SSL")
        self.assertEqual(result["status"], "UNSUP")
        result = self.module.classify_http("TLS1.2", 4, "000", "protocol 'tlsv1.2' not supported")
        self.assertEqual(result["status"], "UNSUP")

    def test_other_failures_are_error(self):
        result = self.module.classify_http("HTTP", 28, "000", "Connection timed out")
        self.assertEqual(result["status"], "ERROR")

    def test_dns_hijack_wins_over_unsupported_like_upstream(self):
        result = self.module.classify_http("HTTP", 35, "000", "certificate verify failed")
        self.assertEqual(result["status"], "SSL")

    def test_ping_summary_parsing(self):
        output = "rtt min/avg/max/mdev = 10.1/20.5/30.2/1.0 ms"
        self.assertEqual(self.module.parse_ping_avg(output), 20.5)
        self.assertIsNone(self.module.parse_ping_avg("nothing here"))

    def test_ping_classification(self):
        ok = self.module.classify_ping("1.1.1.1", 0, "rtt min/avg/max/mdev = 1/2/3/0 ms")
        self.assertEqual(ok["status"], "OK")
        self.assertEqual(ok["avg_ms"], 2.0)
        lost = self.module.classify_ping("1.1.1.1", 1, "ping: sendmsg: Network is unreachable")
        self.assertEqual(lost["status"], "TIMEOUT")
        empty = self.module.classify_ping("1.1.1.1", 0, "no rtt line")
        self.assertEqual(empty["status"], "TIMEOUT")

    def test_dpi_classification(self):
        ok = self.module.classify_dpi(0, "200 65536 128 0.4", "", 5)
        self.assertEqual(ok["status"], "OK")
        self.assertEqual(ok["up_bytes"], 65536)
        self.assertEqual(ok["down_bytes"], 128)
        blocked = self.module.classify_dpi(28, "000 65536 0 5.0", "Operation timed out", 5)
        self.assertEqual(blocked["status"], "LIKELY_BLOCKED")
        partial = self.module.classify_dpi(28, "000 65536 10 5.0", "timed out", 5)
        self.assertEqual(partial["status"], "FAIL")
        unsupported = self.module.classify_dpi(35, "000", "not supported", 5)
        self.assertEqual(unsupported["status"], "UNSUPPORTED")
        fail = self.module.classify_dpi(28, "", "timed out", 5)
        self.assertEqual(fail["status"], "FAIL")
        zero_time_ok = self.module.classify_dpi(0, "", "", 5)
        self.assertEqual(zero_time_ok["status"], "OK")


class SessionTests(unittest.TestCase):
    def test_cancel_last_strategy_stops_remaining_probes_and_no_recommendation(self):
        module = load("src/lib/strategy_tester.py")
        cancel = threading.Event()
        execute = mock.Mock(side_effect=lambda argv, timeout: (cancel.set() or 0, "200", ""))
        report = module.TesterSession(
            strategies=[], targets=[{"name": "Web", "url": "https://example.org", "ping": "example.org"}],
            execute=execute, cancel_event=cancel, curl_path="curl", ping_path="ping").run()
        self.assertEqual(execute.call_count, 1)
        self.assertTrue(report["cancelled"])
        self.assertIsNone(report["best"])
        self.assertEqual([p["status"] for p in report["strategies"][0]["targets"][0]["probes"]],
                         ["OK", "CANCELLED", "CANCELLED"])

    def test_cancel_preserves_all_remaining_strategy_names(self):
        module = load("src/lib/strategy_tester.py")
        cancel = threading.Event()
        cancel.set()
        report = module.TesterSession(
            strategies=["a.bat", "b.bat", "c.bat"], targets=[], cancel_event=cancel).run()
        self.assertEqual([s["name"] for s in report["strategies"]], ["a.bat", "b.bat", "c.bat"])
        self.assertIsNone(report["best"])

    def test_dpi_preserves_target_metadata_and_measured_transfer_time(self):
        module = load("src/lib/strategy_tester.py")
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "data"
            payload.write_bytes(b"data")
            report = module.TesterSession(
                strategies=[], targets=[], test_type="dpi", payload_path=payload,
                dpi_targets=[{"id": "T1", "country": "RU", "provider": "P", "host": "example.org"}],
                execute=lambda argv, timeout: (0, "200 4 5 0.75", ""), curl_path="curl").run()
        target = report["strategies"][0]["targets"][0]
        self.assertEqual((target["id"], target["country"], target["provider"]), ("T1", "RU", "P"))
        self.assertEqual(target["probes"][0]["seconds"], 0.75)

    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")
        self.calls = []

    def runner(self):
        calls = self.calls

        class Runner:
            def snapshot(self):
                calls.append(("snapshot",))
                return {"profile": "general.bat"}

            def start(self, strategy):
                calls.append(("start", strategy))

            def stop(self):
                calls.append(("stop",))

            def restore(self, snapshot):
                calls.append(("restore", snapshot))

        return Runner()

    def fake_execute(self, exit_code=0, stdout="200", stderr=""):
        def execute(argv, timeout):
            self.calls.append(("exec", tuple(argv[:1]) + (argv[-1],) if argv else ()))
            return exit_code, stdout, stderr
        return execute

    def run_session(self, strategies=("a.bat", "b.bat"), runner=True, **kwargs):
        targets = [{"name": "Web", "url": "https://example.org", "ping": "example.org"},
                   {"name": "DNS", "url": None, "ping": "1.1.1.1"}]
        execute = kwargs.pop("execute", self.fake_execute())
        session = self.module.TesterSession(
            strategies=list(strategies), targets=targets, test_type="standard",
            runner=self.runner() if runner else None, execute=execute,
            sleep=lambda seconds: self.calls.append(("sleep", seconds)),
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0, **kwargs)
        return session.run()

    def test_strategy_lifecycle_calls_start_stop_once_and_restore(self):
        report = self.run_session()
        self.assertEqual([call for call in self.calls if call[0] == "start"],
                         [("start", "a.bat"), ("start", "b.bat")])
        self.assertEqual(self.calls.count(("stop",)), 2)
        self.assertEqual(self.calls.count(("snapshot",)), 1)
        restore = [call for call in self.calls if call[0] == "restore"]
        self.assertEqual(restore, [("restore", {"profile": "general.bat"})])
        self.assertIsNone(report["restore_error"])

    def test_baseline_without_runner_never_touches_runner_or_waits(self):
        report = self.run_session(strategies=("baseline",), runner=False)
        self.assertEqual([call[0] for call in self.calls if call[0] != "exec"], [])
        self.assertEqual(report["mode"], "baseline")
        self.assertEqual(len(report["strategies"][0]["targets"]), 2)

    def test_runner_failure_records_error_and_continues(self):
        calls = self.calls

        class FailingRunner:
            def snapshot(self):
                return {"profile": "x"}

            def start(self, strategy):
                if strategy == "a.bat":
                    raise RuntimeError("nfqws refused")
                calls.append(("start", strategy))

            def stop(self):
                calls.append(("stop",))

            def restore(self, snapshot):
                calls.append(("restore", snapshot))

        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat", "b.bat"], targets=targets, test_type="standard",
            runner=FailingRunner(), execute=self.fake_execute(),
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0)
        report = session.run()
        self.assertIn("nfqws refused", report["strategies"][0]["error"])
        self.assertIsNone(report["strategies"][1]["error"])
        self.assertEqual(len([call for call in self.calls if call[0] == "restore"]), 1)

    def test_restore_error_is_reported_not_hidden(self):
        calls = self.calls

        class BadRestore:
            def snapshot(self):
                return {}

            def start(self, strategy):
                calls.append(("start", strategy))

            def stop(self):
                calls.append(("stop",))

            def restore(self, snapshot):
                raise OSError("restore failed")

        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat"], targets=targets, test_type="standard",
            runner=BadRestore(), execute=self.fake_execute(),
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0)
        report = session.run()
        self.assertIn("restore failed", report["restore_error"])

    def test_cancel_skips_remaining_strategies_and_still_restores(self):
        calls = self.calls
        cancel = threading.Event()

        def execute(argv, timeout):
            cancel.set()
            return 0, "200", ""

        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat", "b.bat"], targets=targets, test_type="standard",
            runner=self.runner(), execute=execute, cancel_event=cancel,
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0)
        report = session.run()
        self.assertTrue(report["cancelled"])
        self.assertEqual(len(report["strategies"]), 2)
        self.assertEqual(report["strategies"][0]["targets"][0]["probes"][0]["status"], "OK")
        self.assertEqual(report["strategies"][1]["targets"][0]["probes"][0]["status"], "CANCELLED")
        self.assertEqual([call[0] for call in self.calls if call[0] == "restore"], ["restore"])

    def test_cancel_during_init_wait_interrupts_sleep(self):
        cancel = threading.Event()
        slept = []
        calls = self.calls

        class Runner:
            def snapshot(self):
                return {}

            def start(self, strategy):
                pass

            def stop(self):
                calls.append(("stop",))

            def restore(self, snapshot):
                calls.append(("restore", snapshot))

        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat"], targets=targets, test_type="standard",
            runner=Runner(), execute=self.fake_execute(),
            sleep=lambda seconds: slept.append(seconds) or cancel.set(),
            cancel_event=cancel, init_wait=8.0,
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping")
        session.run()
        self.assertEqual(slept, [0.5])

    def test_probe_counts_per_target_type(self):
        execute = self.fake_execute()
        self.run_session()
        exec_calls = [call for call in self.calls if call[0] == "exec"]
        # URL targets probe HTTP/TLS1.2/TLS1.3 and ping their host; ping-only
        # targets ping once. Two strategies -> 2 * (3 + 2).
        self.assertEqual(len(exec_calls), 2 * (3 + 2))

    def test_probe_failure_is_recorded_as_error_not_crash(self):
        def broken(argv, timeout):
            raise OSError("curl vanished")

        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat"], targets=targets, test_type="standard",
            runner=None, execute=broken,
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0)
        report = session.run()
        probes = report["strategies"][0]["targets"][0]["probes"]
        self.assertEqual({probe["status"] for probe in probes}, {"ERROR"})
        self.assertTrue(all("curl vanished" in probe["reason"] for probe in probes))

    def test_dpi_session_builds_payload_and_classifies(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "payload.bin"
            payload.write_bytes(b"\x00" * 65536)
            targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
            execute = mock.Mock(return_value=(0, "200 65536 10 0.5", ""))
            session = self.module.TesterSession(
                strategies=["a.bat"], targets=targets, test_type="dpi",
                runner=None, execute=execute, curl_path="/usr/bin/curl",
                ping_path="/usr/bin/ping", payload_path=payload, init_wait=0)
            report = session.run()
            probes = report["strategies"][0]["targets"][0]["probes"]
            self.assertEqual({probe["status"] for probe in probes}, {"OK"})
            self.assertEqual(execute.call_count, 3)
            argv = execute.call_args[0][0]
            self.assertIn("@/tmp/opencode/payload.bin".replace("/tmp/opencode", str(payload.parent)), argv)
            self.assertIn("0-65535", argv)
            self.assertIn("-X", argv)

    def test_dpi_requires_payload_file(self):
        targets = [{"name": "Web", "url": "https://example.org", "ping": None}]
        session = self.module.TesterSession(
            strategies=["a.bat"], targets=targets, test_type="dpi",
            runner=None, execute=self.fake_execute(),
            curl_path="/usr/bin/curl", ping_path="/usr/bin/ping", init_wait=0)
        with self.assertRaises(ValueError):
            session.run()

    def test_report_has_timestamps_and_mode(self):
        report = self.run_session(strategies=(), runner=False)
        self.assertEqual(report["mode"], "baseline")
        self.assertIn("started_at", report)
        self.assertIn("finished_at", report)
        datetime.datetime.fromisoformat(report["started_at"])
        self.assertEqual(report["strategies"][0]["name"], "baseline")


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")

    def strategy_report(self, name, statuses, ping=("OK", "OK")):
        probes = [{"label": label, "status": status, "code": "200", "reason": None,
                   "up_bytes": 0, "down_bytes": 0, "seconds": 0.1}
                  for label, status in zip(("HTTP", "TLS1.2", "TLS1.3"), statuses)]
        pings = [{"host": "1.1.1.1", "status": status, "avg_ms": 5.0} for status in ping]
        return {"name": name, "targets": [
            {"name": "Web", "url": "https://example.org", "ping": None, "probes": probes},
            {"name": "DNS", "url": None, "ping": "1.1.1.1", "probes": [], "pings": pings}],
            "error": None, "counts": {}}

    def test_standard_counts_and_best(self):
        report = {"type": "standard", "strategies": [
            self.strategy_report("a.bat", ("OK", "OK", "OK"), ping=("OK", "TIMEOUT")),
            self.strategy_report("b.bat", ("OK", "OK", "ERROR"), ping=("OK", "TIMEOUT")),
            self.strategy_report("c.bat", ("OK", "OK", "OK"), ping=("OK", "OK"))]}
        analytics = self.module.summarize(report)
        self.assertEqual(analytics["strategies"]["a.bat"]["OK"], 3)
        self.assertEqual(analytics["strategies"]["a.bat"]["PingFail"], 1)
        self.assertEqual(analytics["strategies"]["b.bat"]["ERROR"], 1)
        self.assertEqual(analytics["strategies"]["b.bat"]["PingFail"], 1)
        self.assertEqual(analytics["best"], "c.bat")

    def test_tie_break_prefers_ping_then_stable_first(self):
        report = {"type": "standard", "strategies": [
            self.strategy_report("b.bat", ("OK", "OK", "OK"), ping=("OK", "OK")),
            self.strategy_report("a.bat", ("OK", "OK", "OK"), ping=("OK", "TIMEOUT"))]}
        self.assertEqual(self.module.summarize(report)["best"], "b.bat")
        report["strategies"][0]["name"], report["strategies"][1]["name"] = "z.bat", "z.bat"
        self.assertEqual(self.module.summarize(report)["best"], "z.bat")

    def test_dpi_counts_blocked_and_best(self):
        def dpi_report(name, statuses):
            probes = [{"label": label, "status": status, "code": "200", "reason": None,
                       "up_bytes": 1, "down_bytes": 1, "seconds": 0.1}
                      for label, status in zip(("HTTP", "TLS1.2", "TLS1.3"), statuses)]
            return {"name": name, "targets": [
                {"name": "Web", "url": None, "ping": None, "probes": probes}],
                "error": None, "counts": {}}
        report = {"type": "dpi", "strategies": [
            dpi_report("a.bat", ("OK", "OK", "OK")),
            dpi_report("b.bat", ("OK", "LIKELY_BLOCKED", "OK"))]}
        analytics = self.module.summarize(report)
        self.assertEqual(analytics["strategies"]["b.bat"]["LIKELY_BLOCKED"], 1)
        self.assertEqual(analytics["best"], "a.bat")
        self.assertEqual(analytics["strategies"]["a.bat"]["LIKELY_BLOCKED"], 0)

    def test_empty_report_has_no_best(self):
        self.assertEqual(self.module.summarize({"type": "standard", "strategies": []})["best"], None)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")
        self.report = {
            "type": "standard", "mode": "strategies", "started_at": "2026-11-13T10:00:00+00:00",
            "finished_at": "2026-11-13T10:01:00+00:00", "cancelled": False,
            "restore_error": None, "warnings": [], "dpi_license": None, "dpi_targets": [],
            "strategies": [{
                "name": "general.bat", "error": None, "seconds": 2.5,
                "targets": [{
                    "name": "Web", "url": "https://example.org", "ping": "example.org",
                    "probes": [{"label": "HTTP", "status": "OK", "code": "200", "reason": None,
                                "up_bytes": 0, "down_bytes": 0, "seconds": 0.1},
                               {"label": "TLS1.2", "status": "UNSUP", "code": "000",
                                "reason": "unsupported", "up_bytes": 0, "down_bytes": 0, "seconds": 0.1}],
                    "pings": [{"host": "example.org", "status": "OK", "avg_ms": 12.0}]}],
                "counts": {"OK": 1, "SSL": 0, "ERROR": 0, "UNSUP": 1, "PingOK": 1, "PingFail": 0}}],
            "best": "general.bat",
            "analytics": {"strategies": {"general.bat": {"OK": 1, "SSL": 0, "ERROR": 0, "UNSUP": 1,
                                                         "PingOK": 1, "PingFail": 0}},
                          "best": "general.bat"}}

    def test_text_export_matches_upstream_shape_and_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "results.txt"
            self.module.export_text(self.report, target)
            info = target.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_mode & 0o777, 0o600)
            text = target.read_text(encoding="utf-8")
            self.assertIn("Config: general.bat (Type: standard)", text)
            self.assertIn("Web : HTTP:OK TLS1.2:UNSUP | Ping: 12.0 ms", text)
            self.assertIn("HTTP OK: 1", text)
            self.assertIn("Best strategy: general.bat", text)

    def test_dpi_text_export_includes_targets_and_license(self):
        self.report.update(type="dpi", dpi_license="DPI suite: dpi-checkers (Apache-2.0)",
                           dpi_targets=[{"id": "T1", "provider": "P", "country": "RU", "host": "h"}])
        self.report["strategies"][0]["targets"][0] = {
            "id": "T1", "provider": "P", "country": "RU", "host": "h",
            "probes": [{"label": "HTTP", "status": "OK", "code": "200", "reason": None,
                        "up_bytes": 65536, "down_bytes": 128, "seconds": 0.4}], "pings": []}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "results.txt"
            self.module.export_text(self.report, target)
            text = target.read_text(encoding="utf-8")
            self.assertIn("Target: [RU] T1 (P)", text)
            self.assertIn("up=64.0 KB  down=0.1 KB", text)
            self.assertIn("Apache-2.0", text)

    def test_json_export_contains_report(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "results.json"
            self.module.export_json(self.report, target)
            data = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(data["analytics"]["best"], "general.bat")
            self.assertEqual(data["strategies"][0]["name"], "general.bat")

    def test_export_refuses_directory_symlink_and_missing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.module.export_text(None, Path(directory) / "out.txt")
            directory_target = Path(directory) / "folder"
            directory_target.mkdir()
            with self.assertRaises(ValueError):
                self.module.export_text(self.report, directory_target)
            link = Path(directory) / "link.txt"
            os.symlink(directory_target / "unused", link)
            with self.assertRaises(OSError):
                self.module.export_text(self.report, link)

    def test_failed_export_keeps_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "results.txt"
            self.module.export_text(self.report, target)
            original = target.read_bytes()
            with mock.patch.object(self.module, "os") as broken_os:
                broken_os.replace.side_effect = OSError("disk full")
                with self.assertRaises(OSError):
                    self.module.export_text(self.report, target)
            self.assertEqual(target.read_bytes(), original)


class BackendTests(unittest.TestCase):
    def test_strategies_require_capability(self):
        backend = self.real_backend()
        with mock.patch.object(backend, "tester_supported", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Нужен установленный доверенный помощник"):
                backend.tester_run("standard", ["general.bat"], execute=mock.Mock(return_value=(0, "200", "")),
                                   curl_path="curl", ping_path="ping")

    def test_strategies_connect_streaming_runner_when_supported(self):
        backend = self.real_backend()
        fake_runner = mock.Mock()
        fake_runner.snapshot.return_value = {}
        fake_runner.start.return_value = None
        fake_runner.stop.return_value = None
        fake_runner.restore.return_value = None

        with mock.patch.object(backend, "tester_supported", return_value=True), \
                mock.patch.object(backend, "trusted_helper", return_value=Path("/opt/zapret/privileged.py")), \
                mock.patch.object(backend, "load_config", return_value={"sha256": "b" * 64}), \
                mock.patch.object(self.gui, "load_strategy_test_client_module") as mock_client:
            mock_client.return_value.StreamingTesterRunner.return_value = fake_runner
            report = backend.tester_run(
                "standard", ["general.bat"],
                targets=[{"name": "Web", "url": "https://example.org", "ping": "example.org"}],
                execute=mock.Mock(return_value=(0, "HTTP/1.1 200 OK\r\n\r\n", "")),
                curl_path="curl", ping_path="ping")
            self.assertEqual(report["mode"], "strategies")
            fake_runner.snapshot.assert_called_once()
            fake_runner.start.assert_called_once_with("general.bat")
            fake_runner.stop.assert_called_once()
            fake_runner.restore.assert_called_once()

    def test_strategies_fail_if_config_sha256_missing(self):
        backend = self.real_backend()
        with mock.patch.object(backend, "tester_supported", return_value=True), \
                mock.patch.object(backend, "load_config", return_value={"sha256": None}):
            with self.assertRaisesRegex(RuntimeError, "ревизию конфигурации"):
                backend.tester_run("standard", ["general.bat"], execute=mock.Mock(return_value=(0, "200", "")),
                                   curl_path="curl", ping_path="ping")

    def test_custom_dpi_host_does_not_fetch_public_suite(self):
        backend = self.real_backend()
        with mock.patch.object(self.gui, "load_strategy_tester_module", return_value=self.module), \
                mock.patch.object(self.module, "fetch_dpi_suite", side_effect=AssertionError("network")):
            report = backend.tester_run(
                "dpi", [], targets=[{"name": "unused"}], custom_dpi_host="example.org",
                execute=lambda argv, timeout: (0, "200 1 1 0.1", ""), curl_path="curl", ping_path="ping")
        self.assertEqual(report["dpi_targets"][0]["host"], "example.org")

    def setUp(self):
        self.module = load("src/lib/strategy_tester.py")
        self.gui = load("src/gui/backend.py")

    def real_backend(self):
        holder = tempfile.TemporaryDirectory(prefix="tester-backend-")
        self.addCleanup(holder.cleanup)
        base = Path(holder.name)
        return self.gui.Backend(base, current=base / "missing")

    def test_demo_backend_runs_without_subprocesses(self):
        backend = self.gui.DemoBackend()
        with mock.patch("subprocess.run", side_effect=AssertionError("real command")):
            report = backend.tester_run("standard", ["demo_a.bat", "demo_b.bat"])
        self.assertEqual(report["mode"], "strategies")
        self.assertEqual([entry["name"] for entry in report["strategies"]], ["demo_a.bat", "demo_b.bat"])
        self.assertEqual(self.module.summarize(report)["best"], "demo_b.bat")
        self.assertTrue(backend.tester_last_report)
        self.assertIn("demo", backend.snapshot()["tester_supported"])

    def test_demo_baseline_and_cancel(self):
        backend = self.gui.DemoBackend()
        cancel = threading.Event()
        cancel.set()
        report = backend.tester_run("standard", [], cancel_event=cancel)
        self.assertTrue(report["cancelled"])
        self.assertEqual(report["mode"], "baseline")

    def test_real_backend_refuses_strategies_without_helper_capability(self):
        backend = self.real_backend()
        with mock.patch.object(self.gui.Backend, "tester_supported", lambda self: False):
            with self.assertRaisesRegex(RuntimeError, "помощник"):
                backend.tester_run("standard", ["general.bat"])

    def test_real_backend_baseline_is_unprivileged_and_uses_detected_tools(self):
        backend = self.real_backend()
        targets = [{"name": "Local", "url": "http://127.0.0.1:9/", "ping": None}]
        execute = mock.Mock(return_value=(0, "200", ""))
        with mock.patch.object(self.gui, "load_strategy_tester_module", return_value=self.module), \
                mock.patch.object(self.module.TesterSession, "run", return_value={"ok": True}):
            report = backend.tester_run("standard", [], targets=targets, execute=execute,
                                        curl_path="/usr/bin/curl", ping_path="/usr/bin/ping")
            self.assertEqual(report, {"ok": True, "warnings": []})

    def test_missing_probe_tools_are_reported(self):
        backend = self.real_backend()
        with mock.patch.object(backend, "locate_probe_tools", side_effect=RuntimeError("curl не найден")):
            with self.assertRaisesRegex(RuntimeError, "curl не найден"):
                backend.tester_run("standard", [])


if __name__ == "__main__":
    unittest.main()
