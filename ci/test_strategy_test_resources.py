"""Queue selection: fake nft/legacy proc data, no firewall or root operations."""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT / "src/lib/strategy_test_resources.py"
    spec = importlib.util.spec_from_file_location("tester_resources_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QueueParsingTests(unittest.TestCase):
    def setUp(self):
        self.module = load()

    def nft(self, num):
        return {"nftables": [{"rule": {"expr": [{"queue": {"num": num, "flags": ["bypass"]}}]}}]}

    def test_nft_literal_range_and_anonymous_set(self):
        self.assertEqual(self.module.nft_queues(self.nft(40000)), {40000})
        self.assertEqual(self.module.nft_queues(self.nft({"range": [40000, 40002]})), {40000, 40001, 40002})
        self.assertEqual(self.module.nft_queues(self.nft({"set": [40000, {"range": [40002, 40003]}]})),
                         {40000, 40002, 40003})

    def test_nft_dynamic_unknown_or_invalid_queue_refuses_selection(self):
        for value in ({"map": {}}, {"numgen": {}}, "40000", True, -1, 65536, {"range": [5, 2]},
                      {"set": []}, {"range": [1]}, {"range": [1, True]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.nft_queues(self.nft(value))

    def test_unknown_nft_compat_nfqueue_target_is_not_assumed_free(self):
        data = {"nftables": [{"rule": {"expr": [{"xt": {"type": "target", "name": "NFQUEUE"}}]}}]}
        with self.assertRaises(ValueError):
            self.module.nft_queues(data)

    def test_invalid_nft_document_is_not_treated_as_empty(self):
        for data in ({}, {"nftables": {}}, {"nftables": [None]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.module.nft_queues(data)

    def test_legacy_num_balance_default_and_quoted_comment(self):
        text = ('*mangle\n-A OUTPUT -j NFQUEUE --queue-num 40000 --queue-bypass\n'
                '-A OUTPUT -j NFQUEUE --queue-balance 40001:40003\n'
                '-A OUTPUT -j NFQUEUE\n'
                '-A OTHER -m comment --comment "--queue-num 49999" -j ACCEPT\nCOMMIT\n')
        self.assertEqual(self.module.legacy_queues(text), {0, 40000, 40001, 40002, 40003})

    def test_legacy_malformed_queue_options_fail_closed(self):
        for args in ("--queue-num", "--queue-num x", "--queue-num 65536", "--queue-balance 10:5",
                     "--queue-num 1 --queue-num 2", "--queue-num 1 --queue-balance 2:3"):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.module.legacy_queues("-A OUTPUT -j NFQUEUE " + args)

    def test_bound_queue_file_is_validated(self):
        self.assertEqual(self.module.binding_queues("40000 123 0 2 65535 0 0 0 1\n"), {40000})
        for text in ("bad data", "65536 10", "40000", "-1 10"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.module.binding_queues(text)


class ResourceObservationTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.files = {
            "/proc/net/netfilter/nfnetlink_queue": "40000 100 0\n",
            "/proc/net/ip_tables_names": "",
            "/proc/net/ip6_tables_names": "",
        }
        self.nft = {"nftables": [{"rule": {"expr": [{"queue": {"num": 40001}}]}}]}
        self.legacy4 = "-A OUTPUT -j NFQUEUE --queue-num 40002\n"
        self.legacy6 = "-A OUTPUT -j NFQUEUE --queue-balance 40003:40004\n"
        self.calls = []

        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            output = json.dumps(self.nft) if argv[0].endswith("/nft") else (
                self.legacy6 if "ip6tables" in argv[0] else self.legacy4)
            return subprocess.CompletedProcess(argv, 0, output, "")

        self.run = mock.Mock(side_effect=run)

    def observe(self):
        return self.module.observe(run=self.run, read=lambda path: self.files.get(str(path)))

    def test_reads_nft_and_bindings_without_firewall_changes(self):
        self.assertEqual(self.observe(), {40000, 40001})
        self.assertEqual([argv for argv, _ in self.calls], [["/usr/sbin/nft", "-j", "list", "ruleset"]])
        self.assertEqual(self.calls[0][1]["timeout"], 12)
        self.assertFalse(self.calls[0][1].get("shell", False))

    def test_loaded_ipv4_and_ipv6_legacy_tables_are_both_inspected(self):
        self.files["/proc/net/ip_tables_names"] = "filter\nmangle\n"
        self.files["/proc/net/ip6_tables_names"] = "filter\n"
        self.assertEqual(self.observe(), {40000, 40001, 40002, 40003, 40004})
        self.assertEqual([argv[0] for argv, _ in self.calls],
                         ["/usr/sbin/nft", "/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save"])

    def test_unreadable_binding_or_legacy_state_is_not_treated_as_empty(self):
        for path in self.files:
            def read(value):
                if str(value) == path:
                    raise PermissionError("hidden")
                return self.files.get(str(value))
            with self.subTest(path=path), self.assertRaises(PermissionError):
                self.module.observe(run=self.run, read=read)

    def test_failed_nft_or_missing_required_legacy_inspector_refuses(self):
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess([], 1, "", "not permitted")
        with self.assertRaises(ValueError):
            self.observe()
        self.files["/proc/net/ip_tables_names"] = "mangle\n"
        self.run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"nftables":[]}', ""), FileNotFoundError("legacy-save")]
        with self.assertRaises(FileNotFoundError):
            self.observe()

    def test_unloaded_proc_tables_are_allowed_but_corrupt_names_are_not(self):
        self.files.clear()
        self.assertEqual(self.observe(), {40001})
        self.files["/proc/net/ip_tables_names"] = "mangle; rm\n"
        with self.assertRaises(ValueError):
            self.observe()

    def test_queue_selection_excludes_all_observed_and_original_service_queue(self):
        occupied = {220, 40000, 40001, 40002}
        self.assertEqual(self.module.select_queue(occupied, candidates=[220, 40000, 40001, 40003]), 40003)
        with self.assertRaises(ValueError):
            self.module.select_queue(occupied, candidates=[220, 40001])

    def test_invalid_or_unbounded_candidate_input_is_rejected(self):
        for value in ([True], [-1], [65536], ["40000"], list(range(65536))):
            with self.subTest(value=value[:3]), self.assertRaises(ValueError):
                self.module.select_queue(set(), candidates=value)


if __name__ == "__main__":
    unittest.main()
