"""Tester service transaction: fake proc/systemd/nft, never host service calls."""

import contextlib
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT / "src/lib/strategy_test_service.py"
    spec = importlib.util.spec_from_file_location("test_service_transaction", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nft_table(*, exclude_loopback=False):
    entries = [{"table": {"family": "inet", "name": "zapretunix", "handle": 1}}]
    for name, hook, priority in (("post", "postrouting", -150), ("pre", "prerouting", 0)):
        entries.append({"chain": {"family": "inet", "table": "zapretunix", "name": name,
                                 "type": "filter", "hook": hook, "prio": priority, "policy": "accept"}})
    for chain, proto, field, direction, limit in (("post", "tcp", "dport", "original", 6),
                                                ("post", "udp", "dport", "original", 6),
                                                ("pre", "tcp", "sport", "reply", 3)):
        matches = []
        if exclude_loopback:
            matches.append({"match": {"op": "!=", "right": "lo",
                                      "left": {"meta": {"key": "oifname" if chain == "post" else "iifname"}}}})
        if chain == "post":
            matches.append({"match": {"op": "==", "left": {"&": [{"meta": {"key": "mark"}}, 1073741824]}, "right": 0}})
        matches += [
            {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": field}}, "right": 443}},
            {"match": {"op": "in", "left": {"ct": {"key": "packets", "dir": direction}}, "right": {"range": [1, limit]}}},
            {"queue": {"num": 220, "flags": ["bypass"]}}]
        entries.append({"rule": {"family": "inet", "table": "zapretunix", "chain": chain,
                                "comment": "Added by zapret script", "expr": matches}})
    return {"nftables": entries}


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name)
        self.release = Path("/opt/zapret-discord-youtube/releases") / ("a" * 32)
        self.plan = {"tcp_ports": "443", "udp_ports": "443"}

    def process(self, pid, group="/system.slice/zapret_discord_youtube.service", queue=220):
        path = self.proc / str(pid)
        path.mkdir()
        (path / "exe").symlink_to(self.release / "nfqws")
        (path / "cgroup").write_text("0::" + group + "\n")
        (path / "cmdline").write_bytes(b"nfqws\0--qnum=" + str(queue).encode() + b"\0")
        (path / "stat").write_text(str(pid) + " (nfqws tricky) " + " ".join(["S"] + ["0"] * 18 + ["123456", "0"]))
        return path

    def test_engine_identity_includes_start_time_cgroup_and_queue(self):
        self.process(100)
        engines = self.module.engine_processes(self.release, self.proc)
        self.assertEqual(engines, [{"pid": 100, "starttime": "123456", "group": "/system.slice/zapret_discord_youtube.service", "queue": 220}])

    def test_same_binary_outside_service_cgroup_is_detected(self):
        self.process(100)
        self.process(101, "/user.slice/manual")
        engines = self.module.engine_processes(self.release, self.proc)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.module.validate_engines(engines, active=True, group="/system.slice/zapret_discord_youtube.service")

    def test_inactive_service_cannot_adopt_existing_same_binary_process(self):
        self.process(101, "/user.slice/manual")
        with self.assertRaises(ValueError):
            self.module.validate_engines(self.module.engine_processes(self.release, self.proc), active=False, group="")

    def test_deleted_binary_or_ambiguous_queue_is_refused(self):
        path = self.process(100)
        (path / "cmdline").write_bytes(b"nfqws\0--qnum=220\0--qnum=40000\0")
        with self.assertRaises(ValueError):
            self.module.engine_processes(self.release, self.proc)
        (path / "exe").unlink()
        (path / "exe").symlink_to(str(self.release / "nfqws") + " (deleted)")
        with self.assertRaises(ValueError):
            self.module.engine_processes(self.release, self.proc)

    def test_known_table_is_verified_against_capture_plan(self):
        fingerprint = self.module.inspect_table(nft_table(), self.plan, "any", active=True)
        self.assertTrue(fingerprint)
        self.assertIsNone(self.module.inspect_table({"nftables": []}, self.plan, "any", active=False))

    def test_accepts_exact_loopback_exclusion_on_all_any_rules(self):
        self.assertTrue(self.module.inspect_table(nft_table(exclude_loopback=True), self.plan, "any", active=True))

    def test_does_not_adopt_partial_or_altered_loopback_exclusions(self):
        for mutation in ("missing", "interface", "direction", "operator", "duplicate"):
            data = nft_table(exclude_loopback=True)
            expr = data["nftables"][-1]["rule"]["expr"]
            if mutation == "missing":
                del expr[0]
            elif mutation == "interface":
                expr[0]["match"]["right"] = "eth0"
            elif mutation == "direction":
                expr[0]["match"]["left"]["meta"]["key"] = "oifname"
            elif mutation == "operator":
                expr[0]["match"]["op"] = "=="
            else:
                expr.insert(0, copy.deepcopy(expr[0]))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.module.inspect_table(data, self.plan, "any", active=True)

    def test_nft_1_0_9_single_flag_string_has_same_semantics_as_list(self):
        data = nft_table()
        for entry in data["nftables"]:
            if "rule" in entry:
                entry["rule"]["expr"][-1]["queue"]["flags"] = "bypass"
        self.assertTrue(self.module.inspect_table(data, self.plan, "any", active=True))
        data["nftables"][-1]["rule"]["expr"][-1]["queue"]["flags"] = ["bypass", "fanout"]
        with self.assertRaises(ValueError):
            self.module.inspect_table(data, self.plan, "any", active=True)

    def test_foreign_or_mutated_rule_never_grants_deletion_permission(self):
        for mutation in ("comment", "queue", "ports", "extra", "hook"):
            data = nft_table()
            rule = data["nftables"][-1]["rule"]
            if mutation == "comment":
                rule["comment"] = "external rule"
            elif mutation == "queue":
                rule["expr"][-1]["queue"]["num"] = 40000
            elif mutation == "ports":
                rule["expr"][0]["match"]["right"] = 8443
            elif mutation == "extra":
                rule["expr"].insert(0, {"counter": {}})
            else:
                data["nftables"][1]["chain"]["hook"] = "forward"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.module.inspect_table(data, self.plan, "any", active=True)

    def test_inactive_or_missing_app_table_mismatch_is_refused(self):
        with self.assertRaises(ValueError):
            self.module.inspect_table(nft_table(), self.plan, "any", active=False)
        with self.assertRaises(ValueError):
            self.module.inspect_table({"nftables": []}, self.plan, "any", active=True)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.calls = []
        self.state = {"active": True, "autostart": "enabled", "identity": 100}
        self.stamp = "unchanged"
        self.prepared = {"release": Path("/installed"), "plans": {"general.bat": {}}}
        owner = self

        class Installer:
            @contextlib.contextmanager
            def operation(self):
                owner.calls.append("lock")
                try:
                    yield
                finally:
                    owner.calls.append("unlock")

        class Guard:
            def stamp(self, prepared):
                return owner.stamp

            def capture(self, prepared):
                return copy.deepcopy(owner.state)

            def change(self, action):
                owner.calls.append(action)
                owner.state["active"] = action == "start"
                owner.state["identity"] += 1

        self.guard = Guard()
        self.child = mock.Mock(created=False, process=None, queue=40000)
        self.child.resources.return_value = set()
        self.runtime = self.module.InstalledSessionRuntime(
            Installer(), guard=self.guard, prepare=lambda installer, request: self.prepared,
            allocate=lambda prepared: self.child)

    def snapshot(self):
        return self.runtime.snapshot({"strategies": ["general.bat"], "expected_sha256": "a" * 64})

    def test_active_service_is_stopped_then_restored_without_config_writes(self):
        with self.runtime.operation():
            snapshot = self.snapshot()
            self.runtime.enter(snapshot)
            self.runtime.start("general.bat")
            self.runtime.stop()
            self.runtime.restore(snapshot)
        self.assertEqual(self.calls, ["lock", "stop", "start", "unlock"])
        self.assertTrue(self.state["active"])
        self.assertEqual(self.state["autostart"], "enabled")
        self.child.start.assert_called_once_with("general.bat")

    def test_inactive_service_is_not_started_by_restore(self):
        self.state["active"] = False
        snapshot = self.snapshot()
        self.runtime.enter(snapshot)
        self.runtime.restore(snapshot)
        self.assertEqual(self.calls, [])

    def test_drift_before_enter_does_not_stop_or_restart_service(self):
        snapshot = self.snapshot()
        self.stamp = "externally changed"
        with self.assertRaisesRegex(ValueError, "changed"):
            self.runtime.enter(snapshot)
        with self.assertRaises(ValueError):
            self.runtime.restore(snapshot)
        self.assertEqual(self.calls, [])

    def test_manual_restart_before_enter_is_not_overwritten(self):
        snapshot = self.snapshot()
        self.state["identity"] = 200
        with self.assertRaises(ValueError):
            self.runtime.enter(snapshot)
        self.assertEqual(self.calls, [])

    def test_queue_conflict_before_enter_leaves_original_service_running(self):
        snapshot = self.snapshot()
        self.child.resources.return_value = {40000}
        with self.assertRaisesRegex(ValueError, "queue"):
            self.runtime.enter(snapshot)
        self.assertEqual(self.calls, [])

    def test_partial_stop_failure_can_restore_if_verified_inactive(self):
        snapshot = self.snapshot()
        original = self.guard.change
        def stop_then_fail(action):
            original(action)
            if action == "stop":
                raise RuntimeError("stop timed out")
        self.guard.change = stop_then_fail
        with self.assertRaises(RuntimeError):
            self.runtime.enter(snapshot)
        self.runtime.restore(snapshot)
        self.assertEqual(self.calls, ["stop", "start"])

    def test_drift_after_stop_blocks_restart_but_cleans_up_owned_child(self):
        snapshot = self.snapshot()
        self.runtime.enter(snapshot)
        self.stamp = "externally changed"
        with self.assertRaises(ValueError):
            self.runtime.restore(snapshot)
        self.child.stop.assert_called()
        self.assertEqual(self.calls, ["stop"])

    def test_failed_child_cleanup_blocks_original_start(self):
        snapshot = self.snapshot()
        self.runtime.enter(snapshot)
        self.child.stop.side_effect = RuntimeError("ownership unknown")
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            self.runtime.restore(snapshot)
        self.assertEqual(self.calls, ["stop"])

    def test_external_service_start_is_not_stopped_or_restarted_on_restore(self):
        snapshot = self.snapshot()
        self.runtime.enter(snapshot)
        self.state["active"] = True
        with self.assertRaises(ValueError):
            self.runtime.restore(snapshot)
        self.assertEqual(self.calls, ["stop"])

    def test_restart_failure_is_reported_and_not_retried_blindly(self):
        snapshot = self.snapshot()
        self.runtime.enter(snapshot)
        self.guard.change = mock.Mock(side_effect=RuntimeError("start failed"))
        with self.assertRaisesRegex(RuntimeError, "start failed"):
            self.runtime.restore(snapshot)
        self.guard.change.assert_called_once_with("start")

    def test_unknown_snapshot_or_unapproved_profile_is_refused(self):
        snapshot = self.snapshot()
        with self.assertRaises(ValueError):
            self.runtime.enter(dict(snapshot))
        self.runtime.enter(snapshot)
        with self.assertRaises(ValueError):
            self.runtime.start("unknown.bat")
        self.child.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
