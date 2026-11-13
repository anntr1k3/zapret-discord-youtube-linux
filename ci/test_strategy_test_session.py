"""Future installed-helper session protocol: fake runtime and no root/network."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT / "src/lib/strategy_test_session.py"
    spec = importlib.util.spec_from_file_location("test_session_protocol", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SessionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.calls = []
        self.responses = []
        self.request = {"strategies": ["general.bat", "general_alt12.bat"], "expected_sha256": "a" * 64}
        self.commands = []
        owner = self

        class Runtime:
            @contextlib.contextmanager
            def operation(self):
                owner.calls.append("lock")
                try:
                    yield
                finally:
                    owner.calls.append("unlock")

            def snapshot(self, request):
                owner.calls.append("snapshot")
                return {"active": True, "revision": request["expected_sha256"]}

            def enter(self, snapshot):
                owner.calls.append("enter")

            def start(self, name):
                owner.calls.append(("start", name))

            def stop(self):
                owner.calls.append("stop")

            def restore(self, snapshot):
                owner.calls.append(("restore", snapshot))

        self.runtime = Runtime()

    def receive(self, timeout):
        self.assertGreater(timeout, 0)
        return self.commands.pop(0) if self.commands else None

    def run_session(self, send=None, receive=None, **kwargs):
        return self.module.serve(self.runtime, self.request, receive or self.receive,
                                 send or self.responses.append, **kwargs)

    def restores(self):
        return [call for call in self.calls if isinstance(call, tuple) and call[0] == "restore"]

    def test_normal_lifecycle_restores_once_under_lock(self):
        self.commands = [{"command": "start", "strategy": "general.bat"},
                         {"command": "stop"}, {"command": "restore"}]
        result = self.run_session()
        self.assertEqual(self.calls[:4], ["lock", "snapshot", "enter", ("start", "general.bat")])
        self.assertEqual(len(self.restores()), 1)
        self.assertEqual(self.calls[-1], "unlock")
        self.assertEqual(result["reason"], "restore")
        self.assertEqual([response["event"] for response in self.responses], ["ready", "started", "stopped", "restored"])

    def test_eof_with_running_strategy_stops_before_restore(self):
        self.commands = [{"command": "start", "strategy": "general.bat"}]
        result = self.run_session()
        self.assertEqual(result["reason"], "eof")
        self.assertEqual(self.calls[-3], "stop")
        self.assertEqual(len(self.restores()), 1)

    def test_idle_timeout_restores_and_is_reported(self):
        def expired(timeout):
            raise TimeoutError("idle")
        result = self.run_session(receive=expired)
        self.assertEqual(result["reason"], "error")
        self.assertIn("idle", result["error"])
        self.assertEqual(len(self.restores()), 1)

    def test_broken_output_cannot_skip_restoration(self):
        def broken(response):
            raise BrokenPipeError("GUI closed")
        result = self.run_session(send=broken)
        self.assertIn("GUI closed", result["error"])
        self.assertEqual(len(self.restores()), 1)

    def test_partial_enter_failure_still_restores(self):
        def broken(snapshot):
            raise RuntimeError("stop service failed halfway")
        self.runtime.enter = broken
        result = self.run_session()
        self.assertIn("halfway", result["error"])
        self.assertEqual(len(self.restores()), 1)

    def test_snapshot_failure_does_not_restore_unknown_state(self):
        def broken(request):
            raise ValueError("stale config")
        self.runtime.snapshot = broken
        result = self.run_session()
        self.assertIn("stale config", result["error"])
        self.assertNotIn("enter", self.calls)
        self.assertFalse(self.restores())

    def test_interrupt_during_start_still_restores_before_propagating(self):
        def interrupted(name):
            raise KeyboardInterrupt()
        self.runtime.start = interrupted
        self.commands = [{"command": "start", "strategy": "general.bat"}]
        with self.assertRaises(KeyboardInterrupt):
            self.run_session()
        self.assertEqual(self.calls[-3], "stop")
        self.assertEqual(len(self.restores()), 1)
        self.assertEqual(self.calls[-1], "unlock")
        self.assertFalse(self.responses[-1]["ok"])

    def test_busy_operation_never_snapshots_or_changes_runtime(self):
        @contextlib.contextmanager
        def busy():
            raise ValueError("another operation holds lock")
            yield
        self.runtime.operation = busy
        with self.assertRaisesRegex(ValueError, "holds lock"):
            self.run_session()
        self.assertEqual(self.calls, [])

    def test_partial_start_failure_cleans_up_before_restore(self):
        def broken(name):
            self.calls.append("partial start")
            raise RuntimeError("nfqws failed")
        self.runtime.start = broken
        self.commands = [{"command": "start", "strategy": "general.bat"}]
        result = self.run_session()
        self.assertIn("nfqws failed", result["error"])
        self.assertIn("stop", self.calls)
        self.assertEqual(len(self.restores()), 1)

    def test_restore_failure_is_not_success(self):
        def broken(snapshot):
            raise RuntimeError("original service refused")
        self.runtime.restore = broken
        result = self.run_session()
        self.assertFalse(result["ok"])
        self.assertIn("original service refused", result["restore_error"])
        self.assertFalse(self.responses[-1]["ok"])

    def test_stop_failure_is_reported_even_when_restore_returns(self):
        def broken():
            raise RuntimeError("test cleanup failed")
        self.runtime.stop = broken
        self.commands = [{"command": "start", "strategy": "general.bat"}]
        result = self.run_session()
        self.assertFalse(result["ok"])
        self.assertIn("test cleanup failed", result["cleanup_error"])
        self.assertEqual(len(self.restores()), 1)

    def test_total_deadline_cannot_be_extended_by_commands(self):
        ticks = iter([0, 0, 4000])
        self.commands = [{"command": "stop"}]
        result = self.run_session(clock=lambda: next(ticks))
        self.assertFalse(result["ok"])
        self.assertIn("deadline", result["error"])
        self.assertEqual(len(self.restores()), 1)

    def test_unknown_and_out_of_order_commands_close_session(self):
        for commands in ([{"command": "exec", "argv": ["id"]}],
                         [{"command": "start", "strategy": "not-selected.bat"}],
                         [{"command": "start", "strategy": "general.bat"},
                          {"command": "start", "strategy": "general_alt12.bat"}],
                         [{"command": "stop", "path": "/etc/hosts"}]):
            with self.subTest(commands=commands):
                self.setUp()
                self.commands = commands
                result = self.run_session()
                self.assertFalse(result["ok"])
                self.assertEqual(len(self.restores()), 1)

    def test_invalid_begin_is_rejected_before_lock(self):
        for request in ({}, {**self.request, "path": "/tmp/config"},
                        {**self.request, "expected_sha256": "x"},
                        {**self.request, "strategies": []},
                        {**self.request, "strategies": ["../evil.bat"]},
                        {**self.request, "strategies": ["service.bat"]},
                        {**self.request, "strategies": ["general.bat"] * 2},
                        {**self.request, "strategies": [f"s{i}.bat" for i in range(65)]}):
            with self.subTest(request=request):
                self.calls.clear()
                self.request = request
                with self.assertRaises(ValueError):
                    self.run_session()
                self.assertEqual(self.calls, [])


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.input_read, self.input_write = os.pipe()
        self.output_read, self.output_write = os.pipe()
        for fd in (self.input_read, self.input_write, self.output_read, self.output_write):
            self.addCleanup(os.close, fd)
        self.channel = self.module.MessageChannel(self.input_read, self.output_write)

    def test_two_commands_can_share_one_write(self):
        os.write(self.input_write, b'{"command":"stop"}\n{"command":"restore"}\n')
        self.assertEqual(self.channel.receive(0.1), {"command": "stop"})
        self.assertEqual(self.channel.receive(0.1), {"command": "restore"})

    def test_idle_input_times_out(self):
        with self.assertRaises(TimeoutError):
            self.channel.receive(0.01)

    def test_clean_eof_and_truncated_eof_are_distinct(self):
        for data in (b"", b'{"command":'):
            with self.subTest(data=data):
                read_fd, write_fd = os.pipe()
                self.addCleanup(os.close, read_fd)
                channel = self.module.MessageChannel(read_fd, self.output_write)
                if data:
                    os.write(write_fd, data)
                os.close(write_fd)
                if data:
                    with self.assertRaisesRegex(ValueError, "Truncated"):
                        channel.receive(0.1)
                else:
                    self.assertIsNone(channel.receive(0.1))

    def test_oversized_frame_is_rejected_even_with_newline(self):
        self.channel.buffer = b"x" * (self.module.MAX_MESSAGE + 1) + b"\n"
        with self.assertRaisesRegex(ValueError, "large"):
            self.channel.receive(0.1)

    def test_output_is_framed_json(self):
        self.channel.send({"event": "ready", "ok": True})
        data = os.read(self.output_read, 4096)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(json.loads(data), {"event": "ready", "ok": True})

    def test_full_output_pipe_times_out_instead_of_blocking_recovery(self):
        try:
            while True:
                os.write(self.output_write, b"x" * 4096)
        except BlockingIOError:
            pass
        with self.assertRaises(TimeoutError):
            self.channel.send({"event": "ready"}, timeout=0.01)

    def test_strict_json_object_and_size_bound(self):
        module = load()
        self.assertEqual(module.decode_message(b'{"command":"stop"}\n'), {"command": "stop"})
        for value in (b'[]', b'null', b'{"command":"stop","command":"start"}',
                      b'NaN', b'\xff', b'"' + b'a' * module.MAX_MESSAGE + b'"'):
            with self.subTest(value=value[:60]), self.assertRaises(ValueError):
                module.decode_message(value)


if __name__ == "__main__":
    unittest.main()
