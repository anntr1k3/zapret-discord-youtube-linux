"""Streaming helper plumbing with real local pipes and fake installed runtime."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def close(fd):
    try:
        os.close(fd)
    except OSError:
        pass


class StreamHelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = load("stream_helper", "src/gui/privileged.py")
        self.protocol = load("stream_protocol", "src/lib/strategy_test_session.py")
        self.calls = []
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
                return {}

            def enter(self, snapshot):
                owner.calls.append("enter")

            def start(self, strategy):
                owner.calls.append(("start", strategy))

            def stop(self):
                owner.calls.append("stop")

            def restore(self, snapshot):
                owner.calls.append("restore")

        self.runtime = Runtime()
        self.service = types.SimpleNamespace(InstalledSessionRuntime=lambda installer: self.runtime)
        self.input_read, self.input_write = os.pipe()
        self.output_read, self.output_write = os.pipe()
        for fd in (self.input_read, self.input_write, self.output_read, self.output_write):
            self.addCleanup(close, fd)
        self.begin = {"strategies": ["general.bat"], "expected_sha256": "a" * 64}

    def run_stream(self, messages, *, broken_output=False):
        for message in messages:
            os.write(self.input_write, (json.dumps(message) + "\n").encode())
        close(self.input_write)
        if broken_output:
            close(self.output_read)
        with mock.patch.object(self.helper, "load_test_session_modules", return_value=(self.protocol, self.service)), \
                mock.patch.object(self.helper, "make_installer", return_value=object()):
            code = self.helper.run_test_session(ROOT, read_fd=self.input_read, write_fd=self.output_write)
        responses = [] if broken_output else [
            json.loads(line) for line in os.read(self.output_read, 16384).splitlines()]
        return code, responses

    def test_ready_start_stop_restore_on_newline_protocol(self):
        code, replies = self.run_stream([self.begin, {"command": "start", "strategy": "general.bat"},
                                         {"command": "stop"}, {"command": "restore"}])
        self.assertEqual(code, 0)
        self.assertEqual([r["event"] for r in replies], ["ready", "started", "stopped", "restored"])
        self.assertEqual(self.calls.count("restore"), 1)
        self.assertEqual(self.calls[-2:], ["restore", "unlock"])

    def test_eof_after_start_cleans_and_restores(self):
        code, replies = self.run_stream([self.begin, {"command": "start", "strategy": "general.bat"}])
        self.assertEqual(code, 0)
        self.assertTrue(replies[-1]["restored"])
        self.assertEqual(replies[-1]["reason"], "eof")
        self.assertEqual(self.calls[-3:], ["stop", "restore", "unlock"])

    def test_invalid_begin_has_no_operation_or_runtime_changes(self):
        code, replies = self.run_stream([{**self.begin, "path": "/etc/hosts"}])
        self.assertEqual(code, 1)
        self.assertFalse(replies[-1]["ok"])
        self.assertEqual(self.calls, [])

    def test_broken_output_does_not_skip_restore(self):
        code, _ = self.run_stream([self.begin], broken_output=True)
        self.assertEqual(code, 1)
        self.assertEqual(self.calls.count("restore"), 1)

    def test_main_verifies_release_before_stream_and_never_reads_stdin_to_eof(self):
        fake_stdin = mock.Mock()
        fake_stdin.buffer.read.side_effect = AssertionError("must not buffer until EOF")
        with mock.patch.object(sys, "argv", ["privileged.py", "test-session"]), \
                mock.patch.object(sys, "stdin", fake_stdin), \
                mock.patch.object(self.helper.os, "geteuid", return_value=0), \
                mock.patch.object(self.helper, "verify_release", return_value=ROOT) as verified, \
                mock.patch.object(self.helper, "run_test_session", return_value=0) as streamed:
            self.assertEqual(self.helper.main(), 0)
        verified.assert_called_once()
        streamed.assert_called_once_with(ROOT)

    def test_stream_action_cannot_use_single_request_dispatch(self):
        self.assertNotIn("test-session", self.helper.ACTIONS)
        with self.assertRaises(ValueError):
            self.helper.validate_payload("test-session", self.begin)


if __name__ == "__main__":
    unittest.main()
