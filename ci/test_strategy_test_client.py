"""Unit tests for the unprivileged streaming tester runner."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
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


class FakeStreamProcess:
    def __init__(self, stdin_fd, stdout_fd, stderr_bytes=b"", exit_code=0):
        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd
        self.stdin = types.SimpleNamespace(
            fileno=lambda: self.stdin_fd,
            close=lambda: close(self.stdin_fd),
            closed=False,
        )
        self.stdout = types.SimpleNamespace(
            fileno=lambda: self.stdout_fd,
            close=lambda: close(self.stdout_fd),
            closed=False,
        )
        self.stderr = io.BytesIO(stderr_bytes)
        self._exit_code = exit_code
        self._running = True

    def poll(self):
        return None if self._running else self._exit_code

    def wait(self, timeout=None):
        self._running = False
        return self._exit_code

    def send_signal(self, sig):
        self._running = False

    def kill(self):
        self._running = False


class StrategyTestClientTests(unittest.TestCase):
    def setUp(self):
        self.client_mod = load("strategy_test_client", "src/lib/strategy_test_client.py")
        self.protocol = load("strategy_test_session", "src/lib/strategy_test_session.py")
        self.runner_cls = self.client_mod.StreamingTesterRunner

        # Helper pipes:
        # runner writes to client_to_helper_w, helper reads client_to_helper_r
        # helper writes to helper_to_client_w, runner reads helper_to_client_r
        self.c2h_r, self.c2h_w = os.pipe()
        self.h2c_r, self.h2c_w = os.pipe()
        for fd in (self.c2h_r, self.c2h_w, self.h2c_r, self.h2c_w):
            self.addCleanup(close, fd)

    def make_runner(self, process):
        return self.runner_cls(
            helper_path="/opt/zapret/helper.py",
            strategies=["general.bat"],
            expected_sha256="a" * 64,
            spawn=lambda argv: process,
            channel_cls=self.protocol.MessageChannel,
        )

    def write_helper_reply(self, message):
        encoded = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        os.write(self.h2c_w, encoded)

    def read_runner_command(self):
        buffer = b""
        while b"\n" not in buffer:
            chunk = os.read(self.c2h_r, 4096)
            if not chunk:
                break
            buffer += chunk
        return json.loads(buffer.decode("utf-8").strip()) if buffer else None

    def test_snapshot_success(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})

        snapshot = runner.snapshot()
        self.assertTrue(runner.active_snapshot)
        self.assertEqual(snapshot["strategies"], ["general.bat"])
        cmd = self.read_runner_command()
        self.assertEqual(cmd, {"strategies": ["general.bat"], "expected_sha256": "a" * 64})

    def test_snapshot_polkit_cancelled_126(self):
        close(self.h2c_w)
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r, exit_code=126)
        proc._running = False
        runner = self.make_runner(proc)

        with self.assertRaisesRegex(RuntimeError, "Авторизация отменена"):
            runner.snapshot()

    def test_snapshot_polkit_cancelled_127(self):
        close(self.h2c_w)
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r, exit_code=127)
        proc._running = False
        runner = self.make_runner(proc)

        with self.assertRaisesRegex(RuntimeError, "Авторизация отменена"):
            runner.snapshot()

    def test_snapshot_helper_error(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "closed", "ok": False, "error": "Strategy missing"})

        with self.assertRaisesRegex(RuntimeError, "Strategy missing"):
            runner.snapshot()

    def test_start_and_stop_lifecycle(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        runner.snapshot()
        _ = self.read_runner_command()

        # Start strategy
        self.write_helper_reply({"event": "started", "ok": True, "strategy": "general.bat"})
        runner.start("general.bat")
        self.assertEqual(runner.current_strategy, "general.bat")
        self.assertEqual(self.read_runner_command(), {"command": "start", "strategy": "general.bat"})

        # Cannot start another while active
        with self.assertRaisesRegex(RuntimeError, "Предыдущая стратегия ещё активна"):
            runner.start("general_alt12.bat")

        # Stop strategy
        self.write_helper_reply({"event": "stopped", "ok": True})
        runner.stop()
        self.assertIsNone(runner.current_strategy)
        self.assertEqual(self.read_runner_command(), {"command": "stop"})

    def test_start_error_from_helper(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        runner.snapshot()
        _ = self.read_runner_command()

        self.write_helper_reply({"event": "closed", "ok": False, "error": "nfqws dry-run rejected"})
        with self.assertRaisesRegex(RuntimeError, "nfqws dry-run rejected"):
            runner.start("general.bat")
        self.assertIsNone(runner.current_strategy)

    def test_snapshot_timeout_closes_pipes_without_waiting_for_live_stderr(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(proc.__exit__, None, None, None)
        runner = self.make_runner(proc)
        runner.channel_cls = mock.Mock()
        runner.channel_cls.return_value.receive.side_effect = TimeoutError("readiness deadline")
        try:
            # Fail deterministically if the runner tries a blocking stream read.
            with mock.patch.object(proc.stderr, "read", side_effect=AssertionError("blocking stderr read")):
                with self.assertRaisesRegex(RuntimeError, "readiness deadline"):
                    runner.snapshot()
            self.assertTrue(proc.stdin.closed and proc.stdout.closed and proc.stderr.closed)
            self.assertEqual(proc.wait(timeout=1), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)

    def test_start_timeout_rejects_next_command_and_reads_restore_after_late_ack(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        channel = mock.Mock()
        channel.receive.side_effect = [
            {"event": "ready", "ok": True}, TimeoutError("start timed out"),
            {"event": "started", "ok": True, "strategy": "general.bat"},
            {"event": "restored", "restored": True, "ok": True, "reason": "eof"},
        ]
        runner.channel_cls = mock.Mock(return_value=channel)
        snapshot = runner.snapshot()
        with self.assertRaisesRegex(RuntimeError, "start timed out"):
            runner.start("general.bat")
        runner.stop()
        with self.assertRaises(RuntimeError):
            runner.start("general_alt12.bat")
        runner.restore(snapshot)
        self.assertTrue(runner.restored)
        self.assertEqual([args.args[0].get("command") for args in channel.send.call_args_list],
                         [None, "start"])

    def test_started_reply_must_match_strategy(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        runner.snapshot()
        self.write_helper_reply({"event": "started", "ok": True, "strategy": "general_alt12.bat"})
        with self.assertRaises(RuntimeError):
            runner.start("general.bat")
        self.assertIsNone(runner.current_strategy)

    def test_stop_send_failure_closes_session_and_never_sends_again(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        channel = mock.Mock()
        channel.receive.side_effect = [
            {"event": "ready", "ok": True},
            {"event": "started", "ok": True, "strategy": "general.bat"},
            {"event": "restored", "restored": True, "ok": True, "reason": "eof"},
        ]
        channel.send.side_effect = [None, None, BrokenPipeError("pipe closed")]
        runner.channel_cls = mock.Mock(return_value=channel)
        snapshot = runner.snapshot()
        runner.start("general.bat")
        with self.assertRaisesRegex(RuntimeError, "pipe closed"):
            runner.stop()
        with self.assertRaises(RuntimeError):
            runner.start("general.bat")
        runner.restore(snapshot)
        self.assertTrue(runner.restored)
        self.assertEqual(channel.send.call_count, 3)

    def test_helper_can_write_more_than_a_pipe_of_stderr_without_blocking_ready(self):
        code = ("import os, sys\n"
                "sys.stdin.buffer.readline()\n"
                "sys.stderr.buffer.write(b'x' * 262144 + b'diagnostic-tail')\n"
                "sys.stderr.buffer.flush()\n"
                "os.write(1,b'{\"event\":\"ready\",\"ok\":true}\\n')\n"
                "sys.stdin.buffer.readline()\n"
                "os.write(1,b'{\"event\":\"restored\",\"restored\":true}\\n')\n")
        with subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            runner = self.make_runner(proc)
            snapshot = runner.snapshot()
            runner.restore(snapshot)
        self.assertTrue(runner.restored)
        self.assertLessEqual(len(runner.stderr.data), runner.stderr.LIMIT)
        self.assertTrue(runner.stderr.data.endswith(b"diagnostic-tail"))

    def test_restore_rejects_success_flag_without_correct_terminal_event(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        snapshot = runner.snapshot()
        self.write_helper_reply({"event": "started", "ok": True, "restored": True})
        with self.assertRaises(RuntimeError):
            runner.restore(snapshot)
        self.assertFalse(runner.restored)

    def test_restore_normal(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        snapshot = runner.snapshot()
        _ = self.read_runner_command()

        self.write_helper_reply({
            "event": "restored", "ok": True, "restored": True,
            "reason": "restore", "error": None, "restore_error": None
        })
        runner.restore(snapshot)
        self.assertTrue(runner.restored)
        self.assertFalse(runner.active_snapshot)

    def test_restore_fails_when_restore_error_present(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        snapshot = runner.snapshot()
        _ = self.read_runner_command()

        self.write_helper_reply({
            "event": "restored", "ok": False, "restored": False,
            "reason": "restore", "error": "systemd unit failed",
            "restore_error": "failed to restart zapret"
        })
        with self.assertRaisesRegex(RuntimeError, "Ошибка восстановления исходного сервиса: failed to restart zapret"):
            runner.restore(snapshot)

    def test_restore_fails_when_process_crashed_without_response(self):
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r, stderr_bytes=b"crash in cgroup", exit_code=1)
        runner = self.make_runner(proc)
        self.write_helper_reply({"event": "ready", "ok": True})
        snapshot = runner.snapshot()
        _ = self.read_runner_command()

        # Close helper write end without sending restored event
        close(self.h2c_w)
        proc._running = False
        with self.assertRaisesRegex(RuntimeError, "crash in cgroup"):
            runner.restore(snapshot)

    def test_full_tester_session_lifecycle(self):
        import threading
        tester_mod = load("strategy_tester", "src/lib/strategy_tester.py")
        proc = FakeStreamProcess(stdin_fd=self.c2h_w, stdout_fd=self.h2c_r)
        runner = self.make_runner(proc)

        def helper_simulator():
            channel = self.protocol.MessageChannel(self.c2h_r, self.h2c_w)
            # 1. begin -> ready
            req = channel.receive(5.0)
            channel.send({"event": "ready", "ok": True})
            # 2. start -> started
            cmd1 = channel.receive(5.0)
            channel.send({"event": "started", "ok": True, "strategy": cmd1["strategy"]})
            # 3. stop -> stopped
            cmd2 = channel.receive(5.0)
            channel.send({"event": "stopped", "ok": True})
            # 4. restore -> restored
            cmd3 = channel.receive(5.0)
            channel.send({"event": "restored", "ok": True, "restored": True, "reason": "restore"})

        th = threading.Thread(target=helper_simulator)
        th.start()

        targets = [{"name": "Web", "url": "https://example.org", "ping": "example.org"}]
        session = tester_mod.TesterSession(
            strategies=["general.bat"],
            targets=targets,
            test_type="standard",
            runner=runner,
            execute=lambda argv, timeout: (0, "HTTP/1.1 200 OK\r\n\r\n", ""),
            sleep=lambda s: None,
            curl_path="/usr/bin/curl",
            ping_path="/usr/bin/ping",
            init_wait=0,
        )
        report = session.run()
        th.join(timeout=5.0)

        self.assertEqual(report["mode"], "strategies")
        self.assertEqual(len(report["strategies"]), 1)
        self.assertEqual(report["strategies"][0]["name"], "general.bat")
        self.assertIsNone(report["strategies"][0]["error"])
        self.assertIsNone(report["restore_error"])
        self.assertTrue(runner.restored)


if __name__ == "__main__":
    unittest.main()
