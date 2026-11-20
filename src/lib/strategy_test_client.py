"""Unprivileged client runner for the installed streaming tester helper.

Controls one long-lived pkexec process over nonblocking pipe descriptors.
Guarantees that snapshot/enter is followed by restore or process termination,
and never claims successful testing if the helper failed to restore the service.
"""

import importlib.util
import io
import os
from pathlib import Path
import select
import subprocess
import threading
import time


def load_message_channel():
    try:
        from strategy_test_session import MessageChannel
        return MessageChannel
    except ImportError:
        pass
    path = Path(__file__).resolve().parent / "strategy_test_session.py"
    spec = importlib.util.spec_from_file_location("strategy_test_session_client_dep", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MessageChannel


class StderrTail:
    """Continuously drain stderr without storing more than the last 8 KiB."""

    LIMIT = 8192

    def __init__(self, stream):
        self.data = b""
        self.stop = threading.Event()
        self.worker = None
        if isinstance(stream, io.BytesIO):
            self.data = stream.getvalue()[-self.LIMIT:]
        elif stream is not None:
            self.worker = threading.Thread(target=self.drain, args=(stream.fileno(),), daemon=True)
            self.worker.start()

    def drain(self, fd):
        try:
            poll = select.poll()
            poll.register(fd, select.POLLIN | select.POLLHUP)
            os.set_blocking(fd, False)
            while not self.stop.is_set():
                if poll.poll(100):
                    try:
                        chunk = os.read(fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        break
                    self.data = (self.data + chunk)[-self.LIMIT:]
        except OSError:
            pass

    def finish(self):
        if self.worker is not None:
            self.worker.join(0.15)
            self.stop.set()
            self.worker.join(0.15)
        return self.data.decode("utf-8", "replace").strip()


class StreamingTesterRunner:
    """Client runner driving the installed test-session action via MessageChannel."""

    def __init__(self, helper_path, strategies, expected_sha256, *,
                 spawn=None, channel_cls=None, clock=time.monotonic):
        self.helper_path = Path(helper_path)
        self.strategies = list(strategies)
        self.expected_sha256 = str(expected_sha256)
        self.spawn = spawn or self._default_spawn
        self.channel_cls = channel_cls or load_message_channel()
        self.clock = clock
        self.process = None
        self.channel = None
        self.active_snapshot = False
        self.current_strategy = None
        self.restored = False
        self.last_result = None
        self.used = False
        self.desynced = False
        self.stderr = None

    @staticmethod
    def _default_spawn(argv):
        return subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def snapshot(self):
        if self.used:
            raise RuntimeError("Сеанс тестирования уже использован")
        self.used = True
        argv = ["/usr/bin/pkexec", "/usr/bin/python3", "-I", str(self.helper_path), "test-session"]
        self.process = self.spawn(argv)
        ready = None
        begin_attempted = False
        try:
            self.stderr = StderrTail(self.process.stderr)
            self.channel = self.channel_cls(self.process.stdout.fileno(), self.process.stdin.fileno())
            if self.process.poll() in (126, 127):
                raise RuntimeError("pkexec")
            begin_attempted = True
            self.channel.send({"strategies": list(self.strategies), "expected_sha256": self.expected_sha256})
            ready = self.channel.receive(60.0)
            if not isinstance(ready, dict) or ready.get("event") != "ready" or ready.get("ok") is not True:
                detail = ready.get("error") if isinstance(ready, dict) else None
                raise RuntimeError(detail or "Помощник не подтвердил готовность к тестированию")
        except Exception as error:
            self._close(self.process.stdin)
            finished = self._wait(3.0)
            returncode = self.process.poll()
            stderr = self._close_process()
            if returncode in (126, 127):
                raise RuntimeError("Авторизация отменена или отклонена. Никакой успех не предполагается — обновите статус.") from None
            detail = str(error) or stderr or "Не удалось запустить сеанс помощника"
            terminal = ready if isinstance(ready, dict) else {}
            if terminal.get("restore_error"):
                detail += f"; ошибка восстановления: {terminal['restore_error']}"
            elif begin_attempted and (not finished or not (
                    terminal.get("event") == "closed" or self._restored_reply(terminal))):
                detail += "; восстановление не подтверждено — проверьте состояние сервиса"
            raise RuntimeError(detail) from None
        self.active_snapshot = True
        return {"strategies": list(self.strategies), "expected_sha256": self.expected_sha256}

    @staticmethod
    def _close(stream):
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def _close_process(self):
        stderr = self.stderr.finish() if self.stderr else ""
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            self._close(stream)
        self.process = self.channel = None
        self.active_snapshot = False
        self.current_strategy = None
        return stderr

    def _wait(self, timeout):
        try:
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            # EOF is the first recovery trigger. A privileged child may reject
            # signals from this user; in that case leave it to recover on EOF.
            try:
                self.process.terminate()
            except OSError:
                pass
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                threading.Thread(target=self.process.wait, daemon=True).start()
            return False

    @staticmethod
    def _terminal(response):
        return isinstance(response, dict) and response.get("event") in ("restored", "closed")

    @staticmethod
    def _restored_reply(response):
        return (isinstance(response, dict) and response.get("event") == "restored"
                and response.get("restored") is True and not response.get("restore_error")
                and not response.get("cleanup_error"))

    def _request(self, command, event, error_message, *, strategy=None):
        response = None
        try:
            self.channel.send(command)
            response = self.channel.receive(30.0)
            if (not isinstance(response, dict) or response.get("ok") is not True
                    or response.get("event") != event
                    or (strategy is not None and response.get("strategy") != strategy)):
                detail = response.get("error") if isinstance(response, dict) else None
                raise RuntimeError(detail or "ответ не соответствует запросу")
        except Exception as error:
            self.desynced = True
            self.active_snapshot = False
            if self._terminal(response):
                self.last_result = response
            # Do not send any more commands on a desynchronized channel.
            self._close(self.process.stdin)
            raise RuntimeError(f"{error_message}: {error}") from None

    def start(self, strategy):
        if not self.active_snapshot:
            raise RuntimeError("Сеанс тестирования не активен")
        if self.current_strategy:
            raise RuntimeError("Предыдущая стратегия ещё активна; остановите её перед запуском новой")
        self._request({"command": "start", "strategy": strategy}, "started",
                      f"Не удалось запустить тестовую стратегию {strategy}", strategy=strategy)
        self.current_strategy = strategy

    def stop(self):
        if not self.active_snapshot or not self.current_strategy:
            return
        strategy = self.current_strategy
        self._request({"command": "stop"}, "stopped",
                      f"Не удалось остановить тестовую стратегию {strategy}")
        self.current_strategy = None

    def restore(self, snapshot):
        if not self.process:
            return
        final = self.last_result
        try:
            if not self.desynced and self.process.poll() is None:
                try:
                    self.channel.send({"command": "restore"})
                except (OSError, TimeoutError, ValueError):
                    # Closing stdin below still asks the helper to restore.
                    pass
            self._close(self.process.stdin)
            if final is None:
                deadline = self.clock() + 180.0
                try:
                    final = self.channel.receive(max(0.0, deadline - self.clock()))
                    # At most one old acknowledgement can precede the terminal
                    # event: the client never pipelines start/stop commands.
                    if self.desynced and isinstance(final, dict) and final.get("event") in ("started", "stopped"):
                        final = self.channel.receive(max(0.0, deadline - self.clock()))
                except (OSError, ValueError):
                    final = None
            self.last_result = final
            finished = self._wait(3.0)
        finally:
            stderr = self._close_process()
        if not finished:
            raise RuntimeError("Процесс помощника не завершился вовремя; автоматическое восстановление не подтверждено")
        if self._terminal(final):
            if final.get("restore_error"):
                raise RuntimeError(f"Ошибка восстановления исходного сервиса: {final['restore_error']}")
            if final.get("cleanup_error"):
                raise RuntimeError(f"Ошибка очистки тестового окружения: {final['cleanup_error']}")
        if not self._restored_reply(final):
            raise RuntimeError((final.get("error") if self._terminal(final) else None) or stderr
                               or "Помощник завершился без подтверждения восстановления")
        self.restored = True
