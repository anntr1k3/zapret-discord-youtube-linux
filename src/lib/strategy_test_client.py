"""Unprivileged client runner for the installed streaming tester helper.

Controls one long-lived pkexec process over nonblocking pipe descriptors.
Guarantees that snapshot/enter is followed by restore or process termination,
and never claims successful testing if the helper failed to restore the service.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
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

    @staticmethod
    def _default_spawn(argv):
        return subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def snapshot(self):
        argv = ["/usr/bin/pkexec", "/usr/bin/python3", "-I", str(self.helper_path), "test-session"]
        self.process = self.spawn(argv)
        self.channel = self.channel_cls(self.process.stdout.fileno(), self.process.stdin.fileno())
        if self.process.poll() in (126, 127):
            raise RuntimeError("Авторизация отменена или отклонена. Никакой успех не предполагается — обновите статус.")
        try:
            self.channel.send({"strategies": list(self.strategies), "expected_sha256": self.expected_sha256})
            ready = self.channel.receive(60.0)
        except Exception as error:
            returncode = self.process.poll()
            if returncode in (126, 127):
                raise RuntimeError("Авторизация отменена или отклонена. Никакой успех не предполагается — обновите статус.") from None
            stderr = self.process.stderr.read() if self.process.stderr else b""
            err_msg = stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(err_msg or str(error) or "Не удалось запустить сеанс помощника") from None

        if self.process.poll() in (126, 127):
            raise RuntimeError("Авторизация отменена или отклонена. Никакой успех не предполагается — обновите статус.")
        if not isinstance(ready, dict):
            raise RuntimeError("Помощник вернул некорректный ответ")
        if not ready.get("ok"):
            raise RuntimeError(ready.get("error") or "Не удалось инициализировать сеанс тестирования")
        if ready.get("event") != "ready":
            raise RuntimeError(f"Неожиданный ответ сеанса: {ready}")
        self.active_snapshot = True
        return {"strategies": list(self.strategies), "expected_sha256": self.expected_sha256}

    def start(self, strategy):
        if not self.active_snapshot:
            raise RuntimeError("Сеанс тестирования не активен")
        if self.current_strategy:
            raise RuntimeError("Предыдущая стратегия ещё активна; остановите её перед запуском новой")
        self.channel.send({"command": "start", "strategy": strategy})
        try:
            response = self.channel.receive(30.0)
        except Exception as error:
            raise RuntimeError(f"Ошибка ожидания запуска стратегии {strategy}: {error}") from None
        if not isinstance(response, dict) or not response.get("ok") or response.get("event") != "started":
            error = response.get("error") if isinstance(response, dict) else None
            raise RuntimeError(error or f"Не удалось запустить тестовую стратегию {strategy}")
        self.current_strategy = strategy

    def stop(self):
        if not self.active_snapshot or not self.current_strategy:
            return
        strategy = self.current_strategy
        self.current_strategy = None
        self.channel.send({"command": "stop"})
        try:
            response = self.channel.receive(30.0)
        except Exception as error:
            raise RuntimeError(f"Ошибка ожидания остановки стратегии {strategy}: {error}") from None
        if not isinstance(response, dict) or not response.get("ok") or response.get("event") != "stopped":
            error = response.get("error") if isinstance(response, dict) else None
            raise RuntimeError(error or "Не удалось остановить тестовую стратегию")

    def restore(self, snapshot):
        if not self.process:
            return
        if not self.restored:
            try:
                if self.process.poll() is None:
                    try:
                        self.channel.send({"command": "restore"})
                    except (BrokenPipeError, OSError):
                        pass
                if self.process.stdin and not self.process.stdin.closed:
                    try:
                        self.process.stdin.close()
                    except (OSError, ValueError):
                        pass

                final = None
                try:
                    final = self.channel.receive(180.0)
                except (OSError, TimeoutError, ValueError):
                    pass

                try:
                    self.process.wait(timeout=30.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10.0)
                    raise RuntimeError("Процесс помощника не завершился вовремя; автоматическое восстановление не подтверждено")

                self.last_result = final
                if not final or not isinstance(final, dict):
                    stderr = self.process.stderr.read() if self.process.stderr else b""
                    err_text = stderr.decode("utf-8", "replace").strip()
                    raise RuntimeError(err_text or "Помощник завершился без подтверждения восстановления")

                if final.get("restore_error"):
                    raise RuntimeError(f"Ошибка восстановления исходного сервиса: {final['restore_error']}")
                if not final.get("restored"):
                    raise RuntimeError(final.get("error") or "Восстановление исходного сервиса не подтверждено помощником")
                self.restored = True
            finally:
                self.active_snapshot = False
                self.current_strategy = None
                for stream in (self.process.stdout, self.process.stderr):
                    if stream and not stream.closed:
                        try:
                            stream.close()
                        except OSError:
                            pass
