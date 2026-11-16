"""Bounded protocol controller for the installed-only streaming tester helper.

This module performs no service, firewall, subprocess or filesystem operations.
The injected runtime must validate/snapshot without side effects, hold the
installer lock for the entire session, and implement bounded start/stop/restore.
The GUI capability remains gated separately until the client integration is
verified. Signal handling is installed only for the helper's main-thread run.
"""

import json
import os
import re
import select
import signal
import time
from contextlib import contextmanager, nullcontext


MAX_MESSAGE = 16384
MAX_STRATEGIES = 64
MAX_COMMANDS = 2 * MAX_STRATEGIES + 1
IDLE_TIMEOUT = 300.0
SESSION_TIMEOUT = 3600.0
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bat")


class SessionInterrupted(RuntimeError):
    pass


class SessionSignals:
    """Main-thread SIGTERM/SIGINT policy for one helper process.

    Defer Python exceptions through mutation/bookkeeping windows rather than
    blocking OS signals: children must not inherit a blocked SIGTERM mask.
    Once recovery starts, further signals are recorded but never interrupt it.
    SIGKILL and power loss cannot be recovered by this mechanism.
    """

    def __init__(self):
        self.pending = None
        self.depth = 0
        self.recovering = False
        self.previous = {}

    @property
    def message(self):
        return "Session interrupted by " + signal.Signals(self.pending).name if self.pending else None

    def handle(self, number, frame):
        if self.pending is None:
            self.pending = number
        if not self.depth and not self.recovering:
            raise SessionInterrupted(self.message)

    def __enter__(self):
        try:
            for number in (signal.SIGTERM, signal.SIGINT):
                self.previous[number] = signal.getsignal(number)
                signal.signal(number, self.handle)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        for number, handler in self.previous.items():
            signal.signal(number, handler)

    @contextmanager
    def critical(self):
        self.depth += 1
        failed = False
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            self.depth -= 1
            if not failed and not self.depth and self.pending and not self.recovering:
                raise SessionInterrupted(self.message)


def decode_message(data):
    if not isinstance(data, bytes) or len(data) > MAX_MESSAGE:
        raise ValueError("Session message is too large or not bytes")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate session field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Non-JSON constant")

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid session JSON") from error
    if not isinstance(result, dict):
        raise ValueError("Session message must be an object")
    return result


def validate_begin(request):
    if not isinstance(request, dict) or set(request) != {"strategies", "expected_sha256"}:
        raise ValueError("Unexpected session request fields")
    names = request["strategies"]
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_STRATEGIES:
        raise ValueError("Select 1–64 installed strategies")
    for name in names:
        if (not isinstance(name, str) or len(name) > 128 or not NAME.fullmatch(name)
                or name.lower().startswith("service")):
            raise ValueError("Invalid session strategy")
    if len(set(names)) != len(names):
        raise ValueError("Duplicate session strategy")
    token = request["expected_sha256"]
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Read the installed configuration before testing")


def validate_command(command, names):
    if not isinstance(command, dict):
        raise ValueError("Session command must be an object")
    action = command.get("command")
    if action in ("stop", "restore") and set(command) == {"command"}:
        return action
    if action == "start" and set(command) == {"command", "strategy"}:
        if isinstance(command["strategy"], str) and command["strategy"] in names:
            return action
    raise ValueError("Unknown session command, strategy or fields")


class MessageChannel:
    """Newline JSON on owned pipe endpoints, with bounded reads AND writes.

    The caller owns/closes the descriptors; do not pass shared console handles.
    Each descriptor has exactly one reader/writer. Nonblocking mode avoids a
    full stdout pipe preventing the controller's recovery path.
    """

    def __init__(self, read_fd, write_fd):
        self.read_fd, self.write_fd = read_fd, write_fd
        self.buffer = b""
        os.set_blocking(read_fd, False)
        os.set_blocking(write_fd, False)

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                return decode_message(line)
            if len(self.buffer) > MAX_MESSAGE:
                raise ValueError("Session message is too large")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.read_fd], [], [], remaining)[0]:
                raise TimeoutError("Session idle timeout")
            try:
                data = os.read(self.read_fd, 4096)
            except BlockingIOError:
                continue
            if not data:
                if self.buffer:
                    raise ValueError("Truncated session message")
                return None
            self.buffer += data

    def send(self, message, timeout=5.0):
        encoded = json.dumps(message, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE:
            raise ValueError("Session response is too large")
        deadline = time.monotonic() + timeout
        while encoded:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [self.write_fd], [], remaining)[1]:
                raise TimeoutError("Session output timeout")
            try:
                written = os.write(self.write_fd, encoded)
            except BlockingIOError:
                continue
            encoded = encoded[written:]


def serve(runtime, request, receive, send, *, clock=time.monotonic, signals=None):
    """Process one authorized selection, restore on EOF/error, never accept argv.

    receive(timeout) returns one decoded command or None on clean EOF, and must
    raise TimeoutError on expiry. send(response) must also have a bounded write.
    Runtime.restore must independently verify cleanup/ownership before restarting
    the original service; an attempted restore is not proof that it succeeded.
    """
    validate_begin(request)
    # Freeze authorization before handing anything to the runtime or callbacks.
    request = {"strategies": list(request["strategies"]), "expected_sha256": request["expected_sha256"]}
    names = frozenset(request["strategies"])
    result = {"ok": False, "reason": None, "error": None, "cleanup_error": None,
              "restore_error": None, "restored": False}
    deadline = clock() + SESSION_TIMEOUT
    snapshot = None
    have_snapshot = False
    active = False
    def critical():
        return signals.critical() if signals is not None else nullcontext()
    with runtime.operation():
        try:
            snapshot = runtime.snapshot(request)
            have_snapshot = True
            # Even a partially failed enter must run restore under the same lock.
            with critical():
                runtime.enter(snapshot)
            send({"event": "ready", "ok": True})
            for _ in range(MAX_COMMANDS):
                remaining = deadline - clock()
                if remaining <= 0:
                    raise TimeoutError("Session deadline exceeded")
                command = receive(min(IDLE_TIMEOUT, remaining))
                if clock() >= deadline:
                    raise TimeoutError("Session deadline exceeded")
                if command is None:
                    result["reason"] = "eof"
                    break
                action = validate_command(command, names)
                if action == "restore":
                    result["reason"] = "restore"
                    break
                if action == "start":
                    if active:
                        raise ValueError("Stop the current test strategy before starting another")
                    # Mark before calling: failed start can leave partial rules.
                    active = True
                    with critical():
                        runtime.start(command["strategy"])
                    send({"event": "started", "ok": True, "strategy": command["strategy"]})
                else:
                    if active:
                        with critical():
                            runtime.stop()
                        active = False
                    send({"event": "stopped", "ok": True})
            else:
                raise ValueError("Session command limit exceeded")
        except BaseException as error:
            result["reason"] = "error"
            result["error"] = str(error) or type(error).__name__
            if not isinstance(error, Exception):
                raise
        finally:
            if signals is not None:
                signals.recovering = True
            if have_snapshot:
                if active:
                    try:
                        with critical():
                            runtime.stop()
                    except Exception as error:
                        result["cleanup_error"] = str(error)
                try:
                    with critical():
                        runtime.restore(snapshot)
                    result["restored"] = True
                except Exception as error:
                    result["restore_error"] = str(error)
            if signals is not None and signals.pending:
                result["signal"] = signals.pending
                result["reason"] = "signal"
                result["error"] = result["error"] or signals.message
            result["ok"] = have_snapshot and not any(result[field] for field in
                                                     ("error", "cleanup_error", "restore_error"))
            try:
                send({"event": "restored" if have_snapshot else "closed", **result})
            except Exception as error:
                # A closed GUI must never bypass restoration or hide its error.
                result["error"] = result["error"] or str(error)
                result["ok"] = False
    return result
