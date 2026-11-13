#!/usr/bin/env python3
"""Unprivileged loopback-only baseline integration in the marked disposable VM."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() == 0 or socket.gethostname() != "zapret-integration"
            or not Path("/var/tmp/zapret-vm-provisioned").is_file()):
        parser.error("Run as an ordinary user only in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    spec = importlib.util.spec_from_file_location("tester_vm_backend", source / "src/gui/backend.py")
    backend_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend_module)
    curl = shutil.which("curl")
    require(bool(curl), "real curl is available")
    observed = [Path("/etc/hosts"), Path("/proc/sys/net/ipv4/tcp_timestamps")]
    before = {str(path): path.read_bytes() for path in observed}
    service_before = subprocess.run(
        ["systemctl", "is-active", "zapret_discord_youtube.service"], capture_output=True).stdout
    count = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            count.append(self.path)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="tester-vm-") as directory:
            base = Path(directory)
            backend = backend_module.Backend(source, current=base / "not-installed")
            # An explicit local fixture, not downloaded targets. No ping tool is
            # needed: this scenario intentionally tests only real curl transport.
            targets = [{"name": "Loopback", "url": f"http://127.0.0.1:{server.server_port}/", "ping": None}]
            report = backend.tester_run("standard", [], targets=targets, curl_path=curl, ping_path="unused")
            require(report["mode"] == "baseline", "baseline runs without helper")
            require(len(count) == 3, "three actual HEAD requests reach loopback server")
            probes = report["strategies"][0]["targets"][0]["probes"]
            require([p["status"] for p in probes] == ["OK"] * 3, "real HTTP probes succeed")
            require([p["code"] for p in probes] == ["204"] * 3, "actual response codes are recorded")
            require(report["restore_error"] is None, "baseline needs no privileged restore")
            require(backend.tester_last_report is report, "backend retains report for explicit export")
            exported = base / "report.txt"
            backend.export_tester_report(exported)
            require(exported.stat().st_mode & 0o777 == 0o600, "text export has mode 0600")
            require("Config: baseline" in exported.read_text(), "export includes actual baseline result")
            cancel = threading.Event()
            cancel.set()
            cancelled = backend.tester_run("standard", [], targets=targets,
                curl_path=curl, ping_path="unused", cancel_event=cancel)
            require(cancelled["cancelled"] and cancelled["best"] is None, "pre-cancelled run has no recommendation")
            require(len(count) == 3, "pre-cancelled run sends no requests")
            try:
                backend.tester_run("standard", ["general_alt12.bat"])
            except RuntimeError:
                pass
            else:
                raise AssertionError("strategy run unexpectedly accepted")
            require(len(count) == 3, "unavailable strategy runner is rejected before probes")
    finally:
        server.shutdown()
        worker.join()
        server.server_close()
    require(all(path.read_bytes() == before[str(path)] for path in observed), "hosts and runtime timestamps unchanged")
    service_after = subprocess.run(
        ["systemctl", "is-active", "zapret_discord_youtube.service"], capture_output=True).stdout
    require(service_after == service_before, "service state unchanged")
    paths = ("src/lib/strategy_tester.py", "src/gui/backend.py", "ci/vm_strategy_tester_smoke.py")
    evidence = {"status": "passed", "uid": os.geteuid(), "transport": "loopback HTTP only; no TLS/ping/DPI acceptance",
                "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in paths}}
    target = Path("/var/tmp/zapret-strategy-tester-result.json")
    # Do not follow an existing guest-side symlink or overwrite another run.
    with target.open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")
    print("Evidence:", target)


if __name__ == "__main__":
    main()
