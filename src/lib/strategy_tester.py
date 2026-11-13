"""Unprivileged strategy tester engine.

Network probes run as the invoking user with fixed argv and short timeouts.
Running a strategy needs a pluggable runner (privileged helper later); the
session always restores prior state via the runner and reports failures.
"""

import concurrent.futures
import datetime
import json
import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


DEFAULT_DPI_SUITE_URL = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json"
DPI_SUITE_LICENSE = "DPI-набор: hyperion-cs/dpi-checkers (Apache-2.0), без изменений"
MAX_TARGETS = 64
MAX_TARGET_VALUE = 2048
MAX_LIST_BYTES = 65536
TARGET_KEY = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*\"(.*)\"\s*$")
PING_PREFIX = "PING:"
PING_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-_]{0,252}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
STRATEGY_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.bat")
SSL_PATTERNS = re.compile(
    r"Could not resolve host|certificate|self[- ]?signed|certificate verify failed"
    r"|unable to get local issuer certificate", re.IGNORECASE)
UNSUP_PATTERNS = re.compile(
    r"does not support|not supported|protocol\s+'?.+'?\s+not\s+supported|unsupported protocol"
    r"|TLS.*not supported|Unrecognized option|Unknown option|unsupported option"
    r"|unsupported feature|schannel", re.IGNORECASE)
PING_AVG = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms")
HTTP_CODE = "%{http_code}"
DPI_WRITE_OUT = "%{http_code} %{size_upload} %{size_download} %{time_total}"
TLS_VARIANTS = (("HTTP", ("--http1.1",)),
                ("TLS1.2", ("--tlsv1.2", "--tls-max", "1.2")),
                ("TLS1.3", ("--tlsv1.3", "--tls-max", "1.3")))
DEFAULT_TARGETS = {
    "DiscordMain": "https://discord.com",
    "DiscordGateway": "https://gateway.discord.gg",
    "DiscordCDN": "https://cdn.discordapp.com",
    "DiscordUpdates": "https://updates.discord.com",
    "YouTubeWeb": "https://www.youtube.com",
    "YouTubeShort": "https://youtu.be",
    "YouTubeImage": "https://i.ytimg.com",
    "YouTubeVideoRedirect": "https://redirector.googlevideo.com",
    "GoogleMain": "https://www.google.com",
    "GoogleGstatic": "https://www.gstatic.com",
    "CloudflareWeb": "https://www.cloudflare.com",
    "CloudflareCDN": "https://cdnjs.cloudflare.com",
    "CloudflareDNS1111": "PING:1.1.1.1",
    "CloudflareDNS1001": "PING:1.0.0.1",
    "GoogleDNS8888": "PING:8.8.8.8",
    "GoogleDNS8844": "PING:8.8.4.4",
    "Quad9DNS9999": "PING:9.9.9.9",
}


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _number(value):
    return str(int(value)) if float(value) == int(value) else str(value)


def discover_strategies(base):
    """Merged strategy names, same naming rules as the profile switcher."""
    names = set()
    for folder in (base / "zapret-latest", base / "custom-strategies"):
        if folder.is_dir():
            names.update(path.name for path in folder.glob("*.bat")
                         if path.is_file() and STRATEGY_NAME.fullmatch(path.name))
    # service*.bat is the upstream service script, not a testable strategy.
    return sorted(name for name in names if not name.startswith("service"))


def validate_host(host):
    return isinstance(host, str) and 0 < len(host) <= 253 and bool(HOSTNAME.fullmatch(host))


def parse_target_value(value):
    """Return (url, ping). Rejects credentials, schemes and broken hosts."""
    if not isinstance(value, str) or not value or len(value) > MAX_TARGET_VALUE:
        raise ValueError("пустое или слишком длинное значение цели")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValueError("управляющие символы в цели")
    if value.startswith(PING_PREFIX):
        host = value[len(PING_PREFIX):].strip()
        if not PING_HOST.fullmatch(host):
            raise ValueError("неподдерживаемый ping-адрес")
        return None, host
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("нужен http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("URL с учётными данными отклонён")
    if not validate_host(parsed.hostname):
        raise ValueError("неподдерживаемый host в URL")
    return value.rstrip(), parsed.hostname


def load_targets(path=None):
    """Parse the bundled targets file; fall back to documented defaults."""
    raw = {}
    problems = []
    if path is None:
        problems.append("utils/targets.txt не найден; используются цели по умолчанию")
    else:
        try:
            data = Path(path).read_bytes()
        except OSError as error:
            problems.append(f"targets.txt не прочитан ({error}); используются цели по умолчанию")
        else:
            if len(data) > MAX_LIST_BYTES:
                problems.append("targets.txt слишком большой; используются цели по умолчанию")
            else:
                for line in data.decode("utf-8", "replace").splitlines():
                    match = TARGET_KEY.match(line)
                    if match:
                        raw[match.group(1)] = (match.group(1), match.group(2))
                if not raw:
                    problems.append("targets.txt пуст; используются цели по умолчанию")
    if not raw:
        for key, value in DEFAULT_TARGETS.items():
            raw[f"__default__{key}"] = (key, value)
    targets = []
    for _, (key, value) in raw.items():
        if len(targets) >= MAX_TARGETS:
            problems.append(f"Лимит целей: {MAX_TARGETS}; оставшиеся цели пропущены")
            break
        try:
            url, ping = parse_target_value(value)
        except ValueError as error:
            problems.append(f"{key}: {error}")
            continue
        targets.append({"name": key, "url": url, "ping": ping})
    return targets, problems


def http_probe_plan(curl_path, url, timeout=5.0):
    base = [curl_path, "-q", "-I", "-s", "--show-error", "-m", _number(timeout),
            "-o", os.devnull, "-w", HTTP_CODE]
    return [(label, base + list(args) + [url]) for label, args in TLS_VARIANTS]


def ping_probe_plan(ping_path, host, count=3, deadline=10):
    return [ping_path, "-c", str(count), "-w", str(deadline), host], deadline + 5


def dpi_probe_plan(curl_path, host, payload_path, range_bytes=65536, timeout=5.0):
    base = [curl_path, "-q", "-s", "--show-error", "-m", _number(timeout), "-o", os.devnull,
            "-w", DPI_WRITE_OUT, "-X", "POST", "--data-binary", "@" + str(payload_path),
            "--range", f"0-{range_bytes - 1}"]
    return [(label, base + list(args) + [f"https://{host}"]) for label, args in TLS_VARIANTS]


def classify_http(label, exit_code, stdout, stderr):
    stderr = stderr or ""
    code = (stdout or "").strip() or "NA"
    if SSL_PATTERNS.search(stderr):
        reason = "dns" if "Could not resolve host" in stderr else "certificate"
        return {"label": label, "status": "SSL", "code": code, "reason": reason}
    if exit_code == 35 or UNSUP_PATTERNS.search(stderr):
        reason = "exit-35" if exit_code == 35 else "unsupported"
        return {"label": label, "status": "UNSUP", "code": code, "reason": reason}
    if exit_code == 0:
        return {"label": label, "status": "OK", "code": code, "reason": None}
    return {"label": label, "status": "ERROR", "code": code, "reason": "exit"}


def parse_ping_avg(output):
    match = PING_AVG.search(output or "")
    return float(match.group(1)) if match else None


def classify_ping(host, exit_code, output):
    average = parse_ping_avg(output)
    if exit_code == 0 and average is not None:
        return {"host": host, "status": "OK", "avg_ms": average}
    return {"host": host, "status": "TIMEOUT", "avg_ms": None}


DPI_LINE = re.compile(r"^\s*(\d{3})\s+(\d+)\s+(\d+)\s+([\d.]+)\s*$")


def classify_dpi(exit_code, stdout, stderr, timeout):
    stderr = stderr or ""
    match = DPI_LINE.match(stdout or "")
    if exit_code == 35 or UNSUP_PATTERNS.search(stderr):
        reason = "exit-35" if exit_code == 35 else "unsupported"
        parsed = {"label": None, "status": "UNSUPPORTED", "code": "NA", "reason": reason,
                  "up_bytes": 0, "down_bytes": 0, "seconds": None}
        if match:
            parsed["code"] = match.group(1)
            parsed["up_bytes"], parsed["down_bytes"] = int(match.group(2)), int(match.group(3))
            parsed["seconds"] = float(match.group(4))
        return parsed
    if match:
        code, up, down, seconds = match.group(1), int(match.group(2)), int(match.group(3)), float(match.group(4))
        if exit_code == 0:
            status = "OK"
        elif down == 0 and up > 0 and seconds >= timeout:
            status = "LIKELY_BLOCKED"
        else:
            status = "FAIL"
        return {"label": None, "status": status, "code": code, "reason": None,
                "up_bytes": up, "down_bytes": down, "seconds": seconds}
    if exit_code == 0:
        return {"label": None, "status": "OK", "code": "NA", "reason": None,
                "up_bytes": 0, "down_bytes": 0, "seconds": None}
    return {"label": None, "status": "FAIL", "code": "NA", "reason": "exit",
            "up_bytes": 0, "down_bytes": 0, "seconds": None}


def dpi_suite_targets(entries, custom_host=None):
    """Validate untrusted suite data. Returns only entries with safe hosts."""
    if custom_host is not None:
        if not validate_host(custom_host):
            raise ValueError("Неподдерживаемый пользовательский host для DPI-теста")
        return [{"id": "CUSTOM", "provider": "Пользовательский", "country": "", "host": custom_host}]
    result = []
    for entry in entries or []:
        if len(result) >= MAX_TARGETS:
            break
        if not isinstance(entry, dict):
            continue
        host, identifier = entry.get("host"), entry.get("id")
        if not validate_host(host) or not isinstance(identifier, str) or not identifier:
            continue
        provider = entry.get("provider") if isinstance(entry.get("provider"), str) else ""
        country = entry.get("country") if isinstance(entry.get("country"), str) else ""
        result.append({"id": identifier[:128], "provider": provider[:128],
                       "country": country[:16], "host": host})
    return result


def fetch_dpi_suite(url=DEFAULT_DPI_SUITE_URL, timeout=5.0):
    """User-triggered fetch of the DPI suite. Failure yields a warning, not a crash."""
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read(MAX_LIST_BYTES).decode("utf-8"))
    except Exception as error:
        return [], f"Набор DPI-целей не получен ({error}); доступен собственный host"
    if not isinstance(data, list):
        return [], "Набор DPI-целей имеет неожиданный формат; доступен собственный host"
    return data, None


def default_execute(argv, timeout):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "probe timeout"


def public_suite_execute(argv, timeout):
    """Pin an untrusted suite host to a globally routable DNS answer.

    No redirects are requested by the fixed probe plan; bypass proxies so they
    cannot re-resolve a checked hostname into a private destination.
    """
    parsed = urlsplit(argv[-1])
    if parsed.scheme != "https" or not validate_host(parsed.hostname):
        raise ValueError("DPI-набор: нужен публичный HTTPS host")
    answers = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    addresses = [ipaddress.ip_address(answer[4][0]) for answer in answers]
    if not addresses or any(not address.is_global or address.is_multicast for address in addresses):
        raise ValueError("DPI-набор: DNS содержит непубличный адрес; проба отклонена")
    address = addresses[0]
    literal = f"[{address}]" if address.version == 6 else str(address)
    pinned = argv[:-1] + ["--noproxy", "*", "--resolve", f"{parsed.hostname}:443:{literal}", argv[-1]]
    return default_execute(pinned, timeout)


def count_outcomes(entry, test_type):
    counts = {"OK": 0, "SSL": 0, "ERROR": 0, "UNSUP": 0, "PingOK": 0, "PingFail": 0,
              "FAIL": 0, "UNSUPPORTED": 0, "LIKELY_BLOCKED": 0, "CANCELLED": 0}
    for target in entry.get("targets", []):
        for probe in target.get("probes", []):
            counts[probe["status"]] = counts.get(probe["status"], 0) + 1
        for ping in target.get("pings", []):
            if ping["status"] == "OK":
                counts["PingOK"] += 1
            elif ping["status"] in ("TIMEOUT", "CANCELLED"):
                counts["PingFail"] += 1
    if test_type != "standard":
        for key in ("SSL", "UNSUP", "PingOK", "PingFail"):
            counts.pop(key, None)
    else:
        for key in ("FAIL", "UNSUPPORTED", "LIKELY_BLOCKED"):
            counts.pop(key, None)
    counts.pop("CANCELLED", None)
    return counts


def summarize(report):
    analytics = {"strategies": {}, "best": None}
    for entry in report.get("strategies", []):
        counts = count_outcomes(entry, report.get("type", "standard"))
        entry["counts"] = counts
        analytics["strategies"][entry["name"]] = counts
    best, best_key = None, None
    for entry in report.get("strategies", []):
        if report.get("cancelled") or entry.get("error"):
            continue
        counts = entry.get("counts", {})
        ok = counts.get("OK", 0)
        ping_ok = counts.get("PingOK", 0)
        blocked = counts.get("LIKELY_BLOCKED", 0)
        key = (ok, ping_ok, -blocked)
        if best_key is None or key > best_key:
            best, best_key = entry["name"], key
    analytics["best"] = best
    return analytics


class TesterSession:
    """One explicit test run. The runner interface owns every privileged change."""

    def __init__(self, *, strategies, targets, test_type="standard", runner=None,
                 execute=None, sleep=None, cancel_event=None, progress=None,
                 init_wait=5.0, max_parallel=8, range_bytes=65536, dpi_targets=(),
                 dpi_timeout=5.0, payload_path=None, curl_path=None, ping_path=None):
        if test_type not in ("standard", "dpi"):
            raise ValueError("Неподдерживаемый тип теста")
        self.strategies = list(strategies)
        self.targets = list(targets)
        self.test_type = test_type
        self.runner = runner
        self.mode = "strategies" if self.strategies and runner is not None else "baseline"
        self.execute = execute or default_execute
        self.sleep = sleep or time.sleep
        self.cancel_event = cancel_event
        self.progress = progress
        self.init_wait = float(init_wait)
        self.max_parallel = max(1, int(max_parallel))
        self.range_bytes = int(range_bytes)
        self.dpi_targets = list(dpi_targets)
        self.dpi_timeout = float(dpi_timeout)
        self.payload_path = Path(payload_path) if payload_path is not None else None
        self.curl_path = curl_path
        self.ping_path = ping_path

    def cancelled(self):
        return bool(self.cancel_event and self.cancel_event.is_set())

    def progress_event(self, event):
        if self.progress is not None:
            try:
                self.progress(event)
            except Exception:
                pass

    def wait_init(self):
        remaining = self.init_wait
        while remaining > 0:
            if self.cancelled():
                return
            step = min(0.5, remaining)
            self.sleep(step)
            remaining -= step

    def run(self):
        if self.test_type == "dpi" and (self.payload_path is None or not self.payload_path.is_file()):
            raise ValueError("Не удалось подготовить файл данных DPI-теста")
        report = {"type": self.test_type, "mode": self.mode, "started_at": now_iso(),
                  "cancelled": False, "restore_error": None, "warnings": [],
                  "dpi_license": DPI_SUITE_LICENSE if self.test_type == "dpi" else None,
                  "dpi_targets": list(self.dpi_targets), "strategies": []}
        snapshot = None
        try:
            if self.runner is not None:
                snapshot = self.runner.snapshot()
            names = self.strategies or ["baseline"]
            total = len(names)
            try:
                for index, name in enumerate(names):
                    if self.cancelled():
                        report["cancelled"] = True
                        report["strategies"].append(self._cancelled_entry(name))
                        continue
                    entry = {"name": name, "error": None, "seconds": None, "targets": []}
                    report["strategies"].append(entry)
                    self.progress_event({"event": "strategy", "name": name, "index": index, "total": total})
                    started = time.monotonic()
                    try:
                        if self.runner is not None:
                            self.runner.start(name)
                            self.wait_init()
                        self.probe_targets(entry)
                    except Exception as error:
                        entry["error"] = str(error)
                    finally:
                        if self.runner is not None:
                            self.safe_stop(report, self.runner)
                    entry["seconds"] = round(time.monotonic() - started, 2)
            finally:
                if self.runner is not None:
                    try:
                        self.runner.restore(snapshot)
                    except Exception as error:
                        report["restore_error"] = str(error)
            report["cancelled"] = report["cancelled"] or self.cancelled()
            report["finished_at"] = now_iso()
            analytics = summarize(report)
            report["analytics"] = analytics
            report["best"] = analytics["best"]
        finally:
            if self.test_type == "dpi" and self.payload_path is not None:
                try:
                    self.payload_path.unlink(missing_ok=True)
                except OSError:
                    pass
        self.progress_event({"event": "done"})
        return report

    @staticmethod
    def safe_stop(report, runner):
        try:
            runner.stop()
        except Exception as error:
            report["warnings"].append(f"Остановка тестового nfqws: {error}")

    def _cancelled_entry(self, name):
        # The normal jobs check cancellation before each probe, retaining exact
        # target names/types (including ping-only targets) without doing I/O.
        jobs = ([self._dpi_job(spec) for spec in self.dpi_target_specs()] if self.test_type == "dpi"
                else [self._standard_job(target) for target in self.targets])
        targets = [job() for job in jobs]
        return {"name": name, "error": None, "seconds": None, "targets": targets}

    def run_probe(self, argv, timeout):
        started = time.monotonic()
        exit_code, stdout, stderr = self.execute(argv, timeout)
        return exit_code, stdout, stderr, round(time.monotonic() - started, 2)

    def probe_targets(self, entry):
        if self.test_type == "dpi":
            jobs = [self._dpi_job(spec) for spec in self.dpi_target_specs()]
        else:
            jobs = [self._standard_job(target) for target in self.targets]
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_parallel, max(1, len(jobs))))
        futures = []
        try:
            for job in jobs:
                futures.append(executor.submit(job))
            collected = [future.result() for future in futures]
        finally:
            # Never restore the runner while a worker might still be probing.
            executor.shutdown(wait=True, cancel_futures=True)
        entry["targets"] = collected
        self.progress_event({"event": "probes", "name": entry["name"], "count": len(collected)})

    def dpi_target_specs(self):
        specs = []
        if self.dpi_targets:
            for target in self.dpi_targets:
                specs.append({**target, "label": f"[{target.get('country', '')}] {target['id']} ({target.get('provider', '')})".strip(),
                              "host": target["host"], "url": None, "ping": None})
        else:
            for target in self.targets:
                if target.get("url"):
                    specs.append({"label": target["name"], "host": urlsplit(target["url"]).hostname,
                                  "url": None, "ping": None})
        return specs

    def _standard_job(self, target):
        def task():
            probes, pings = [], []
            if target.get("url"):
                for label, argv in http_probe_plan(self.curl_path, target["url"]):
                    if self.cancelled():
                        probes.append(self.cancelled_probe(label))
                        continue
                    try:
                        exit_code, stdout, stderr, seconds = self.run_probe(argv, 8.0)
                    except Exception as error:
                        probes.append({"label": label, "status": "ERROR", "code": "NA",
                                       "reason": str(error), "up_bytes": 0, "down_bytes": 0,
                                       "seconds": None})
                        continue
                    outcome = classify_http(label, exit_code, stdout, stderr)
                    outcome["up_bytes"], outcome["down_bytes"] = 0, 0
                    outcome["seconds"] = seconds
                    probes.append(outcome)
            if target.get("ping"):
                if self.cancelled():
                    return {"name": target["name"], "url": target.get("url"), "ping": target["ping"],
                            "probes": probes, "pings": [{"host": target["ping"], "status": "CANCELLED", "avg_ms": None}]}
                argv, timeout = ping_probe_plan(self.ping_path, target["ping"])
                try:
                    exit_code, stdout, stderr, seconds = self.run_probe(argv, timeout)
                    outcome = classify_ping(target["ping"], exit_code, stdout)
                except Exception as error:
                    outcome = {"host": target["ping"], "status": "TIMEOUT", "avg_ms": None,
                               "reason": str(error)}
                pings.append(outcome)
            return {"name": target["name"], "url": target.get("url"), "ping": target.get("ping"),
                    "probes": probes, "pings": pings}
        return task

    def _dpi_job(self, spec):
        def task():
            probes = []
            for label, argv in dpi_probe_plan(self.curl_path, spec["host"], self.payload_path,
                                              self.range_bytes, self.dpi_timeout):
                if self.cancelled():
                    probes.append(self.cancelled_probe(label))
                    continue
                try:
                    exit_code, stdout, stderr, seconds = self.run_probe(argv, self.dpi_timeout + 8.0)
                except Exception as error:
                    probes.append({"label": label, "status": "FAIL", "code": "NA", "reason": str(error),
                                   "up_bytes": 0, "down_bytes": 0, "seconds": None})
                    continue
                outcome = classify_dpi(exit_code, stdout, stderr, self.dpi_timeout)
                outcome["label"] = label
                outcome["elapsed_seconds"] = seconds
                probes.append(outcome)
            return {"name": spec["label"], "id": spec.get("id"), "provider": spec.get("provider"), "country": spec.get("country"),
                    "host": spec["host"], "probes": probes, "pings": []}
        return task

    @staticmethod
    def cancelled_probe(label):
        return {"label": label, "status": "CANCELLED", "code": "NA", "reason": None,
                "up_bytes": 0, "down_bytes": 0, "seconds": None}

def _require_report(report):
    if not isinstance(report, dict) or "strategies" not in report or not report.get("started_at"):
        raise ValueError("Сначала выполните тестирование")


def _atomic_write(target, encoded, prefix):
    target = Path(target)
    if not target.is_absolute() or target.is_dir():
        raise ValueError("Выберите абсолютный путь файла отчёта")
    if target.is_symlink():
        raise OSError("Экспорт в symlink не допускается")
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return target


def _kb(value):
    return f"{value / 1024:.1f}"


def format_text(report):
    """Readable report without touching the filesystem."""
    _require_report(report)
    lines = [f"Тест стратегий · тип {report['type']} · режим {report['mode']}",
             f"Начало: {report['started_at']}",
             f"Завершение: {report['finished_at']}"]
    if report.get("cancelled"):
        lines.append("Прогон прерван пользователем; результаты неполные.")
    if report.get("restore_error"):
        lines.append(f"ОШИБКА ВОССТАНОВЛЕНИЯ: {report['restore_error']}")
    lines.extend(report.get("warnings", []))
    if report.get("dpi_license"):
        lines.append(report["dpi_license"])
    if report.get("dpi_targets"):
        lines.append(f"DPI-целей: {len(report['dpi_targets'])}")
    for entry in report.get("strategies", []):
        lines.append(f"Config: {entry['name']} (Type: {report['type']})")
        if entry.get("error"):
            lines.append(f"  ОШИБКА ЗАПУСКА: {entry['error']}")
        for item in entry.get("targets", []):
            if report["type"] == "standard":
                probes = " ".join(f"{probe['label']}:{probe['status']}" for probe in item.get("probes", []))
                pings = []
                for ping in item.get("pings", []):
                    value = f"{ping['avg_ms']:.1f} ms" if ping.get("avg_ms") is not None else ping["status"]
                    pings.append(value)
                lines.append(f"  {item['name']} : {probes} | Ping: {', '.join(pings)}")
            else:
                heading = f"  Target: [{item.get('country', '')}] {item.get('id') or item.get('name') or '?'}"
                heading += f" ({item.get('provider')})" if item.get("provider") else ""
                lines.append(heading)
                for probe in item.get("probes", []):
                    lines.append(f"    {probe['label']}: code={probe['code']}  up={_kb(probe['up_bytes'])} KB"
                                 f"  down={_kb(probe['down_bytes'])} KB  time={probe['seconds']}s"
                                 f"  status={probe['status']}")
    lines.append("=== ANALYTICS ===")
    analytics = report.get("analytics") or {}
    entries = analytics.get("strategies") if isinstance(analytics, dict) else None
    for name, counts in (entries or {}).items():
        if "PingOK" in counts:
            lines.append(f"{name} : HTTP OK: {counts.get('OK', 0)}, SSL: {counts.get('SSL', 0)},"
                         f" ERR: {counts.get('ERROR', 0)}, UNSUP: {counts.get('UNSUP', 0)},"
                         f" Ping OK: {counts.get('PingOK', 0)}, Fail: {counts.get('PingFail', 0)}")
        else:
            lines.append(f"{name} : OK: {counts.get('OK', 0)}, FAIL: {counts.get('FAIL', 0)},"
                         f" UNSUP: {counts.get('UNSUPPORTED', 0)}, BLOCKED: {counts.get('LIKELY_BLOCKED', 0)}")
    if report.get("best"):
        lines.append(f"Best strategy: {report['best']}")
        lines.append("Рекомендация информационная: профиль применяется только вручную через «Стратегию».")
    return "\n".join(lines) + "\n"


def export_text(report, target):
    encoded = format_text(report).encode("utf-8")
    written = _atomic_write(target, encoded, ".strategy-test-export-")
    return {"target": str(written), "size": len(encoded)}


def export_json(report, target):
    _require_report(report)
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    written = _atomic_write(target, encoded, ".strategy-test-export-")
    return {"target": str(written), "size": len(encoded)}
