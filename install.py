#!/usr/bin/env python3
"""Offline-capable systemd installer. Only the standard library is required."""

import argparse
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid


APP = "zapret-discord-youtube"
SERVICE = "zapret_discord_youtube.service"
MARKER = "zapret-system-installer-v1\n"
UNIT_HEADER = "# Managed by zapret-system-installer-v1\n"
USER_LISTS = ("ipset-exclude-user.txt", "list-general-user.txt", "list-exclude-user.txt")


def load_strategy_sync():
    # Load only this installer's trusted local implementation, never a stage script.
    path = Path(__file__).resolve().parent / "src/lib/strategy_sync.py"
    spec = importlib.util.spec_from_file_location("zapret_strategy_sync", path)
    module = importlib.util.module_from_spec(spec)
    # Do not create __pycache__ in an otherwise immutable installed release.
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_ipset_mode():
    # Only this installer's local trusted code, never candidate/staged Python.
    path = Path(__file__).resolve().parent / "src/lib/ipset_mode.py"
    spec = importlib.util.spec_from_file_location("zapret_ipset_mode", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_fake_select():
    # Only this installer's local trusted code, never candidate/staged Python.
    path = Path(__file__).resolve().parent / "src/lib/fake_select.py"
    spec = importlib.util.spec_from_file_location("zapret_fake_select", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


class Systemd:
    def unit_exists(self):
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", SERVICE],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip() != "not-found"

    def is_active(self):
        return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", SERVICE], check=False).returncode == 0

    def is_enabled(self):
        return subprocess.run(["/usr/bin/systemctl", "is-enabled", "--quiet", SERVICE], check=False).returncode == 0

    def run(self, *args):
        subprocess.run(["/usr/bin/systemctl", *args], check=True)


class OfflineSystemd:
    """A staged filesystem must never contact the host service manager."""

    def is_active(self):
        return False

    def unit_exists(self):
        return False

    def is_enabled(self):
        return False

    def run(self, *args):
        print("offline systemd:", *args)


def atomic_write(path, content, mode=0o644):
    fd, name = tempfile.mkstemp(prefix=".install-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def copy_entry(parent_fd, name, destination):
    """Copy through anchored descriptors: never follow a source symlink or FIFO."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    except OSError as error:
        raise ValueError(f"Cannot safely open {name}: {error}") from error
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            destination.mkdir(mode=0o755)
            with os.scandir(fd) as entries:
                for entry in entries:
                    copy_entry(fd, entry.name, destination / entry.name)
        elif stat.S_ISREG(info.st_mode):
            with os.fdopen(os.dup(fd), "rb") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target)
            destination.chmod(0o755 if name.endswith(".sh") or name == "nfqws" else 0o644)
        else:
            raise ValueError(f"Unsupported source entry: {name}")
    except OSError as error:
        raise ValueError(f"Cannot safely copy {name}: {error}") from error
    finally:
        os.close(fd)


@contextlib.contextmanager
def package_snapshot(source, temporary_parent=None):
    """Do not execute the source's scripts, binaries or configuration as root."""
    source = Path(source).absolute()
    try:
        fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError(f"Invalid source directory: {source}") from error
    try:
        with tempfile.TemporaryDirectory(prefix=".package-", dir=temporary_parent) as temporary:
            package = Path(temporary)
            names = set(os.listdir(fd))
            for name in ("service.sh", "src", "custom-strategies", "zapret-latest", "nfqws"):
                if name not in names:
                    raise ValueError(f"Missing {name}; prepare dependencies in the checkout first")
                try:
                    copy_entry(fd, name, package / name)
                except OSError as error:
                    raise ValueError(f"Unsafe source entry: {name}") from error
            for name in ("conf.env", "user-lists"):
                if name in names:
                    copy_entry(fd, name, package / name)
            for name in ("service.sh", "nfqws", "src/lib/common.sh", "src/lib/paths.sh"):
                if not (package / name).is_file():
                    raise ValueError(f"Invalid package: {name} must be a regular file")
            for name in ("src", "custom-strategies", "zapret-latest", "zapret-latest/lists"):
                if not (package / name).is_dir():
                    raise ValueError(f"Invalid package: {name} must be a directory")
            lists = package / "user-lists"
            if lists.exists():
                if not lists.is_dir():
                    raise ValueError("User lists must be regular .txt files with simple filenames")
                for entry in lists.iterdir():
                    if not entry.is_file() or not re.fullmatch(r"[a-zA-Z0-9_.-]+\.txt(?:\.backup)?", entry.name):
                        raise ValueError("User lists must be regular .txt files with simple filenames")
                    if entry.name.endswith(".txt.backup"):
                        if entry.name == "ipset-all.txt.backup" and not (lists / "ipset-loaded.txt").exists():
                            try:
                                loaded = load_ipset_mode().inspect_list(entry)
                            except ValueError:
                                loaded = None
                            if loaded and loaded["kind"] == "loaded":
                                # Preserve a valid legacy saved set in permanent
                                # data; change only this private snapshot copy.
                                entry.rename(lists / "ipset-loaded.txt")
                                continue
                        # Legacy ipswitch backups are not runtime lists. Remove
                        # only this private snapshot copy, never the source file.
                        entry.unlink()
            yield package
    finally:
        os.close(fd)


def valid_game_filter_ports(value):
    # Keep this standalone installer check aligned with the runtime validator.
    if (not isinstance(value, str) or not 0 < len(value) <= 512
            or len(value.split(",")) > 128
            or not re.fullmatch(r"[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?(?:,[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?)*", value)):
        return False
    for item in value.split(","):
        bounds = [int(part) for part in item.split("-")]
        if max(bounds) > 65535 or bounds[0] > bounds[-1]:
            return False
    return True


def validate_config(config, release, validate_ipset=True, validate_fakes=True):
    if not config.is_file():
        raise ValueError("A valid conf.env is required before installation")
    values = {}
    for line in config.read_bytes().decode("utf-8").split("\n"):
        line = line.removesuffix("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError("Invalid or duplicate configuration key")
        if key == "interface":
            valid = re.fullmatch(r"[a-zA-Z0-9_.:-]+", value)
        elif key in ("gamefiltertcp", "gamefilterudp"):
            valid = value in ("true", "false")
        elif key in ("gamefiltertcp_ports", "gamefilterudp_ports"):
            valid = valid_game_filter_ports(value)
        elif key == "ipset_mode":
            valid = value in ("legacy", "loaded", "none", "any")
        elif key in ("fakediscord", "fakegameudp"):
            valid = value == "" or re.fullmatch(r"[0-9a-f]{64}", value)
        elif key == "strategy":
            valid = re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*\.bat", value)
        elif key == "firewall_backend":
            backends = {re.sub(r"^\d{2}-", "", item.stem)
                        for item in (release / "src/firewall-backends").glob("*.sh")}
            valid = re.fullmatch(r"[a-zA-Z0-9_-]+", value) and (value == "auto" or value in backends)
        else:
            valid = False
        if not valid:
            raise ValueError(f"Invalid configuration value for {key}")
        values[key] = value
    if not {"interface", "gamefiltertcp", "gamefilterudp", "strategy"} <= values.keys():
        raise ValueError("Missing required configuration keys")
    if (any(key in values for key in ("gamefiltertcp_ports", "gamefilterudp_ports"))
            and "# game filter ranges v1" not in (release / "src/lib/common.sh").read_text()):
        raise ValueError("Candidate runtime does not support custom Game Filter ranges; update the adapter first")
    if not any((release / folder / values["strategy"]).is_file()
               for folder in ("custom-strategies", "zapret-latest")):
        raise ValueError("Configured strategy is absent from the candidate release")
    if "ipset_mode" in values:
        if "# ipset mode v1" not in (release / "src/lib/common.sh").read_text():
            raise ValueError("Candidate runtime does not support IPSet modes; update the adapter first")
        if validate_ipset:
            load_ipset_mode().resolve_list(values["ipset_mode"], release / "zapret-latest", config.parent / "user-lists")
    if any(key in values for key in ("fakediscord", "fakegameudp")):
        if "# active fakes v1" not in (release / "src/lib/common.sh").read_text():
            raise ValueError("Candidate runtime does not support active fake selection; update the adapter first")
        if validate_fakes:
            load_fake_select().resolve(release / "zapret-latest", config.parent, values)
    return values


class Installer:
    def ipset_state(self, config, release):
        return load_ipset_mode().describe(config.get("ipset_mode", "legacy"), release / "zapret-latest", self.data / "user-lists")

    def fake_state(self, config, release):
        return load_fake_select().describe(release / "zapret-latest", self.data, config)

    def __init__(self, root=Path("/"), systemd=None):
        requested_root = Path(root).absolute()
        for entry in (requested_root, *requested_root.parents):
            if entry.is_symlink():
                raise ValueError(f"Target root must not use symlinks: {entry}")
        self.root = requested_root.resolve(strict=True)
        if requested_root != Path("/") and self.root == Path("/"):
            raise ValueError("An offline root must not resolve to the host root")
        self.live = self.root == Path("/")
        if self.live and os.geteuid() != 0:
            raise ValueError("Live installation requires root; use --root for offline staging")
        if self.live and (not Path("/run/systemd/system").is_dir()
                          or not Path("/usr/bin/systemctl").is_file()
                          or not Path("/usr/bin/systemd-notify").is_file()):
            raise ValueError("Live installation currently supports running systemd systems only")
        if not self.root.is_dir():
            raise ValueError("The target root must already exist")
        self.systemd = systemd or (Systemd() if self.live else OfflineSystemd())
        self.app = self.root / "opt" / APP
        self.data = self.root / "etc" / APP
        self.state_dir = self.root / "var/lib" / APP
        self.unit = self.root / "etc/systemd/system" / SERVICE
        self.current = self.app / "current"
        self.releases = self.app / "releases"
        self.state_file = self.state_dir / "state.json"

    def check_path(self, path):
        # Check parents too: a root-owned file under a writable parent is unsafe.
        for entry in reversed((path, *path.parents)):
            if not os.path.lexists(entry):
                continue
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"Destination symlink is not allowed: {entry}")
            if self.live and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError(f"Destination must be root-owned and not group/world writable: {entry}")

    def check_tree(self, directory, allow_current=False):
        self.check_path(directory)
        if not directory.exists():
            return
        for parent, directories, files in os.walk(directory, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                if allow_current and path == self.current:
                    continue
                self.check_path(path)
                if not path.is_dir() and not path.is_file():
                    raise ValueError(f"Unexpected installed entry: {path}")

    def managed_directory(self, path, mode=0o755):
        self.check_path(path)
        marker = path / ".managed"
        if path.exists() and any(path.iterdir()):
            if not marker.is_file() or marker.read_text() != MARKER:
                raise ValueError(f"Refusing to adopt an unmanaged directory: {path}")
        # Explicit modes also for newly created parents, irrespective of root's umask.
        missing = []
        parent = path
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for entry in reversed(missing):
            entry_mode = mode if entry == path else 0o755
            entry.mkdir(mode=entry_mode)
            entry.chmod(entry_mode)
        if not marker.exists():
            atomic_write(marker, MARKER.encode())

    @contextlib.contextmanager
    def operation(self):
        for path in (self.app, self.data, self.state_dir, self.unit):
            self.check_path(path)
        for path in (self.app, self.data, self.state_dir):
            self.check_tree(path, allow_current=path == self.app)
        if self.unit.exists() and not self.unit.read_text().startswith(UNIT_HEADER):
            raise ValueError(f"Refusing to replace an unmanaged unit: {self.unit}")
        self.managed_directory(self.state_dir, 0o700)
        lock_path = self.state_dir / ".install.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError("Another installation operation is in progress") from error
            previous_umask = os.umask(0o022)
            try:
                yield
            finally:
                os.umask(previous_umask)

    def release(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise ValueError("Invalid release identifier")
        path = self.releases / identifier
        self.check_tree(path)
        if not (path / ".system-install").is_file() or (path / ".system-install").read_text() != MARKER:
            raise ValueError("Release is not managed by this installer")
        return path

    def state(self):
        if not self.state_file.exists():
            if os.path.lexists(self.current) or self.unit.exists():
                raise ValueError("Installation metadata is missing; refusing to adopt existing files")
            return None
        state = json.loads(self.state_file.read_text())
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ValueError("Unknown installation metadata schema")
        self.release(state.get("current"))
        if state.get("previous") is not None:
            self.release(state["previous"])
        if not self.current.is_symlink() or os.readlink(self.current) != f'releases/{state["current"]}':
            raise ValueError("Current release does not match metadata")
        return state

    def switch(self, identifier):
        self.release(identifier)
        link = self.app / (".current-" + uuid.uuid4().hex)
        try:
            link.symlink_to("releases/" + identifier)
            os.replace(link, self.current)
        finally:
            link.unlink(missing_ok=True)

    def unit_content(self):
        return (UNIT_HEADER + f"""[Unit]
Description=Zapret Discord YouTube
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/{APP}/conf.env

[Service]
Type=notify
NotifyAccess=all
User=root
WorkingDirectory=/opt/{APP}/current
ExecStart=/bin/bash /opt/{APP}/current/service.sh daemon
ExecStop=/bin/bash /opt/{APP}/current/service.sh kill
ExecStopPost=/bin/bash /opt/{APP}/current/service.sh kill
KillMode=control-group
TimeoutStopSec=20
TimeoutStartSec=45
Restart=on-failure
RestartSec=3
UMask=0022
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
""").encode()

    def backup(self):
        if not self.data.exists():
            return
        directory = self.state_dir / "backups" / uuid.uuid4().hex
        directory.mkdir(parents=True, mode=0o700)
        fd = os.open(self.data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in ("conf.env", "user-lists"):
                if (self.data / name).exists():
                    copy_entry(fd, name, directory / name)
        finally:
            os.close(fd)

    def activate(self, identifier, old, start=False):
        active = self.systemd.is_active()
        enabled = self.systemd.is_enabled()
        old_unit = self.unit.read_bytes() if self.unit.exists() else None
        new_state = {"schema": 1, "current": identifier,
                     "previous": old["current"] if old else None}
        enable_attempted = False
        try:
            if active:
                self.systemd.run("stop", SERVICE)
            self.switch(identifier)
            self.unit.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self.unit, self.unit_content())
            self.systemd.run("daemon-reload")
            if start and not enabled:
                enable_attempted = True
                self.systemd.run("enable", SERVICE)
            if active or start:
                self.systemd.run("start", SERVICE)
                if not self.systemd.is_active():
                    raise RuntimeError("Service did not become active")
            atomic_write(self.state_file, (json.dumps(new_state) + "\n").encode(), 0o600)
        except BaseException as error:
            try:
                # Stop the candidate BEFORE restoring current: ExecStop uses it.
                self.systemd.run("stop", SERVICE)
                # disable needs the candidate unit file to remove its [Install]
                # symlinks. Do this before unlinking/restoring the unit itself.
                if enable_attempted:
                    self.systemd.run("disable", SERVICE)
                if old:
                    self.switch(old["current"])
                else:
                    self.current.unlink(missing_ok=True)
                if old_unit is None:
                    self.unit.unlink(missing_ok=True)
                else:
                    atomic_write(self.unit, old_unit)
                self.systemd.run("daemon-reload")
                if active:
                    # Failed candidates/rapid updates can exhaust StartLimitBurst.
                    # Reset only for the explicit recovery, never disable the limit.
                    self.systemd.run("reset-failed", SERVICE)
                    self.systemd.run("start", SERVICE)
            except Exception as recovery:
                raise RuntimeError(f"Activation failed; recovery also failed: {recovery}. Inspect current/unit/state before retrying.") from error
            raise

    def deploy(self, source, update=False, start=False):
        with self.operation():
            old = self.state()
            if bool(old) != update:
                raise ValueError("Use update for an installed instance, install for a new instance")
            if not old and self.systemd.unit_exists():
                raise ValueError("A systemd unit with this name already exists; refusing to replace a vendor/transient service")
            # Never trust root's inherited TMPDIR for a privileged package snapshot.
            with package_snapshot(source, self.state_dir) as package:
                config = self.data / "conf.env"
                validate_config(config if config.exists() else package / "conf.env", package)
                self.managed_directory(self.app)
                self.managed_directory(self.data)
                self.backup()
                if not config.exists():
                    atomic_write(config, (package / "conf.env").read_bytes(), 0o640)
                lists = self.data / "user-lists"
                lists.mkdir(exist_ok=True, mode=0o755)
                initial_lists = package / "user-lists"
                if initial_lists.is_dir():
                    for entry in initial_lists.iterdir():
                        if not entry.is_file() or entry.suffix != ".txt":
                            raise ValueError("User lists must be regular .txt files")
                        if not (lists / entry.name).exists():
                            atomic_write(lists / entry.name, entry.read_bytes())
                for name in USER_LISTS:
                    if not (lists / name).exists():
                        atomic_write(lists / name, b"")
                self.publish(package, old, Path(__file__).read_bytes(), start)

    def publish(self, package, old, installer_code, start=False, validator=None):
        self.releases.mkdir(exist_ok=True, mode=0o755)
        identifier = uuid.uuid4().hex
        destination = self.releases / identifier
        destination.mkdir(mode=0o755)
        try:
            fd = os.open(package, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for name in ("service.sh", "src", "custom-strategies", "zapret-latest", "nfqws"):
                    copy_entry(fd, name, destination / name)
            finally:
                os.close(fd)
            atomic_write(destination / ".system-install", MARKER.encode())
            atomic_write(destination / "install.py", installer_code)
            if validator is not None:
                validator(destination)
            self.activate(identifier, old, start)
        except BaseException:
            # Keep the candidate if recovery failed and it is still current.
            if not self.current.is_symlink() or os.readlink(self.current) != f"releases/{identifier}":
                shutil.rmtree(destination)
            raise

    def apply_strategies(self, stage, digest, confirmed=False):
        if not confirmed:
            raise ValueError("Applying strategies requires explicit --yes approval and the prepared stage digest")
        sync = load_strategy_sync()
        with self.operation():
            old = self.state()
            if not old:
                raise ValueError("Strategy-only updates require an existing managed installation")
            current = self.release(old["current"])
            if (not (current / "src/lib/strategy_sync.py").is_file()
                    or "# synchronized profile runtime v1" not in (current / "src/lib/common.sh").read_text()):
                raise ValueError("Update the adapter code once before enabling strategy synchronization")
            manifest, files = sync.load_stage(stage, digest)
            compiled = sync.compile_payload(files)
            provenance = {"schema": 1, "repository": sync.REPOSITORY, "revision": manifest["revision"],
                          "tag": manifest.get("tag"), "channel": manifest["channel"], "stage_digest": digest}
            existing = current / "zapret-latest" / sync.PROVENANCE
            if existing.is_file() and json.loads(existing.read_text()).get("stage_digest") == digest:
                return
            config = validate_config(self.data / "conf.env", current)
            if (current / "custom-strategies" / config["strategy"]).is_file():
                raise ValueError("Selected custom strategy cannot be automatically validated; select a Flowseal profile first")
            with package_snapshot(current, self.state_dir) as package:
                # This is a private snapshot, never the current release or user data.
                shutil.rmtree(package / "zapret-latest")
                sync.write_catalog(package / "zapret-latest", files, compiled, provenance)
                validate_config(self.data / "conf.env", package)
                sync.validate_catalog(package / "nfqws", package / "zapret-latest", compiled,
                                      self.data / "user-lists", private=True,
                                      tcp_range=config.get("gamefiltertcp_ports", "1024-65535"),
                                      udp_range=config.get("gamefilterudp_ports", "1024-65535"),
                                      ipset_mode=config.get("ipset_mode", "legacy"),
                                      fakes=load_fake_select().resolve(package / "zapret-latest",
                                                                       self.data, config))
                self.backup()
                def public_validation(candidate):
                    sync.validate_catalog(candidate / "nfqws", candidate / "zapret-latest", compiled,
                                          self.data / "user-lists",
                                          tcp_range=config.get("gamefiltertcp_ports", "1024-65535"),
                                          udp_range=config.get("gamefilterudp_ports", "1024-65535"),
                                          ipset_mode=config.get("ipset_mode", "legacy"),
                                          fakes=load_fake_select().resolve(candidate / "zapret-latest",
                                                                           self.data, config))
                self.publish(package, old, (current / "install.py").read_bytes(), validator=public_validation)

    def install(self, source, start=False):
        self.deploy(source, start=start)

    def update(self, source):
        self.deploy(source, update=True)

    def rollback(self):
        with self.operation():
            old = self.state()
            if not old or not old.get("previous"):
                raise ValueError("No previous release is available")
            validate_config(self.data / "conf.env", self.release(old["previous"]))
            self.backup()
            self.activate(old["previous"], old)

    def remove(self):
        with self.operation():
            old = self.state()
            if not old:
                raise ValueError("No managed installation is present")
            # Validate every directory before deleting any release.
            releases = [self.release(entry.name) for entry in self.releases.iterdir()]
            self.backup()
            active = self.systemd.is_active()
            enabled = self.systemd.is_enabled()
            old_unit = self.unit.read_bytes() if self.unit.exists() else None
            try:
                self.systemd.run("stop", SERVICE)
                self.systemd.run("disable", SERVICE)
                self.unit.unlink(missing_ok=True)
                self.systemd.run("daemon-reload")
            except BaseException as error:
                try:
                    if old_unit is not None:
                        atomic_write(self.unit, old_unit)
                    self.systemd.run("daemon-reload")
                    if enabled:
                        self.systemd.run("enable", SERVICE)
                    if active:
                        self.systemd.run("reset-failed", SERVICE)
                        self.systemd.run("start", SERVICE)
                except Exception as recovery:
                    raise RuntimeError(f"Removal failed; recovery also failed: {recovery}") from error
                raise
            self.current.unlink()
            self.state_file.unlink()
            for release in releases:
                shutil.rmtree(release)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "update", "rollback", "remove", "apply-strategies"))
    parser.add_argument("--source", type=Path, default=Path(__file__).absolute().parent,
                        help="prepared, reviewed checkout (install/update only)")
    parser.add_argument("--root", type=Path, default=Path("/"),
                        help="existing offline root; never contacts host systemd")
    parser.add_argument("--start", action="store_true", help="enable/start after initial live install")
    parser.add_argument("--stage", type=Path, help="prepared data-only strategy stage")
    parser.add_argument("--digest", help="SHA-256 digest printed by strategy preparation")
    parser.add_argument("--yes", action="store_true", help="approve applying this exact prepared stage")
    args = parser.parse_args()
    if args.start and (args.command != "install" or args.root.absolute() != Path("/")):
        parser.error("--start is only available for an initial live installation")
    if args.command == "apply-strategies" and (not args.stage or not args.digest or not args.yes):
        parser.error("apply-strategies requires --stage PATH --digest SHA256 --yes")
    try:
        installer = Installer(args.root)
        if args.command == "install":
            installer.install(args.source, start=args.start)
        elif args.command == "update":
            installer.update(args.source)
        elif args.command == "apply-strategies":
            installer.apply_strategies(args.stage, args.digest, confirmed=args.yes)
        else:
            getattr(installer, args.command)()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Installation error: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted. Check service status before retrying.\n")
    print(f"{args.command}: completed" + (" (offline filesystem only)" if not installer.live else ""))


if __name__ == "__main__":
    main()
