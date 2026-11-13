#!/usr/bin/env python3
"""Destructive synthetic-cache tests, ONLY in an explicitly marked disposable VM."""

import argparse
import json
import os
from pathlib import Path
import shutil

from vm_ipset_update_smoke import sha
from vm_smoke import active, require, run, table_present


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--acknowledge-disposable-vm", action="store_true", required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not Path("/var/tmp/zapret-vm-provisioned").is_file()
            or run("hostname").stdout.strip() != "zapret-integration"):
        parser.error("Only root in the explicitly marked disposable VM")
    source = args.source.resolve(strict=True)
    fixture = Path("/home/vmtest/discord-cache-fixture")
    require(not os.path.lexists(fixture), "no preexisting synthetic Discord home")
    before_rules = run("nft", "--stateless", "list", "ruleset").stdout
    before_hosts = sha("/etc/hosts")
    before_timestamps = Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes()
    user_code = r'''
import ctypes, importlib.util, json, os, subprocess, sys
from pathlib import Path
source, mode = Path(sys.argv[1]), sys.argv[2]
home = Path.home()
os.umask(0o022)
spec = importlib.util.spec_from_file_location("vm_cache_backend", source / "src/gui/backend.py")
backend_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend_module)
backend = backend_module.Backend(source)
manager = backend.discord_manager()
def check(condition, text):
    assert condition, text
    print("PASS:", text, flush=True)
def item(instance):
    return next(value for value in backend.scan_discord()["instances"] if value["id"] == instance)
def protected():
    return {str(path.relative_to(home)): path.read_bytes() for path in home.rglob("*")
            if path.is_file() and path.name in ("token", "Cookies", "settings.json", "keep")}
if mode == "exercise":
    paths = {"native-stable": home / ".config/discord", "native-ptb": home / ".config/discordptb",
             "native-canary": home / ".config/discordcanary", "native-development": home / ".config/discorddevelopment",
             "flatpak-stable": home / ".var/app/com.discordapp.Discord/config/discord",
             "snap-stable": home / "snap/discord/42/.config/discord"}
    for profile in paths.values():
        for name in ("Cache", "Code Cache", "GPUCache"):
            directory = profile / name / "nested"
            directory.mkdir(parents=True)
            (directory / "entry").write_bytes(b"synthetic cache")
        for name in ("Local Storage/leveldb/token", "Cookies", "settings.json", "Session Storage/keep"):
            path = profile / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic settings: must survive")
    (home / "snap/discord/current").symlink_to("42")
    outside = home / "outside-preserve"
    outside.mkdir()
    (outside / "keep").write_bytes(b"external sentinel")
    before = protected()
    report = backend.scan_discord()
    check(report["processes"]["state"] == "clear", "real procfs check initially clear")
    check(len(report["instances"]) == 6 and all(value["files"] == 3 for value in report["instances"]),
          "six supported synthetic layouts discovered without deletion")
    selected = item("native-stable")
    child = subprocess.Popen([sys.executable, "-c",
        "import ctypes,time; ctypes.CDLL(None).prctl(15,b'Discord',0,0,0); print('ready',flush=True); time.sleep(120)"], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        check(child.pid in backend.scan_discord()["processes"]["pids"], "real same-user Discord-named process is detected")
        try:
            backend.clean_discord(selected["id"], selected["token"])
        except ValueError:
            pass
        else:
            raise AssertionError("running process did not block cleanup")
        check(child.poll() is None and (paths["native-stable"] / "Cache/nested/entry").exists(),
              "blocked cleanup neither kills process nor deletes cache")
    finally:
        child.terminate()  # Only this fixture's child, never a discovered client.
        child.wait(timeout=10)
    selected = item("native-stable")
    result = backend.clean_discord(selected["id"], selected["token"])
    check(result["removed_files"] == 3 and not (paths["native-stable"] / "Cache").exists(), "confirmed backend cleans only selected native cache")
    check((paths["flatpak-stable"] / "Cache/nested/entry").exists() and protected() == before,
          "other instances and all synthetic tokens/settings survive")
    selected = item("native-ptb")
    (paths["native-ptb"] / "Cache/new").write_bytes(b"new cache")
    try:
        backend.clean_discord(selected["id"], selected["token"])
    except ValueError:
        pass
    else:
        raise AssertionError("stale confirmation was accepted")
    check((paths["native-ptb"] / "Cache/new").exists(), "changed cache invalidates old confirmation before deletion")
    link = paths["native-canary"] / "Cache/link"
    link.symlink_to(outside)
    check(item("native-canary")["token"] is None and (outside / "keep").read_bytes() == b"external sentinel",
          "symlink to outside data disables instance and preserves sentinel")
    link.unlink()
    selected = item("snap-stable")
    (home / "snap/discord/current").unlink()
    (home / "snap/discord/current").symlink_to("../../.config")
    try:
        backend.clean_discord(selected["id"], selected["token"])
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe Snap revision accepted")
    check((paths["snap-stable"] / "Cache/nested/entry").exists(), "Snap current escape does not touch previous revision")
    (home / "snap/discord/current").unlink()
    (home / "snap/discord/current").symlink_to("42")
    # Post-unlink error: honest partial result and safe restoration of remainder.
    manager = backend.discord_manager()
    original_delete = manager.delete_tree
    def injected(parent, name, node, counts):
        original_delete(parent, name, node, counts)
        if counts["removed_files"]:
            raise OSError("VM synthetic post-unlink failure")
    selected = manager.preview("native-development")
    manager.delete_tree = injected
    try:
        manager.clean("native-development", selected["token"])
    except RuntimeError as error:
        assert "удалено файлов: 1" in str(error), str(error)
    else:
        raise AssertionError("injected failure did not occur")
    check((paths["native-development"] / "Code Cache/nested/entry").exists() and protected() == before,
          "partial failure reports deleted count and restores nondeleted cache without touching settings")
    for instance in paths:
        selected = item(instance)
        backend.clean_discord(instance, selected["token"])
    check(all(value["files"] == 0 for value in backend.scan_discord()["instances"]), "all selected synthetic variants can be cleaned independently")
    check(protected() == before, "all token/Cookies/settings/Session Storage and outside files still byte-identical")
    check(not list(home.rglob(".zapret-discord-cache-*")), "successful cleanup and recoverable failure leave no staging directories")
    selected = item("native-stable")
    check(backend.clean_discord(selected["id"], selected["token"])["removed_files"] == 0, "repeated empty cleanup is a no-op")
    cache = paths["native-stable"] / "Cache"
    cache.mkdir()
    (cache / "entry").write_text("mountpoint fixture")
elif mode == "mount":
    try:
        manager.preview("native-stable")
    except ValueError as error:
        assert "монтирован" in str(error), str(error)
    else:
        raise AssertionError("real same-filesystem bind mount was not rejected")
    check((home / "outside-preserve/keep").read_bytes() == b"external sentinel", "real bind mount detected without deleting outside data")
else:
    raise AssertionError("unknown mode")
'''
    def user(mode):
        result = run("runuser", "-u", "vmtest", "--", "env", "PYTHONDONTWRITEBYTECODE=1",
                     f"HOME={fixture}", f"XDG_CONFIG_HOME={fixture}/.config", "python3", "-B", "-c", user_code,
                     str(source), mode)
        print(result.stdout, end="", flush=True)
    mounted = False
    try:
        run("runuser", "-u", "vmtest", "--", "mkdir", "-m", "700", str(fixture))
        user("exercise")
        run("mount", "--bind", str(fixture / "outside-preserve"), str(fixture / ".config/discord/Cache"))
        mounted = True
        user("mount")
        run("umount", str(fixture / ".config/discord/Cache"))
        mounted = False
        # The real module explicitly refuses root even in this guest.
        code = "import importlib.util; from pathlib import Path; p=Path(" + repr(str(source)) + ")/'src/lib/discord_cache.py'; s=importlib.util.spec_from_file_location('root_cache_probe',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.CacheManager(home=" + repr(str(fixture)) + ").clean('native-stable','a'*64)"
        root = run("python3", "-B", "-c", code, check=False)
        require(root.returncode != 0 and "от root запрещена" in root.stderr, "actual root invocation is refused")
        require(run("nft", "--stateless", "list", "ruleset").stdout == before_rules and sha("/etc/hosts") == before_hosts
                and Path("/proc/sys/net/ipv4/tcp_timestamps").read_bytes() == before_timestamps,
                "firewall, hosts and sysctl unchanged")
        require(not active() and not table_present(), "cache maintenance starts no system service or application rules")
    finally:
        if mounted:
            run("umount", str(fixture / ".config/discord/Cache"))
        if fixture.exists():
            shutil.rmtree(fixture)
    require(not fixture.exists(), "synthetic Discord home removed")
    evidence = {"status": "passed", "kernel": run("uname", "-r").stdout.strip(),
                "real_discord_installed": False, "source_sha256": {name: sha(source / name) for name in
                    ("src/lib/discord_cache.py", "src/gui/backend.py", "src/gui/presentation.py",
                     "src/gui/app.py", "ci/vm_discord_cache_smoke.py")}}
    Path("/var/tmp/zapret-discord-cache-result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("DISCORD CACHE VM TEST PASSED (synthetic profiles only; real Discord and desktop confirmation not tested)")


if __name__ == "__main__":
    main()
