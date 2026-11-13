"""User-only Discord cache maintenance: allowlisted profiles, fd-based traversal.

No arbitrary paths from the GUI, token/storage reads, process termination or root.
An interrupted deletion can be partial; remaining data is restored when safe.
"""

from contextlib import contextmanager
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import uuid


CACHES = ("Cache", "Code Cache", "GPUCache")
MAX_ENTRIES = 50000
MAX_DEPTH = 32
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
INSTANCES = {
    "native-stable": ("Discord Stable · native", "discord"),
    "native-ptb": ("Discord PTB · native", "discordptb"),
    "native-canary": ("Discord Canary · native", "discordcanary"),
    "native-development": ("Discord Development · native", "discorddevelopment"),
    "flatpak-stable": ("Discord Stable · Flatpak", None),
    "snap-stable": ("Discord Stable · Snap", None),
}
PROCESS_NAMES = {"discord", "discordptb", "discordcanary", "discorddevelopm", "discorddevelop",
                 "discorddevelopment", "electron"}


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_nlink, None if stat.S_ISDIR(info.st_mode) else info.st_ctime_ns]


def read_small(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Слишком большой системный файл проверки")
    return data.decode("utf-8")


class CacheManager:
    def __init__(self, home=None, config=None, proc=Path("/proc"), mounts=None, process_probe=None):
        self.home = Path(home or Path.home()).resolve(strict=True)
        self.config = Path(config or self.home / ".config").absolute()
        if not self.config.is_relative_to(self.home):
            raise ValueError("XDG_CONFIG_HOME вне домашнего каталога: автоматическая очистка не поддерживается")
        self.proc, self.uid = Path(proc), os.getuid()
        self.live_mounts = mounts is None
        self.mounts = set(mounts or ())
        self.process_probe = process_probe or self.processes

    def refresh_mounts(self):
        if self.live_mounts:
            try:
                lines = read_small(self.proc / "self/mountinfo", 2 * 1024 * 1024).splitlines()
                mounts = set()
                for line in lines:
                    fields = line.split()
                    if len(fields) < 6:
                        raise ValueError("Неполные сведения о точках монтирования")
                    mounts.add(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4]))
                self.mounts = mounts
            except (OSError, ValueError) as error:
                raise ValueError("Нельзя безопасно проверить точки монтирования") from error

    def processes(self):
        pids, incomplete = [], False
        try:
            entries = list(itertools.islice((path for path in self.proc.iterdir() if path.name.isdecimal()), 32769))
            incomplete = len(entries) > 32768
            for entry in entries[:32768]:
                try:
                    if entry.stat().st_uid != self.uid:
                        continue
                    name = read_small(entry / "comm", 256).strip().lower()
                    if name in PROCESS_NAMES:
                        pids.append(int(entry.name))
                except FileNotFoundError:
                    continue  # A process exited during the observation.
                except (OSError, ValueError):
                    incomplete = True
        except OSError:
            incomplete = True
        return {"state": "running" if pids else "unknown" if incomplete else "clear", "pids": sorted(pids)}

    def candidate(self, instance):
        if instance not in INSTANCES:
            raise ValueError("Неизвестный экземпляр Discord")
        folder = INSTANCES[instance][1]
        if folder:
            return self.config / folder
        if instance == "flatpak-stable":
            return self.home / ".var/app/com.discordapp.Discord/config/discord"
        current = self.home / "snap/discord/current"
        if not current.is_symlink():
            if os.path.lexists(current):
                raise ValueError("Snap current должен быть ссылкой на поддерживаемую ревизию")
            return None
        revision = str(current.readlink())
        if not re.fullmatch(r"(?:[1-9][0-9]*|x[1-9][0-9]*)", revision):
            raise ValueError("Snap current указывает вне поддерживаемой ревизии")
        return self.home / "snap/discord" / revision / ".config/discord"

    def safe_info(self, info, path):
        if (info.st_uid != self.uid or info.st_mode & 0o022
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ValueError(f"Небезопасный тип, владелец, права или hardlink: {path}")
        if str(path) in self.mounts:
            raise ValueError(f"Очистка точки монтирования запрещена: {path}")

    @contextmanager
    def profile(self, path):
        relative = path.relative_to(self.home)
        if any(part in (".", "..") for part in relative.parts):
            raise ValueError("Недопустимый путь профиля")
        fd = os.open(self.home, DIR_FLAGS)
        try:
            info = os.fstat(fd)
            if info.st_uid != self.uid or info.st_mode & 0o022:
                raise ValueError("Домашний каталог должен принадлежать пользователю и быть защищён от чужой записи")
            cursor = self.home
            for part in relative.parts:
                cursor = cursor / part
                if str(cursor) in self.mounts:
                    raise ValueError(f"Вложенная точка монтирования не поддерживается: {cursor}")
                new = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = new
                info = os.fstat(fd)
                if info.st_uid not in (0, self.uid) or info.st_mode & 0o022:
                    raise ValueError(f"Небезопасный каталог профиля: {cursor}")
            self.safe_info(os.fstat(fd), path)
            yield fd
        except OSError as error:
            raise ValueError(f"Профиль недоступен, заменён или содержит symlink: {path}") from error
        finally:
            os.close(fd)

    def tree(self, parent, name, path, budget, depth=0, device=None):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self.safe_info(info, path)
        if device is not None and info.st_dev != device:
            raise ValueError("Переход на другую файловую систему запрещён")
        budget["entries"] += 1
        if budget["entries"] > MAX_ENTRIES or depth > MAX_DEPTH:
            raise ValueError("Кэш превышает безопасный лимит обхода")
        node = {"meta": metadata(info)}
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
            try:
                if metadata(os.fstat(fd)) != node["meta"]:
                    raise ValueError("Каталог изменился при чтении")
                names = os.listdir(fd)
                if len(names) + budget["entries"] > MAX_ENTRIES:
                    raise ValueError("Слишком много элементов кэша")
                node["children"] = {child: self.tree(fd, child, path / child, budget, depth + 1, info.st_dev)
                                    for child in sorted(names)}
                if metadata(os.fstat(fd)) != node["meta"]:
                    raise ValueError("Кэш изменился при чтении; повторите просмотр")
            finally:
                os.close(fd)
        else:
            budget["files"] += 1
            budget["bytes"] += info.st_size
        return node

    def snapshot(self, instance):
        self.refresh_mounts()
        path = self.candidate(instance)
        if path is None:
            raise ValueError("Профиль Discord не найден")
        budget = {"entries": 0, "files": 0, "bytes": 0}
        trees, caches = {}, []
        with self.profile(path) as fd:
            profile_info = metadata(os.fstat(fd))
            for name in CACHES:
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError(f"Кэш должен быть обычным каталогом, не symlink: {path / name}")
                before = dict(budget)
                trees[name] = self.tree(fd, name, path / name, budget, device=os.fstat(fd).st_dev)
                caches.append({"path": str(path / name), "files": budget["files"] - before["files"],
                               "bytes": budget["bytes"] - before["bytes"]})
            if profile_info != metadata(os.fstat(fd)):
                raise ValueError("Профиль изменился при чтении")
        digest = hashlib.sha256(json.dumps([instance, str(path), profile_info, trees], sort_keys=True).encode()).hexdigest()
        result = {"id": instance, "label": INSTANCES[instance][0], "path": str(path), "caches": caches,
                  "files": budget["files"], "bytes": budget["bytes"], "token": digest, "error": None}
        return result, trees, profile_info

    def preview(self, instance):
        try:
            return self.snapshot(instance)[0]
        except OSError as error:
            raise ValueError("Кэш недоступен или изменился при чтении") from error

    def discover(self):
        instances = []
        for instance, (label, _) in INSTANCES.items():
            path = None
            try:
                path = self.candidate(instance)
                if path is None or not os.path.lexists(path):
                    continue
                instances.append(self.preview(instance))
            except (OSError, ValueError) as error:
                instances.append({"id": instance, "label": label, "path": str(path) if path else "не определён",
                                  "caches": [], "files": 0, "bytes": 0, "token": None, "error": str(error)})
        return {"instances": instances, "processes": self.process_probe()}

    def delete_tree(self, parent, name, node, counts):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if metadata(info) != node["meta"]:
            raise ValueError("Кэш изменился после подтверждения")
        if "children" in node:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
            try:
                if metadata(os.fstat(fd)) != node["meta"] or set(os.listdir(fd)) != set(node["children"]):
                    raise ValueError("Состав каталога изменился")
                for child, child_node in node["children"].items():
                    self.delete_tree(fd, child, child_node, counts)
            finally:
                os.close(fd)
            os.rmdir(name, dir_fd=parent)
        else:
            os.unlink(name, dir_fd=parent)
            counts["removed_files"] += 1
            counts["removed_bytes"] += info.st_size

    def clean(self, instance, token):
        if os.geteuid() == 0:
            raise ValueError("Очистка Discord от root запрещена")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("Нужен токен подтверждённого предпросмотра")
        if self.process_probe().get("state") != "clear":
            raise ValueError("Закройте Discord/electron; при неполной проверке процессов очистка запрещена")
        result, trees, profile_info = self.snapshot(instance)
        if result["token"] != token:
            raise ValueError("Кэш или профиль изменился после просмотра. Проверьте его заново.")
        counts = {"removed_files": 0, "removed_bytes": 0}
        if not trees:
            return {"id": instance, **counts}
        path = Path(result["path"])
        with self.profile(path) as fd:
            if metadata(os.fstat(fd)) != profile_info or self.process_probe().get("state") != "clear":
                raise ValueError("Профиль или процессы изменились; очистка отменена")
            stage = ".zapret-discord-cache-" + uuid.uuid4().hex
            os.mkdir(stage, 0o700, dir_fd=fd)
            try:
                temporary = os.open(stage, DIR_FLAGS, dir_fd=fd)
            except OSError:
                os.rmdir(stage, dir_fd=fd)
                raise
            moved = []
            try:
                for name, node in trees.items():
                    os.rename(name, name, src_dir_fd=fd, dst_dir_fd=temporary)
                    moved.append(name)
                    budget = {"entries": 0, "files": 0, "bytes": 0}
                    if self.tree(temporary, name, path / name, budget) != node:
                        raise ValueError("Кэш изменился во время подготовки удаления")
                if self.process_probe().get("state") != "clear":
                    raise ValueError("Discord/electron запущен; удаление отменено")
                for name, node in trees.items():
                    self.delete_tree(temporary, name, node, counts)
                os.rmdir(stage, dir_fd=fd)
            except Exception as error:
                retained = False
                for name in moved:
                    try:
                        os.stat(name, dir_fd=temporary, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    try:
                        try:
                            os.stat(name, dir_fd=fd, follow_symlinks=False)
                        except FileNotFoundError:
                            os.rename(name, name, src_dir_fd=temporary, dst_dir_fd=fd)
                        else:
                            retained = True  # Never overwrite a recreated cache.
                    except OSError:
                        retained = True
                if not retained:
                    try:
                        os.rmdir(stage, dir_fd=fd)
                    except OSError:
                        retained = True
                detail = f" Остаток сохранён: {path / stage}." if retained else " Неудалённые каталоги возвращены."
                raise RuntimeError(f"Очистка прервана; удалено файлов: {counts['removed_files']}. "
                                   f"Уже удалённые данные не восстанавливаются.{detail} Причина: {error}") from error
            finally:
                os.close(temporary)
        return {"id": instance, **counts}
