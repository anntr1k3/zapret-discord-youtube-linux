"""One fixed, runtime-only sysctl. No sysctl.d, subprocesses or service changes."""

import datetime
import os
from pathlib import Path
import stat


TARGET = Path("/proc/sys/net/ipv4/tcp_timestamps")


def valid_value(value):
    return isinstance(value, str) and value in ("0", "1", "2")


def read_value():
    fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Параметр timestamps имеет неподдерживаемый тип")
        data = os.read(fd, 33)
        if data not in (b"0", b"1", b"2", b"0\n", b"1\n", b"2\n"):
            raise ValueError("Неизвестный формат или значение TCP timestamps")
        return data.decode("ascii").strip()
    finally:
        os.close(fd)


def write_value(value):
    # Zero is only for internal recovery. The public protocol can only enable.
    if value not in ("0", "1"):
        raise ValueError("Неподдерживаемое значение внутренней записи timestamps")
    fd = os.open(TARGET, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Параметр timestamps должен быть обычным root-owned файлом без чужой записи")
        data = (value + "\n").encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("Неполная запись TCP timestamps")
    finally:
        os.close(fd)


def state(value, error=None):
    return {"value": value, "enabled": value != "0" if value is not None else None,
            "scope": "running-kernel", "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "error": error}


def status():
    try:
        return state(read_value())
    except (OSError, ValueError) as error:
        return state(None, str(error))


def enable(expected_value, read=None, write=None):
    if not valid_value(expected_value):
        raise ValueError("Требуется прочитанное значение TCP timestamps (0, 1 или 2)")
    read, write = read or read_value, write or write_value
    old = read()
    if old != expected_value:
        raise ValueError("TCP timestamps изменился после просмотра. Прочитайте значение заново.")
    if old in ("1", "2"):
        return {"changed": False, "tcp_timestamps": state(old)}
    if read() != old:
        raise ValueError("TCP timestamps изменился во время подготовки. Изменения отменены.")
    try:
        write("1")
        if read() != "1":
            raise RuntimeError("TCP timestamps не совпал после записи")
    except Exception as error:
        try:
            current = read()
        except (OSError, ValueError) as recovery_read:
            raise RuntimeError("Результат записи TCP timestamps неизвестен; слепое восстановление запрещено. "
                               "Прочитайте параметр заново.") from recovery_read
        if current == old:
            raise
        if current != "1":
            raise RuntimeError("Обнаружено параллельное изменение TCP timestamps. Чужое значение сохранено; "
                               "повторно проверьте параметр.") from error
        try:
            write(old)
            if read() != old:
                raise RuntimeError("Прежнее значение не подтвердилось после восстановления")
        except Exception as recovery:
            raise RuntimeError(f"Ошибка TCP timestamps; восстановление также не удалось: {recovery}") from error
        raise
    return {"changed": True, "tcp_timestamps": state("1")}
