"""Stage only data and the exact pinned upstream executable for the Debian build."""

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/lib"))
import strategy_sync as sync


ENGINE_ARCHIVE = "zapret-v72.9.tar.gz"
ENGINE_ARCHIVE_SHA256 = "1e14dc6320dd7b5a1f28ab8145ac76d7a7010ca3cbe71824aa4aa407f7279ddf"
ENGINE_SHA256 = "e57db44af46835f68a8cacbf98267c694ee863e27622a8c3a3609eb14ebad11c"
FLOWSEAL_REV = "176f56dc3f11ce5915c26abcdde903f93d835b64"
FLOWSEAL_SHA256 = "84b80721afb76635c0768bfacb146227d303c6b242684680bf9ca34849467a21"
MAX_ARCHIVE = 32 * 1024 * 1024


def checked_archive(path, digest):
    with path.open("rb") as stream:
        data = stream.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Неверный SHA-256 или размер архива: {path.name}")
    return data


def tar_regular(archive, name, limit):
    matches = [entry for entry in archive if entry.name == name]
    if len(matches) != 1 or not matches[0].isfile() or matches[0].size > limit:
        raise ValueError(f"Небезопасный или отсутствующий файл в tar: {name}")
    with archive.extractfile(matches[0]) as stream:
        return stream.read()


def stage(inputs, runtime, docs):
    engine_archive = checked_archive(inputs / ENGINE_ARCHIVE, ENGINE_ARCHIVE_SHA256)
    catalog_archive = checked_archive(inputs / "flowseal.zip", FLOWSEAL_SHA256)
    with tarfile.open(fileobj=io.BytesIO(engine_archive), mode="r:gz") as archive:
        engine = tar_regular(archive, "zapret-v72.9/binaries/linux-x86_64/nfqws", 1024 * 1024)
        engine_license = tar_regular(archive, "zapret-v72.9/docs/LICENSE.txt", 65536)
    if hashlib.sha256(engine).hexdigest() != ENGINE_SHA256:
        raise ValueError("Неверный SHA-256 nfqws")
    files = sync.read_archive(catalog_archive)
    compiled = sync.compile_payload(files)
    if "general_alt12.bat" not in compiled or "utils/targets.txt" not in files:
        raise ValueError("В каталоге отсутствуют ALT12 или цели тестировщика")
    with zipfile.ZipFile(io.BytesIO(catalog_archive)) as archive:
        flowseal_license = archive.read(f"zapret-discord-youtube-{FLOWSEAL_REV}/LICENSE.txt")

    (runtime / "nfqws").write_bytes(engine)
    (docs / "nfqws-LICENSE.txt").write_bytes(engine_license)
    (docs / "flowseal-LICENSE.txt").write_bytes(flowseal_license)
    sync.write_catalog(runtime / "zapret-latest", files, compiled, {
        "schema": 1, "repository": sync.REPOSITORY, "revision": FLOWSEAL_REV,
        "tag": "1.10.4", "channel": "release", "archive_sha256": FLOWSEAL_SHA256,
    })


if __name__ == "__main__":
    try:
        stage(*(Path(argument) for argument in sys.argv[1:]))
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        sys.exit(str(error))
