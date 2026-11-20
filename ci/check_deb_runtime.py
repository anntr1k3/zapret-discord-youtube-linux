#!/usr/bin/env python3
"""Check compiled profiles in a locally built Debian artifact without installing it."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/lib"))
import strategy_sync


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("The runtime check must be unprivileged")
    with tempfile.TemporaryDirectory(prefix="zapret-deb-check-") as directory:
        subprocess.run(["dpkg-deb", "-x", args.artifact.resolve(strict=True), directory],
                       check=True, timeout=30)
        runtime = Path(directory) / "usr/lib/zapret-discord-youtube/runtime"
        catalog = runtime / "zapret-latest"
        compiled = json.loads((catalog / strategy_sync.CATALOG).read_text())["strategies"]
        if not compiled or "general_alt12.bat" not in compiled:
            raise ValueError("Packaged catalog must include ALT12")
        strategy_sync.validate_catalog(runtime / "nfqws", catalog, compiled)
        print(f"Packaged nfqws accepted {len(compiled)} profiles in {len(compiled) * 4} dry runs.")


if __name__ == "__main__":
    main()
