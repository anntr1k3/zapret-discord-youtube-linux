#!/usr/bin/env python3
"""Convenience entry point; installed copies can use src/lib/strategy_sync.py."""

from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent / "src/lib/strategy_sync.py"), run_name="__main__")
