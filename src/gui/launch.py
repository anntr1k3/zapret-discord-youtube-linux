#!/usr/bin/env python3
"""Entry point also included in managed releases by the existing installer."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.gui.app import main


if __name__ == "__main__":
    raise SystemExit(main())
