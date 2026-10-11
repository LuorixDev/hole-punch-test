"""Frozen-app entry point: ``p2p-desktop`` behaves exactly like the module CLI.

Kept separate so the PyInstaller spec has a stable, side-effect-free target and
``python -m p2pchat.python_desktop`` and the packaged binary cannot drift.
"""
from __future__ import annotations

import sys

from .app import main

if __name__ == "__main__":
    sys.exit(main())
