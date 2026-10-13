"""Separate writable client state from a frozen application's bundled assets."""

import os
import sys
from pathlib import Path


def application_directory():
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()


def default_client_data():
    if not getattr(sys, "frozen", False):
        return Path("data/client")
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) if sys.platform == "win32" else (
        Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    )
    return base / "P2PLab/client"
