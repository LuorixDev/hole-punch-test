"""Separate writable client state from a frozen application's bundled assets."""

import os
import sys
from pathlib import Path


def configure_console_encoding():
    if sys.platform != "win32":
        return
    # Frozen Python does not necessarily honor PYTHONIOENCODING for pipes.
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace" if name == "stdin" else "backslashreplace")


def application_directory():
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()


def default_client_data():
    if not getattr(sys, "frozen", False):
        return Path("data/client")
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) if sys.platform == "win32" else (
        Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    )
    return base / "P2PLab/client"
