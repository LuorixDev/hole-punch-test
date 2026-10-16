"""Separate writable client state from a frozen application's bundled assets."""

import os
import sys
from pathlib import Path

MACOS_DATA_DIRECTORY = "Library/Application Support"


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
    """Locate writable client state, preferring each platform's own convention."""
    if not getattr(sys, "frozen", False):
        return Path("data/client")
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "P2PLab/client"
    # An explicitly exported XDG_DATA_HOME is a deliberate choice and still wins; macOS otherwise
    # keeps state in Application Support rather than Linux's ~/.local/share.
    override = os.environ.get("XDG_DATA_HOME")
    if override:
        base = Path(override)
    elif sys.platform == "darwin":
        base = Path.home() / MACOS_DATA_DIRECTORY
    else:
        base = Path.home() / ".local/share"
    return base / "P2PLab/client"
