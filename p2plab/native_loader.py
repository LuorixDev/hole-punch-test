"""Resolve native dependencies in both source trees and one-file bundles."""

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_dll_directories = []


def library_path(name):
    if name == "utp":
        override = os.environ.get("P2PLAB_LIBUTP")
        bundled = ROOT / "data/native" / ("libutp.dll" if sys.platform == "win32" else "libutp.so")
    else:
        override = None
        filenames = {"nice": "libnice-10.dll", "glib-2.0": "libglib-2.0-0.dll",
                     "gobject-2.0": "libgobject-2.0-0.dll"}
        bundled = (ROOT / ".tools/libnice/bin" / filenames[name] if sys.platform == "win32" else
                   ROOT / ".tools/libnice/lib/libnice.so.10" if name == "nice" else None)
    if override:
        return override
    if bundled is not None and bundled.is_file():
        return str(bundled)
    fallback = {"utp": "libutp.so", "nice": "libnice.so.10", "glib-2.0": "libglib-2.0.so.0",
                "gobject-2.0": "libgobject-2.0.so.0"}
    return ctypes.util.find_library(name) or (str(bundled) if bundled else fallback[name])


def load_library(name):
    if sys.platform == "win32" and not _dll_directories:
        # Handles must remain alive: closing them removes the DLL search directories.
        for directory in (ROOT / "data/native", ROOT / ".tools/libnice/bin"):
            if directory.is_dir():
                _dll_directories.append(os.add_dll_directory(str(directory)))
    return ctypes.CDLL(library_path(name))
