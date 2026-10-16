"""Resolve native dependencies in both source trees and one-file bundles."""

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_dll_directories = []

#: Windows libraries carry no soname version; macOS uses versioned dylibs, Linux versioned sonames.
_library_versions = {"nice": 10, "glib-2.0": 0, "gobject-2.0": 0}
_windows_filenames = {"nice": "libnice-10.dll", "glib-2.0": "libglib-2.0-0.dll",
                      "gobject-2.0": "libgobject-2.0-0.dll", "utp": "libutp.dll"}
#: Homebrew installs here, and ctypes.util.find_library does not search it.
_DARWIN_PACKAGE_DIRECTORIES = (Path("/opt/homebrew/lib"), Path("/usr/local/lib"))


def library_filename(name):
    """File name of a native dependency on this platform, whether bundled or system-installed."""
    if sys.platform == "win32":
        return _windows_filenames[name]
    version = _library_versions.get(name)
    if sys.platform == "darwin":
        return f"lib{name}.{version}.dylib" if version is not None else f"lib{name}.dylib"
    return f"lib{name}.so.{version}" if version is not None else f"lib{name}.so"


def library_path(name):
    if name == "utp":
        override = os.environ.get("P2PLAB_LIBUTP")
        bundled = ROOT / "data/native" / library_filename(name)
    else:
        override = None
        bundled = (ROOT / ".tools/libnice/bin" / library_filename(name) if sys.platform == "win32" else
                   ROOT / ".tools/libnice/lib" / library_filename(name) if name == "nice" else None)
    if override:
        return override
    if bundled is not None and bundled.is_file():
        return str(bundled)
    if sys.platform == "darwin":
        for directory in _DARWIN_PACKAGE_DIRECTORIES:
            candidate = directory / library_filename(name)
            if candidate.is_file():
                return str(candidate)
    return ctypes.util.find_library(name) or (str(bundled) if bundled else library_filename(name))


def load_library(name):
    if sys.platform == "win32" and not _dll_directories:
        # Handles must remain alive: closing them removes the DLL search directories.
        for directory in (ROOT / "data/native", ROOT / ".tools/libnice/bin"):
            if directory.is_dir():
                _dll_directories.append(os.add_dll_directory(str(directory)))
    return ctypes.CDLL(library_path(name))
