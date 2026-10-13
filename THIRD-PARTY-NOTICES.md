# Third-Party Notices

P2P Lab's original source is MIT licensed. Bundled third-party components retain
their own licenses; the MIT license does not replace those terms. Release assets
include a platform-specific license archive and dependency/version inventory.
The same notices are embedded in each single-file executable's extracted bundle.

## Rebuilding and Replacing Components

The complete application source and build recipes are available at
https://github.com/LuorixDev/hole-punch-test, at the release tag. The application
does not prohibit modification or reverse engineering of bundled libraries.
Rebuild with the desired dependency versions using `tools/build_release.py`.
Use `P2PLAB_LIBUTP` to replace libutp and `[wan].executable` to replace LibreSpeed
with an independently installed program; neither uses an application relay.

- Python: PSF license, https://www.python.org/downloads/source/.
- PyInstaller: GPL with the bootloader distribution exception; original license
  included. Source: https://github.com/pyinstaller/pyinstaller.
- Python dependencies: exact versions in `requirements.lock`, original licenses
  and upstream project URLs in each release's third-party archive.
- PyAV: BSD-3-Clause, https://github.com/PyAV-Org/PyAV. Its wheels include FFmpeg
  libraries under their own licenses. FFmpeg source/build instructions for PyAV
  wheels: https://github.com/PyAV-Org/pyav-ffmpeg and https://ffmpeg.org/download.html.
  Corresponding upstream license texts and build/source references accompany
  the release; do not assume all FFmpeg components use the application's license.
  FFmpeg's exact source archive and original GPL/LGPL texts accompany release
  assets; the inventory records its runtime version and library ABI versions.
- LibreSpeed CLI 1.0.14: LGPL-3.0, launched as a separate program. Exact source:
  https://github.com/librespeed/speedtest-cli/tree/v1.0.14.
  Download: https://github.com/librespeed/speedtest-cli/archive/refs/tags/v1.0.14.tar.gz.
  Build with the upstream Go build recipe and its pinned `go.mod`/`go.sum`.
  The executable is unmodified, checksum-verified by `tools/install_librespeed.py`.
- Optional Linux libutp: MIT, exact revision and source in
  `tools/install_libutp.py`; its original license is bundled when present.
- Optional Linux libnice/GLib: upstream LGPL licenses and system package source
  information are included when these libraries are bundled. Linux builds use
  Ubuntu 22.04 packages; see https://launchpad.net/ubuntu/+source/libnice and
  https://launchpad.net/ubuntu/+source/glib2.0.

For source distributions of a Python dependency, use its exact version's PyPI
source distribution and the recorded upstream URLs, not a moving default branch.
Binary build reports record the Python, package, platform and Git versions.
