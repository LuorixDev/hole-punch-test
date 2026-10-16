# Build on the target OS using the installed, locked dependencies.
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

root = Path(SPECPATH).parent
datas, binaries, hiddenimports = [], [], collect_submodules("p2plab")
for package in ("textual", "aioquic", "aiortc", "certifi", "av"):
    package_data, package_bins, package_imports = collect_all(package)
    datas += package_data
    binaries += package_bins
    hiddenimports += package_imports

for name in ("LICENSE", "THIRD-PARTY-NOTICES.md", "client.example.toml"):
    datas.append((str(root / name), "."))
if (root / ".tools/licenses").is_dir():
    datas.append((str(root / ".tools/licenses"), "third-party-licenses"))

utp = root / "data/native" / {"win32": "libutp.dll", "darwin": "libutp.dylib"}.get(sys.platform, "libutp.so")
if utp.is_file():
    binaries.append((str(utp), "data/native"))
    datas.append((str(root / "data/native/libutp.LICENSE"), "data/native"))

nice = root / ".tools/libnice/lib" / ("libnice.10.dylib" if sys.platform == "darwin" else "libnice.so.10")
if sys.platform in ("linux", "darwin") and nice.is_file():
    binaries.append((str(nice), ".tools/libnice/lib"))
    for name in ("COPYING", "COPYING.LGPL", "COPYING.MPL"):
        datas.append((str(root / ".tools/libnice" / name), ".tools/libnice"))

if sys.platform == "win32":
    for dll in (root / ".tools/libnice/bin").glob("*.dll"):
        binaries.append((str(dll), ".tools/libnice/bin"))
    for name in ("COPYING", "COPYING.LGPL", "COPYING.MPL", "windows-dependencies.json", "dependency-licenses"):
        source = root / ".tools/libnice" / name
        if source.exists():
            datas.append((str(source), ".tools/libnice"))

speedtest = root / ".tools" / ("librespeed-cli.exe" if sys.platform == "win32" else "librespeed-cli")
if speedtest.is_file():
    binaries.append((str(speedtest), ".tools"))
    license = root / ".tools/LIBRESPEED-LICENSE"
    if not license.is_file():
        raise SystemExit("Bundled LibreSpeed requires .tools/LIBRESPEED-LICENSE")
    datas.append((str(license), ".tools"))

a = Analysis([str(root / "client.py")], pathex=[str(root)], binaries=binaries, datas=datas,
             hiddenimports=hiddenimports, hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, name="P2PLab-Client", debug=False,
          bootloader_ignore_signals=False, strip=False, upx=False, console=True)
