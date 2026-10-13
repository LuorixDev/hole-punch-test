from pathlib import Path

from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
datas, binaries, hiddenimports = [], [], []
for package in ("aiohttp", "cryptography", "certifi"):
    package_data, package_bins, package_imports = collect_all(package)
    datas += package_data
    binaries += package_bins
    hiddenimports += package_imports
for name in ("LICENSE", "THIRD-PARTY-NOTICES.md"):
    datas.append((str(root / name), "."))
if (root / ".tools/licenses").is_dir():
    datas.append((str(root / ".tools/licenses"), "third-party-licenses"))
a = Analysis([str(root / "server.py")], pathex=[str(root)], binaries=binaries, datas=datas,
             hiddenimports=hiddenimports, hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, name="P2PLab-Server", debug=False,
          bootloader_ignore_signals=False, strip=False, upx=False, console=True)
