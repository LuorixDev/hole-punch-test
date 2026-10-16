param([switch]$SkipInstall, [string]$Msys2Root = "C:\msys64")
$ErrorActionPreference = "Stop"
$Project = Split-Path -Parent $PSScriptRoot
Push-Location $Project
try {
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        py -3.12 -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Python 3.12 environment creation failed" }
    }
    $Python = Join-Path $Project ".venv\Scripts\python.exe"
    & $Python -c "import struct, sys; assert sys.platform == 'win32' and struct.calcsize('P') == 8 and sys.version_info[:2] == (3, 12), 'Requires Windows x64 Python 3.12'"
    if ($LASTEXITCODE -ne 0) { throw "Windows x64 Python 3.12 is required" }
    if (-not $SkipInstall) {
        & $Python -m pip install --only-binary=:all: -r requirements.lock
        if ($LASTEXITCODE -ne 0) { throw "Locked dependency installation failed" }
        & $Python -m pip install -r packaging/build-requirements.txt
        if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed" }
    }
    $MsysBash = Join-Path $Msys2Root "usr\bin\bash.exe"
    if (-not (Test-Path $MsysBash)) { throw "Install MSYS2 UCRT64 first; see README native build instructions" }
    $env:MSYSTEM = "UCRT64"
    $env:CHERE_INVOKING = "1"
    & $MsysBash -lc "python tools/install_libnice.py && python tools/install_libutp.py"
    if ($LASTEXITCODE -ne 0) { throw "Windows native library build failed" }
    $env:P2PLAB_REQUIRE_NATIVE = "1"
    & $Python -m pytest -q tests/test_windows.py tests/test_startup.py tests/test_native.py tests/test_cold_paths.py
    if ($LASTEXITCODE -ne 0) { throw "Windows startup/network tests failed" }
    & $Python tools/build_release.py
    if ($LASTEXITCODE -ne 0) { throw "Single-file build or frozen P2P smoke test failed" }
    Write-Output "Built client/server single-file executables in dist\release"
} finally {
    Pop-Location
}
