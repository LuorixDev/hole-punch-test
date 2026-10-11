"""CI-only process-tree watchdog; no product imports, test exclusions, or log scraping.

Launches a stdin-gated bootstrap so Windows Job assignment precedes ALL test
children. No command or environment values are printed. Output is inherited,
not piped through a thread that could block shutdown. Timeout always exits 124.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


class WindowsJob:
    """Own a kill-on-close Job; descendants cannot escape via normal child spawn."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def terminate(self):
        if not self.kernel.TerminateJobObject(self.handle, 124):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def bootstrap(command):
    # Parent may exit or fail Job assignment: EOF fails closed without spawning tests.
    if sys.stdin.buffer.read(1) != b"G":
        return 125
    return subprocess.call(command, stdin=subprocess.DEVNULL, shell=False)


def run(command, timeout_seconds):
    if not command or timeout_seconds <= 0 or timeout_seconds > 3600:
        raise ValueError("invalid watchdog arguments")
    started = time.monotonic()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONFAULTHANDLER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    job = WindowsJob() if os.name == "nt" else None
    process = None
    code = 125
    timed_out = False
    try:
        process = subprocess.Popen(
            [sys.executable, "-u", str(Path(__file__).resolve()), "--bootstrap", json.dumps(command)],
            stdin=subprocess.PIPE, env=env, shell=False,
            start_new_session=(os.name != "nt"),
        )
        if job:
            job.assign(process)
        process.stdin.write(b"G")
        process.stdin.close()
        print(f"WATCHDOG_STARTED pid={process.pid} timeoutSeconds={timeout_seconds:g}", flush=True)
        try:
            code = process.wait(timeout=max(0.01, timeout_seconds - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            timed_out = True
            code = 124
            print("WATCHDOG_TIMEOUT exitCode=124; terminating owned test process tree", flush=True)
    except Exception as error:
        # Avoid echoing argv/env, potentially containing test credentials.
        print(f"WATCHDOG_ERROR type={type(error).__name__} exitCode=125", flush=True)
        code = 125
    finally:
        if job:
            # Also kills orphan grandchildren after normal/failed pytest exit.
            try:
                if process is not None and process.poll() is None:
                    job.terminate()
            finally:
                job.close()
        elif process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process is not None:
            if process.poll() is None:
                process.kill()  # assignment failure leaves only the blocked bootstrap
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("WATCHDOG_REAP_FAILED exitCode=125", flush=True)
                if not timed_out:
                    code = 125
        print(f"WATCHDOG_FINISHED exitCode={code} elapsedSeconds={time.monotonic()-started:.3f}", flush=True)
    return code if code >= 0 else 128 - code


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--bootstrap":
        return bootstrap(json.loads(sys.argv[2]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return run(command, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
