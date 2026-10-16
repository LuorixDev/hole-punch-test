import asyncio
import ctypes
import json
from unittest.mock import Mock

import pytest
from aioice import stun

from p2plab import native_loader
from p2plab.ice_compat import GuardedTransaction, install_retry_guard


@pytest.mark.parametrize("cancel", [False, True])
async def test_stun_queued_retry_after_completion_is_noop(cancel):
    install_retry_guard()
    sender = Mock()
    request = stun.Message(stun.Method.BINDING, stun.Class.REQUEST)
    transaction = stun.Transaction(request, ("127.0.0.1", 1), sender, retransmissions=0)
    assert isinstance(transaction, GuardedTransaction)
    task = asyncio.create_task(transaction.run())
    await asyncio.sleep(0)
    if cancel:
        task.cancel()
    else:
        transaction.response_received(stun.Message(stun.Method.BINDING, stun.Class.RESPONSE),
                                      ("127.0.0.1", 1))
    # Emulate an already-ready timeout callback before run()'s finally executes.
    transaction._Transaction__retry()
    result = await asyncio.gather(task, return_exceptions=True)
    assert isinstance(result[0], asyncio.CancelledError) if cancel else isinstance(result[0], tuple)
    assert sender.send_stun.call_count == 1


async def test_stun_guard_preserves_real_timeout(monkeypatch):
    monkeypatch.setattr(stun, "RETRY_RTO", 0.001)
    transaction = GuardedTransaction(stun.Message(stun.Method.BINDING, stun.Class.REQUEST),
                                     ("127.0.0.1", 1), Mock(), retransmissions=0)
    with pytest.raises(stun.TransactionTimeout):
        await asyncio.wait_for(transaction.run(), 1)


def test_windows_loader_prefers_bundle_and_keeps_directory_handles(tmp_path, monkeypatch):
    monkeypatch.setattr(native_loader, "ROOT", tmp_path)
    monkeypatch.setattr(native_loader.sys, "platform", "win32")
    monkeypatch.setattr(native_loader, "_dll_directories", [])
    monkeypatch.setattr(native_loader.ctypes.util, "find_library", lambda name: "wrong-system-library")
    add_directory, cdll = Mock(), Mock()
    monkeypatch.setattr(native_loader.os, "add_dll_directory", add_directory, raising=False)
    monkeypatch.setattr(ctypes, "CDLL", cdll)
    for directory, name in (("data/native", "libutp.dll"), (".tools/libnice/bin", "libnice-10.dll")):
        path = tmp_path / directory / name
        path.parent.mkdir(parents=True)
        path.touch()
    native_loader.load_library("nice")
    native_loader.load_library("utp")
    assert len(native_loader._dll_directories) == 2 and add_directory.call_count == 2
    assert cdll.call_args_list[0].args[0] == str(tmp_path / ".tools/libnice/bin/libnice-10.dll")
    assert cdll.call_args_list[1].args[0] == str(tmp_path / "data/native/libutp.dll")


async def test_native_acceptance_report_contains_every_backend_and_family(tmp_path):
    import os

    from p2plab.native_check import check_native

    try:
        native_loader.load_library("nice")
        native_loader.load_library("utp")
    except OSError:
        if os.environ.get("P2PLAB_REQUIRE_NATIVE"):
            raise
        pytest.skip("optional native libraries unavailable")
    path = tmp_path / "native-report.json"
    result = await check_native(path)
    assert json.loads(path.read_text()) == result
    assert result["state"] == "passed" and not result["background_errors"]
    assert {(row["method"], row["host"]) for row in result["cases"]} == {
        (method, host) for method in ("utp", "ice-native", "ice-tcp") for host in ("127.0.0.1", "::1")}
