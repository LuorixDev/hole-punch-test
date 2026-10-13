import asyncio
import json
import os
import shutil
import sys

import pytest


async def test_simulated_ipv6_stateful_cpes_and_static_inbound_block():
    if not sys.platform.startswith("linux") or not all(
        shutil.which(name) for name in ("unshare", "nsenter", "nft", "ip", "sysctl")
    ):
        pytest.skip("Linux user/network namespaces and nftables required")
    probe = await asyncio.create_subprocess_exec(
        "unshare", "-Urn", "true", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    await probe.communicate()
    if probe.returncode:
        pytest.skip("Unprivileged user/network namespaces disabled")
    process = await asyncio.create_subprocess_exec(
        "unshare",
        "-Urn",
        sys.executable,
        "tests/netns_lab.py",
        os.readlink("/proc/self/ns/net"),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), 45)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    assert process.returncode == 0, err.decode()
    evidence = json.loads(out)
    assert evidence["results"][0]["mode"] == "stateful"
    assert all(peer["state"] == "authenticated" for peer in evidence["results"][0]["peers"])
    assert evidence["results"][1]["mode"] == "stateful-small-mtu"
    assert all(peer["state"] == "timeout-not-authenticated" for peer in evidence["results"][2]["peers"])


async def test_additional_raw_and_cross_family_isolated_namespace():
    if not sys.platform.startswith("linux") or not all(shutil.which(name) for name in ("unshare", "nft", "ip")):
        pytest.skip("isolated Linux namespaces and nftables required")
    probe = await asyncio.create_subprocess_exec("unshare", "-Urn", "true")
    await probe.wait()
    if probe.returncode:
        pytest.skip("unprivileged network namespaces unavailable")
    process = await asyncio.create_subprocess_exec("unshare", "-Urn", sys.executable, "tests/research_netns.py",
        os.readlink("/proc/self/ns/net"), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(process.communicate(), 40)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    assert process.returncode == 0, out.decode() + err.decode()
    assert "3 passed" in out.decode()
