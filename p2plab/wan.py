"""LibreSpeed subprocess measurements with bounded discovery, time and output."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import aiohttp

from .network import address_rejection, command
from .status import positive_rate, utcnow

SERVER_LIST = "https://librespeed.org/backend-servers/servers.php"
BUNDLED_CLI = Path(__file__).resolve().parents[1] / ".tools" / (
    "librespeed-cli.exe" if sys.platform == "win32" else "librespeed-cli"
)


def executable(options):
    configured = options.get("executable")
    if configured:
        return shutil.which(str(configured))
    return shutil.which("librespeed-cli") or (str(BUNDLED_CLI) if os.access(BUNDLED_CLI, os.X_OK) else None)


def configured_families(options, inventory):
    up, down = options.get("upload_mbps"), options.get("download_mbps")
    for value in (up, down):
        if value is not None and not positive_rate(value):
            raise ValueError("INVALID_WAN_CONFIGURED_RATE")
    if up is None and down is None:
        return {}
    return {
        str(family): {
            "upload_mbps": up,
            "download_mbps": down,
            "measured_at": utcnow(),
            "basis": "configured",
            "source": None,
            "interface": "",
        }
        for family in {r["family"] for r in inventory}
    }


def sources(network):
    records = [r for r in network.get("address_inventory", []) if not address_rejection(r)]
    result = []
    for family in (4, 6):
        available = [
            r
            for r in records
            if r["family"] == family
            and (
                ipaddress.ip_address(r["address"]).is_global
                or family == 4
                and not ipaddress.ip_address(r["address"]).is_loopback
            )
        ]
        gateways = network.get("gateways" if family == 4 else "gateways6", [])
        interfaces = {r.get("interface") for r in gateways}
        available.sort(key=lambda r: (r.get("interface") not in interfaces, r.get("temporary", False)))
        if available:
            result.append(available[0])
    return result


def parse_result(output):
    if not isinstance(output, list) or len(output) != 1 or not isinstance(output[0], dict):
        raise ValueError("INVALID_LIBRESPEED_JSON")
    row = output[0]
    if not all(positive_rate(row.get(k)) for k in ("upload", "download")):
        raise ValueError("LIBRESPEED_INCOMPLETE_DIRECTIONS")
    if not all(type(row.get(k)) is int and row[k] > 0 for k in ("bytes_sent", "bytes_received")):
        raise ValueError("LIBRESPEED_NO_CONFIRMED_TRANSFER")
    return row


async def discover_servers(source, journal, *, selected_ids=(), maximum=2):
    connector = aiohttp.TCPConnector(
        family=socket.AF_INET if source["family"] == 4 else socket.AF_INET6,
        local_addr=(source["address"], 0),
        limit=8,
    )
    async with aiohttp.ClientSession(
        connector=connector, trust_env=False, timeout=aiohttp.ClientTimeout(total=5)
    ) as session:
        async with session.get(SERVER_LIST, allow_redirects=False) as response:
            response.raise_for_status()
            raw = await response.content.read(131073)
            if len(raw) > 131072:
                raise ValueError("WAN_SERVER_LIST_LIMIT")
            rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError("WAN_SERVER_LIST_INVALID")
        servers = []
        for row in rows[:64]:
            if not isinstance(row, dict) or type(row.get("id")) is not int:
                continue
            if selected_ids and row["id"] not in selected_ids:
                continue
            server = row.get("server", "")
            if not isinstance(server, str):
                continue
            if server.startswith("//"):
                server = "https:" + server
            url = urlsplit(server)
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                continue
            if not all(
                isinstance(row.get(key), str) and len(row[key]) <= 1024
                for key in ("name", "dlURL", "ulURL", "pingURL", "getIpURL")
            ):
                continue
            servers.append({**row, "server": server})
        semaphore = asyncio.Semaphore(8)

        async def probe(row):
            import time

            async with semaphore:
                start = time.monotonic()
                try:
                    async with session.get(
                        urljoin(row["server"].rstrip("/") + "/", row["pingURL"]),
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as response:
                        response.raise_for_status()
                        await response.content.read(1)
                    elapsed = (time.monotonic() - start) * 1000
                    journal.event(
                        "wan.server_probe",
                        family=source["family"],
                        server_id=row["id"],
                        name=row["name"],
                        elapsed_ms=elapsed,
                        state="reachable",
                    )
                    return elapsed, row
                except Exception as exc:
                    journal.event(
                        "wan.server_probe",
                        family=source["family"],
                        server_id=row["id"],
                        state="failed",
                        reason=type(exc).__name__ + ":" + str(exc),
                    )
                    return float("inf"), row

        probes = await asyncio.gather(*(probe(row) for row in servers))
        return [row for latency, row in sorted(probes, key=lambda r: r[0]) if latency != float("inf")][
            :maximum
        ]


async def measure(network, options, journal):
    cli = executable(options)
    if not cli:
        return {"state": "not-tested", "families": {}, "reason": "LIBRESPEED_CLI_MISSING"}
    duration = int(options.get("duration", 8))
    count = int(options.get("servers_per_family", 2))
    if not 3 <= duration <= 15 or not 1 <= count <= 2:
        raise ValueError("INVALID_WAN_TEST_BUDGET")
    ids = options.get("server_ids", [])
    if not isinstance(ids, list) or len(ids) > 4 or any(type(i) is not int or i < 0 for i in ids):
        raise ValueError("INVALID_WAN_SERVER_IDS")
    result = {"state": "failed", "families": {}, "samples": [], "reason": "NO_REACHABLE_WAN_TARGET"}
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
    }
    for source in sources(network):
        try:
            targets = await discover_servers(source, journal, selected_ids=ids, maximum=count)
            with tempfile.TemporaryDirectory(prefix="p2plab-wan-") as directory:
                path = Path(directory) / "servers.json"
                path.write_text(json.dumps(targets), encoding="utf-8")
                for target in targets:
                    journal.event(
                        "wan.test_started",
                        family=source["family"],
                        source=source["address"],
                        server=target,
                        duration_per_direction=duration,
                    )
                    raw = await command(
                        cli,
                        "--json",
                        "--no-icmp",
                        "--telemetry-level",
                        "disabled",
                        "--secure",
                        "--ipv" + str(source["family"]),
                        "--source",
                        source["address"],
                        "--local-json",
                        str(path),
                        "--server",
                        str(target["id"]),
                        "--duration",
                        str(duration),
                        "--timeout",
                        "4",
                        "--concurrent",
                        "6",
                        "--upload-size",
                        "4096",
                        timeout=duration * 2 + 25,
                        limit=32768,
                        env=env,
                    )
                    journal.event("wan.cli_output", family=source["family"], evidence=raw)
                    try:
                        if raw.get("state") != "completed":
                            raise ValueError("LIBRESPEED_PROCESS_FAILED")
                        sample = parse_result(raw.get("output"))
                    except ValueError as exc:
                        journal.event(
                            "wan.test_failed",
                            str(exc),
                            "WARNING",
                            family=source["family"],
                            server_id=target["id"],
                        )
                        continue
                    sample = {
                        **sample,
                        "family": source["family"],
                        "source": source["address"],
                        "interface": source.get("interface", ""),
                        "duration": duration,
                    }
                    result["samples"].append(sample)
                    journal.event("wan.sample", evidence=sample)
            samples = [s for s in result["samples"] if s["family"] == source["family"]]
            if samples:
                result["families"][str(source["family"])] = {
                    "upload_mbps": max(s["upload"] for s in samples),
                    "download_mbps": max(s["download"] for s in samples),
                    "measured_at": utcnow(),
                    "basis": "measured",
                    "source": source["address"],
                    "interface": source.get("interface", ""),
                }
        except Exception as exc:
            journal.event(
                "wan.family_failed",
                str(exc),
                "WARNING",
                family=source["family"],
                exception=type(exc).__name__,
            )
    if result["families"]:
        result["state"], result["reason"] = "measured", "BEST_OBSERVED_NOT_ISP_THEORETICAL_LIMIT"
    return result
