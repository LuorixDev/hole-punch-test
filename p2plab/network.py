from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import time
from copy import deepcopy
from html.parser import HTMLParser

import aiohttp
import psutil

MIN_ADDRESS_LIFETIME = 30.0
IP_PROVIDERS = (
    ("3322", "https://ip.3322.net", 4),
    ("oray", "https://ddns.oray.com/checkip", 4),
    ("ipw", "https://4.ipw.cn", 4),
    ("ipw", "https://6.ipw.cn", 6),
    ("neu6", "https://speed.neu6.edu.cn/getIP.php", 6),
    ("ipify", "https://api.ipify.org", 4),
    ("ipify", "https://api6.ipify.org", 6),
    ("aws", "https://checkip.amazonaws.com", 4),
    ("icanhazip", "https://ipv4.icanhazip.com", 4),
    ("icanhazip", "https://ipv6.icanhazip.com", 6),
)
DOMESTIC_IP_PROVIDERS = {"3322", "oray", "ipw", "neu6"}
WINDOWS_ADDRESSES = """
$ErrorActionPreference = 'Stop'
$rows = @(Get-NetIPAddress -Type Unicast | ForEach-Object {
    [PSCustomObject]@{
        address = $_.IPAddress; interface = $_.InterfaceAlias
        prefixlen = $_.PrefixLength; state = [string]$_.AddressState
        suffix_origin = [string]$_.SuffixOrigin; skip_as_source = $_.SkipAsSource
        valid_lifetime = $_.ValidLifetime.TotalSeconds
        preferred_lifetime = $_.PreferredLifetime.TotalSeconds
    }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""
WINDOWS_ROUTES = """
$ErrorActionPreference = 'Stop'
$rows = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/0', '::/0')
} | ForEach-Object {
    [PSCustomObject]@{
        prefix = $_.DestinationPrefix; gateway = $_.NextHop
        dev = $_.InterfaceAlias
        metric = $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily $_.AddressFamily).InterfaceMetric
    }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""


async def command(*args, timeout=4.0, limit=65536, env=None):
    if not shutil.which(args[0]):
        return {"command": list(args), "state": "unsupported", "reason": "COMMAND_MISSING"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
        )
    except (OSError, NotImplementedError) as exc:
        return {"command": list(args), "state": "failed", "reason": type(exc).__name__ + ":" + str(exc)}

    async def read_limited(stream):
        data = bytearray()
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("COMMAND_OUTPUT_LIMIT")

    try:
        out, err, _ = await asyncio.wait_for(
            asyncio.gather(read_limited(proc.stdout), read_limited(proc.stderr), proc.wait()), timeout
        )
        text = out.decode(errors="replace")
        result = {
            "command": list(args),
            "state": "completed" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "stderr": err.decode(errors="replace"),
        }
        try:
            result["output"] = json.loads(text)
        except ValueError:
            result["output"] = text
        return result
    except (TimeoutError, ValueError) as exc:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        return {"command": list(args), "state": "failed", "reason": type(exc).__name__ + ":" + str(exc)}
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        raise


def system_addresses(*, loopback=False, maximum: int | None = 4):
    result = []
    stats = psutil.net_if_stats()
    for interface, addresses in psutil.net_if_addrs().items():
        if interface not in stats:
            continue
        for record in addresses:
            if record.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = record.address.split("%", 1)[0]
            ip = ipaddress.ip_address(address)
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                continue
            if ip.is_loopback != loopback:
                continue
            if ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15"):
                continue
            result.append(
                {
                    "address": address,
                    "family": ip.version,
                    "interface": interface,
                    "mtu": stats[interface].mtu,
                    "type": "unverified",
                    "state": "unverified",
                    "source": "psutil",
                    "interface_up": stats[interface].isup,
                    "netmask": record.netmask,
                }
            )
    return result if maximum is None else select_addresses(result, maximum=maximum)


def lifetime(value):
    if value is None or value == "forever":
        return None
    try:
        seconds = float(value)
        return None if seconds == 4294967295 else max(0.0, seconds)
    except (TypeError, ValueError):
        return None


def remaining_lifetime(record, key, *, now=None):
    seconds = record.get(key)
    if seconds is None:
        return None
    now = time.monotonic() if now is None else now
    elapsed = max(0.0, now - record.get("observed_monotonic", now))
    return max(0.0, seconds - elapsed)


def lifetimes_reported(record):
    """False when this platform's address inventory cannot report lifetimes (macOS ifconfig)."""
    return record.get("lifetime_source") != DARWIN_LIFETIME_SOURCE


def address_rejection(record, *, minimum=MIN_ADDRESS_LIFETIME, now=None):
    if not record.get("interface_up", True):
        return "INTERFACE_DOWN"
    if record.get("skip_as_source"):
        return "ADDRESS_SKIP_AS_SOURCE"
    for flag in ("dadfailed", "tentative"):
        if record.get(flag) or record.get("state") == flag:
            return "ADDRESS_" + flag.upper()
    valid = remaining_lifetime(record, "valid_lifetime", now=now)
    preferred = remaining_lifetime(record, "preferred_lifetime", now=now)
    if record.get("state") == "invalid" or valid == 0:
        return "ADDRESS_EXPIRED"
    if record.get("deprecated") or record.get("state") == "deprecated" or preferred == 0:
        return "ADDRESS_DEPRECATED"
    if record["family"] == 6 and record.get("state", "unverified") == "unverified":
        return "IPV6_STATE_UNVERIFIED"
    if any(value is not None and value < minimum for value in (valid, preferred)):
        return "ADDRESS_LIFETIME_TOO_SHORT"
    return None


def address_fingerprint(records):
    return sorted(
        (
            record.get("interface", ""),
            record["address"],
            record.get("type", "unverified"),
            record.get("state", "unverified"),
            address_rejection(record) or "eligible",
        )
        for record in records
    )


def select_addresses(records, *, maximum: int | None = 4, inbound=False, loopback=False, routes=()):
    now = time.monotonic()
    defaults = {}
    for family, route in routes:
        if route.get("dst") == "default" and route.get("dev"):
            metric = route.get("metric", 0)
            metric = metric if type(metric) in (int, float) else 0
            key = (family, route["dev"])
            defaults[key] = min(defaults.get(key, float("inf")), metric)

    def rank(record):
        preferred = remaining_lifetime(record, "preferred_lifetime", now=now)
        valid = remaining_lifetime(record, "valid_lifetime", now=now)
        return (
            defaults.get((record["family"], record.get("interface")), float("inf")),
            not ipaddress.ip_address(record["address"]).is_global,
            record.get("type") == "temporary",
            -(preferred if preferred is not None else float("inf")),
            -(valid if valid is not None else float("inf")),
            record.get("interface", ""),
            record["address"],
        )

    eligible = []
    for record in records:
        if address_rejection(record, now=now):
            continue
        ip = ipaddress.ip_address(record["address"])
        if inbound and (ip.version != 6 or not (ip.is_global or (loopback and ip.is_loopback))):
            continue
        eligible.append(record)
    # Validate per-interface records before deduplicating an address shared by two NICs.
    unique = {}
    for record in sorted(eligible, key=rank):
        unique.setdefault(record["address"], record)
    ordered = list(unique.values())
    chosen = []
    ipv6 = [r for r in ordered if r["family"] == 6]
    ipv6_pool = [r for r in ipv6 if ipaddress.ip_address(r["address"]).is_global] or ipv6
    groups = (
        [r for r in ipv6_pool if r.get("type") != "temporary"],
        [r for r in ordered if r["family"] == 4],
        [r for r in ipv6_pool if r.get("type") == "temporary"],
    )
    if not groups[0]:
        groups = (groups[2], groups[1], groups[0])
    for group in groups:
        if group:
            chosen.append(group[0])
    remaining = [r for r in ordered if r not in chosen]
    while remaining:
        interfaces = {r.get("interface") for r in chosen}
        next_record = next((r for r in remaining if (r["family"], r.get("interface")) in defaults), None)
        if next_record is None:
            next_record = next((r for r in remaining if r.get("interface") not in interfaces), remaining[0])
        chosen.append(next_record)
        remaining.remove(next_record)
    return chosen if maximum is None else chosen[:maximum]


async def read_address_inventory(*, loopback=False):
    fallback = system_addresses(loopback=loopback, maximum=None)
    if platform.system() == "Windows":
        return await windows_address_inventory(fallback, loopback=loopback)
    if platform.system() == "Darwin":
        return await darwin_address_inventory(fallback, loopback=loopback)
    if platform.system() != "Linux":
        return fallback, {"state": "unsupported", "reason": "LINUX_STRUCTURED_ADDRESS_ONLY"}
    observed = time.monotonic()
    result = await command("ip", "-j", "address", "show")
    interfaces = result.get("output")
    if result.get("state") != "completed" or not isinstance(interfaces, list):
        return fallback, result
    result = deepcopy(result)
    records = []
    stats = psutil.net_if_stats()
    for interface in result["output"]:
        # Strip link-layer identities from the raw evidence, not IPv4/IPv6 addresses.
        for key in ("address", "broadcast", "altnames"):
            interface.pop(key, None)
        name = interface.get("ifname", "")
        stat = stats.get(name)
        up = "UP" in interface["flags"] if "flags" in interface else bool(stat and stat.isup)
        for info in interface.get("addr_info", []):
            if info.get("family") not in ("inet", "inet6"):
                continue
            try:
                ip = ipaddress.ip_address(info["local"])
            except (KeyError, ValueError):
                continue
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_loopback != loopback:
                continue
            if ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15"):
                continue
            flags = {str(flag).lower() for flag in info.get("flags", [])}
            temporary = bool(
                info.get("temporary")
                or "temporary" in flags
                or (ip.version == 6 and (info.get("secondary") or "secondary" in flags))
            )
            valid, preferred = (
                lifetime(info.get("valid_life_time")),
                lifetime(info.get("preferred_life_time")),
            )
            record = {
                "address": str(ip),
                "family": ip.version,
                "interface": name,
                "interface_up": up,
                "mtu": interface.get("mtu", stat.mtu if stat else None),
                "prefixlen": info.get("prefixlen"),
                "scope": info.get("scope"),
                "type": "temporary" if temporary else "stable",
                "temporary": temporary,
                "tentative": bool(info.get("tentative") or "tentative" in flags),
                "dadfailed": bool(info.get("dadfailed") or "dadfailed" in flags),
                "deprecated": bool(info.get("deprecated") or "deprecated" in flags or preferred == 0),
                "valid_lifetime": valid,
                "preferred_lifetime": preferred,
                "observed_monotonic": observed,
                "source": "ip-json",
            }
            record["state"] = (
                "dadfailed"
                if record["dadfailed"]
                else "tentative"
                if record["tentative"]
                else "invalid"
                if valid == 0
                else "deprecated"
                if record["deprecated"]
                else "preferred"
                if "valid_life_time" in info and "preferred_life_time" in info
                else "unverified"
            )
            if record["prefixlen"] is not None:
                record["prefix"] = str(ipaddress.ip_network(f"{ip}/{record['prefixlen']}", strict=False))
            records.append(record)
    return records, result


async def powershell(script):
    encoding = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
    return await command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                         "-Command", encoding + script, timeout=30)


async def windows_address_inventory(fallback, *, loopback=False):
    observed = time.monotonic()
    result = await powershell(WINDOWS_ADDRESSES)
    rows = result.get("output")
    if result.get("state") != "completed" or not isinstance(rows, list):
        return fallback, result
    stats = psutil.net_if_stats()
    records = []
    for row in rows:
        try:
            ip = ipaddress.ip_address(row["address"].split("%", 1)[0])
            prefix = int(row["prefixlen"])
            if not 0 <= prefix <= ip.max_prefixlen:
                continue
            if (
                ip.is_link_local
                or ip.is_multicast
                or ip.is_unspecified
                or ip.is_loopback != loopback
                or ip.version == 4
                and ip in ipaddress.ip_network("198.18.0.0/15")
            ):
                continue
            name = row["interface"]
            stat = stats.get(name)
            state = {
                "preferred": "preferred",
                "deprecated": "deprecated",
                "tentative": "tentative",
                "duplicate": "dadfailed",
                "invalid": "invalid",
            }.get(str(row["state"]).lower(), "unverified")
            lifetimes = {}
            for key in ("valid_lifetime", "preferred_lifetime"):
                value = row.get(key)
                lifetimes[key] = None if value is not None and float(value) >= 4294967295 else lifetime(value)
            origin = str(row.get("suffix_origin", ""))
            # Random suffix origin alone does not prove temporary versus stable privacy addressing.
            kind = (
                "stable"
                if ip.version == 4 or origin in ("Manual", "Link", "Dhcp", "WellKnown")
                else "unverified"
            )
            records.append(
                {
                    "address": str(ip),
                    "family": ip.version,
                    "interface": name,
                    "interface_up": bool(stat and stat.isup),
                    "mtu": stat.mtu if stat else None,
                    "prefixlen": prefix,
                    "prefix": str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)),
                    "state": state,
                    "type": kind,
                    "suffix_origin": origin,
                    "temporary": None if kind == "unverified" else False,
                    "tentative": state == "tentative",
                    "dadfailed": state == "dadfailed",
                    "deprecated": state == "deprecated",
                    "skip_as_source": row.get("skip_as_source", False),
                    "observed_monotonic": observed,
                    "source": "windows-netipaddress",
                    **lifetimes,
                }
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    return records, result


async def windows_routes():
    evidence = await powershell(WINDOWS_ROUTES)
    outputs = {4: [], 6: []}
    if evidence.get("state") == "completed" and isinstance(evidence.get("output"), list):
        for row in evidence["output"]:
            try:
                ip = ipaddress.ip_address(row["gateway"].split("%", 1)[0])
                if row["prefix"] != ("0.0.0.0/0" if ip.version == 4 else "::/0") or ip.is_unspecified:
                    continue
                outputs[ip.version].append(
                    {"dst": "default", "gateway": str(ip), "dev": row["dev"], "metric": row.get("metric")}
                )
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
    return [{**evidence, "output": outputs[version]} for version in (4, 6)]


async def read_default_routes():
    if platform.system() == "Windows":
        return await windows_routes()
    if platform.system() == "Linux":
        return await asyncio.gather(command("ip", "-j", "-4", "route", "show"),
                                    command("ip", "-j", "-6", "route", "show"))
    if platform.system() == "Darwin":
        return await darwin_routes()
    return [{"state": "unsupported", "output": []} for _ in range(2)]


def route_fingerprint(result):
    commands = result.get("system_commands", [])
    routes = []
    for family, index in ((4, 1), (6, 2)):
        if len(commands) <= index or commands[index].get("state") != "completed":
            return None
        output = commands[index].get("output")
        if not isinstance(output, list):
            return None
        routes.extend((family, str(row.get("dev", "")), str(row.get("gateway", "")), str(row.get("metric", 0)))
                      for row in output if isinstance(row, dict) and row.get("dst") == "default")
    return tuple(sorted(routes))


def default_routes(result):
    commands = result.get("system_commands", [])
    routes = []
    for version, index in ((4, 1), (6, 2)):
        output = commands[index].get("output", []) if len(commands) > index else []
        if isinstance(output, list):
            routes.extend((version, route) for route in output
                          if isinstance(route, dict) and route.get("dst") == "default")
    return routes



# macOS ships no structured `ip -j` equivalent: ifconfig is the only read-only source that reports
# per-address IPv6 flags, and netstat is the only one that reports the default route list.
DARWIN_INTERFACE = re.compile(
    r"^(?P<name>[^\s:]+):\s+flags=(?P<flags>[0-9a-fx]+)<(?P<set>[^>]*)>(?:\s+mtu\s+(?P<mtu>\d+))?"
)
DARWIN_ANGLE = re.compile(r"<([^>]*)>")
DARWIN_INET6_FLAGS = ("tentative", "dadfailed", "deprecated", "temporary", "autoconf", "secured")
DARWIN_ROUTE_KEYS = ("route to", "destination", "mask", "gateway", "interface", "flags")
# ifconfig never prints an address lifetime, so a missing value here means unreported, not forever.
DARWIN_LIFETIME_SOURCE = "unreported"


def system_tool(name):
    """Resolve a system utility that may sit outside a frozen or GUI-launched process PATH."""
    found = shutil.which(name)
    if found:
        return found
    return shutil.which(name, path="/sbin:/usr/sbin:/usr/bin:/bin") or name


def darwin_prefix_length(fields, ip):
    """ifconfig prints an IPv6 prefixlen or an IPv4 netmask; nothing else is guessed."""
    for index, token in enumerate(fields[:-1]):
        value = fields[index + 1]
        if token == "prefixlen":
            try:
                return int(value)
            except ValueError:
                return None
        if token == "netmask" and ip.version == 4:
            try:
                if value.lower().startswith("0x"):
                    return bin(int(value, 16)).count("1")
                return ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen
            except (TypeError, ValueError):
                return None
    return None


def darwin_address_record(family, fields, *, interface, up, mtu, neighbor_discovery, loopback, observed):
    try:
        ip = ipaddress.ip_address(fields[0].split("%", 1)[0])
    except (IndexError, ValueError):
        return None
    if ip.version != (4 if family == "inet" else 6):
        return None
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_loopback != loopback:
        return None
    if ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15"):
        return None
    flags = {token for token in fields[1:] if token in DARWIN_INET6_FLAGS}
    prefixlen = darwin_prefix_length(fields, ip)
    record = {
        "address": str(ip),
        "family": ip.version,
        "interface": interface,
        "interface_up": up,
        "mtu": mtu,
        "prefixlen": prefixlen,
        "type": "temporary" if "temporary" in flags else "stable",
        "temporary": "temporary" in flags,
        "tentative": "tentative" in flags,
        "dadfailed": "dadfailed" in flags,
        "deprecated": "deprecated" in flags,
        "observed_monotonic": observed,
        "source": "darwin-ifconfig",
        "valid_lifetime": None,
        "preferred_lifetime": None,
        "lifetime_source": DARWIN_LIFETIME_SOURCE,
    }
    if prefixlen is not None:
        record["prefix"] = str(ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False))
    if ip.version == 6 and neighbor_discovery is not None:
        record["neighbor_discovery"] = neighbor_discovery
    record["state"] = (
        "dadfailed"
        if record["dadfailed"]
        else "tentative"
        if record["tentative"]
        else "deprecated"
        if record["deprecated"]
        else "preferred"
    )
    return record


def parse_ifconfig(text, *, loopback=False, observed=None):
    """Read macOS ifconfig output into the record shape the Linux ip-json reader produces.

    The kernel flags an IPv6 address as tentative, dadfailed or deprecated; it reports no
    lifetimes, so an address is never called permanent and no lifetime is invented. The IPv6
    ifconfig `nd6 options` line is kept verbatim as `neighbor_discovery` evidence.
    """
    observed = time.monotonic() if observed is None else observed
    interfaces, current = [], None
    for line in text.splitlines():
        header = DARWIN_INTERFACE.match(line)
        if header:
            current = {
                "name": header["name"],
                "up": "UP" in header["set"].split(","),
                "mtu": int(header["mtu"]) if header["mtu"] else None,
                "status": None,
                "neighbor_discovery": None,
                "addresses": [],
            }
            interfaces.append(current)
            continue
        if current is None or not line[:1].isspace():
            continue
        fields = line.split()
        key = fields[0].rstrip(":")
        if key == "status" and len(fields) > 1:
            current["status"] = fields[1]
        elif key == "nd6":
            match = DARWIN_ANGLE.search(line)
            current["neighbor_discovery"] = match[1] if match else line.strip()
        elif key in ("inet", "inet6"):
            current["addresses"].append((key, fields[1:]))
    records, seen = [], set()
    for interface in interfaces:
        # A UP flag alone is not reachability: Wi-Fi and bridge members keep UP with no carrier.
        up = interface["up"] and interface["status"] in (None, "active")
        for family, fields in interface["addresses"]:
            record = darwin_address_record(
                family,
                fields,
                interface=interface["name"],
                up=up,
                mtu=interface["mtu"],
                neighbor_discovery=interface["neighbor_discovery"],
                loopback=loopback,
                observed=observed,
            )
            key = None if record is None else (record["interface"], record["address"])
            if key is None or key in seen:
                continue
            seen.add(key)
            records.append(record)
    return records


async def darwin_address_inventory(fallback, *, loopback=False):
    observed = time.monotonic()
    result = await command(system_tool("ifconfig"), "-a")
    text = result.get("output")
    if result.get("state") != "completed" or not isinstance(text, str):
        return fallback, result
    records = parse_ifconfig(text, loopback=loopback, observed=observed)
    if not records and fallback:
        # psutil still sees addresses, so an empty parse means the output format moved.
        return fallback, {**result, "state": "failed", "reason": "DARWIN_IFCONFIG_UNPARSED"}
    return records, result


def parse_netstat_defaults(text):
    """Read usable default routes from `netstat -rn -f inet|inet6`.

    A row flagged with `!` is a kernel entry that is not in the routing table, and a `link#N`
    gateway is a local interface rather than a next hop, so neither becomes a gateway.
    """
    routes, seen = [], set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "default" or "!" in fields[2]:
            continue
        gateway, interface = fields[1], fields[3]
        try:
            ip = ipaddress.ip_address(gateway.split("%", 1)[0])
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_multicast or (str(ip), interface) in seen:
            continue
        seen.add((str(ip), interface))
        routes.append(
            {
                "dst": "default",
                "gateway": str(ip),
                "dev": interface,
                "metric": None,
                "flags": fields[2],
                "scoped_gateway": gateway,
            }
        )
    return routes


async def darwin_routes():
    evidence = []
    for family in ("inet", "inet6"):
        result = await command(system_tool("netstat"), "-rn", "-f", family)
        text = result.get("output")
        evidence.append(
            {
                **result,
                "family": family,
                "output": parse_netstat_defaults(text) if isinstance(text, str) else [],
            }
        )
    return evidence


def parse_route_get(text):
    """Read `route -n get` keyed text; None means the kernel reported no usable route."""
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        key = key.strip().lower()
        if separator and key in DARWIN_ROUTE_KEYS:
            fields[key.replace(" ", "_")] = value.strip().strip("<>")
    return fields if "gateway" in fields or "interface" in fields else None


async def darwin_route_to(target, resolution):
    """macOS route(8) resolves an IPv4 next hop; its IPv6 lookup returns no usable route."""
    if ipaddress.ip_address(target).version == 6:
        return {
            "state": "unsupported",
            "reason": "DARWIN_ROUTE_GET_IPV6_UNSUPPORTED",
            "resolution": resolution,
        }
    result = await command(system_tool("route"), "-n", "get", target)
    text = result.get("output")
    parsed = parse_route_get(text) if isinstance(text, str) else None
    if parsed is None:
        return {
            "state": "not-tested",
            "reason": "DARWIN_ROUTE_NOT_IN_TABLE",
            "command": result.get("command"),
            "stderr": result.get("stderr", ""),
            "resolution": resolution,
        }
    return {**result, "output": parsed, "resolution": resolution}


def path_route_backend(system=None):
    """Name the tool that can report the kernel's route to a peer, or None where none can."""
    name = (system or platform.system()).lower()
    if name == "linux":
        return "linux-ip-route"
    if name == "darwin":
        return "darwin-route-get"
    return None


async def path_route_evidence(target, source=None):
    """Report the route the kernel would use to reach `target`, pinned to `source` when asked.

    Linux answers with `ip -j route get`. macOS route(8) has no source-pinned form and cannot
    resolve an IPv6 next hop, so those cases say so instead of inventing evidence. Platforms with
    neither tool return None and the caller records nothing at all.
    """
    backend = path_route_backend()
    if backend is None:
        return None
    if backend == "darwin-route-get":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return {"state": "not-tested", "reason": "ROUTE_TARGET_NOT_AN_ADDRESS", "target": target}
        result = await darwin_route_to(target, {"host": target, "state": "literal", "addresses": [target]})
        result["source"] = source
        result["source_scoped"] = False
        return result
    arguments = ["ip", "-j", "route", "get", target]
    if source:
        arguments += ["from", source]
    return await command(*arguments)


def apply_address_inventory(result, records, *, maximum=4):
    result["address_inventory"] = records
    commands = result.get("system_commands", [])
    routes = default_routes(result)
    result["addresses"] = select_addresses(records, maximum=maximum, routes=routes)
    result["address_selection"] = {
        "basis": "default-route-and-metric-before-lifetimes;retain-other-interfaces-within-budget",
        "default_routes": [{"family": family, **route} for family, route in routes if route.get("dst") == "default"],
    }
    selected = {(r["interface"], r["address"]) for r in result["addresses"]}
    result["excluded_addresses"] = [
        {**r, "reason": address_rejection(r) or "ADDRESS_CANDIDATE_BUDGET"}
        for r in records
        if (r["interface"], r["address"]) not in selected
    ]
    for version, index in ((4, 1), (6, 2)):
        gateways = []
        routes = commands[index].get("output", []) if len(commands) > index else []
        if isinstance(routes, list):
            for route in routes:
                if route.get("dst") == "default" and route.get("gateway"):
                    for address in result["addresses"]:
                        if address["family"] == version and address["interface"] == route.get("dev"):
                            gateways.append(
                                {
                                    "gateway": route["gateway"],
                                    "local": address["address"],
                                    "interface": route["dev"],
                                }
                            )
        result["gateways" if version == 4 else "gateways6"] = gateways
    result["ipv6_status"] = (
        "GLOBAL_ADDRESS_PRESENT"
        if any(r["family"] == 6 and ipaddress.ip_address(r["address"]).is_global for r in result["addresses"])
        else "NO_USABLE_GLOBAL_V6_NOT_A_FIREWALL_VERDICT"
    )


class CheckIPHTML(HTMLParser):
    """Accept only the small legacy CheckIP document, not arbitrary portal HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.text = []
        self.body_seen = False

    def handle_starttag(self, tag, attrs):
        allowed = {None: {"html"}, "html": {"head", "body"}, "head": {"title"}}
        parent = self.stack[-1] if self.stack else None
        if attrs or tag not in allowed.get(parent, set()) or (tag == "body" and self.body_seen):
            raise ValueError("IP_QUERY_UNEXPECTED_HTML")
        if tag == "body":
            self.body_seen = True
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise ValueError("IP_QUERY_UNEXPECTED_HTML")

    def handle_data(self, data):
        if self.stack and self.stack[-1] == "body":
            self.text.append(data)
        elif data.strip() and (not self.stack or self.stack[-1] != "title"):
            raise ValueError("IP_QUERY_UNEXPECTED_HTML")

    def handle_startendtag(self, tag, attrs):
        raise ValueError("IP_QUERY_UNEXPECTED_HTML")


def parse_ip_response(provider, raw, version):
    text = raw.decode("utf-8").strip()
    if provider == "oray":
        if text.startswith("<"):
            parser = CheckIPHTML()
            parser.feed(text)
            parser.close()
            if parser.stack or not parser.body_seen:
                raise ValueError("IP_QUERY_UNEXPECTED_HTML")
            text = "".join(parser.text).strip()
        label = "Current IP Address:"
        if not text.startswith(label):
            raise ValueError("IP_QUERY_RESPONSE_FORMAT")
        text = text[len(label):].strip()
    address = ipaddress.ip_address(text)
    if address.version != version or not address.is_global or address.is_multicast or "%" in text:
        raise ValueError("IP_QUERY_FAMILY_OR_SCOPE_MISMATCH")
    return str(address)


async def query_ip(provider, url, version):
    started = time.monotonic()
    details = {
        "provider": provider, "url": url, "family": version,
        "region": "domestic" if provider in DOMESTIC_IP_PROVIDERS else "international",
    }
    try:
        connector = aiohttp.TCPConnector(family=socket.AF_INET if version == 4 else socket.AF_INET6)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False,
            timeout=aiohttp.ClientTimeout(total=4 if provider in DOMESTIC_IP_PROVIDERS else 3.5),
        ) as session:
            async with session.get(url, allow_redirects=False) as response:
                if response.status != 200:
                    raise aiohttp.ClientResponseError(
                        response.request_info, response.history, status=response.status,
                        message="IP_QUERY_EXPECTED_HTTP_200",
                    )
                response.raise_for_status()
                raw = bytearray()
                while chunk := await response.content.read(513 - len(raw)):
                    raw.extend(chunk)
                    if len(raw) > 512:
                        raise ValueError("IP_QUERY_RESPONSE_LIMIT")
                address = parse_ip_response(provider, raw, version)
                return {
                    **details,
                    "state": "observed",
                    "address": str(address),
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                    "evidence": "https-egress-not-udp-mapping",
                }
    except Exception as exc:
        # Read the status through getattr: the isinstance guard already proves the attribute exists.
        status = getattr(exc, "status", None)
        retryable = (
            isinstance(exc, (TimeoutError, aiohttp.ClientConnectionError))
            and not isinstance(exc, aiohttp.ClientSSLError)
        ) or (isinstance(exc, aiohttp.ClientResponseError) and status in (500, 502, 503, 504))
        return {
            **details,
            "state": "unavailable",
            "reason": type(exc).__name__ + ":" + str(exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "retryable": retryable,
        }


async def query_public_ips():
    async def collect(item):
        attempts = [await query_ip(*item)]
        if item[0] in DOMESTIC_IP_PROVIDERS and attempts[0].get("retryable"):
            await asyncio.sleep(0.25)
            attempts.append(await query_ip(*item))
        # Keep every failed request as evidence, even if its retry succeeds.
        return {**attempts[-1], "attempts": attempts}

    # Queries are independent; one failed provider cannot suppress another.
    return await asyncio.gather(*(collect(item) for item in IP_PROVIDERS))


def http_ip_summary(observations, inventory):
    result = {}
    for family in (4, 6):
        rows = [r for r in observations if r.get("family") == family and r.get("state") == "observed"]
        addresses = sorted({r["address"] for r in rows})
        providers = sorted({r["provider"] for r in rows})
        result[str(family)] = {
            "state": "multiple-egresses" if len(addresses) > 1 else "corroborated"
            if len(providers) > 1 else "single-provider" if addresses else "not-observed",
            "addresses": addresses,
            "providers": providers,
            "evidence": "http-egress-only-not-a-p2p-candidate",
        }
        if family == 6:
            local = {r["address"] for r in inventory if r["family"] == 6 and not address_rejection(r)}
            result["6"]["not_in_local_inventory"] = [a for a in addresses if a not in local]
    return result


async def route_to_server(host):
    resolution = {"host": host}
    try:
        try:
            target = str(ipaddress.ip_address(host))
            resolution.update(state="literal", addresses=[target])
        except ValueError:
            rows = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(
                    host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                ),
                3,
            )
            addresses = list(dict.fromkeys(row[4][0] for row in rows))
            if not addresses:
                raise ValueError("SERVER_NO_IPV4_DNS_RESULT")
            target = addresses[0]
            resolution.update(state="resolved", addresses=addresses)
        if platform.system() == "Darwin":
            return await darwin_route_to(target, resolution)
        result = await command("ip", "-j", "route", "get", target)
        return {**result, "resolution": resolution}
    except (OSError, TimeoutError, ValueError) as exc:
        return {
            "state": "not-tested",
            "reason": type(exc).__name__ + ":" + str(exc),
            "resolution": {**resolution, "state": "failed"},
        }


async def snapshot(journal, *, server_host, external=True, loopback=False, maximum=4):
    journal.event("network.started", "Collecting bounded, read-only network evidence")
    result = {
        "platform": platform.platform(),
        "proxy_environment": {
            k: "present"
            for k in os.environ
            if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        },
        "udp_mapping": "not-measured-yet",
    }
    if platform.system() == "Linux":
        tasks = [
            read_address_inventory(loopback=loopback),
            command("ip", "-j", "-4", "route", "show"),
            command("ip", "-j", "-6", "route", "show"),
            route_to_server(server_host),
        ]
        address_result, *routes = await asyncio.gather(*tasks)
        inventory, address_command = address_result
        result["system_commands"] = [address_command, *routes]
        if external:
            result["active_commands"] = await asyncio.gather(
                command("ping", "-n", "-c", "1", "-W", "2", server_host),
                command("tracepath", "-n", server_host, timeout=4),
            )
    elif platform.system() == "Windows":
        (inventory, address_command), routes = await asyncio.gather(
            read_address_inventory(loopback=loopback), windows_routes(),
        )
        result["system_commands"] = [address_command, *routes]
        if external:
            result["active_commands"] = await asyncio.gather(
                command("ping.exe", "-n", "1", "-w", "2000", server_host),
                command("tracert.exe", "-d", "-h", "5", "-w", "500", server_host, timeout=5),
            )
    elif platform.system() == "Darwin":
        (inventory, address_command), routes, server_route = await asyncio.gather(
            read_address_inventory(loopback=loopback),
            darwin_routes(),
            route_to_server(server_host),
        )
        result["system_commands"] = [address_command, *routes, server_route]
        if external:
            result["active_commands"] = await asyncio.gather(
                command(system_tool("ping"), "-n", "-c", "1", "-W", "2000", server_host),
                command(
                    system_tool("traceroute"), "-n", "-w", "1", "-q", "1", "-m", "5", server_host, timeout=6
                ),
            )
    else:
        inventory, address_command = await read_address_inventory(loopback=loopback)
        result["system_commands"] = [{"state": "unsupported", "reason": "LINUX_STRUCTURED_ROUTE_ONLY"}]
    if external:
        result["http_observations"] = await query_public_ips()
    else:
        result["http_observations"] = [{"state": "not-tested", "reason": "EXTERNAL_DIAGNOSTICS_DISABLED"}]
    # Apply budgets only after states/lifetimes are known and slow diagnostics have finished.
    apply_address_inventory(result, inventory, maximum=maximum)
    result["http_ip_summary"] = http_ip_summary(result["http_observations"], inventory)
    for section, evidence in result.items():
        journal.event("network." + section, evidence=evidence)
    journal.event("network.completed", address_count=len(result["addresses"]))
    return result
