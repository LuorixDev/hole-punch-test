"""Bounded diagnostic metadata; never application payload or a firewall verdict."""

from __future__ import annotations

import datetime as dt
import ipaddress
import math

from .inbound import MESSAGES

INBOUND_CODES = set(MESSAGES) | {"NOT_TESTED", "RESULT_UNRECOGNIZED"}
WAN_STATES = {"not-tested", "running", "measured", "failed", "cancelled", "configured"}
MAX_AGE_SECONDS = 1800


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def timestamp_age(value):
    try:
        stamp = dt.datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            return None
        return (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()
    except (TypeError, ValueError):
        return None


def positive_rate(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 < value <= 1_000_000


def valid_ip(value):
    try:
        return isinstance(value, str) and len(value) <= 45 and not ipaddress.ip_address(value).is_unspecified
    except ValueError:
        return False


def public_ip_evidence(status):
    result = {}
    for family in (4, 6):
        sources = {
            source: sorted({r["address"] for r in status.get("public_ips", [])
                            if r["family"] == family and r["source"] == source})
            for source in ("http", "signaling", "stun")
        }
        observed = {a for addresses in sources.values() for a in addresses
                    if ipaddress.ip_address(a).is_global and not ipaddress.ip_address(a).is_multicast}
        non_global = {source: [a for a in addresses if a not in observed]
                      for source, addresses in sources.items()}
        result[str(family)] = {
            "sources": sources,
            "non_global_sources": non_global,
            "state": "multiple-observed-addresses" if len(observed) > 1 else
            "observed" if observed else "not-observed",
        }
    return result


def validate_status(status):
    if not isinstance(status, dict) or set(status) != {
        "addresses",
        "public_ips",
        "inbound",
        "wan",
        "updated_at",
    }:
        raise ValueError("INVALID_NETWORK_STATUS_FIELDS")
    age = timestamp_age(status["updated_at"])
    if age is None or age < -60 or age > MAX_AGE_SECONDS:
        raise ValueError("INVALID_NETWORK_STATUS_TIME")
    for key, maximum in (("addresses", 16), ("public_ips", 8), ("inbound", 8)):
        if not isinstance(status[key], list) or len(status[key]) > maximum:
            raise ValueError("NETWORK_STATUS_LIMIT")
    for row in status["addresses"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"address", "family", "interface", "type"}
            or not valid_ip(row["address"])
            or type(row["family"]) is not int
            or ipaddress.ip_address(row["address"]).version != row["family"]
            or not isinstance(row["interface"], str)
            or len(row["interface"]) > 64
            or not isinstance(row["type"], str)
            or row["type"] not in ("stable", "temporary", "unverified")
        ):
            raise ValueError("INVALID_NETWORK_STATUS_ADDRESS")
    for row in status["public_ips"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"address", "family", "source"}
            or not valid_ip(row["address"])
            or type(row["family"]) is not int
            or ipaddress.ip_address(row["address"]).version != row["family"]
            or not isinstance(row["source"], str)
            or row["source"] not in ("http", "signaling", "stun")
        ):
            raise ValueError("INVALID_PUBLIC_IP_STATUS")
    for row in status["inbound"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"address", "code", "listener_received", "tested_at"}
            or not valid_ip(row["address"])
            or not isinstance(row["code"], str)
            or row["code"] not in INBOUND_CODES
            or type(row["listener_received"]) is not bool
            or timestamp_age(row["tested_at"]) is None
        ):
            raise ValueError("INVALID_INBOUND_STATUS")
    wan = status["wan"]
    if (
        not isinstance(wan, dict)
        or set(wan) != {"state", "families"}
        or not isinstance(wan["state"], str)
        or wan["state"] not in WAN_STATES
    ):
        raise ValueError("INVALID_WAN_STATUS")
    if not isinstance(wan["families"], dict) or not set(wan["families"]) <= {"4", "6"}:
        raise ValueError("INVALID_WAN_FAMILIES")
    for family, row in wan["families"].items():
        if (
            not isinstance(row, dict)
            or set(row) != {"upload_mbps", "download_mbps", "measured_at", "basis", "source", "interface"}
            or not all(row[k] is None or positive_rate(row[k]) for k in ("upload_mbps", "download_mbps"))
            or not isinstance(row["basis"], str)
            or row["basis"] not in ("measured", "configured")
            or not isinstance(row["interface"], str)
            or len(row["interface"]) > 64
            or (
                row["source"] is not None
                and (
                    not valid_ip(row["source"]) or ipaddress.ip_address(row["source"]).version != int(family)
                )
            )
            or timestamp_age(row["measured_at"]) is None
        ):
            raise ValueError("INVALID_WAN_REFERENCE")
    return status


def direction_reference(local, peer, family, direction, *, peer_family=None):
    """A measured WAN baseline is a reference, not proof of an ISP's ceiling."""
    left = local.get("wan", {}).get("families", {}).get(str(family), {})
    right = peer.get("wan", {}).get("families", {}).get(str(peer_family or family), {})
    for status, row in ((local, left), (peer, right)):
        age = timestamp_age(status.get("updated_at"))
        measured_age = timestamp_age(row.get("measured_at"))
        if (
            not row
            or age is None
            or not -60 <= age <= MAX_AGE_SECONDS
            or measured_age is None
            or not -60 <= measured_age <= MAX_AGE_SECONDS
            or status.get("wan", {}).get("state") in ("running", "failed", "cancelled")
        ):
            return None
    rates = (
        (left.get("upload_mbps"), right.get("download_mbps"))
        if direction == "local-to-peer"
        else (right.get("upload_mbps"), left.get("download_mbps"))
    )
    if not all(positive_rate(rate) for rate in rates):
        return None
    return {
        "mbps": min(rates),
        "basis": "configured" if all(r["basis"] == "configured" for r in (left, right)) else "measured",
        "endpoint_rates_mbps": list(rates),
    }


def speed_assessment(result, reference):
    if not reference or not positive_rate(result.get("mbps")) or result.get("short_sample"):
        return None
    if result.get("seconds", 0) < 1:
        return None
    fraction = result["mbps"] / reference["mbps"]
    # LAN paths, routing differences and underestimated test servers can exceed WAN measurements.
    return {
        **reference,
        "fraction": fraction,
        "state": "above-reference"
        if fraction > 1.2
        else ("near-limit" if fraction >= 0.9 else "below-limit"),
    }
