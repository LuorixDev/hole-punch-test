"""Multi-observer STUN probe for NAT mapping and filtering behavior.

Terms follow RFC 4787. Transactions use RFC 5389 Binding; the filtering test uses
RFC 5780 CHANGE-REQUEST and OTHER-ADDRESS from the same socket.

What this module does
- Sends Binding requests only to the observation points the caller configured, plus
  the alternate source a configured point advertises through OTHER-ADDRESS (or an
  alternate the caller configured explicitly).
- Uses several local ports, and repeated requests per point, then classifies
  mapping and filtering behavior from how the OBSERVED mapped endpoints change
  with the destination and from which response sources the path accepted.

What this module is not
- It never infers a NAT type from one mapped address. `mapping`/`filtering` are
  inferences; `observations`/`mappedEndpoints` are the raw observations, and the
  two are reported separately.
- Local controlled responders are not real home-network evidence. A result is
  only real-network evidence once the user runs this on the real network.
- No relay, no TURN, no discovery, no third-party STUN, no DNS (hosts are literal
  IPs, enforced by the shared canonical_endpoint rule), no interface enumeration.

Privacy
- Mapped public endpoints are local private diagnostics. `NatProfile.report()`
  omits them unless the caller explicitly asks for a local view.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import secrets
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

from .stun import COOKIE, canonical_endpoint, receive_udp_retry, socket_address, udp_unreachable

BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_CHANGE_REQUEST = 0x0003
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_OTHER_ADDRESS = 0x802C
CHANGE_IP = 0x02
CHANGE_PORT = 0x04

MAPPING_ENDPOINT_INDEPENDENT = "endpoint-independent"
MAPPING_ADDRESS_DEPENDENT = "address-dependent"
MAPPING_ADDRESS_AND_PORT_DEPENDENT = "address-and-port-dependent"
FILTERING_ENDPOINT_INDEPENDENT = "endpoint-independent"
FILTERING_ADDRESS_DEPENDENT = "address-dependent"
FILTERING_ADDRESS_AND_PORT_DEPENDENT = "address-and-port-dependent"
UNDETERMINED = "undetermined"

REACHABILITY_HIGH = "high"
REACHABILITY_MEDIUM = "medium"
REACHABILITY_LOW = "low"
REACHABILITY_UNKNOWN = "unknown"

MAPPING_LABELS = {
    MAPPING_ENDPOINT_INDEPENDENT: "端点无关（对外端口不随目标变化）",
    MAPPING_ADDRESS_DEPENDENT: "地址相关（对外端口随目标地址变化）",
    MAPPING_ADDRESS_AND_PORT_DEPENDENT: "地址+端口相关（对称型）",
    UNDETERMINED: "无法判定（观测不足）",
}
FILTERING_LABELS = {
    FILTERING_ENDPOINT_INDEPENDENT: "端点无关（不限制外部来源）",
    FILTERING_ADDRESS_DEPENDENT: "地址相关（只允许联系过的地址回包）",
    FILTERING_ADDRESS_AND_PORT_DEPENDENT: "地址+端口相关（只允许联系过的地址和端口回包）",
    UNDETERMINED: "无法判定（观测不足或缺可选观测点）",
}
REACHABILITY_LABELS = {
    REACHABILITY_HIGH: "高",
    REACHABILITY_MEDIUM: "中",
    REACHABILITY_LOW: "低",
    REACHABILITY_UNKNOWN: "未知（数据不足）",
}

RETRY_WAITS = (.1, .2, .4, .8, 1.6)
MAX_ERRORS = 64


class ProbeTimeout(TimeoutError):
    """No usable Binding response inside the caller's timeout."""

    def __init__(self, code="PROBE_TIMEOUT"):
        super().__init__(code)
        self.code = code


class ProbeSendFailed(OSError):
    """The OS refused to send to the observation point (not an ICMP no-response)."""


def _encode_request(transaction, change=None):
    body = struct.pack("!HHI", ATTR_CHANGE_REQUEST, 4, change) if change else b""
    return struct.pack("!HHI12s", BINDING_REQUEST, len(body), COOKIE, transaction) + body


def _decode_xor_address(value, transaction):
    if len(value) < 4 or value[0] != 0 or value[1] not in {1, 2}:
        raise ValueError("STUN_INVALID_ADDRESS")
    expected = 8 if value[1] == 1 else 20
    if len(value) != expected:
        raise ValueError("STUN_INVALID_ADDRESS")
    port = struct.unpack("!H", value[2:4])[0] ^ (COOKIE >> 16)
    if not 1 <= port <= 65535:
        raise ValueError("STUN_INVALID_PORT")
    mask = struct.pack("!I", COOKIE) + transaction
    address = ipaddress.ip_address(bytes(a ^ b for a, b in zip(value[4:], mask[:len(value) - 4])))
    if address.is_multicast or address.is_unspecified or address.is_link_local:
        raise ValueError("STUN_INVALID_ADDRESS")
    return str(address), port


def _parse_response(data, transaction):
    """Return {'mapped': (host, port), 'other': (host, port) | absent} or raise ValueError.

    Forged or malformed replies (wrong message type, cookie, transaction id,
    truncated length, missing/mis-sized XOR-MAPPED-ADDRESS) never parse.
    """
    if len(data) < 20:
        raise ValueError("STUN_TRUNCATED")
    kind, size, cookie, tid = struct.unpack("!HHI12s", data[:20])
    if kind != BINDING_SUCCESS or cookie != COOKIE or tid != transaction or size != len(data) - 20 or size % 4:
        raise ValueError("STUN_TRANSACTION_MISMATCH")
    parsed = {}
    position = 20
    while position + 4 <= len(data):
        attribute, length = struct.unpack("!HH", data[position:position + 4])
        value = data[position + 4:position + 4 + length]
        if len(value) != length:
            raise ValueError("STUN_TRUNCATED")
        position += 4 + ((length + 3) // 4) * 4
        if attribute == ATTR_XOR_MAPPED_ADDRESS:
            parsed["mapped"] = _decode_xor_address(value, transaction)
        elif attribute == ATTR_OTHER_ADDRESS:
            parsed["other"] = _decode_xor_address(value, transaction)
    if "mapped" not in parsed:
        raise ValueError("STUN_NO_XOR_MAPPED_ADDRESS")
    return parsed


async def _transaction(sock, destination, family, timeout, change=None, accept=()):
    """One bounded Binding transaction on an existing socket.

    Only replies from `destination` (or an explicitly accepted alternate source)
    count; a reply from anywhere else is rejected, never recorded. Replies that
    fail to parse are rejected the same way. The retry schedule is bounded by
    `timeout`, which is never extended.
    """
    loop = asyncio.get_running_loop()
    transaction = secrets.token_bytes(12)
    request = _encode_request(transaction, change)
    allowed = {canonical_endpoint(destination, family)}
    for endpoint in accept:
        allowed.add(canonical_endpoint(endpoint, family))
    start = time.monotonic()
    rejected = False
    for wait in RETRY_WAITS:
        remaining = timeout - (time.monotonic() - start)
        if remaining <= 0:
            break
        try:
            await loop.sock_sendto(sock, request, socket_address(destination, family))
        except OSError as exc:
            if udp_unreachable(exc):
                pass  # ICMP unreachable is a bounded no-response, never evidence
            else:
                raise ProbeSendFailed(exc.errno, str(exc)) from exc
        deadline = time.monotonic() + min(wait, remaining)
        while time.monotonic() < deadline:
            try:
                packet, remote = await asyncio.wait_for(receive_udp_retry(sock, 2048), deadline - time.monotonic())
            except asyncio.TimeoutError:
                break
            try:
                source = canonical_endpoint(remote, family)
            except ValueError:
                rejected = True
                continue
            if source not in allowed:
                rejected = True
                continue
            try:
                return source, _parse_response(packet, transaction)
            except ValueError:
                rejected = True
                continue
    raise ProbeTimeout("RESPONSE_REJECTED" if rejected else "PROBE_TIMEOUT")


@dataclass(frozen=True)
class StunObservationPoint:
    """One explicitly configured observation point (literal IP, never a DNS name).

    `alternate_address` (different IP) and `alternate_port` (same IP, other port)
    are only needed when the point does not advertise OTHER-ADDRESS; they are the
    sources used by the RFC 5780 CHANGE-REQUEST filtering test.
    """

    host: str
    port: int
    alternate_address: tuple[str, int] | None = None
    alternate_port: tuple[str, int] | None = None
    label: str = ""

    def destination(self, family):
        return canonical_endpoint((self.host, self.port), family)

    def alternates(self, family):
        result = []
        for endpoint in (self.alternate_address, self.alternate_port):
            if endpoint is not None:
                result.append(canonical_endpoint(endpoint, family))
        return tuple(result)


@dataclass(frozen=True)
class NatProbeConfig:
    bind_host: str
    points: tuple[StunObservationPoint, ...]
    local_ports: int = 2
    repeats: int = 2
    timeout: float = 2.0

    def family(self):
        return socket.AF_INET6 if ipaddress.ip_address(self.bind_host).version == 6 else socket.AF_INET

    def destinations(self):
        family = self.family()
        return tuple(point.destination(family) for point in self.points)

    def validate(self):
        address = ipaddress.ip_address(self.bind_host)
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("EXPLICIT_BIND_REQUIRED")
        if not isinstance(self.points, tuple) or not self.points:
            raise ValueError("OBSERVATION_POINTS_REQUIRED")
        family = self.family()
        if len(set(self.destinations())) < 2:
            raise ValueError("INSUFFICIENT_OBSERVATION_POINTS")
        if not 1 <= self.local_ports <= 8:
            raise ValueError("INVALID_LOCAL_PORT_COUNT")
        if not 1 <= self.repeats <= 8:
            raise ValueError("INVALID_REPEAT_COUNT")
        if not 0 < self.timeout <= 10:
            raise ValueError("INVALID_TIMEOUT")
        for point in self.points:
            destination = point.destination(family)  # literal IP + family match
            for alternate in point.alternates(family):
                if alternate == destination:
                    raise ValueError("ALTERNATE_IS_PRIMARY")
            if point.alternate_address is not None:
                alternate = canonical_endpoint(point.alternate_address, family)
                if alternate[0] == destination[0]:
                    raise ValueError("ALTERNATE_ADDRESS_MUST_DIFFER_IN_ADDRESS")
            if point.alternate_port is not None:
                alternate = canonical_endpoint(point.alternate_port, family)
                if alternate[0] != destination[0]:
                    raise ValueError("ALTERNATE_PORT_MUST_SHARE_ADDRESS")
        return self


@dataclass(frozen=True)
class MappingSample:
    """One accepted Binding observation. Local private (it names a mapped endpoint)."""

    local_port: int
    destination: tuple[str, int]
    mapped: tuple[str, int]
    repeat: int


def classify_mapping(samples, destinations):
    """Infer mapping behavior from observed mapped endpoints only.

    Returns (behavior, evidence, partial). `partial` carries an honest coarse hint
    when a full classification is impossible; the behavior is never guessed.
    """
    if not samples:
        return UNDETERMINED, "no Binding response was observed from any configured observation point", None
    expected = set(destinations)
    by_local = {}
    for sample in samples:
        by_local.setdefault(sample.local_port, {}).setdefault(sample.destination, set()).add(sample.mapped)
    for local_port, per_destination in sorted(by_local.items()):
        for destination, mapped in sorted(per_destination.items()):
            if len(mapped) > 1:
                return UNDETERMINED, (
                    f"local port {local_port} received {len(mapped)} different mapped endpoints from the same "
                    f"observation point {destination[0]}:{destination[1]} across repeats; the mapping is unstable, "
                    "so no behavior can be inferred"), None
    complete = [(local_port, per_destination) for local_port, per_destination in sorted(by_local.items())
                if set(per_destination) == expected]
    if not complete:
        best = max((len(per_destination) for per_destination in by_local.values()), default=0)
        return UNDETERMINED, (
            f"incomplete observations: the best-covered local port answered {best}/{len(expected)} configured "
            "observation points, so the mapping dependence cannot be compared"), None
    distinct_addresses = {destination[0] for destination in expected}
    varies_within_address = False
    differs_across_addresses = False
    for _, per_destination in complete:
        by_address = {}
        for destination, mapped in per_destination.items():
            by_address.setdefault(destination[0], set()).add(next(iter(mapped)))
        if any(len(values) > 1 for values in by_address.values()):
            varies_within_address = True
        if len({next(iter(values)) for values in by_address.values()}) > 1:
            differs_across_addresses = True
    if varies_within_address:
        return MAPPING_ADDRESS_AND_PORT_DEPENDENT, (
            "the same local port received different mapped endpoints from two observation points sharing one address "
            "but using different ports, so the mapped endpoint depends on the destination port"), None
    if differs_across_addresses:
        return MAPPING_ADDRESS_DEPENDENT, (
            "mapped endpoints differed between observation-point addresses and stayed constant across the ports of "
            "each address, so the mapped endpoint depends on the destination address only"), None
    if len(distinct_addresses) >= 2:
        return MAPPING_ENDPOINT_INDEPENDENT, (
            f"{len(complete)} local ports x {len(expected)} observation points across {len(distinct_addresses)} "
            "destination addresses all produced one stable mapped endpoint per local port, so the mapped endpoint "
            "does not depend on the destination"), None
    return UNDETERMINED, (
        "every observation used the same destination address, so endpoint-independent and address-dependent mapping "
        "cannot be told apart; configure an observation point with a different address"), \
        "endpoint-independent-or-address-dependent"


@dataclass(frozen=True)
class FilteringEvidence:
    primary: tuple[str, int]
    alternate_address: tuple[str, int] | None
    alternate_port: tuple[str, int] | None
    change_ip_response: tuple[str, int] | None
    change_port_response: tuple[str, int] | None
    primary_confirmed: bool


def classify_filtering(evidence):
    """Infer filtering behavior from which response sources were accepted."""
    if evidence.alternate_address is None and evidence.alternate_port is None:
        return UNDETERMINED, (
            "no alternate source is known: the observation point advertised no OTHER-ADDRESS and none was "
            "configured, so filtering behavior cannot be tested")
    if (evidence.alternate_address is not None
            and evidence.alternate_address[0] != evidence.primary[0]
            and evidence.change_ip_response == evidence.alternate_address):
        return FILTERING_ENDPOINT_INDEPENDENT, (
            "after a mapping existed only toward the primary address, a response still arrived from the alternate "
            "address, so inbound packets are not restricted to the addresses already contacted")
    if (evidence.alternate_port is not None
            and evidence.alternate_port[0] == evidence.primary[0]
            and evidence.alternate_port != evidence.primary
            and evidence.change_port_response == evidence.alternate_port):
        return FILTERING_ADDRESS_DEPENDENT, (
            "a response arrived from a different port of the same address while the response from a different "
            "address did not, so inbound packets are restricted to the contacted address")
    if evidence.change_ip_response == evidence.primary or evidence.change_port_response == evidence.primary:
        return UNDETERMINED, (
            "the observation point answered a CHANGE-REQUEST from its primary address, so it does not implement the "
            "RFC 5780 filtering test and filtering behavior cannot be classified")
    if evidence.change_ip_response is not None or evidence.change_port_response is not None:
        return UNDETERMINED, (
            "a CHANGE-REQUEST response source did not match the alternate configured for that request, so filtering "
            "behavior cannot be classified")
    if not evidence.primary_confirmed:
        return UNDETERMINED, (
            "the observation point stopped answering during the filtering test, so the missing responses cannot be "
            "attributed to the NAT filter")
    return FILTERING_ADDRESS_AND_PORT_DEPENDENT, (
        "responses from the alternate address and from the alternate port of the same address were both dropped "
        "while the primary address still answered, so inbound packets are restricted to the contacted address and "
        "port")


def reachability_for(mapping, filtering):
    if mapping == MAPPING_ADDRESS_AND_PORT_DEPENDENT:
        return REACHABILITY_LOW
    if mapping == UNDETERMINED:
        return REACHABILITY_UNKNOWN
    if filtering == FILTERING_ENDPOINT_INDEPENDENT:
        return REACHABILITY_HIGH
    return REACHABILITY_MEDIUM


def guidance_for(mapping, filtering, reachability, partial):
    """Plain-language conclusion. No jargon-only labels, no NAT claim beyond evidence."""
    if mapping == MAPPING_ADDRESS_AND_PORT_DEPENDENT:
        return ("你的网络对每个目标地址和端口都会换一个对外端口（常说的“对称型 NAT”）。IPv4 直连打洞成功率低，"
                "双方同时发包也很难刚好对上端口。建议优先走 IPv6 直连；或在自家路由器/网关上显式放行"
                "（UPnP/PCP/NAT-PMP 授权映射）后再用 IPv4。")
    if mapping == UNDETERMINED:
        hint = "（现有数据只来自同一个目标地址，无法区分“端点无关”和“地址相关”）" if partial else ""
        return ("现有观测不足以判断 NAT 行为" + hint + "，请不要据此下结论。建议再提供至少一个不同公网地址的 "
                "STUN 观测点，并在每个点上从多个本地端口多次探测后重试。")
    if filtering == FILTERING_ENDPOINT_INDEPENDENT:
        return ("你的网络对外端口不随目标变化，而且不限制外部来源（常说的全锥 / 端点无关）。"
                "IPv4 直连打洞成功率较高，可以优先尝试 UDP 直连。")
    if filtering in {FILTERING_ADDRESS_DEPENDENT, FILTERING_ADDRESS_AND_PORT_DEPENDENT}:
        return ("你的网络对外端口不随目标变化，但只允许你主动联系过的地址（或地址+端口）回包"
                "（常说的受限锥 / 端口受限锥）。IPv4 打洞仍然可行，需要双方同时向对方的候选地址发包；"
                "若失败，优先改用 IPv6。")
    return ("对外端口不随目标变化，这一步只确认了映射行为；过滤行为没有测出来。"
            "建议补齐观测点后再判断，或先同时尝试 IPv4 直连与 IPv6。")


@dataclass
class NatProfile:
    """Local classification result.

    `mapping`/`filtering`/`guidance` are inferences from the observations;
    `observations`/`mapped_endpoints` are the raw mapped endpoints. Keep them apart
    when reporting: a mapped endpoint is not a NAT type.
    """

    mapping: str
    mapping_evidence: str
    mapping_partial: str | None
    filtering: str
    filtering_evidence: str
    reachability: str
    guidance: str
    observations: list[MappingSample] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    errors_truncated: bool = False
    evidence_scope: str = "local-controlled-observation-points-only-not-real-home-network-evidence"

    @property
    def mapped_endpoints(self):
        return sorted({sample.mapped for sample in self.observations})

    @property
    def mapping_label(self):
        return MAPPING_LABELS.get(self.mapping, self.mapping)

    @property
    def filtering_label(self):
        return FILTERING_LABELS.get(self.filtering, self.filtering)

    @property
    def reachability_label(self):
        return REACHABILITY_LABELS.get(self.reachability, self.reachability)

    @property
    def summary(self):
        """One plain-language line for the user; contains no mapped address."""
        return (f"你的网络：映射行为={self.mapping_label}；过滤行为={self.filtering_label}；"
                f"直连打洞预期成功率={self.reachability_label}。{self.guidance}")

    def report(self, include_mappings=False):
        """Center-safe view. Mapped public endpoints are omitted by default."""
        payload = {
            "summary": self.summary,
            "mapping": self.mapping,
            "mappingLabel": self.mapping_label,
            "mappingEvidence": self.mapping_evidence,
            "mappingPartial": self.mapping_partial,
            "filtering": self.filtering,
            "filteringLabel": self.filtering_label,
            "filteringEvidence": self.filtering_evidence,
            "reachability": self.reachability,
            "reachabilityLabel": self.reachability_label,
            "guidance": self.guidance,
            "observationCount": len(self.observations),
            "distinctMappedEndpointCount": len(self.mapped_endpoints),
            "errors": list(self.errors),
            "errorsTruncated": self.errors_truncated,
            "mappedEndpointsIncluded": bool(include_mappings),
            "inferenceNote": ("mapping/filtering are inferred from how observed mapped endpoints change with the "
                              "destination and from which response sources were accepted; they are not the mapped "
                              "addresses themselves"),
            "privacy": ("observed public mapped endpoints are local private diagnostics and stay out of this report "
                        "unless include_mappings=True is passed for a local view"),
            "evidenceScope": self.evidence_scope,
        }
        if include_mappings:
            payload["mappedEndpoints"] = [list(endpoint) for endpoint in self.mapped_endpoints]
            payload["observations"] = [
                {"localPort": sample.local_port, "point": list(sample.destination),
                 "mapped": list(sample.mapped), "repeat": sample.repeat}
                for sample in self.observations]
        return payload


class NatBehaviorProbe:
    def __init__(self, config):
        self.config = config.validate() if isinstance(config, NatProbeConfig) else config

    async def run(self):
        config = self.config
        family = config.family()
        destinations = config.destinations()
        samples, errors, advertised = [], [], {}
        truncated = [False]

        def record(entry):
            if len(errors) >= MAX_ERRORS:
                truncated[0] = True
                return
            errors.append(entry)

        for _ in range(config.local_ports):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setblocking(False)
            try:
                sock.bind((config.bind_host, 0))
                local_port = sock.getsockname()[1]
                for point, destination in zip(config.points, destinations):
                    for repeat in range(config.repeats):
                        try:
                            _, parsed = await _transaction(sock, destination, family, config.timeout)
                        except (ProbeTimeout, ProbeSendFailed) as exc:
                            code = exc.code if isinstance(exc, ProbeTimeout) else "SEND_FAILED"
                            record(f"{code}:{destination[0]}:{destination[1]}")
                            continue
                        samples.append(MappingSample(local_port, destination, parsed["mapped"], repeat))
                        if "other" in parsed and point.alternate_address is None and point.alternate_port is None:
                            advertised.setdefault(destination, parsed["other"])
            finally:
                sock.close()
        mapping, mapping_evidence, partial = classify_mapping(samples, destinations)
        point, destination = self._filtering_point(destinations)
        filtering, filtering_evidence = await self._filtering(point, destination, advertised.get(destination), record)
        reachability = reachability_for(mapping, filtering)
        return NatProfile(mapping, mapping_evidence, partial, filtering, filtering_evidence, reachability,
                          guidance_for(mapping, filtering, reachability, partial), samples, errors, truncated[0])

    def _filtering_point(self, destinations):
        for point, destination in zip(self.config.points, destinations):
            if point.alternate_address is not None or point.alternate_port is not None:
                return point, destination
        return self.config.points[0], destinations[0]

    async def _filtering(self, point, destination, advertised, record):
        config = self.config
        family = config.family()
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setblocking(False)
        try:
            sock.bind((config.bind_host, 0))
            try:
                await _transaction(sock, destination, family, config.timeout)
            except (ProbeTimeout, ProbeSendFailed) as exc:
                code = exc.code if isinstance(exc, ProbeTimeout) else "SEND_FAILED"
                record(f"FILTERING_PRIMARY_{code}:{destination[0]}:{destination[1]}")
                return UNDETERMINED, ("the primary observation point did not answer, so the filtering test was not "
                                      "attempted")
            alternate_address, alternate_port = point.alternate_address, point.alternate_port
            if alternate_address is None and alternate_port is None and advertised is not None:
                if advertised[0] == destination[0]:
                    alternate_port = advertised
                else:
                    alternate_address = advertised
                    alternate_port = (destination[0], advertised[1])
            change_ip_response = await self._try_change(sock, destination, family, CHANGE_IP | CHANGE_PORT,
                                                        alternate_address, record)
            change_port_response = await self._try_change(sock, destination, family, CHANGE_PORT,
                                                          alternate_port, record)
            primary_confirmed = False
            try:
                await _transaction(sock, destination, family, config.timeout)
                primary_confirmed = True
            except (ProbeTimeout, ProbeSendFailed):
                primary_confirmed = False
            evidence = FilteringEvidence(destination, alternate_address, alternate_port,
                                         change_ip_response, change_port_response, primary_confirmed)
            return classify_filtering(evidence)
        finally:
            sock.close()

    async def _try_change(self, sock, destination, family, change, alternate, record):
        if alternate is None:
            return None
        try:
            source, _ = await _transaction(sock, destination, family, self.config.timeout, change=change,
                                           accept=(alternate,))
            return source
        except (ProbeTimeout, ProbeSendFailed) as exc:
            code = exc.code if isinstance(exc, ProbeTimeout) else "SEND_FAILED"
            record(f"FILTERING_{code}:{destination[0]}:{destination[1]}")
            return None


async def probe_nat_behavior(config):
    """Run one bounded probe and return a NatProfile."""
    return await NatBehaviorProbe(config).run()


def _parse_point(text):
    host, separator, port = text.rpartition(":")
    if not separator or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected IP:PORT, got {text!r}")
    return StunObservationPoint(host.strip("[]"), int(port))


def _emit(payload):
    """Print JSON without dying on a non-UTF-8 Windows console codepage."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except (UnicodeEncodeError, ValueError):
        print(json.dumps(payload, ensure_ascii=True, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe NAT mapping/filtering behavior against the STUN servers you name explicitly "
                    "(literal IP:PORT; no discovery, no third-party servers).")
    parser.add_argument("--server", action="append", required=True, type=_parse_point, dest="servers",
                        metavar="IP:PORT", help="observation point; repeat for at least two distinct points")
    parser.add_argument("--bind", required=True, metavar="LOCAL_IP",
                        help="explicit local address of the family to test (e.g. 192.168.1.20); interfaces are "
                             "never enumerated")
    parser.add_argument("--local-ports", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--include-mappings", action="store_true",
                        help="also print observed public mapped endpoints (local private data; never upload them)")
    args = parser.parse_args(argv)
    try:
        config = NatProbeConfig(args.bind, tuple(args.servers), args.local_ports, args.repeats, args.timeout).validate()
    except ValueError as exc:
        parser.error(str(exc))
    profile = asyncio.run(probe_nat_behavior(config))
    _emit(profile.report(include_mappings=args.include_mappings))
    return 0 if profile.mapping != UNDETERMINED else 3


if __name__ == "__main__":
    sys.exit(main())
