import json
import secrets
import struct

import pytest

from p2plab.common import BENCH_CHUNK, Identity, encode_frame, endpoint, extract_frames, read_frame
from p2plab.experiments import MAX_ATTEMPTS, Experiments, build_plan, prediction_candidates
from p2plab.gateway import natpmp_request, parse_natpmp, parse_pcp, pcp_request, safe_control_url
from p2plab.journal import Journal, redact
from p2plab.rtc import filter_sdp
from p2plab.stun import COOKIE, HEADER, OTHER, XOR_MAPPED, address_value, attribute, parse_response
from p2plab.udp import parse_probe, probe_packet


@pytest.mark.parametrize("address", ["203.0.113.8", "2001:db8::1234"])
def test_stun_other_is_not_xor(address):
    tid = secrets.token_bytes(12)
    mapped, other = (address, 54321), (address, 3479)
    body = attribute(XOR_MAPPED, address_value(mapped, tid, xor=True))
    body += attribute(OTHER, address_value(other, tid, xor=False))
    response = HEADER.pack(0x0101, len(body), COOKIE, tid) + body
    assert parse_response(response, tid) == {"mapped": mapped, "other": other}
    with pytest.raises(ValueError):
        parse_response(response, secrets.token_bytes(12))


def test_frame_fragmentation_and_limits():
    data = encode_frame({"kind": "chat", "text": "hello"})
    buf = bytearray(data[:7])
    assert extract_frames(buf) == []
    buf.extend(data[7:] + data)
    assert len(extract_frames(buf)) == 2
    assert buf == bytearray()
    with pytest.raises(ValueError):
        extract_frames(bytearray(struct.pack("!I", 1_000_000)))


def test_device_key_persistence_and_duplicate_directory_lock(tmp_path):
    first = Identity(tmp_path / "device")
    public = first.public
    with pytest.raises(ValueError, match="DATA_DIRECTORY_ALREADY_IN_USE"):
        Identity(tmp_path / "device")
    first.close()
    second = Identity(tmp_path / "device")
    assert second.public == public
    second.close()


def test_signed_probe_and_padding(peers):
    a, b = peers
    frame = a.identity.sign({"v": 1, "kind": "hello", "size": 512})
    data = probe_packet(frame)
    assert len(data) == 512
    assert a.identity.verify(parse_probe(data), a.identity.public)["kind"] == "hello"
    with pytest.raises(Exception):
        b.identity.verify(parse_probe(data), b.identity.public)
    with pytest.raises(ValueError):
        parse_probe(data[:-1] + b"1")


def test_journal_replay_dedup_and_durable_ack(tmp_path):
    local = Journal(tmp_path / "local.db", role="client", room="100", console=False)
    central = Journal(tmp_path / "central.db", role="server", console=False)
    event = local.event("test", token="not-for-export", nested={"authorization": "hidden"})
    persistent = local.client
    local.close()
    local = Journal(tmp_path / "local.db", role="client", console=False)
    assert local.client == persistent
    batch = local.pending()
    assert batch[0]["fields"]["token"] == "[redacted]"
    assert central.ingest(batch, local.client) == [event["id"]]
    assert central.ingest(batch, local.client) == [event["id"]]
    assert len(central.query()) == 1
    local.ack(["unknown-id"])
    assert len(local.pending()) == 1
    local.ack([event["id"]])
    assert local.pending() == []
    local.close()
    central.close()


def test_ingest_batch_rolls_back(tmp_path):
    local = Journal(tmp_path / "local.db", role="client", console=False)
    central = Journal(tmp_path / "central.db", role="server", console=False)
    first = local.event("first")
    second = {**first, "client": "wrong"}
    with pytest.raises(ValueError):
        central.ingest([first, second], local.client)
    assert central.query() == []
    local.close()
    central.close()


def test_redaction():
    assert "hunter2" not in json.dumps(redact({"url": "http://x/?token=hunter2", "password": "hunter2"}))


def test_large_logs_are_losslessly_fragmented_and_do_not_block_upload(tmp_path):
    local = Journal(tmp_path / "large-local.db", role="client", console=False)
    central = Journal(tmp_path / "large-central.db", role="server", console=False)
    try:
        payload = "x" * 200_000 + ' Bearer private-secret "tail"'
        original = local.event("large", payload=payload)
        while local.pending():
            local.ack(central.ingest(local.pending(), local.client))
        fragments = central.query()
        assert len(fragments) > 1
        assert all(fragment["event"] == "journal.fragment" for fragment in fragments)
        text = "".join(
            event["fields"]["json_part"]
            for event in sorted(fragments, key=lambda event: event["fields"]["index"])
        )
        restored = json.loads(text)
        assert restored["id"] == original["id"]
        assert restored["fields"]["payload"] == original["fields"]["payload"]
        assert "private-secret" not in text
    finally:
        local.close()
        central.close()


def test_plan_baselines_then_gateways():
    plan = build_plan(
        ["192.168.1.2", "2001:db8::1"], ["192.168.2.2", "2001:db8::2"], ["balanced", "fast", "staggered"]
    )
    phases = [spec["phase"] for spec in plan]
    assert phases == sorted(phases)
    assert {s["profile"] for s in plan if s["method"] == "udp"} == {"balanced", "fast", "staggered"}
    assert {s["leader_initiator"] for s in plan if s["method"] == "tcp"} == {True, False}
    assert len({s["attempt"] for s in plan}) == len(plan)
    assert all(s["datagram_size"] >= 1200 for s in plan if "datagram_size" in s)


def test_default_quic_and_simopen_cover_uncoupled_parameters():
    profiles = ["balanced", "fast", "staggered"]
    plan = build_plan(["2001:db8::1"], ["2001:db8::2"], profiles)
    assert {
        (s["profile"], s["datagram_size"], s["leader_initiator"]) for s in plan if s["method"] == "quic"
    } == {(p, size, role) for p in profiles for size in (1200, 1400) for role in (True, False)}
    assert {(s["offset"], s["leader_initiator"]) for s in plan if s["method"] == "tcp-simopen"} == {
        (offset, role) for offset in (0, 0.15, 0.4) for role in (True, False)
    }


def test_plan_budget_is_enforced_locally_and_omissions_are_explicit():
    addresses = [f"2001:db8::{i}" for i in range(1, 5)] + [f"192.0.2.{i}" for i in range(1, 5)]
    coverage = {}
    plan = build_plan(
        addresses, addresses, ["balanced", "fast", "staggered"], max_pairs=8, expanded=True, coverage=coverage
    )
    assert len(plan) == MAX_ATTEMPTS
    assert coverage["requested"] == len(plan) + len(coverage["omitted"])
    assert coverage["omitted"]
    assert plan[0]["matrix_coverage"]["omitted_count"] == len(coverage["omitted"])
    assert {s["profile"] for s in plan if s["method"] == "quic"} == {"balanced", "fast", "staggered"}
    assert {s["method"] for s in plan} == {
        "udp",
        "quic",
        "tcp",
        "tcp-simopen",
        "prediction",
        "webrtc",
        "pinhole",
        "pcp",
        "upnp",
        "natpmp",
    }
    assert all(any(s["a_host"] == a and s["b_host"] == b for s in plan) for a, b in coverage["address_pairs"])
    assert [s["phase"] for s in plan] == sorted(s["phase"] for s in plan)


def test_small_address_budget_samples_both_peers_addresses():
    plan = build_plan(
        ["2001:db8:a::1", "2001:db8:a::2"],
        ["2001:db8:b::1", "2001:db8:b::2"],
        ["fast"],
        max_pairs=2,
        gateway=False,
    )
    assert {(s["a_host"], s["b_host"]) for s in plan if s["method"] == "udp"} == {
        ("2001:db8:a::1", "2001:db8:b::1"),
        ("2001:db8:a::2", "2001:db8:b::2"),
    }


async def test_follower_receives_budget_summary_without_full_omission_list(peers):
    _, peer = peers
    peer.network = {"addresses": [{"address": "2001:db8::2"}]}
    manager = Experiments(peer)
    coverage = {}
    plan = build_plan(["2001:db8::1"], ["2001:db8::2"], ["fast"], coverage=coverage)
    await manager.handle({"kind": "plan", "plan": plan})
    assert manager.coverage["selected"] == len(plan)
    assert manager.coverage["omitted_count"] == 0


@pytest.mark.parametrize("field,value,error", [
    ("leader_initiator", 1, "PLAN_ROLE"),
    ("offset", float("nan"), "PLAN_OFFSET"),
    ("offset", 30, "PLAN_OFFSET"),
    ("trial", 3, "PLAN_TRIAL"),
    ("phase", "gateway", "PLAN_PHASE"),
    ("profile", "dual", "PLAN_PROFILE"),
])
async def test_matrix_rejects_invalid_roles_timing_and_profiles(peers, field, value, error):
    _, peer = peers
    peer.network = {"addresses": [{"address": "2001:db8::2"}]}
    manager = Experiments(peer)
    plan = build_plan(["2001:db8::1"], ["2001:db8::2"], ["fast"])
    plan[0][field] = value
    with pytest.raises(ValueError, match=error):
        await manager.handle({"kind": "plan", "plan": plan})


async def test_binary_speed_frames_fragment_coalesce_and_match_tcp_reader():
    import asyncio

    bodies = [
        {"kind": "bench_chunk", "id": "1234567890abcdef", "seq": i, "data": secrets.token_bytes(size)}
        for i, size in enumerate((1, 8192, BENCH_CHUNK))
    ]
    wire = b"".join(encode_frame(body) for body in bodies)
    buffer, decoded = bytearray(), []
    for offset in range(0, len(wire), 1001):
        buffer.extend(wire[offset : offset + 1001])
        decoded.extend(extract_frames(buffer))
    assert decoded == bodies and not buffer
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    assert [await read_frame(reader) for _ in bodies] == bodies
    with pytest.raises(ValueError, match="BENCH_BINARY_FRAME_LIMIT"):
        extract_frames(bytearray(struct.pack("!I", 0x80000001) + b"x"))
    with pytest.raises(ValueError, match="BENCH_CHUNK_LIMIT"):
        encode_frame({**bodies[0], "data": bytes(BENCH_CHUNK + 1)})


def test_many_ipv6_addresses_do_not_crowd_out_ipv4_pairs():
    addresses = ["2001:db8::1", "2001:db8::2", "2001:db8::3", "192.168.0.2"]
    plan = build_plan(addresses, addresses, ["balanced"], max_pairs=2, gateway=False)
    udp = [spec for spec in plan if spec["method"] == "udp"]
    assert len(udp) == 2
    assert any(":" in spec["a_host"] for spec in udp)
    assert any("." in spec["a_host"] for spec in udp)


def test_prediction_bounded_same_socket_samples():
    samples = [
        {"observer": [host, 3478], "mapped": ["203.0.113.5", port]}
        for host, port in [
            ("192.0.2.1", 40000),
            ("192.0.2.1", 40000),
            ("192.0.2.2", 40002),
            ("192.0.2.2", 40002),
        ]
    ]
    assert prediction_candidates(samples) == [["203.0.113.5", p] for p in (40004, 40006, 40008, 40010)]
    samples[1]["mapped"][1] = 50000
    assert prediction_candidates(samples) == []


def test_pcp_nonce_and_layout():
    nonce = secrets.token_bytes(12)
    request = pcp_request("192.168.1.2", 12345, 12345, nonce)
    assert len(request) == 60
    assert request[24:36] == nonce
    response = struct.pack("!BBBBII12x", 2, 0x81, 0, 0, 120, 50)
    response += struct.pack(
        "!12sB3xHH16s", nonce, 17, 12345, 54321, bytes(10) + b"\xff\xff" + bytes([203, 0, 113, 5])
    )
    assert parse_pcp(response, nonce, 12345)["external"] == ("203.0.113.5", 54321)
    with pytest.raises(ValueError):
        parse_pcp(response, secrets.token_bytes(12), 12345)


def test_natpmp_request_and_response():
    assert len(natpmp_request(10000, 20000)) == 12
    response = struct.pack("!BBHIHHI", 0, 129, 0, 5, 10000, 20000, 120)
    assert parse_natpmp(response, 10000)["port"] == 20000
    with pytest.raises(ValueError):
        parse_natpmp(response, 10001)


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test/control",
        "http://127.0.0.1/control",
        "http://user:pass@192.168.1.1/control",
        "https://192.168.1.1/control",
    ],
)
def test_gateway_ssrf_guard(url):
    with pytest.raises(ValueError):
        safe_control_url(url, "192.168.1.1")


def test_sdp_family_and_relay_filter():
    sdp = "\r\n".join(
        [
            "v=0",
            "a=candidate:1 1 udp 100 192.0.2.1 5000 typ host",
            "a=candidate:2 1 udp 100 2001:db8::1 5000 typ host",
            "a=candidate:3 1 udp 100 192.0.2.2 5000 typ relay",
        ]
    )
    assert "relay" not in filter_sdp(sdp, "dual")
    assert "192.0.2.1" not in filter_sdp(sdp, "6")
    assert "2001:db8" not in filter_sdp(sdp, "4")


@pytest.mark.parametrize("address", ["0.0.0.0", "ff02::1", "fe80::1", "255.255.255.255"])
def test_invalid_candidate_scope(address):
    with pytest.raises(ValueError):
        endpoint(address, 1234)
