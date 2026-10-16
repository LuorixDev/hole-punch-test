import asyncio
import secrets

import pytest

from p2plab.experiments import select_quic_payload
from p2plab.udp import MAGIC, UdpAttempt


class DatagramFilter:
    def __init__(self, transport, *, limit=1500, drop_first=0, duplicate=False):
        self.transport, self.limit = transport, limit
        self.drop_first, self.duplicate = drop_first, duplicate

    def sendto(self, data, target):
        if len(data) > self.limit:
            return
        if data.startswith(MAGIC) and self.drop_first:
            self.drop_first -= 1
            return
        self.transport.sendto(data, target)
        if self.duplicate and data.startswith(MAGIC):
            asyncio.get_running_loop().call_later(0.01, self.transport.sendto, data, target)

    def close(self):
        self.transport.close()


async def udp_pair(peers):
    a, b = peers
    spec = {"attempt": secrets.token_hex(8), "profile": "fast", "method": "udp"}
    ua = UdpAttempt(a, {**spec, "initiator": True}, "127.0.0.1")
    ub = UdpAttempt(b, {**spec, "initiator": False}, "127.0.0.1")
    await asyncio.gather(ua.open(), ub.open())
    ua.set_candidates(ub.candidates)
    ub.set_candidates(ua.candidates)
    return ua, ub


async def test_loss_and_duplicate_hellos_retry_successfully(peers):
    ua, ub = await udp_pair(peers)
    try:
        ua.transport = DatagramFilter(ua.transport, drop_first=3, duplicate=True)
        ub.transport = DatagramFilter(ub.transport, drop_first=2, duplicate=True)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        assert ua.direct.is_set() and ub.direct.is_set()
    finally:
        await asyncio.gather(ua.close(), ub.close())


async def test_mtu_blackhole_rechecks_small_packets_and_avoids_1400(peers):
    ua, ub = await udp_pair(peers)
    try:
        ua.transport = DatagramFilter(ua.transport, limit=1250)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        evidence = await ua.mtu()
        large = next(item for item in evidence if item["udp_payload_bytes"] == 1400)
        assert large["confirmed"] == 0 and large["small_payload_recheck"] == 2
        assert large["classification"] == "suspected-size-blackhole"
        assert select_quic_payload(evidence, 1400) == 1200
    finally:
        await asyncio.gather(ua.close(), ub.close())


async def test_sub_1200_path_is_not_reported_as_quic_capable(peers):
    ua, ub = await udp_pair(peers)
    try:
        ua.transport = DatagramFilter(ua.transport, limit=1000)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        evidence = await ua.mtu()
        with pytest.raises(ValueError, match="QUIC_MINIMUM"):
            select_quic_payload(evidence, 1200)
        with pytest.raises(ValueError, match="NEVER_BELOW_1200"):
            await ua.start_quic(size=900)
    finally:
        await asyncio.gather(ua.close(), ub.close())


async def test_mtu_uses_authenticated_round_trip_budget_on_high_latency_path(peers):
    class DelayedDatagrams(DatagramFilter):
        def __init__(self, transport):
            super().__init__(transport)
            self.pending = []

        def sendto(self, data, target):
            self.pending.append(asyncio.get_running_loop().call_later(0.35, self.transport.sendto, data, target))

        def close(self):
            for handle in self.pending:
                handle.cancel()
            super().close()

    ua, ub = await udp_pair(peers)
    try:
        ua.transport = DelayedDatagrams(ua.transport)
        ub.transport = DelayedDatagrams(ub.transport)
        await asyncio.gather(ua.punch(5), ub.punch(5))
        hits, errors = await ua.mtu_trials(1200)
        assert hits == 2 and errors == []
    finally:
        await asyncio.gather(ua.close(), ub.close())


async def test_one_way_block_never_passes_mutual_auth(peers):
    ua, ub = await udp_pair(peers)
    try:
        ub.transport = DatagramFilter(ub.transport, drop_first=1000)
        results = await asyncio.gather(ua.punch(0.2), ub.punch(0.2), return_exceptions=True)
        assert all(isinstance(item, TimeoutError) for item in results)
        assert not ua.direct.is_set() and not ub.direct.is_set()
    finally:
        await asyncio.gather(ua.close(), ub.close())


async def test_replayed_candidate_ack_cannot_authenticate_another_source(peers):
    ua, ub = await udp_pair(peers)
    try:
        real = tuple(ub.candidates[0])
        forged_source = (real[0], real[1] + 1 if real[1] < 65535 else real[1] - 1)
        ua.nonce_for(real)
        peer_nonce = ub.nonce_for(tuple(ua.candidates[0]))
        hello = ub.frame("hello", target=tuple(ua.candidates[0]))
        from p2plab.udp import probe_packet

        ua.datagram_received(probe_packet(hello), forged_source)
        ack = ub.frame("hello_ack", target=tuple(ua.candidates[0]), echo=ua.nonce_for(real))
        ua.datagram_received(probe_packet(ack), forged_source)
        assert peer_nonce == hello["nonce"]
        assert ua.nonce_for(real) != ua.nonce_for(forged_source)
        assert not ua.direct.is_set()
    finally:
        await asyncio.gather(ua.close(), ub.close())
