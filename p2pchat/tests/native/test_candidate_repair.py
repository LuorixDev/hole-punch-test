"""R2 controlled UDP translation, NOT residential NAT evidence or product relay.
Two bound translator sockets model reciprocal external tuples. Host candidates
point to bound sinks and cannot authenticate; only signaled srflx tuples work.
"""
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import uuid

import pytest
from p2pchat.native.adapter import NativeAdapter, Budget
from p2pchat.native.auth import Auth, packed
from p2pchat.native.bridge import stun_config
from .test_transport import bridge_frames, cli_env, params, run_bridge, wait_states


class Translation(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = self.other = self.target = self.allowed_source = None
        self.packets = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        # Exact known peer source only; this test shim is not a deployed relay.
        if self.other and source == self.allowed_source:
            self.packets += 1
            self.other.transport.sendto(data, self.target)


async def endpoint(protocol):
    return await asyncio.get_running_loop().create_datagram_endpoint(lambda: protocol, local_addr=('127.0.0.1', 0))


@pytest.mark.asyncio
@pytest.mark.parametrize('mechanism,bad_secret', [('udp-probe', False), ('quic', False), ('quic', True)])
async def test_host_blackholed_then_late_srflx_same_socket(mechanism, bad_secret):
    a, b = NativeAdapter(), NativeAdapter()
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    events = [[], []]
    for i, adapter in enumerate([a, b]):
        adapter.subscribe(lambda kind, value, i=i: events[i].append((kind, value)))
    transports = []
    try:
        await a.start(params(mechanism, 'offerer', cid, aid))
        bp = params(mechanism, 'answerer', cid, aid)
        if bad_secret:
            bp['auth']['secret'] = 'wrong-room-secret'
        await b.start(bp)
        snapshots = [(x.attempts[aid].sock.fileno(), x.attempts[aid].sock.getsockname()) for x in [a, b]]
        original = [dict(x.attempts[aid].candidate) for x in [a, b]]
        # Sink sockets make advertised host candidates genuinely unusable.
        dead = []
        for _ in range(2):
            transport, _ = await endpoint(asyncio.DatagramProtocol())
            transports.append(transport)
            dead.append(transport.get_extra_info('sockname')[1])
        for i, target in enumerate([a, b]):
            for kind, event in events[1-i]:
                if kind == 'candidate' and 'description' in event:
                    await target.signal({**event, 'from': 'b' if i == 0 else 'a'})
            await target.signal(dict(connectionId=cid, attemptId=aid, **{'from': 'b' if i == 0 else 'a'},
                nativeCandidate={**original[1-i], 'port': dead[1-i]}))
        await asyncio.sleep(.25)
        assert all(x.attempts[aid].state == 'probing' for x in [a, b])
        pa, pb = Translation(), Translation()
        ta, _ = await endpoint(pa)
        tb, _ = await endpoint(pb)
        transports.extend([ta, tb])
        pa.other, pa.target, pa.allowed_source = pb, snapshots[0][1], snapshots[1][1]
        pb.other, pb.target, pb.allowed_source = pa, snapshots[1][1], snapshots[0][1]
        external = [ta.get_extra_info('sockname'), tb.get_extra_info('sockname')]
        for i, target in enumerate([a, b]):
            await target.signal(dict(connectionId=cid, attemptId=aid, **{'from': 'b' if i == 0 else 'a'},
                nativeCandidate={**original[1-i], 'id': str(uuid.uuid4()), 'kind': 'srflx', 'port': external[1-i][1]}))
        if bad_secret:
            assert await wait_states(a, b, aid) == ['timeout', 'timeout']
            assert not any(kind == 'data' for stream in events for kind, _ in stream)
            return
        assert await wait_states(a, b, aid) == ['direct', 'direct']
        for i, x in enumerate([a, b]):
            attempt = x.attempts[aid]
            assert (attempt.sock.fileno(), attempt.sock.getsockname()) == snapshots[i]
            assert attempt.remote == external[1-i]
            assert attempt.remote_candidate['kind'] == 'srflx'
            assert attempt.auth.direct
        assert pa.packets and pb.packets
        if mechanism == 'quic':
            payload = os.urandom(65536)
            for x in [a, b]:
                await x.send(dict(attemptId=aid, lane='chat', data=payload))
            async with asyncio.timeout(4):
                while not all(any(k == 'data' for k, _ in stream) for stream in events):
                    await asyncio.sleep(.01)
            assert all(base64.b64decode(next(e['dataB64'] for k, e in stream if k == 'data')) == payload for stream in events)
    finally:
        await a.shutdown()
        await b.shutdown()
        for transport in transports:
            transport.close()


@pytest.mark.asyncio
async def test_candidate_identity_certificate_budget_and_source_binding():
    a = NativeAdapter(budget=Budget(candidates=4))
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    await a.start(params('quic', 'offerer', cid, aid))
    original = dict(a.attempts[aid].candidate)
    frame = dict(connectionId=cid, attemptId=aid, **{'from': 'b'})
    try:
        await a.signal({**frame, 'nativeCandidate': original})
        with pytest.raises(ValueError, match='SIGNAL_IDENTITY_MISMATCH'):
            await a.signal({**frame, 'from': 'evil', 'nativeCandidate': original})
        with pytest.raises(ValueError, match='CANDIDATE_SOCKET_CHANGED'):
            await a.signal({**frame, 'nativeCandidate': {**original, 'socketId': 'other'}})
        with pytest.raises(ValueError, match='CERTIFICATE_FINGERPRINT_MISMATCH'):
            await a.signal({**frame, 'nativeCandidate': {**original, 'certificateFingerprint': '0'*64}})
        await a.signal({**frame, 'nativeCandidate': {**original, 'kind': 'srflx'}})
        with pytest.raises(ValueError, match='CANDIDATE_LIMIT'):
            await a.signal({**frame, 'nativeCandidate': original})
        assert len(a.attempts[aid].remote_candidates) == 1
    finally:
        await a.shutdown()

    # Correct HMAC from an UNSIGNALED exact source must not select a path.
    a = NativeAdapter()
    await a.start(params('udp-probe', 'offerer', cid, str(uuid.uuid4())))
    attempt = next(iter(a.attempts.values()))
    sink, _ = await endpoint(asyncio.DatagramProtocol())
    attacker, _ = await endpoint(asyncio.DatagramProtocol())
    try:
        await a.signal(dict(connectionId=cid, attemptId=attempt.id, **{'from': 'b'},
                            nativeCandidate={**attempt.candidate, 'port': sink.get_extra_info('sockname')[1]}))
        auth = Auth('test', 'test-secret-128-bit', cid, attempt.id, 'b', 'a')
        await asyncio.sleep(.02)
        attacker.sendto(b'P2POBS1'+packed(auth.frame()), attempt.sock.getsockname())
        await asyncio.sleep(.1)
        assert not attempt.selected and attempt.state == 'probing'
    finally:
        await a.shutdown()
        sink.close()
        attacker.close()


@pytest.mark.asyncio
async def test_stdio_explicit_stun_emits_same_socket_srflx():
    from .test_gateway import MockGateway
    transport, protocol = await endpoint(MockGateway('stun'))
    process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'p2pchat.native.bridge',
        '--stun-address', '127.0.0.1', '--stun-port', str(transport.get_extra_info('sockname')[1]),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=cli_env())
    try:
        p = params('quic', 'offerer', str(uuid.uuid4()), str(uuid.uuid4()))
        process.stdin.write((json.dumps(dict(v=1, id=1, method='start', params=p))+'\n').encode())
        await process.stdin.drain()
        candidates = []
        async with asyncio.timeout(5):
            while True:
                frame = json.loads(await process.stdout.readline())
                if frame.get('event') == 'candidate' and 'nativeCandidate' in frame['params']:
                    candidates.append(frame['params']['nativeCandidate'])
                if frame.get('id') == 1:
                    assert 'error' not in frame
                    break
        assert [c['kind'] for c in candidates] == ['host', 'srflx']
        assert candidates[0]['socketId'] == candidates[1]['socketId']
        assert candidates[0]['port'] == candidates[1]['port']
        assert candidates[0]['certificateFingerprint'] == candidates[1]['certificateFingerprint']
        assert len(protocol.requests) == 1
    finally:
        process.stdin.close()
        await asyncio.wait_for(process.wait(), 5)
        transport.close()


@pytest.mark.asyncio
async def test_proof_fragments_from_different_candidates_cannot_combine():
    a = NativeAdapter()
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    p = params('udp-probe', 'offerer', cid, aid)
    await a.start(p)
    attempt = a.attempts[aid]
    senders = []
    try:
        for _ in range(2):
            transport, _ = await endpoint(asyncio.DatagramProtocol())
            senders.append(transport)
            await a.signal(dict(connectionId=cid, attemptId=aid, **{'from': 'b'},
                nativeCandidate={**attempt.candidate, 'port': transport.get_extra_info('sockname')[1]}))
        auth = Auth('test', 'test-secret-128-bit', cid, aid, 'b', 'a')
        auth.receive(attempt.candidate_auth[senders[0].get_extra_info('sockname')].frame())
        await asyncio.sleep(.02)
        senders[0].sendto(b'P2POBS1'+packed(auth.frame()), attempt.sock.getsockname())
        senders[1].sendto(b'P2POBS1'+packed(auth.frame(ack=True)), attempt.sock.getsockname())
        await asyncio.sleep(.1)
        assert not attempt.selected and attempt.state == 'probing'
        assert all(not auth.direct for auth in attempt.candidate_auth.values())
    finally:
        await a.shutdown()
        for transport in senders:
            transport.close()


def test_stun_cli_and_capability_contract():
    assert stun_config() is None
    assert stun_config('127.0.0.1', 3478) == ('127.0.0.1', 3478)
    for address, port in [('localhost', 3478), ('224.0.0.1', 3478), ('0.0.0.0', 3478), ('169.254.1.1', 3478), ('127.0.0.1', 0), ('127.0.0.1', None)]:
        with pytest.raises(ValueError, match='INVALID_STUN_CONFIG'):
            stun_config(address, port)
    # 显式 utf-8 两端契约：Windows 代码页既编码不了能力文案，也会让父进程拿到空输出。
    result = run_bridge(args=['--stun-address', '127.0.0.1', '--stun-port', '3478'],
                        requests=[dict(v=1, id=1, method='capabilities', params={})])
    frames = bridge_frames(result)
    methods = frames[-1]['result']['methods']
    assert {m['mechanism']: m['limits']['independentBenchmark'] for m in methods} == {
        'udp-probe': False, 'quic': True, 'tcp': False, 'tcp-simopen': False, 'upnp': False, 'pcp': False, 'natpmp': False}
