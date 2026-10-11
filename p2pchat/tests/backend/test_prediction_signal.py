"""nat-samples signaling: strict whitelist, room/attempt binding, relay unchanged.

Real HTTP(POST+SSE) server on loopback. The server holds no room key: the samples'
HMAC is opaque to it. This is loopback evidence, not deployment evidence.
"""
import asyncio
import json
import secrets
import uuid

import pytest
from aiohttp import ClientSession

from p2pchat.server import make_app
from p2pchat.tests.backend.test_http_signal import HttpPeer, ORIGIN, start

ROOM = 'prediction-signal-room'
SECRET = 'prediction-signal-secret-128bit'


def samples(ports=(41000, 41001)):
    return [{'sequence': index, 'localPort': 40001 + index,
             'destination': ['203.0.113.1', 3478], 'mappedPort': port}
            for index, port in enumerate(ports)]


def samples_body(to, connection, attempt, payload=None, mechanism='udp-probe', **extra):
    return {'v': 1, 'type': 'nat-samples', 'to': to, 'connectionId': connection, 'attemptId': attempt,
            'mechanism': mechanism, 'profile': mechanism, 'nonce': secrets.token_hex(24), 'proof': 'ab' * 32,
            'samples': samples() if payload is None else payload, **extra}


def candidate():
    return {'id': str(uuid.uuid4()), 'family': 4, 'transport': 'udp', 'address': '127.0.0.1',
            'port': 41234, 'kind': 'host', 'socketId': 'socket-1'}


async def pair_with_attempt(session, base, room=None):
    """Two joined peers plus one udp-probe attempt binding owned by the lower id.

    A rejected POST closes that session server-side, so every negative case gets
    its own room/session instead of reusing a closed one.
    """
    room = room or ROOM
    first, second = HttpPeer(session, base), HttpPeer(session, base)
    status, _ = await first.join(room, SECRET, 'first')
    assert status in (200, 202)
    status, _ = await second.join(room, SECRET, 'second')
    assert status in (200, 202)
    await first.open_events()
    await second.open_events()
    lower, upper = (first, second) if first.id < second.id else (second, first)
    connection, attempt = str(uuid.uuid4()), str(uuid.uuid4())
    status, body = await lower.post({'v': 1, 'type': 'signal', 'to': upper.id, 'connectionId': connection,
                                     'attemptId': attempt, 'mechanism': 'udp-probe', 'profile': 'udp-probe',
                                     'nativeCandidate': candidate()})
    assert status in (200, 202), body
    return first, second, lower, upper, connection, attempt


async def relayed(sender, timeout=5):
    async with asyncio.timeout(timeout):
        while True:
            frame = await sender.next_event(timeout)
            if frame.get('type') == 'nat-samples':
                return frame


@pytest.mark.asyncio
async def test_samples_are_relayed_unchanged_to_the_room_peer(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base)
            payload = samples((42000, 42001, 42002))
            body = samples_body(lower.id, connection, attempt, payload=payload)
            status, response = await upper.post(body)
            assert status in (200, 202)
            frame = await relayed(lower)
            assert frame['from'] == upper.id
            assert frame['samples'] == payload                      # forwarded unchanged
            assert frame['attemptId'] == attempt and frame['connectionId'] == connection
            assert SECRET not in json.dumps(frame)                  # the room key never travels
    finally:
        await runner.cleanup()


# --- exhaustive schema checks at the hub layer (no HTTP sessions needed) ------

class StubStore:
    salt = '00' * 16


class StubLink:
    closed = False

    async def send(self, payload):
        return None


def hub_with_attempt():
    from p2pchat.server import Hub

    hub = Hub(StubStore(), {})
    hub.peers['a'] = {'link': StubLink(), 'room': 'r'}
    hub.peers['b'] = {'link': StubLink(), 'room': 'r'}
    connection, attempt = str(uuid.uuid4()), str(uuid.uuid4())
    hub.attempts[attempt] = {'binding': (connection, ('a', 'b'), 'udp-probe', 'udp-probe'),
                             'created': 0.0, 'counts': {}, 'offer': False, 'answer': False, 'closed': False}
    return hub, connection, attempt


def test_unknown_fields_and_bad_shapes_are_rejected():
    from p2pchat.backend.protocol import ProtocolError

    hub, connection, attempt = hub_with_attempt()
    base = samples_body('b', connection, attempt)
    cases = [({**base, 'chat': 'hello'}, 'SCHEMA_INVALID'),           # no passthrough field
             ({**base, 'proof': 'not-hex'}, 'SCHEMA_INVALID'),
             ({**base, 'nonce': 'x' * 48}, 'SCHEMA_INVALID'),
             ({**base, 'mechanism': 'webrtc'}, 'SCHEMA_INVALID'),
             ({**base, 'samples': []}, 'LIMIT_EXCEEDED'),
             ({**base, 'samples': samples() * 33}, 'LIMIT_EXCEEDED')]
    bad = samples(); bad[0]['destination'] = ['224.0.0.1', 3478]; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0]['destination'] = ['169.254.1.2', 3478]; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0]['destination'] = ['0.0.0.0', 3478]; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0]['mappedPort'] = 0; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0]['destination'] = ['203.0.113.1', 70000]; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0]['sequence'] = 'zero'; cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    bad = samples(); bad[0].pop('mappedPort'); cases.append(({**base, 'samples': bad}, 'SCHEMA_INVALID'))
    for body, expected in cases:
        with pytest.raises(ProtocolError) as raised:
            hub.bind_samples('a', body)
        assert str(raised.value) == expected, body


def test_bind_samples_requires_a_live_attempt_and_relays_only_the_attempt_peer():
    from p2pchat.backend.protocol import ProtocolError

    hub, connection, attempt = hub_with_attempt()
    body = samples_body('b', connection, attempt)
    assert hub.bind_samples('a', body) is hub.peers['b']
    with pytest.raises(ProtocolError) as raised:
        hub.bind_samples('a', samples_body('b', str(uuid.uuid4()), attempt))
    assert str(raised.value) == 'ATTEMPT_CONFLICT'
    with pytest.raises(ProtocolError) as raised:
        hub.bind_samples('a', samples_body('b', connection, attempt, mechanism='quic'))
    assert str(raised.value) == 'ATTEMPT_CONFLICT'
    hub.attempts[attempt]['closed'] = True
    with pytest.raises(ProtocolError) as raised:
        hub.bind_samples('a', samples_body('b', connection, attempt))
    assert str(raised.value) == 'ATTEMPT_CONFLICT'


@pytest.mark.asyncio
async def test_samples_require_an_existing_attempt_binding(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base)
            status, response = await upper.post(samples_body(lower.id, str(uuid.uuid4()), str(uuid.uuid4())))
            assert response.get('code') == 'ATTEMPT_CONFLICT', (status, response)
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base, room=ROOM + '-m')
            status, response = await upper.post(samples_body(lower.id, connection, attempt, mechanism='quic'))
            assert response.get('code') == 'ATTEMPT_CONFLICT', (status, response)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_samples_to_an_unknown_peer_are_refused(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base)
            status, response = await upper.post(samples_body(str(uuid.uuid4()), connection, attempt))
            assert response.get('code') == 'PEER_UNAVAILABLE', (status, response)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_samples_are_rate_limited_per_attempt(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base)
            for _ in range(8):
                status, response = await upper.post(samples_body(lower.id, connection, attempt))
                assert status in (200, 202), response
            status, response = await upper.post(samples_body(lower.id, connection, attempt))
            assert response.get('code') == 'LIMIT_EXCEEDED', (status, response)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_signal_schema_still_rejects_embedded_samples(tmp_path):
    """No arbitrary passthrough: samples cannot ride inside a normal signal frame."""
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first, second, lower, upper, connection, attempt = await pair_with_attempt(session, base)
            status, response = await lower.post({'v': 1, 'type': 'signal', 'to': upper.id,
                                                 'connectionId': connection, 'attemptId': attempt,
                                                 'mechanism': 'udp-probe', 'profile': 'udp-probe',
                                                 'samples': samples()})
            assert response.get('code') == 'SCHEMA_INVALID', (status, response)
    finally:
        await runner.cleanup()
