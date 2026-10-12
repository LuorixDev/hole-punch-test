"""HTTP(POST+SSE) signaling transport: equivalence, no-relay, bounds, origin/auth.

Real server over real HTTP (no WebSocket) for the main flows; parity tests run the same
payload through both transports and compare the resulting codes. Evidence scope: this is
loopback HTTP on Linux — it is not a substitute for a real deployment, and Windows/macOS
behavior is unverified (see docs/HTTP-SIGNALING.md).
"""
import asyncio
import json
import uuid

import pytest
from aiohttp import ClientConnectionError, ClientSession, ClientTimeout, WSServerHandshakeError, web

from p2pchat.server import Hub, SseLink, error_code, make_app
from p2pchat.tests.backend.test_security import join_message

ORIGIN = 'https://p2p.example'
SECRET = 'http-signal-room-secret'
EMPTY = {'peers': 0, 'rooms': 0, 'room_keys': 0, 'attempts': 0}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

async def start(tmp_path, **kwargs):
    kwargs.setdefault('origins', [ORIGIN])
    app = make_app(tmp_path, **kwargs)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return app, runner, f'http://127.0.0.1:{port}'


def join_body(room, secret=SECRET, name='peer'):
    return {'v': 1, 'type': 'join', 'room': room, 'secret': secret, 'name': name,
            'clientSessionId': str(uuid.uuid4()), 'capabilities': ['webrtc']}


def signal_body(to, sdp='v=0\r\n', **extra):
    return {'v': 1, 'type': 'signal', 'to': to, 'connectionId': str(uuid.uuid4()),
            'attemptId': str(uuid.uuid4()), 'mechanism': 'webrtc', 'profile': 'ice-dual',
            'description': {'type': 'offer', 'sdp': sdp}, **extra}


class HttpPeer:
    """A client that only speaks the HTTP transport: POST up, SSE down."""

    def __init__(self, session, base, origin=ORIGIN):
        self.session, self.base, self.origin = session, base, origin
        self.welcome = None
        self.status = None
        self.token = None
        self.client_session = None
        self.response = None

    def headers(self, origin=None):
        value = self.origin if origin is None else origin
        return {} if value is None else {'Origin': value}

    @property
    def id(self):
        return self.welcome['id']

    async def join(self, room, secret=SECRET, name='http-peer', origin=None):
        body = join_body(room, secret, name)
        self.client_session = body['clientSessionId']
        async with self.session.post(f'{self.base}/signal/join', json=body,
                                     headers=self.headers(origin)) as response:
            self.status = response.status
            self.welcome = await response.json()
        if self.status == 200:
            self.token = self.welcome['eventToken']
        return self.status, self.welcome

    async def open_events(self, origin=None):
        self.response = await self.session.get(
            f'{self.base}/signal/events', params={'token': self.token},
            headers=self.headers(origin), timeout=ClientTimeout(total=None))
        return self.response

    async def post(self, payload, origin=None, token=None):
        headers = {**self.headers(origin), 'X-P2P-Token': self.token if token is None else token}
        async with self.session.post(f'{self.base}/signal', json=payload, headers=headers) as response:
            return response.status, await response.json()

    async def next_event(self, timeout=5):
        return await asyncio.wait_for(self._read_frame(), timeout)

    async def _read_frame(self):
        while True:
            line = await self.response.content.readline()
            if not line:
                raise EOFError('SSE stream closed')
            line = line.strip()
            if line.startswith(b'data: '):
                return json.loads(line[6:])

    async def roster_names(self, expected=None, timeout=5):
        """读花名册；给了 expected 就一直读到匹配为止（队列里可能先有旧的一份）。"""
        last = None
        async with asyncio.timeout(timeout):
            while True:
                frame = await self.next_event(timeout)
                if frame.get('type') != 'roster':
                    continue
                last = {peer['name'] for peer in frame['peers']}
                if expected is None or last == set(expected):
                    return last

    def close(self):
        if self.response is not None:
            self.response.close()
            self.response = None


async def wait_for(predicate, timeout=5):
    async with asyncio.timeout(timeout):
        while True:
            if predicate():
                return True
            await asyncio.sleep(0.05)


async def wait_empty(hub, timeout=5):
    await wait_for(lambda: {'peers': len(hub.peers), 'rooms': len(hub.rooms),
                            'room_keys': len(hub.room_keys), 'attempts': len(hub.attempts)} == EMPTY
                   and not hub.http_sessions, timeout)
    return EMPTY


async def _ws_join(session, url, room, name):
    ws = await session.ws_connect(url, origin=ORIGIN)
    message = join_message(room=room)
    message['secret'] = SECRET
    message['name'] = name
    await ws.send_json(message)
    welcome = await ws.receive_json()
    assert welcome['type'] == 'welcome'
    await ws.receive_json()  # roster
    return ws, welcome


async def ws_error_code(url, payload, room, target=None):
    """Same payload over WebSocket: returns the error code the WS transport produced."""
    async with ClientSession() as session:
        ws, welcome = await _ws_join(session, url, room, 'ws-sender')
        other = None
        if target == 'peer':
            other, other_welcome = await _ws_join(session, url, room, 'ws-target')
            payload = {**payload, 'to': other_welcome['id']}
        elif target:
            payload = {**payload, 'to': target}
        await ws.send_json(payload)
        async with asyncio.timeout(5):
            while True:
                frame = await ws.receive_json()
                if frame['type'] == 'error':
                    code = frame['code']
                    break
        await ws.close()
        if other is not None:
            await other.close()
        return code


# ---------------------------------------------------------------------------
# hub/link unit level: bounded queue, explicit overflow (no silent drops)
# ---------------------------------------------------------------------------

def test_sse_link_is_bounded_and_reports_overflow_explicitly():
    overflows = []
    link = SseLink(limit=2, on_overflow=lambda: overflows.append(1))
    assert link.send_nowait({'type': 'roster', 'peers': []}) is True
    assert link.send_nowait({'type': 'roster', 'peers': []}) is True
    assert link.send_nowait({'type': 'roster', 'peers': []}) is False  # 超限：不入队
    assert len(link.queue) == 2
    assert link.closed is True and link.close_reason == 'LIMIT_EXCEEDED'
    assert overflows == [1]

    async def drain():
        return [frame async for frame in link.stream()]

    frames = asyncio.run(drain())
    assert frames[-1] == b'data: {"v": 1, "type": "error", "code": "LIMIT_EXCEEDED"}\n\n'
    assert len(frames) == 3  # 两条已入队 + 明确的收尾原因；绝不静默丢弃


def test_sse_link_close_wakes_stream_without_reason():
    link = SseLink(limit=4)
    link.close()
    assert link.close_reason is None

    async def drain():
        return [frame async for frame in link.stream()]

    assert asyncio.run(drain()) == []


def test_error_code_mapping_matches_ws_set():
    for code in ('AUTH_FAILED', 'SCHEMA_INVALID', 'LIMIT_EXCEEDED', 'RELAY_FORBIDDEN',
                 'PEER_UNAVAILABLE', 'EVENT_CONFLICT', 'UNSUPPORTED_VERSION',
                 'ROOM_EXPIRED', 'ATTEMPT_CONFLICT', 'TIMEOUT'):
        assert error_code(ValueError(code)) == code
    assert error_code(ValueError('anything-else')) == 'SCHEMA_INVALID'
    assert error_code(KeyError('boom')) == 'SCHEMA_INVALID'


def test_origin_allowed_switch_is_off_by_default():
    class FakeRequest:
        def __init__(self, origin):
            self.headers = {} if origin is None else {'Origin': origin}

    hub = Hub.__new__(Hub)
    hub.config = {'origins': [ORIGIN]}
    assert hub.origin_allowed(FakeRequest(ORIGIN)) is True
    assert hub.origin_allowed(FakeRequest('https://evil.example')) is False
    assert hub.origin_allowed(FakeRequest(None)) is False           # 默认不放开无 Origin
    hub.config = {'origins': [ORIGIN], 'allowNoOrigin': True}
    assert hub.origin_allowed(FakeRequest(None)) is True            # 只有显式开关才允许
    assert hub.origin_allowed(FakeRequest('https://evil.example')) is False
    hub.config = {'origins': []}
    assert hub.origin_allowed(FakeRequest('https://evil.example')) is True   # 未配 allowlist：旧语义
    assert hub.origin_allowed(FakeRequest(None)) is True


# ---------------------------------------------------------------------------
# end-to-end over HTTP only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_http_clients_join_see_each_other_forward_signal_and_disconnect(tmp_path):
    app, runner, base = await start(tmp_path)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            a, b = HttpPeer(session, base), HttpPeer(session, base)
            assert (await a.join('http-room', name='http-a'))[0] == 200
            assert (await b.join('http-room', name='http-b'))[0] == 200
            assert a.welcome['strictP2P'] is True and a.welcome['iceServers'] == []
            assert a.welcome['transport'] == 'http' and a.welcome['eventsPath'] == '/signal/events'
            assert a.welcome['id'] != b.welcome['id']
            assert a.token and b.token and a.token != b.token

            assert (await a.open_events()).status == 200
            assert (await b.open_events()).status == 200
            assert await a.roster_names({'http-a', 'http-b'}) == {'http-a', 'http-b'}
            assert await b.roster_names({'http-a', 'http-b'}) == {'http-a', 'http-b'}

            sender, receiver = (a, b) if a.id < b.id else (b, a)  # 只有较小的 id 能宣告新连接
            status, body = await sender.post(signal_body(receiver.id))
            assert (status, body['type']) == (202, 'accepted')
            forwarded = await receiver.next_event()
            assert forwarded['type'] == 'signal'
            assert forwarded['from'] == sender.id and forwarded['mechanism'] == 'webrtc'

            status, _ = await sender.post({'v': 1, 'type': 'ping', 'ts': 12345})
            assert status == 202
            assert await sender.next_event() == {'v': 1, 'type': 'pong', 'ts': 12345}

            a.close()
            b.close()
        assert await wait_empty(hub) == EMPTY
        journal = (tmp_path / 'server.jsonl').read_text(encoding='utf-8', errors='replace')
        assert SECRET not in journal and 'http-a' not in journal
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_and_ws_share_one_room_and_forward_across_transports(tmp_path):
    """No behavioral fork: one Hub, one room, one auth; WS and HTTP peers interoperate."""
    app, runner, base = await start(tmp_path)
    hub = app['hub']
    ws_url = f'{base.replace("http://", "ws://")}/ws'
    try:
        async with ClientSession() as session:
            http_peer = HttpPeer(session, base)
            assert (await http_peer.join('mixed-room', name='http-side'))[0] == 200
            await http_peer.open_events()
            await http_peer.roster_names()

            ws, ws_welcome = await _ws_join(session, ws_url, 'mixed-room', 'ws-side')
            assert await http_peer.roster_names({'http-side', 'ws-side'}) == {'http-side', 'ws-side'}

            if ws_welcome['id'] < http_peer.id:
                await ws.send_json(signal_body(http_peer.id))
                frame = await http_peer.next_event()
            else:
                status, _ = await http_peer.post(signal_body(ws_welcome['id']))
                assert status == 202
                frame = await ws.receive_json()
            assert frame['type'] == 'signal' and frame['mechanism'] == 'webrtc'

            await ws.close()
            http_peer.close()
        assert await wait_empty(hub) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_telemetry_parity_with_ws(tmp_path):
    """Same telemetry rules: mismatched clientSessionId -> AUTH_FAILED; valid -> ack with ids."""
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('telemetry-room'))[0] == 200
            await peer.open_events()
            event = {'v': 1, 'id': str(uuid.uuid4()), 'clientSessionId': peer.client_session, 'seq': 1,
                     'tsWallMs': 1.0, 'monoMs': 1.0, 'connectionId': None, 'attemptId': None,
                     'event': 'client.boot', 'data': {}}
            status, body = await peer.post({'v': 1, 'type': 'telemetry',
                                            'clientSessionId': str(uuid.uuid4()), 'events': [event]})
            assert (status, body['code']) == (401, 'AUTH_FAILED')
        assert await wait_empty(app['hub']) == EMPTY

        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('telemetry-ok'))[0] == 200
            await peer.open_events()
            event = {**event, 'clientSessionId': peer.client_session}
            status, _ = await peer.post({'v': 1, 'type': 'telemetry',
                                         'clientSessionId': peer.client_session, 'events': [event]})
            assert status == 202
            async with asyncio.timeout(5):
                while True:
                    frame = await peer.next_event()
                    if frame.get('type') == 'telemetry_ack':
                        break
            assert frame == {'v': 1, 'type': 'telemetry_ack',
                             'clientSessionId': peer.client_session, 'ids': [event['id']]}
            peer.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# no-relay invariants + error-code parity with WS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('payload,expected', [
    ({'v': 1, 'type': 'chat', 'text': 'never relay me'}, 'SCHEMA_INVALID'),
    ({'v': 1, 'type': 'file-start', 'id': str(uuid.uuid4())}, 'SCHEMA_INVALID'),
    ({'v': 1, 'type': 'voice', 'data': 'x'}, 'SCHEMA_INVALID'),
    ({'v': 1, 'type': 'telemetry', 'clientSessionId': str(uuid.uuid4()), 'events': []}, 'AUTH_FAILED'),
    ({'v': 2, 'type': 'ping'}, 'UNSUPPORTED_VERSION'),
])
@pytest.mark.asyncio
async def test_http_rejects_relay_shapes_with_same_codes_as_ws(tmp_path, payload, expected):
    app, runner, base = await start(tmp_path)
    ws_url = f'{base.replace("http://", "ws://")}/ws'
    room = f'parity-{uuid.uuid4().hex[:6]}'
    try:
        assert await ws_error_code(ws_url, payload, room=room) == expected
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join(room))[0] == 200
            await peer.open_events()
            status, body = await peer.post(payload)
            assert body == {'v': 1, 'type': 'error', 'code': expected}
            assert status in {400, 401, 403}
            assert await wait_empty(app['hub']) == EMPTY   # 出错即断开，和 WS 一致
            journal = (tmp_path / 'server.jsonl').read_text(encoding='utf-8', errors='replace')
            assert expected in journal
            assert 'never relay me' not in journal
            peer.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_rejects_turn_candidates_with_relay_forbidden(tmp_path):
    """候选/scp 里的 relay 候选必须被拒，且与 WS 同码——两条通道都不允许 TURN。"""
    app, runner, base = await start(tmp_path)
    ws_url = f'{base.replace("http://", "ws://")}/ws'
    relay_sdp = ('a=candidate:1 1 udp 10 192.0.2.9 4000 typ relay\r\n')
    try:
        assert await ws_error_code(ws_url, {'v': 1, 'type': 'signal', 'connectionId': str(uuid.uuid4()),
                                            'attemptId': str(uuid.uuid4()), 'mechanism': 'webrtc',
                                            'profile': 'ice-dual',
                                            'description': {'type': 'offer', 'sdp': relay_sdp}},
                                   room='parity-relay', target='peer') == 'RELAY_FORBIDDEN'
        async with ClientSession() as session:
            peer, other = HttpPeer(session, base), HttpPeer(session, base)
            assert (await peer.join('relay-http'))[0] == 200
            assert (await other.join('relay-http', name='other'))[0] == 200
            await peer.open_events()
            await other.open_events()
            status, body = await peer.post(signal_body(other.id, sdp=relay_sdp))
            assert (status, body['code']) == (403, 'RELAY_FORBIDDEN')
            assert 'typ relay' not in (tmp_path / 'server.jsonl').read_text(encoding='utf-8', errors='replace')
            peer.close()
            other.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_join_auth_and_schema_errors(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            first = HttpPeer(session, base)
            assert (await first.join('auth-room', name='first'))[0] == 200
            await first.open_events()

            wrong = HttpPeer(session, base)
            status, body = await wrong.join('auth-room', secret='WRONG-ROOM-SECRET', name='wrong')
            assert status == 403 and body['code'] == 'AUTH_FAILED'
            assert wrong.token is None and len(app['hub'].peers) == 1

            async with session.post(f'{base}/signal/join', json={'v': 1, 'type': 'join'},
                                    headers={'Origin': ORIGIN}) as response:
                body = await response.json()
                assert response.status == 400 and body['code'] == 'SCHEMA_INVALID'

            malformed = await session.post(f'{base}/signal/join', data=b'{not json',
                                           headers={'Origin': ORIGIN, 'Content-Type': 'application/json'})
            assert malformed.status == 400 and (await malformed.json())['code'] == 'SCHEMA_INVALID'
            malformed.close()
            first.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_requires_valid_token(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            await peer.join('token-room')
            status, body = await peer.post({'v': 1, 'type': 'ping'}, token='')
            assert status == 401 and body['code'] == 'AUTH_FAILED'
            status, body = await peer.post({'v': 1, 'type': 'ping'}, token='forged-token')
            assert status == 401 and body['code'] == 'AUTH_FAILED'
            response = await session.get(f'{base}/signal/events', params={'token': 'forged-token'},
                                         headers={'Origin': ORIGIN})
            assert response.status == 401
            response.close()
            status, _ = await peer.post({'v': 1, 'type': 'ping', 'ts': 7})
            assert status == 202
            await peer.open_events()   # 开流后关闭，会话才会结束（与 WS 断开等价）
            peer.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_origin_exact_allowlist_and_explicit_no_origin_switch(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            for origin in (None, 'null', 'https://evil.example'):
                peer = HttpPeer(session, base, origin=origin)
                status, _ = await peer.join(f'origin-{origin}')
                assert status == 403, (origin, status)
            approved = HttpPeer(session, base, origin=ORIGIN)
            assert (await approved.join('origin-ok'))[0] == 200
            await approved.open_events()
            approved.close()
        await wait_empty(app['hub'])
    finally:
        await runner.cleanup()

    app, runner, base = await start(tmp_path / 'allow-no-origin', allowNoOrigin=True)
    try:
        async with ClientSession() as session:
            no_origin = HttpPeer(session, base, origin=None)
            assert (await no_origin.join('no-origin-ok'))[0] == 200
            await no_origin.open_events()
            no_origin.close()
            evil = HttpPeer(session, base, origin='https://evil.example')
            assert (await evil.join('no-origin-evil'))[0] == 403  # 有 Origin 就必须命中
        await wait_empty(app['hub'])
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ws_keeps_exact_allowlist_and_switch_is_transport_neutral(tmp_path):
    app, runner, base = await start(tmp_path)
    ws_url = f'{base.replace("http://", "ws://")}/ws'
    try:
        async with ClientSession() as session:
            with pytest.raises(WSServerHandshakeError):
                await session.ws_connect(ws_url)  # 无 Origin：默认拒绝
    finally:
        await runner.cleanup()

    app, runner, base = await start(tmp_path / 'ws-no-origin', allowNoOrigin=True)
    ws_url = f'{base.replace("http://", "ws://")}/ws'
    try:
        async with ClientSession() as session:
            ws = await session.ws_connect(ws_url)  # 显式开关后才允许无 Origin
            assert ws._response.status == 101
            await ws.close()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# bounds: size, rate, connection caps, slow consumer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_oversize_body_is_rejected(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('big-room'))[0] == 200
            await peer.open_events()
            huge = {'v': 1, 'type': 'ping', 'pad': 'x' * (140 * 1024)}
            try:
                response = await session.post(f'{base}/signal', json=huge,
                                              headers={'Origin': ORIGIN, 'X-P2P-Token': peer.token})
                assert response.status == 413
                assert (await response.json())['code'] == 'LIMIT_EXCEEDED'
                response.close()
            except (ClientConnectionError, ConnectionResetError):
                pass  # 服务器拒绝后立刻关闭；下面用日志与状态确认确实按 LIMIT_EXCEEDED 处理
            await wait_for(lambda: 'LIMIT_EXCEEDED' in (tmp_path / 'server.jsonl').read_text(encoding='utf-8', errors='replace'))
            peer.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_message_rate_limit_is_enforced_per_session(tmp_path):
    """Same 80 msg/s window as WS; over the limit is an explicit 429 LIMIT_EXCEEDED."""
    app, runner, base = await start(tmp_path, max_http_queue=200, max_http_messages_per_source=10000)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('rate-room'))[0] == 200
            await peer.open_events()
            codes = []
            for _ in range(90):
                status, body = await peer.post({'v': 1, 'type': 'ping', 'ts': 1})
                codes.append((status, body.get('code')))
                if status != 202:
                    break
            assert codes[-1] == (429, 'LIMIT_EXCEEDED'), codes[-3:]
            assert codes.count((202, None)) == 80
            peer.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_source_rate_limit_is_enforced(tmp_path):
    app, runner, base = await start(tmp_path, max_http_queue=200, max_http_messages_per_source=5)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('source-rate'))[0] == 200
            await peer.open_events()
            results = [await peer.post({'v': 1, 'type': 'ping', 'ts': 1}) for _ in range(6)]
            assert results[-1][0] == 429 and results[-1][1]['code'] == 'LIMIT_EXCEEDED'
            assert [status for status, _ in results[:5]] == [202] * 5
            peer.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_http_connection_caps_per_source_and_global(tmp_path):
    app, runner, base = await start(tmp_path, max_http_sse=2, max_http_sse_per_source=1)
    try:
        async with ClientSession() as session:
            first = HttpPeer(session, base)
            assert (await first.join('cap-room-a'))[0] == 200
            second = HttpPeer(session, base)
            status, body = await second.join('cap-room-b')      # 同一来源超过每来源上限
            assert status == 429 and body['code'] == 'LIMIT_EXCEEDED'
            await first.open_events()
            first.close()
        await wait_empty(app['hub'])
    finally:
        await runner.cleanup()

    app, runner, base = await start(tmp_path / 'global', max_http_sse=1, max_http_sse_per_source=5)
    try:
        async with ClientSession() as session:
            first = HttpPeer(session, base)
            assert (await first.join('global-cap-a'))[0] == 200
            second = HttpPeer(session, base)
            status, body = await second.join('global-cap-b')    # 全局上限
            assert status == 429 and body['code'] == 'LIMIT_EXCEEDED'
            await first.open_events()
            first.close()
        await wait_empty(app['hub'])
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_slow_consumer_overflow_disconnects_and_logs_reason(tmp_path):
    """极端慢消费者（从不打开下行流）不得让内存无界增长：超限即断开并记原因。"""
    app, runner, base = await start(tmp_path, max_http_queue=4)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            one, two = HttpPeer(session, base), HttpPeer(session, base)
            assert (await one.join('slow-room', name='one'))[0] == 200
            assert (await two.join('slow-room', name='two'))[0] == 200
            sender, slow = (one, two) if one.id < two.id else (two, one)
            assert (await sender.open_events()).status == 200   # 只有 slow 从不读下行
            await sender.roster_names()
            sent = []
            for _ in range(12):
                status, body = await sender.post(signal_body(slow.id))
                sent.append((status, body.get('code')))
                if status != 202:
                    break
            assert sent[0] == (202, None)                       # 溢出前正常受理
            assert sent[-1][0] in {404, 429}                    # 目标已被拆掉：明确失败
            assert sent[-1][1] == 'PEER_UNAVAILABLE'
            await wait_for(lambda: slow.id not in hub.peers)
            journal = (tmp_path / 'server.jsonl').read_text(encoding='utf-8', errors='replace')
            assert 'session.error' in journal and 'LIMIT_EXCEEDED' in journal
            status, body = await slow.post({'v': 1, 'type': 'ping'})
            assert status == 401 and body['code'] == 'AUTH_FAILED'   # token 已失效：明确失败
            sender.close()
        assert await wait_empty(hub) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_second_sse_stream_for_one_session_is_rejected(tmp_path):
    app, runner, base = await start(tmp_path)
    try:
        async with ClientSession() as session:
            peer = HttpPeer(session, base)
            assert (await peer.join('stream-room'))[0] == 200
            assert (await peer.open_events()).status == 200
            second = await session.get(f'{base}/signal/events', params={'token': peer.token},
                                       headers={'Origin': ORIGIN})
            assert second.status == 409
            second.close()
            peer.close()
        assert await wait_empty(app['hub']) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_stale_sessions_are_pruned(tmp_path):
    """Never-streamed sessions expire (bounded token map), while active ones survive."""
    app, runner, base = await start(tmp_path, http_session_ttl=0.2)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            stale = HttpPeer(session, base)
            assert (await stale.join('ttl-a'))[0] == 200
            active = HttpPeer(session, base)
            assert (await active.join('ttl-b'))[0] == 200
            await active.open_events()
            await asyncio.sleep(0.3)
            fresh = HttpPeer(session, base)
            assert (await fresh.join('ttl-c'))[0] == 200   # 任何 HTTP 请求都会触发清理
            assert stale.id not in hub.peers               # 从未开流的会话已过期
            assert active.id in hub.peers                  # 正在流的会话不受影响
            await fresh.open_events()
            fresh.close()
            active.close()
        assert await wait_empty(hub) == EMPTY
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_shutdown_ends_open_sse_streams(tmp_path):
    app, runner, base = await start(tmp_path)
    async with ClientSession() as session:
        peer = HttpPeer(session, base)
        assert (await peer.join('shutdown-room'))[0] == 200
        await peer.open_events()
        assert await peer.roster_names() == {'http-peer'}
        await runner.cleanup()          # 关停服务端：SSE 流必须结束，处理器不能挂住
        with pytest.raises((EOFError, ConnectionResetError, ClientConnectionError)):
            await peer.next_event(timeout=5)
        peer.close()
