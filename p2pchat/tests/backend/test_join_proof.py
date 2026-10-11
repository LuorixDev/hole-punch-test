"""加入证明 v2：信令链路不再传输可复用的房间密钥（nonce + HMAC 派生值）。

覆盖：正例（首次建立房间密钥 / 同密钥后来者）、错密钥、nonce 重放、过期 nonce、
缺失/伪造 nonce、nonce 绑定房间与会话、服务器不含原始 secret（内存与数据目录）、
旧协议(v1 明文密钥)的来源策略与明确拒绝路径、不存在静默降级的路径、以及
--allow-plaintext 的默认关闭与显式开启。

证据范围：本机 loopback 实验（Linux）。不是家宽/NAT 证据。
"""
import asyncio
import json
import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from aiohttp import ClientSession, ClientTimeout, web

from p2pchat.peer import derive_join_key, join_proof
from p2pchat.server import JOIN_PROOF_ALGO, JOIN_VERSION, make_app, public_bind_error
from p2pchat.tests.backend.test_security import join_message

ORIGIN = 'https://p2p.example'
SECRET = 'join-proof-room-secret-please-rotate'
SECRET_HEX_MARK = '746869732d69732d6e6f742d612d6b6579'  # 仅用于确证“不含原始密钥”的负例字样


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
    return app, runner, f'http://127.0.0.1:{port}', f'ws://127.0.0.1:{port}/ws'


def headers(origin=ORIGIN):
    return {} if origin is None else {'Origin': origin}


async def http_challenge(session, base, room, client_session, origin=ORIGIN):
    body = {'v': 1, 'type': 'join_challenge', 'room': room, 'clientSessionId': client_session}
    async with session.post(f'{base}/signal/join/challenge', json=body, headers=headers(origin)) as response:
        return response.status, await response.json()


async def http_join(session, base, room, secret=SECRET, name='peer', client_session=None,
                    nonce=None, proof=None, origin=ORIGIN, verifier='auto', extra=None):
    client_session = client_session or str(uuid.uuid4())
    if nonce is None:
        status, challenge = await http_challenge(session, base, room, client_session, origin)
        assert status == 200, challenge
        nonce = challenge['nonce']
        estimated = challenge.get('roomEstablished', False)
    else:
        estimated = False
    key = derive_join_key(secret, room)
    body = {'v': 1, 'type': 'join', 'joinVersion': JOIN_VERSION, 'room': room, 'name': name,
            'clientSessionId': client_session, 'capabilities': ['webrtc'], 'nonce': nonce,
            'proof': proof if proof is not None else join_proof(key, room, nonce, client_session)}
    if verifier == 'auto':
        if not estimated:
            body['verifier'] = key
    elif verifier is not None:
        body['verifier'] = verifier
    if extra:
        body.update(extra)
    async with session.post(f'{base}/signal/join', json=body, headers=headers(origin)) as response:
        return response.status, await response.json()


async def ws_join(session, url, room, secret=SECRET, name='ws-peer', client_session=None,
                  nonce=None, proof=None, verifier='auto', join_extra=None):
    client_session = client_session or str(uuid.uuid4())
    ws = await session.ws_connect(url, origin=ORIGIN)
    if nonce is None:
        await ws.send_json({'v': 1, 'type': 'join_challenge', 'room': room, 'clientSessionId': client_session})
        challenge = await ws.receive_json()
        assert challenge['type'] == 'join_challenge', challenge
        nonce = challenge['nonce']
        estimated = challenge.get('roomEstablished', False)
    else:
        estimated = False
    key = derive_join_key(secret, room)
    body = {'v': 1, 'type': 'join', 'joinVersion': JOIN_VERSION, 'room': room, 'name': name,
            'clientSessionId': client_session, 'capabilities': ['webrtc'], 'nonce': nonce,
            'proof': proof if proof is not None else join_proof(key, room, nonce, client_session)}
    if verifier == 'auto':
        if not estimated:
            body['verifier'] = key
    elif verifier is not None:
        body['verifier'] = verifier
    if join_extra:
        body.update(join_extra)
    await ws.send_json(body)
    return ws, await ws.receive_json()


async def receive_type(ws, kind, timeout=5):
    async with asyncio.timeout(timeout):
        while True:
            frame = await ws.receive_json()
            if frame['type'] == kind:
                return frame


def data_dir_text(path):
    """数据目录里所有文件的字节（用于“密钥不出现在服务器数据目录”的断言）。"""
    blob = b''
    for item in sorted(Path(path).rglob('*')):
        if item.is_file():
            blob += item.read_bytes()
    return blob


# ---------------------------------------------------------------------------
# 正例
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v2_join_establishes_and_reuses_room_key(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            ws_a, welcome_a = await ws_join(session, ws_url, 'proof-room', name='a')
            assert welcome_a['type'] == 'welcome' and welcome_a['strictP2P'] is True
            assert welcome_a['id']
            await receive_type(ws_a, 'roster')
            stored = hub.room_keys['proof-room']
            assert stored['version'] == JOIN_VERSION
            assert stored['digest'].hex() == derive_join_key(SECRET, 'proof-room')  # 只存派生值

            # 第二个客户端：同一个 secret，走新 nonce，不再交 verifier
            ws_b, welcome_b = await ws_join(session, ws_url, 'proof-room', name='b', verifier=None)
            assert welcome_b['type'] == 'welcome'
            roster = await receive_type(ws_a, 'roster')
            assert {peer['name'] for peer in roster['peers']} == {'a', 'b'}

            # 两个地址族/传输都行：HTTP 客户端也能加入同一房间
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'proof-room', session_id)
            assert status == 200 and challenge['roomEstablished'] is True
            status, welcome_c = await http_join(session, base, 'proof-room', name='c', client_session=session_id)
            assert status == 200 and welcome_c['type'] == 'welcome'
            await ws_a.close()
            await ws_b.close()
        assert not hub.room_keys.get('proof-room') or hub.room_keys['proof-room']['version'] == JOIN_VERSION
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_challenge_response_shape(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'shape-room', session_id)
            assert status == 200
            assert challenge['v'] == 1 and challenge['type'] == 'join_challenge'
            assert len(challenge['nonce']) == 48 and all(c in '0123456789abcdef' for c in challenge['nonce'])
            assert challenge['proof'] == JOIN_PROOF_ALGO
            assert challenge['expiresInMs'] > 0 and challenge['roomEstablished'] is False
            # WS 上同样可以拿 nonce
            ws = await session.ws_connect(ws_url, origin=ORIGIN)
            await ws.send_json({'v': 1, 'type': 'join_challenge', 'room': 'shape-room',
                                'clientSessionId': session_id})
            frame = await ws.receive_json()
            assert frame['type'] == 'join_challenge' and frame['nonce'] != challenge['nonce']
            await ws.close()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 负例：错密钥 / 重放 / 过期 / 缺失 / 伪造 / 绑定
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wrong_secret_is_auth_failed_and_leaves_no_room(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            ws_a, _ = await ws_join(session, ws_url, 'auth-room', name='a')
            await receive_type(ws_a, 'roster')
            before = dict(hub.room_keys)
            ws_b, error = await ws_join(session, ws_url, 'auth-room', secret='wrong-secret', name='b')
            assert error['type'] == 'error' and error['code'] == 'AUTH_FAILED'
            assert hub.room_keys == before                     # 房间密钥没被改动
            assert len(hub.peers) == 1                         # 冒充者没进入房间
            await ws_b.close()
            await ws_a.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_nonce_replay_fails(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'replay-room', session_id)
            assert status == 200
            key = derive_join_key(SECRET, 'replay-room')
            proof = join_proof(key, 'replay-room', challenge['nonce'], session_id)
            status, welcome = await http_join(session, base, 'replay-room', client_session=session_id,
                                              nonce=challenge['nonce'], proof=proof)
            assert status == 200 and welcome['type'] == 'welcome'
            status, error = await http_join(session, base, 'replay-room', client_session=session_id,
                                            nonce=challenge['nonce'], proof=proof)
            assert status == 403 and error['code'] == 'AUTH_FAILED'   # 同一个 nonce 只能用一次
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_expired_nonce_fails(tmp_path):
    app, runner, base, ws_url = await start(tmp_path, join_nonce_ttl=30)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'expire-room', session_id)
            assert status == 200
            hub.join_nonces[challenge['nonce']]['created'] -= 120      # 人为放到过期
            key = derive_join_key(SECRET, 'expire-room')
            status, error = await http_join(session, base, 'expire-room', client_session=session_id,
                                            nonce=challenge['nonce'],
                                            proof=join_proof(key, 'expire-room', challenge['nonce'], session_id))
            assert status == 403 and error['code'] == 'AUTH_FAILED'
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_missing_or_fabricated_nonce_and_missing_proof(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    hub = app['hub']
    try:
        async with ClientSession() as session:
            room, session_id = 'missing-room', str(uuid.uuid4())
            key = derive_join_key(SECRET, room)
            # 凭空编造的 nonce
            fake = 'ab' * 24
            status, error = await http_join(session, base, room, client_session=session_id,
                                            nonce=fake, proof=join_proof(key, room, fake, session_id))
            assert status == 403 and error['code'] == 'AUTH_FAILED'
            # 完全不带的 nonce / proof：schema 直接拒绝
            async with session.post(f'{base}/signal/join', headers=headers(),
                                    json={'v': 1, 'type': 'join', 'joinVersion': JOIN_VERSION, 'room': room,
                                          'name': 'x', 'clientSessionId': session_id,
                                          'capabilities': ['webrtc'], 'verifier': key}) as response:
                body = await response.json()
                assert response.status == 400 and body['code'] == 'SCHEMA_INVALID'
            # 有 nonce 没有 proof
            status, challenge = await http_challenge(session, base, room, session_id)
            async with session.post(f'{base}/signal/join', headers=headers(),
                                    json={'v': 1, 'type': 'join', 'joinVersion': JOIN_VERSION, 'room': room,
                                          'name': 'x', 'clientSessionId': session_id, 'capabilities': ['webrtc'],
                                          'nonce': challenge['nonce'], 'verifier': key}) as response:
                body = await response.json()
                assert response.status == 400 and body['code'] == 'SCHEMA_INVALID'
            # 证明格式不对（长度/字符集）
            status, challenge = await http_challenge(session, base, room, session_id)
            status, error = await http_join(session, base, room, client_session=session_id,
                                            nonce=challenge['nonce'], proof='zz' * 32)
            assert status == 400 and error['code'] == 'SCHEMA_INVALID'
            assert not hub.peers and not hub.room_keys
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_nonce_is_bound_to_room_and_session(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'bound-a', session_id)
            assert status == 200
            nonce = challenge['nonce']
            key_b = derive_join_key(SECRET, 'bound-b')
            # 同一个 nonce 拿去加另一个房间
            status, error = await http_join(session, base, 'bound-b', client_session=session_id,
                                            nonce=nonce, proof=join_proof(key_b, 'bound-b', nonce, session_id))
            assert status == 403 and error['code'] == 'AUTH_FAILED'
            # 同一个 nonce 换一个 clientSessionId
            status, challenge = await http_challenge(session, base, 'bound-a', session_id)
            other = str(uuid.uuid4())
            key_a = derive_join_key(SECRET, 'bound-a')
            status, error = await http_join(session, base, 'bound-a', client_session=other,
                                            nonce=challenge['nonce'],
                                            proof=join_proof(key_a, 'bound-a', challenge['nonce'], session_id))
            assert status == 403 and error['code'] == 'AUTH_FAILED'
            # 正确绑定才通过
            status, welcome = await http_join(session, base, 'bound-a', client_session=session_id)
            assert status == 200 and welcome['type'] == 'welcome'
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 服务器不接触原始密钥
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_server_never_receives_or_stores_the_raw_secret(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    hub = app['hub']
    # 直接抓服务器实际收到的 join 报文（而不是只查内部状态）
    seen = []
    original = hub.open_session
    async def spy(pid, data, link, transport, source=None, event_token=None):
        seen.append(json.loads(json.dumps(data, default=str)))
        return await original(pid, data, link, transport, source=source, event_token=event_token)
    hub.open_session = spy
    try:
        async with ClientSession() as session:
            ws_a, welcome = await ws_join(session, ws_url, 'nostore', name='a')
            await receive_type(ws_a, 'roster')
            status, _ = await http_join(session, base, 'nostore', name='b')
            assert status == 200
            await ws_a.close()
        assert len(seen) == 2
        for payload in seen:
            assert 'secret' not in payload                     # 报文里没有房间密钥字段
            assert SECRET not in json.dumps(payload)           # 也没有以任何形式夹带

        stored = hub.room_keys['nostore']
        assert stored['digest'].hex() == derive_join_key(SECRET, 'nostore')
        assert SECRET.encode() not in stored['digest']
        assert SECRET not in repr(hub.room_keys)
        assert SECRET not in repr(hub.peers)
        assert SECRET not in repr(hub.join_nonces)
        # 派生值不能被当成数据面密钥：它既不等于 secret，也不等于旧的 HMAC(salt, room+secret)
        assert stored['digest'].hex() != SECRET
        assert stored['digest'].hex() != hub.digest('nostore', SECRET).hex()

        blob = data_dir_text(tmp_path)
        assert SECRET.encode() not in blob                 # 原始密钥不落盘
        assert derive_join_key(SECRET, 'nostore').encode() not in blob   # 连派生值也不落盘
        assert SECRET_HEX_MARK.encode() not in blob
        assert b'"secret"' not in blob
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_plaintext_mode_keeps_the_secret_out_of_the_data_dir(tmp_path):
    """明文监听下同样不把密钥写进数据目录（run a real plaintext process)."""
    data_dir = tmp_path / 'central'
    port = _reserve_port()
    log = (tmp_path / 'server.log').open('wb')
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server', '--host', '0.0.0.0', '--port', str(port),
        '--stun-port', '0', '--stun-host', '127.0.0.1', '--data', str(data_dir),
        '--origin', ORIGIN, '--allow-plaintext', stdout=log, stderr=log)
    try:
        async with asyncio.timeout(15):
            while True:
                if process.returncode is not None:
                    raise AssertionError('server exited early')
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        async with ClientSession() as session:
            status, welcome = await http_join(session, f'http://127.0.0.1:{port}', 'plain-room', name='plain')
            assert status == 200 and welcome['type'] == 'welcome'
        await asyncio.sleep(0.2)
        blob = data_dir_text(data_dir)
        assert blob and SECRET.encode() not in blob
        assert derive_join_key(SECRET, 'plain-room').encode() not in blob
    finally:
        await _stop(process, log)


@pytest.mark.asyncio
async def test_allow_and_deny_legacy_join_conflict_is_rejected(tmp_path):
    port = _reserve_port()
    log = (tmp_path / 'conflict.log').open('wb')
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server', '--host', '127.0.0.1', '--port', str(port),
        '--stun-port', '0', '--data', str(tmp_path / 'conflict'), '--allow-legacy-join', '--deny-legacy-join',
        stdout=log, stderr=log)
    try:
        assert await asyncio.wait_for(process.wait(), 20) != 0
        log.flush()
        assert 'not both' in (tmp_path / 'conflict.log').read_text()
    finally:
        await _stop(process, log)


# ---------------------------------------------------------------------------
# 旧协议(v1)与显式迁移策略：默认不静默降级
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_legacy_join_from_loopback_is_accepted_but_logged(tmp_path, caplog):
    """默认策略：本机来源兼容旧协议（否则 CI/本地开发全断），但必须留下醒目记录。"""
    app, runner, base, ws_url = await start(tmp_path)
    try:
        with caplog.at_level('WARNING', logger='p2pchat'):
            async with ClientSession() as session:
                ws = await session.ws_connect(ws_url, origin=ORIGIN)
                await ws.send_json(join_message(room='legacy-local'))
                welcome = await ws.receive_json()
                assert welcome['type'] == 'welcome'
                await receive_type(ws, 'roster')
                # 房间还有人在，密钥是旧协议建立的
                assert app['hub'].room_keys['legacy-local']['version'] == 1
                await ws.close()
        assert any('legacy v1 join accepted' in record.message for record in caplog.records)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_legacy_join_rejection_path_with_human_readable_error(tmp_path):
    """显式关掉兼容：旧协议被明确拒绝，带 hint 与人话说明，绝不静默降级。"""
    app, runner, base, ws_url = await start(tmp_path, allowLegacyJoin=False)
    try:
        async with ClientSession() as session:
            ws = await session.ws_connect(ws_url, origin=ORIGIN)
            await ws.send_json(join_message(room='legacy-refused'))
            error = await ws.receive_json()
            assert error['type'] == 'error'
            assert error['code'] == 'UNSUPPORTED_VERSION'
            assert error['hint'] == 'JOIN_PROOF_V2_REQUIRED'
            assert '房间密钥' in error['detail'] and 'v2' in error['detail']
            await ws.close()

            # HTTP 通道同样：拒绝且有 hint
            status, body = await http_join(session, base, 'legacy-refused', name='x')
            assert status == 200 and body['type'] == 'welcome'     # v2 客户端照常可用
            async with session.post(f'{base}/signal/join', headers=headers(),
                                    json=join_message(room='legacy-refused-2')) as response:
                payload = await response.json()
                assert response.status == 400
                assert payload['code'] == 'UNSUPPORTED_VERSION'
                assert payload['hint'] == 'JOIN_PROOF_V2_REQUIRED'
        # 被拒的旧协议加入没有留下任何房间；'legacy-refused' 只有 v2 客户端建立的那一份
        assert app['hub'].room_keys['legacy-refused']['version'] == JOIN_VERSION
        assert 'legacy-refused-2' not in app['hub'].room_keys
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_legacy_join_explicit_opt_in(tmp_path):
    app, runner, base, ws_url = await start(tmp_path, allowLegacyJoin=True)
    try:
        async with ClientSession() as session:
            status, body = await http_join(session, base, 'legacy-allowed', name='legacy')
            assert status == 200 and body['type'] == 'welcome'      # v2 仍然优先可用
        assert app['hub'].room_keys['legacy-allowed']['version'] == 2
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_room_cannot_mix_legacy_and_v2(tmp_path):
    """同一房间不能在两种协议之间混用（校验值的含义不同），必须明确失败。"""
    app, runner, base, ws_url = await start(tmp_path, allowLegacyJoin=True)
    try:
        async with ClientSession() as session:
            ws = await session.ws_connect(ws_url, origin=ORIGIN)
            await ws.send_json(join_message(room='mixed-protocol'))
            assert (await ws.receive_json())['type'] == 'welcome'
            await receive_type(ws, 'roster')
            # 旧协议客户端还在房间里（房间密钥仍然是 v1 派生的）
            assert app['hub'].room_keys['mixed-protocol']['version'] == 1
            status, body = await http_join(session, base, 'mixed-protocol', name='v2')
            assert status == 403 and body['code'] == 'AUTH_FAILED'
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_v2_join_with_a_smuggled_secret_field_is_schema_invalid(tmp_path):
    """没有任何“v2 里塞回 secret”的旁路：未知字段一律拒绝。"""
    app, runner, base, ws_url = await start(tmp_path)
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'smuggle', session_id)
            key = derive_join_key(SECRET, 'smuggle')
            status, body = await http_join(session, base, 'smuggle', client_session=session_id,
                                           nonce=challenge['nonce'],
                                           proof=join_proof(key, 'smuggle', challenge['nonce'], session_id),
                                           extra={'secret': SECRET})
            assert status == 400 and body['code'] == 'SCHEMA_INVALID'
            assert not app['hub'].peers and not app['hub'].room_keys
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_bad_proof_never_falls_back_to_legacy(tmp_path):
    app, runner, base, ws_url = await start(tmp_path)
    app['hub'].room_keys['fallback-room'] = {'version': 2, 'digest': bytes.fromhex(derive_join_key(SECRET, 'fallback-room'))}
    try:
        async with ClientSession() as session:
            session_id = str(uuid.uuid4())
            status, challenge = await http_challenge(session, base, 'fallback-room', session_id)
            status, body = await http_join(session, base, 'fallback-room', client_session=session_id,
                                           nonce=challenge['nonce'], proof='00' * 32)
            assert status == 403 and body['code'] == 'AUTH_FAILED'
            assert not app['hub'].peers
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# --allow-plaintext：默认关闭，显式开启并打印醒目警告
# ---------------------------------------------------------------------------

def test_public_bind_policy_pure_function():
    assert public_bind_error(['127.0.0.1'], None, [], False) is None          # 默认 loopback 不变
    assert public_bind_error(['::1'], None, ['https://p2p.example'], False) is None
    assert public_bind_error(['0.0.0.0'], None, [], False)                    # 缺 origin
    assert 'origin' in public_bind_error(['0.0.0.0'], None, [], False)
    assert 'TLS' in public_bind_error(['0.0.0.0'], None, [ORIGIN], False)     # 非回环+无证书+无开关
    assert public_bind_error(['0.0.0.0'], None, [ORIGIN], True) is None       # 显式开关才放开明文
    assert public_bind_error(['0.0.0.0'], None, [], True)                     # 开关不能替代 origin
    assert public_bind_error(['0.0.0.0', '::'], 'cert', [ORIGIN], False) is None
    assert public_bind_error(['127.0.0.1', '::'], None, [ORIGIN], False) is not None  # 混合仍按公网


def _reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


async def _stop(process, log):
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            process.kill()
            await process.wait()
    log.close()


@pytest.mark.asyncio
async def test_plaintext_flag_default_off_and_on(tmp_path):
    port = _reserve_port()
    refused_log = (tmp_path / 'refused.log').open('wb')
    refused = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server', '--host', '0.0.0.0', '--port', str(port),
        '--stun-port', '0', '--data', str(tmp_path / 'refused'), '--origin', ORIGIN,
        stdout=refused_log, stderr=refused_log)
    try:
        assert await asyncio.wait_for(refused.wait(), 20) != 0
        refused_log.flush()
        assert 'public signaling requires TLS' in (tmp_path / 'refused.log').read_text()
    finally:
        await _stop(refused, refused_log)

    port = _reserve_port()
    allowed_log = (tmp_path / 'allowed.log').open('wb')
    allowed = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server', '--host', '0.0.0.0', '--port', str(port),
        '--stun-port', '0', '--data', str(tmp_path / 'allowed'), '--origin', ORIGIN,
        '--allow-plaintext', stdout=allowed_log, stderr=allowed_log)
    try:
        async with asyncio.timeout(15):
            while True:
                if allowed.returncode is not None:
                    raise AssertionError('server exited early')
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        allowed_log.flush()
        text = (tmp_path / 'allowed.log').read_text()
        assert '信令未加密，链路可被观察/干扰；房间密钥不再在链路上传输' in text
        async with ClientSession() as session:
            status, welcome = await http_join(session, f'http://127.0.0.1:{port}', 'plain-flag', name='plain')
            assert status == 200 and welcome['type'] == 'welcome'
        assert derive_join_key(SECRET, 'plain-flag').encode() not in data_dir_text(tmp_path / 'allowed')
    finally:
        await _stop(allowed, allowed_log)


@pytest.mark.asyncio
async def test_deny_legacy_flag_refuses_even_loopback(tmp_path):
    """--deny-legacy-join：连本机来源的旧协议也拒绝（同机反代场景用得上）。"""
    port = _reserve_port()
    log = (tmp_path / 'deny.log').open('wb')
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server', '--host', '127.0.0.1', '--port', str(port),
        '--stun-port', '0', '--data', str(tmp_path / 'deny'), '--origin', ORIGIN,
        '--deny-legacy-join', stdout=log, stderr=log)
    try:
        async with asyncio.timeout(15):
            while True:
                if process.returncode is not None:
                    raise AssertionError('server exited early')
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        async with ClientSession() as session:
            ws = await session.ws_connect(f'ws://127.0.0.1:{port}/ws', origin=ORIGIN)
            await ws.send_json(join_message(room='deny-room'))
            error = await ws.receive_json()
            assert error['code'] == 'UNSUPPORTED_VERSION' and error['hint'] == 'JOIN_PROOF_V2_REQUIRED'
            await ws.close()
            # v2 客户端照样可用
            status, welcome = await http_join(session, f'http://127.0.0.1:{port}', 'deny-room', name='v2')
            assert status == 200 and welcome['type'] == 'welcome'
        log.flush()
        assert '--deny-legacy-join is ON' in (tmp_path / 'deny.log').read_text()
    finally:
        await _stop(process, log)
