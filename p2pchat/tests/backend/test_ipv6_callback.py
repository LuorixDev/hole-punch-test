"""受控 IPv6 入站回连验证：真实 socket、真实 ::1 HTTP 服务、真实信令链路。

只用真东西验证：真 aiohttp 服务端（make_app + 真实 WS 信令）、真 ::1 上监听的本地 HTTP
服务（把 query 里的 token 原样写回响应体，这是客户端本地服务的约定）、真 TCP 接受但不
响应的服务（模拟"被防火墙接受后丢包"）、真关闭端口（没人监听）。没有用 mock 冒充任何
一条判决路径。

判决六选一，互不重叠：REACHABLE / TIMEOUT / CONNECTION_REFUSED / UNREACHABLE_NO_ROUTE /
TOKEN_MISMATCH / REJECTED_BY_POLICY。任何非 REACHABLE 都不算成功（ok 只在 REACHABLE 为真）。
"""
import asyncio
import json
import secrets
import socket
import uuid
from pathlib import Path

import pytest
from aiohttp import ClientSession, web

from p2pchat.server import (INBOUND_CHECK, INBOUND_CHECK_CHALLENGE, INBOUND_CHECK_LOG,
                            INBOUND_CHECK_PATH, INBOUND_CHECK_RESULT, INBOUND_CHECK_VERDICTS,
                            inbound_result_payload, make_app)

# 客户端解析器（native/ipv6_reach.py）允许的结果字段：服务器回报必须落在这个集合里（只多
# code/ok 两个），否则对端会判 INVALID_REACH_VERDICT 而不是"看不懂原因"。
CLIENT_RESULT_FIELDS = ('v', 'type', 'connectionId', 'attemptId', 'verdict', 'token', 'port',
                        'addressType', 'elapsedMs', 'failureCode', 'note')

ROOM = 'ipv6-callback'
SECRET = 'callback-room-secret'
MARKER = 'CALLBACK-BODY-MARKER'          # 目标响应体里的标记：用来证明服务器不转发内容
REACHABLE_CONFIG = dict(inboundCheckEnabled=True, inboundCheckAllowPrefixes=['::1/128'],
                        inboundCheckTimeout=2.0)


# ---------------------------------------------------------------------------
# 真实环境助手
# ---------------------------------------------------------------------------

async def start_hub(tmp_path, **kwargs):
    app = make_app(tmp_path, **kwargs)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    return app, runner, f"ws://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/ws"


async def connect(session, url):
    ws = await session.ws_connect(url)
    await ws.send_json({'v': 1, 'type': 'join', 'room': ROOM, 'secret': SECRET, 'name': 'n',
                        'clientSessionId': str(uuid.uuid4()), 'capabilities': ['webrtc']})
    welcome = await ws.receive_json()
    assert welcome['type'] == 'welcome'
    await ws.receive_json()                                  # roster
    return ws, welcome['id']


async def receive_kind(ws, kind, timeout=10.0):
    async with asyncio.timeout(timeout):
        while True:
            message = await ws.receive_json()
            if message['type'] == kind:
                return message


def request(address, port, *, token=None, request=True, connection_id=None, attempt_id=None):
    body = {'v': 1, 'type': INBOUND_CHECK, 'address': address, 'port': port}
    if request is not None:
        body['request'] = request
    if token is not None:
        body['token'] = token
    if connection_id is not None:
        body['connectionId'] = connection_id
    if attempt_id is not None:
        body['attemptId'] = attempt_id
    return body


async def challenge(ws, address, port, **extra):
    await ws.send_json(request(address, port, **extra))
    reply = await receive_kind(ws, INBOUND_CHECK_CHALLENGE)
    assert reply['address'] == address and reply['port'] == port
    return reply['token']


async def check(ws, address, port, token, **extra):
    await ws.send_json(request(address, port, token=token, **extra))
    return await receive_kind(ws, INBOUND_CHECK_RESULT)


def free_v6_port():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.bind(('::1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class EchoTarget:
    """真 ::1 HTTP 服务：响应体带回 token（可加标记），并记录收到的请求。"""

    def __init__(self, marker=''):
        self.marker = marker
        self.requests = []

    async def __aenter__(self):
        app = web.Application()
        app.router.add_get(INBOUND_CHECK_PATH, self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '::1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        return self

    async def handle(self, request):
        self.requests.append({'path': request.path, 'query': dict(request.query),
                              'headers': dict(request.headers)})
        return web.Response(text=f"{self.marker}{request.query.get('token', '')}")

    async def __aexit__(self, *exc):
        await self.runner.cleanup()


class HangingTarget:
    """真 ::1 TCP 服务：接受连接但永不响应（防火墙接受后丢包的等价物）。"""

    def __init__(self):
        self.connections = 0
        self.writers = []

    async def __aenter__(self):
        async def handler(reader, writer):
            self.connections += 1
            self.writers.append(writer)          # 保持打开、不写任何字节
        self.server = await asyncio.start_server(handler, '::1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        for writer in self.writers:
            writer.close()
        self.server.close()
        await self.server.wait_closed()


def log_rows(tmp_path):
    path = Path(tmp_path) / 'server.jsonl'
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []


# ---------------------------------------------------------------------------
# 三条真判决路径
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reachable_over_real_ipv6_socket(tmp_path):
    app, runner, url = await start_hub(tmp_path, **REACHABLE_CONFIG)
    try:
        async with ClientSession() as session, EchoTarget(MARKER) as target:
            ws, pid = await connect(session, url)
            token = await challenge(ws, '::1', target.port)
            connection_id, attempt_id = str(uuid.uuid4()), str(uuid.uuid4())
            result = await check(ws, '::1', target.port, token,
                                 connection_id=connection_id, attempt_id=attempt_id)
            assert result['code'] == 'REACHABLE' and result['ok'] is True
            assert result['type'] == INBOUND_CHECK_RESULT and result['verdict'] == 'REACHED_BY_SERVER'
            assert result['elapsedMs'] >= 0 and result['port'] == target.port
            # 回连目标地址不回带（客户端自己的 fullAddressShared 决定它本地记不记全地址）
            assert 'address' not in result and result['connectionId'] and result['attemptId']
            # 单次尝试、只连声明的地址/端口、请求里没有任何凭据或房间密钥
            assert len(target.requests) == 1
            probe = target.requests[0]
            assert probe['path'] == INBOUND_CHECK_PATH and probe['query'] == {'token': token}
            joined = ' '.join(f'{k}:{v}' for k, v in probe['headers'].items()).lower()
            assert 'cookie' not in joined and 'authorization' not in joined and SECRET.lower() not in joined
            # 不是中继：目标的响应体（含标记）既不在回报里，也不在中心日志里
            assert MARKER not in json.dumps(result)
            rows = log_rows(tmp_path)
            assert rows and MARKER not in json.dumps(rows) and token not in json.dumps(rows) and SECRET not in json.dumps(rows)
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_timeout_and_connection_refused_are_distinct(tmp_path):
    config = dict(REACHABLE_CONFIG, inboundCheckTimeout=0.5, maxInboundChecksPerSession=4)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, HangingTarget() as hanging:
            ws, _ = await connect(session, url)
            timed_out = await check(ws, '::1', hanging.port,
                                    await challenge(ws, '::1', hanging.port))
            assert timed_out['code'] == 'TIMEOUT' and timed_out['ok'] is False
            assert hanging.connections == 1                    # 接受过连接，只是没有可用响应
            dead = free_v6_port()
            refused = await check(ws, '::1', dead, await challenge(ws, '::1', dead))
            assert refused['code'] == 'CONNECTION_REFUSED' and refused['ok'] is False
            assert refused['code'] != timed_out['code']        # 两条路径没有糊在一起
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_no_route_is_not_reported_as_timeout(tmp_path):
    config = dict(inboundCheckEnabled=True, inboundCheckAllowPrefixes=['2001:db8::/32'],
                  inboundCheckTimeout=2.0)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session:
            ws, _ = await connect(session, url)
            result = await check(ws, '2001:db8::1', 8080, await challenge(ws, '2001:db8::1', 8080))
            assert result['code'] == 'UNREACHABLE_NO_ROUTE' and result['ok'] is False
            assert result['code'] != 'TIMEOUT'                 # 无路由不等于超时
            assert result['note']                           # 人话说明（含底层原因，例如 ERRNO_101）留着排查
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_token_mismatch_when_target_does_not_echo(tmp_path):
    """有人应答但没带回本次 token ⇒ TOKEN_MISMATCH，绝不是成功。"""
    config = dict(REACHABLE_CONFIG)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session:
            async def never_echoes(request):
                return web.Response(text='nope')
            app2 = web.Application()
            app2.router.add_get(INBOUND_CHECK_PATH, never_echoes)
            echo_runner = web.AppRunner(app2)
            await echo_runner.setup()
            site = web.TCPSite(echo_runner, '::1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            try:
                ws, _ = await connect(session, url)
                result = await check(ws, '::1', port, await challenge(ws, '::1', port))
                assert result['code'] == 'TOKEN_MISMATCH' and result['ok'] is False
                await ws.close()
            finally:
                await echo_runner.cleanup()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# SSRF 负例：默认策略下这些目标必须被拒，且不产生任何出站连接
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize('address,reason', [
    ('::1', 'ADDRESS_NOT_ALLOWED'),           # 环回
    ('fe80::1', 'ADDRESS_NOT_ALLOWED'),       # 链路本地
    ('ff02::1', 'ADDRESS_NOT_ALLOWED'),       # 组播
    ('::', 'ADDRESS_NOT_ALLOWED'),            # 未指定
    ('fd00::1', 'ADDRESS_NOT_ALLOWED'),       # ULA（IPv6 私网）
    ('::ffff:127.0.0.1', 'ADDRESS_NOT_ALLOWED'),   # IPv4-mapped
    ('127.0.0.1', 'ADDRESS_NOT_ALLOWED'),     # IPv4 环回
    ('192.168.1.1', 'ADDRESS_NOT_ALLOWED'),   # 私网 IPv4
    ('example.com', 'ADDRESS_NOT_ALLOWED'),   # 主机名（不做 DNS）
    ('fe80::1%eth0', 'ADDRESS_NOT_ALLOWED'),  # 带 scope
])
async def test_ssrf_targets_rejected_by_default_policy(tmp_path, address, reason):
    app, runner, url = await start_hub(tmp_path, inboundCheckEnabled=True)   # 功能开着，但没放行任何前缀
    try:
        async with ClientSession() as session:
            ws, _ = await connect(session, url)
            await ws.send_json(request(address, 8080))
            result = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert result['code'] == 'REJECTED_BY_POLICY' and result['ok'] is False
            assert result['failureCode'] == reason
            assert app['hub'].inbound_tokens == {}               # 连 token 都不发，不登记目标
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_low_port_and_optin_are_policy_rejections(tmp_path):
    app, runner, url = await start_hub(tmp_path, inboundCheckEnabled=True,
                                       inboundCheckAllowPrefixes=['::1/128'])
    try:
        async with ClientSession() as session:
            ws, _ = await connect(session, url)
            await ws.send_json(request('::1', 80))               # 低于 1024：默认拒绝
            low = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert low['code'] == 'REJECTED_BY_POLICY' and low['failureCode'] == 'PORT_NOT_ALLOWED'
            await ws.send_json(request('::1', 8080, request=False))   # 客户端没有显式请求
            no_optin = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert no_optin['code'] == 'REJECTED_BY_POLICY' and no_optin['failureCode'] == 'NOT_OPT_IN'
            await ws.send_json(request('::1', 8080, request=None))    # 连 request 字段都没有
            missing = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert missing['code'] == 'REJECTED_BY_POLICY' and missing['failureCode'] == 'NOT_OPT_IN'
            assert app['hub'].inbound_tokens == {}
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_feature_is_off_unless_operator_enables_it(tmp_path):
    app, runner, url = await start_hub(tmp_path)                 # 默认：完全关闭
    try:
        async with ClientSession() as session:
            ws, _ = await connect(session, url)
            await ws.send_json(request('::1', 8080))
            result = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert result['code'] == 'REJECTED_BY_POLICY' and result['failureCode'] == 'FEATURE_DISABLED'
            assert app['hub'].inbound_inflight == 0 and app['hub'].inbound_checks == {}
            await ws.close()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 一次性 token：复用 / 过期 / 换目标
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_token_is_one_time(tmp_path):
    config = dict(REACHABLE_CONFIG, maxInboundChecksPerSession=2)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, EchoTarget() as target:
            ws, _ = await connect(session, url)
            token = await challenge(ws, '::1', target.port)
            assert (await check(ws, '::1', target.port, token))['code'] == 'REACHABLE'
            replay = await check(ws, '::1', target.port, token)          # 同一个 token 再来一次
            assert replay['code'] == 'REJECTED_BY_POLICY' and replay['failureCode'] == 'TOKEN_REUSED'
            assert len(target.requests) == 1                            # 重放没有产生第二次回连
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_token_expires_and_target_must_match_declaration(tmp_path):
    config = dict(REACHABLE_CONFIG, inboundCheckTokenTtl=1.0, maxInboundChecksPerSession=3)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, EchoTarget() as target:
            ws, _ = await connect(session, url)
            stale = await challenge(ws, '::1', target.port)
            await asyncio.sleep(1.2)                                     # 超过 1 秒时效
            expired = await check(ws, '::1', target.port, stale)
            assert expired['code'] == 'REJECTED_BY_POLICY' and expired['failureCode'] == 'TOKEN_EXPIRED'
            # token 与声明目标绑定：换个端口（哪怕也合法）就是 TARGET_NOT_DECLARED
            fresh = await challenge(ws, '::1', target.port)
            swapped = await check(ws, '::1', free_v6_port(), fresh)
            assert swapped['code'] == 'REJECTED_BY_POLICY' and swapped['failureCode'] == 'TARGET_NOT_DECLARED'
            assert target.requests == []                                 # 两次都没发出站连接
            await ws.close()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 限次与并发边界
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_per_session_check_limit(tmp_path):
    config = dict(REACHABLE_CONFIG, maxInboundChecksPerSession=1)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, EchoTarget() as target:
            ws, _ = await connect(session, url)
            assert (await check(ws, '::1', target.port,
                                await challenge(ws, '::1', target.port)))['code'] == 'REACHABLE'
            second = await check(ws, '::1', target.port, await challenge(ws, '::1', target.port))
            assert second['code'] == 'REJECTED_BY_POLICY' and second['failureCode'] == 'SESSION_LIMIT'
            assert len(target.requests) == 1
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_concurrency_and_challenge_limits(tmp_path):
    config = dict(REACHABLE_CONFIG, inboundCheckTimeout=1.0, maxInboundChecksPerSession=2,
                  maxInboundCheckInflight=1, maxInboundCheckChallengesPerSession=2)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, HangingTarget() as hanging:
            first, _ = await connect(session, url)
            second, _ = await connect(session, url)                  # 同一房间的第二个会话
            token_a = await challenge(first, '::1', hanging.port)
            await first.send_json(request('::1', hanging.port, token=token_a))
            await asyncio.sleep(0.05)                                # 让第一个检查占到名额
            token_b = await challenge(second, '::1', hanging.port)
            busy = await check(second, '::1', hanging.port, token_b)
            assert busy['code'] == 'REJECTED_BY_POLICY' and busy['failureCode'] == 'CONCURRENCY_LIMIT'
            assert (await receive_kind(first, INBOUND_CHECK_RESULT))['code'] == 'TIMEOUT'
            # 每会话挑战次数上限：第三个挑战被拒（错误码是既有的 LIMIT_EXCEEDED）
            third, _ = await connect(session, url)
            await challenge(third, '::1', hanging.port)
            await challenge(third, '::1', hanging.port)
            await third.send_json(request('::1', hanging.port))
            limited = await receive_kind(third, INBOUND_CHECK_RESULT)
            assert limited['code'] == 'REJECTED_BY_POLICY' and limited['failureCode'] == 'LIMIT_EXCEEDED'
            await first.close(); await second.close(); await third.close()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 中心日志：投影互不重叠、可关联、脱敏
# ---------------------------------------------------------------------------

def test_log_projection_is_injective_and_never_claims_success():
    pairs = {verdict: INBOUND_CHECK_LOG[verdict] for verdict in INBOUND_CHECK_VERDICTS}
    assert len(set(pairs.values())) == len(pairs)                   # 六种判决各占不同的 (state, reason)
    assert [v for v, (state, _) in pairs.items() if state == 'completed'] == ['REACHABLE']
    assert all(INBOUND_CHECK_LOG[v][1] is not None for v in INBOUND_CHECK_VERDICTS if v != 'REACHABLE')


@pytest.mark.asyncio
async def test_central_log_is_correlated_and_redacted(tmp_path):
    config = dict(REACHABLE_CONFIG, inboundCheckTimeout=0.5, maxInboundChecksPerSession=2)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, EchoTarget(MARKER) as target, HangingTarget() as hanging:
            ws, pid = await connect(session, url)
            connection_id, attempt_id = str(uuid.uuid4()), str(uuid.uuid4())
            token = await challenge(ws, '::1', target.port)
            await check(ws, '::1', target.port, token, connection_id=connection_id, attempt_id=attempt_id)
            await check(ws, '::1', hanging.port, await challenge(ws, '::1', hanging.port))
            rows = [row for row in log_rows(tmp_path) if row['event'] == 'path.state']
            reachable = [row for row in rows if row['data'].get('state') == 'completed']
            timed_out = [row for row in rows if row['data'].get('state') == 'timeout']
            assert len(reachable) == 1 and len(timed_out) == 1
            assert reachable[0]['data']['ok'] is True and reachable[0]['data']['family'] == 6
            assert reachable[0]['data']['mechanism'] == 'tcp' and reachable[0]['data']['rttMs'] >= 0
            assert reachable[0]['data'].get('reason') is None
            assert reachable[0]['connectionId'] == connection_id and reachable[0]['attemptId'] == attempt_id
            assert reachable[0]['peerId'] == pid                    # 可按 peer/会话关联
            assert timed_out[0]['data']['ok'] is False and timed_out[0]['data']['reason'] == 'TIMEOUT'
            # 脱敏：日志里没有 token 原文、没有房间密钥、没有目标响应体内容
            text = json.dumps(log_rows(tmp_path))
            assert token not in text and SECRET not in text and MARKER not in text
            await ws.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_per_source_limit_across_sessions(tmp_path):
    """限次还要按来源算：一个来源（例如同一个 NAT 后面的多台机器）不能无限刷检查。"""
    config = dict(REACHABLE_CONFIG, maxInboundChecksPerSession=2, maxInboundChecksPerSource=1)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session, EchoTarget() as target:
            first, _ = await connect(session, url)
            second, _ = await connect(session, url)
            assert (await check(first, '::1', target.port,
                                await challenge(first, '::1', target.port)))['code'] == 'REACHABLE'
            other = await check(second, '::1', target.port, await challenge(second, '::1', target.port))
            assert other['code'] == 'REJECTED_BY_POLICY' and other['failureCode'] == 'SOURCE_LIMIT'
            assert len(target.requests) == 1                       # 第二次没有发出站连接
            await first.close(); await second.close()
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_session_state_is_released_on_close(tmp_path):
    """会话断开后：未用 token、挑战/检查计数、在飞归属都清掉（长期进程不涨内存）。"""
    config = dict(REACHABLE_CONFIG, maxInboundChecksPerSession=1)
    app, runner, url = await start_hub(tmp_path, **config)
    hub = app['hub']
    try:
        async with ClientSession() as session, EchoTarget() as target:
            ws, pid = await connect(session, url)
            token = await challenge(ws, '::1', target.port)
            assert hub.inbound_challenges.get(pid) == 1 and token in hub.inbound_tokens
            await ws.close()
            async with asyncio.timeout(5):
                while pid in hub.inbound_challenges or token in hub.inbound_tokens:
                    await asyncio.sleep(0.02)
            assert hub.inbound_checks.get(pid) is None and hub.inbound_inflight == 0
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 硬边界与"不是中继"
# ---------------------------------------------------------------------------

def test_timeout_is_hard_capped_at_five_seconds(tmp_path):
    """超时上限在任何调用方都兜住：配置成 99 秒也只能是 5 秒。"""
    app = make_app(tmp_path, inboundCheckEnabled=True, inboundCheckTimeout=99.0)
    assert app['hub'].config['inboundCheckTimeout'] == 5.0          # 上限
    assert make_app(tmp_path, inboundCheckTimeout=-1.0)['hub'].config['inboundCheckTimeout'] == 0.2   # 下限
    assert make_app(tmp_path)['hub'].config.get('inboundCheckTimeout') is None   # 默认走 4.0（代码内默认）


def test_no_new_route_and_no_relay_endpoint(tmp_path):
    """这个能力只挂在既有信令路径上：没有新增 HTTP 入口，更没有 relay/tunnel/forward 路由。"""
    app = make_app(tmp_path, **REACHABLE_CONFIG)
    names = {getattr(resource, 'canonical', '') for resource in app.router.resources()}
    assert '/ws' in names and '/signal' in names and '/signal/events' in names
    lowered = ' '.join(names).lower()
    for forbidden in ('relay', 'turn', 'tunnel', 'forward', 'proxy', 'callback'):
        assert forbidden not in lowered


@pytest.mark.asyncio
async def test_redirects_are_not_followed(tmp_path):
    """3xx 不跟随：否则目标就能把服务器当成可控 SSRF 跳板去连别的地方。"""
    config = dict(REACHABLE_CONFIG)
    app, runner, url = await start_hub(tmp_path, **config)
    try:
        async with ClientSession() as session:
            bait_hits = []

            async def bait(request):
                bait_hits.append(request.path)
                return web.Response(text='bait')

            async def redirect(request):
                raise web.HTTPFound(f"http://127.0.0.1:{bait_port}/steal?token={request.query.get('token', '')}")

            bait_app = web.Application()
            bait_app.router.add_get('/steal', bait)
            bait_runner = web.AppRunner(bait_app)
            await bait_runner.setup()
            bait_site = web.TCPSite(bait_runner, '127.0.0.1', 0)
            await bait_site.start()
            bait_port = bait_site._server.sockets[0].getsockname()[1]
            redirect_app = web.Application()
            redirect_app.router.add_get(INBOUND_CHECK_PATH, redirect)
            redirect_runner = web.AppRunner(redirect_app)
            await redirect_runner.setup()
            redirect_site = web.TCPSite(redirect_runner, '::1', 0)
            await redirect_site.start()
            port = redirect_site._server.sockets[0].getsockname()[1]
            try:
                ws, _ = await connect(session, url)
                result = await check(ws, '::1', port, await challenge(ws, '::1', port))
                assert result['code'] == 'TOKEN_MISMATCH' and 'HTTP_302' in result['note']
                assert bait_hits == []                       # 跳转目标一次都没被连
                await ws.close()
            finally:
                await redirect_runner.cleanup()
                await bait_runner.cleanup()
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 与客户端（native/ipv6_reach.py）逐字对齐的线上契约
# ---------------------------------------------------------------------------

class ClientStyleTarget:
    """按客户端监听点的契约行事：GET /p2p-reach?token=… ⇒ 校验+一次性 ⇒ 204 空体，否则 403。"""

    def __init__(self):
        self.requests = []
        self.consumed = False

    async def __aenter__(self):
        app = web.Application()
        app.router.add_get(INBOUND_CHECK_PATH, self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '::1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        return self

    async def handle(self, request):
        token = request.query.get('token', '')
        accepted = bool(token) and token == self.token and not self.consumed
        self.requests.append({'path': request.path, 'token': token, 'accepted': accepted})
        if accepted:
            self.consumed = True
            return web.Response(status=204)
        return web.Response(status=403)

    async def __aexit__(self, *exc):
        await self.runner.cleanup()


def client_offer(port, token, *, connection_id=None, attempt_id=None, expires_in_ms=4000):
    """客户端 build_offer() 的输出形状（OFFER_FIELDS），注意它不带 request 字段。"""
    return {'v': 1, 'type': INBOUND_CHECK, 'connectionId': connection_id or str(uuid.uuid4()),
            'attemptId': attempt_id or str(uuid.uuid4()), 'session': str(uuid.uuid4()),
            'address': '::1', 'addressType': 'stable', 'scope': 0, 'prefixLength': 128,
            'port': port, 'token': token, 'mechanism': 'ipv6-inbound',
            'expiresInMs': expires_in_ms, 'fullAddressShared': False}


@pytest.mark.asyncio
async def test_client_offer_shape_is_accepted_verbatim(tmp_path):
    """客户端原样发它的 offer（自带 token、不带 request）⇒ REACHABLE，且 token 一次性。"""
    app, runner, url = await start_hub(tmp_path, **REACHABLE_CONFIG)
    try:
        async with ClientSession() as session, ClientStyleTarget() as target:
            target.token = secrets.token_hex(24)
            ws, _ = await connect(session, url)
            offer = client_offer(target.port, target.token)
            await ws.send_json(offer)
            result = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert result['code'] == 'REACHABLE' and result['ok'] is True
            assert result['verdict'] == 'REACHED_BY_SERVER' and result.get('failureCode') is None
            assert result['connectionId'] == offer['connectionId'] and result['attemptId'] == offer['attemptId']
            assert result['port'] == target.port and result['addressType'] == 'stable'
            assert target.requests == [{'path': '/p2p-reach', 'token': target.token, 'accepted': True}]
            # 同一个 offer 重放一次：服务端侧一次性记忆 ⇒ TOKEN_REUSED，且不再回连
            await ws.send_json(offer)
            replay = await receive_kind(ws, INBOUND_CHECK_RESULT)
            assert replay['code'] == 'REJECTED_BY_POLICY' and replay['failureCode'] == 'TOKEN_REUSED'
            assert len(target.requests) == 1
            await ws.close()
    finally:
        await runner.cleanup()


def test_result_payload_keys_match_the_client_parser():
    """回报字段必须能过客户端的解析器；三种没有诚实对应项的判决绝不硬套 verdict。"""
    for verdict in INBOUND_CHECK_VERDICTS:
        payload = inbound_result_payload(verdict, 4567,
                                         reason='DETAIL_REASON' if verdict != 'REACHABLE' else None,
                                         detail=None,
                                         rtt_ms=1.5 if verdict == 'REACHABLE' else None,
                                         connection_id='c', attempt_id='a')
        assert payload['type'] == INBOUND_CHECK_RESULT and payload['v'] == 1
        assert payload['code'] == verdict and payload['ok'] is (verdict == 'REACHABLE')
        assert set(payload) <= set(CLIENT_RESULT_FIELDS) | {'code', 'ok'}
        if verdict != 'REACHABLE':
            assert payload['failureCode'] == 'DETAIL_REASON' and payload['note']
        if verdict in ('CONNECTION_REFUSED', 'TOKEN_MISMATCH', 'REJECTED_BY_POLICY'):
            assert 'verdict' not in payload          # 客户端词表没有对应项：不硬套
        else:
            assert payload['verdict'] in ('REACHED_BY_SERVER', 'TIMEOUT', 'NO_V6_ROUTE')
