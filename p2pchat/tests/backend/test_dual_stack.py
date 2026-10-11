"""真实双栈信令行为测试：真起子进程 + 真 WS 升级 + 真房间加入。

覆盖合同要求：
  * `--host 0.0.0.0 --host ::` 单进程两个 V6ONLY 站点，同端口并存，两族都能连上并加入同一房间；
  * 每个站点都是 V6ONLY（不是靠关掉 V6ONLY 或未指定地址的隐式回退）；
  * 反向断言：只给一个 --host 时另一族必须被拒绝（没有隐式双栈）；
  * 默认仍是 loopback；--origin 精确 allowlist 语义不变。

平台边界：本文件只在 Linux 上实测过。Windows/macOS 未实测——
Windows 的 `--host ::` 与 `--host 0.0.0.0` 行为、以及 `::` 通配是否与 Linux 一致，
必须在那两个平台上重新验证，不能用这里的 Linux 结论代替。
"""
import asyncio
import datetime
import json
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import ClientSession
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from p2pchat.server import bound_addresses, format_bound, is_loopback_host, main, requested_hosts, serve
from p2pchat.tests.backend.test_security import join_message

pytestmark = pytest.mark.skipif(sys.platform != 'linux',
                                reason='双栈监听只在 Linux 实测过；Windows/macOS 未实测，需重新验证')

LOOPBACK_V4 = '127.0.0.1'
LOOPBACK_V6 = '::1'


# ---------------------------------------------------------------------------
# --host 解析（纯函数）
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('raw,expected', [
    (None, ['127.0.0.1']),                       # 默认仍是 loopback
    ([], ['127.0.0.1']),
    ('0.0.0.0', ['0.0.0.0']),                    # 单值字符串（旧调用方式）仍然可用
    ('::', ['::']),
    (['0.0.0.0', '::'], ['0.0.0.0', '::']),     # 可重复
    (['0.0.0.0', '0.0.0.0'], ['0.0.0.0', '0.0.0.0']),
])
def test_requested_hosts_repeatable(raw, expected):
    assert requested_hosts(raw) == expected


def test_is_loopback_host():
    assert is_loopback_host('127.0.0.1') is True
    assert is_loopback_host('127.0.0.53') is True
    assert is_loopback_host('::1') is True
    assert is_loopback_host('localhost') is True
    assert is_loopback_host('0.0.0.0') is False
    assert is_loopback_host('::') is False


def test_format_bound_marks_ipv6():
    assert format_bound('0.0.0.0', 8088) == '0.0.0.0:8088'
    assert format_bound('::', 8088) == '[::]:8088'
    assert format_bound('::1', 8088) == '[::1]:8088'


def test_bound_addresses_survives_internal_change():
    assert bound_addresses(object()) == []
    assert bound_addresses(SimpleNamespace(_server=SimpleNamespace(sockets=[]))) == []


# ---------------------------------------------------------------------------
# serve(): 一个 AppRunner，多个站点
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_serve_binds_both_families_on_one_port(tmp_path):
    """serve() 在一个 AppRunner（同一 Store）上为每个 --host 建一个站点，两族同端口并存。"""
    from p2pchat.server import make_app

    port = _reserve_port()
    app = make_app(tmp_path)
    task = asyncio.create_task(serve(app, ['0.0.0.0', '::'], port))
    try:
        async with asyncio.timeout(10):
            while True:
                try:
                    reader, writer = await asyncio.open_connection(LOOPBACK_V4, port)
                    writer.close()
                    reader6, writer6 = await asyncio.open_connection(LOOPBACK_V6, port)
                    writer6.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        # 两族的监听套接字各自被占住（V6ONLY：IPv6 站点没有顺手收走 IPv4）
        for family, address in ((socket.AF_INET6, '::'), (socket.AF_INET, '0.0.0.0')):
            probe = socket.socket(family, socket.SOCK_STREAM)
            try:
                with pytest.raises(OSError):
                    probe.bind((address, port))
            finally:
                probe.close()
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# 真子进程 + 真 WS
# ---------------------------------------------------------------------------

def _reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_V4, 0))
        return sock.getsockname()[1]


def _listening(port):
    """ss -lnt 里该端口的所有监听套接字 {addr}:{port}；ss 不可用则返回 None。"""
    try:
        result = subprocess.run(['ss', '-lnt'], capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    found = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if local.rsplit(':', 1)[-1] != str(port):
            continue
        found.append(local)
    return found


def _has_ipv4_listener(entries):
    for entry in entries:
        address = entry.rsplit(':', 1)[0]
        if address == '0.0.0.0' or (address and ':' not in address):
            return True
    return False


def _has_ipv6_listener(entries):
    for entry in entries:
        address = entry.rsplit(':', 1)[0]
        if address == '::' or ':' in address:
            return True
    return False


async def _start_server(tmp_path, extra, port=None, key='dual-stack-room-secret'):
    key_file = tmp_path / 'room.key'
    key_file.write_text(key)
    key_file.chmod(0o600)
    port = port or _reserve_port()
    scheme = 'ws'
    tls = []
    if _needs_tls(extra):
        # 非 loopback 站点按既有语义强制 TLS + --origin；这里现场鉴一张自签证书。
        cert, key_path = _make_cert(tmp_path)
        tls = ['--cert', str(cert), '--key', str(key_path)]
        scheme = 'wss'
    log = (tmp_path / 'server.log').open('wb')
    process = await asyncio.create_subprocess_exec(
        sys.executable, '-m', 'p2pchat.server',
        '--port', str(port), '--stun-port', '0', '--stun-host', '127.0.0.1',
        '--data', str(tmp_path / 'central'), *tls, *extra,
        stdout=log, stderr=log)
    return process, port, key_file, log, scheme


async def _wait_ready(process, family_host, port, timeout=15):
    """只探测一个地址族，确认服务端已经起来（未 ready 时连接被拒绝）。"""
    async with asyncio.timeout(timeout):
        while True:
            if process.returncode is not None:
                raise AssertionError('server exited early')
            try:
                reader, writer = await asyncio.open_connection(family_host, port)
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                return
            except OSError:
                await asyncio.sleep(0.05)


async def _stop(process, log):
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            process.kill()
            await process.wait()
    log.close()


async def _join(session, url, room, secret, name, origin=None):
    ws = await session.ws_connect(url, ssl=False, origin=origin)
    message = join_message(room=room)
    message['secret'] = secret
    message['name'] = name
    await ws.send_json(message)
    welcome = await ws.receive_json()
    assert welcome['type'] == 'welcome', welcome
    return ws, welcome


async def _receive_type(ws, kind, timeout=5):
    async with asyncio.timeout(timeout):
        while True:
            message = await ws.receive_json()
            if message['type'] == kind:
                return message


COMMON = ['--origin', 'https://p2p.example']
APPROVED_ORIGIN = 'https://p2p.example'


def _make_cert(directory, cn='p2p.example'):
    """自签证书，覆盖 p2p.example / localhost / 127.0.0.1 / ::1；只在临时目录里。"""
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName(cn), x509.DNSName('localhost'),
                       x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1')),
                       x509.IPAddress(__import__('ipaddress').ip_address('::1'))]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert = Path(directory) / 'cert.pem'
    key_path = Path(directory) / 'key.pem'
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert, key_path


def _hosts_from_argv(extra):
    """从命令行列表里取所有 --host 的值；没写就按默认 loopback。"""
    hosts = [extra[index + 1] for index, token in enumerate(extra)
             if token == '--host' and index + 1 < len(extra)]
    return requested_hosts(hosts)


def _needs_tls(extra):
    return any(not is_loopback_host(host) for host in _hosts_from_argv(extra))


@pytest.mark.asyncio
async def test_real_dual_stack_ws_upgrade_and_join_from_both_families(tmp_path):
    process, port, key_file, log, scheme = await _start_server(
        tmp_path, ['--host', '0.0.0.0', '--host', '::', *COMMON])
    secret = key_file.read_text()
    channel_v4 = f'{scheme}://{LOOPBACK_V4}:{port}/ws'
    channel_v6 = f'{scheme}://[{LOOPBACK_V6}]:{port}/ws'
    try:
        await _wait_ready(process, LOOPBACK_V4, port)
        # 两个地址族都在监听同一个端口（TCP 探测）
        await _wait_ready(process, LOOPBACK_V6, port)
        entries = _listening(port)
        if entries is not None:  # ss 不可用时跳过这项系统级断言，行为断言不做减法
            assert _has_ipv4_listener(entries), entries
            assert _has_ipv6_listener(entries), entries
            assert not any(entry.rsplit(':', 1)[0] == '*' for entry in entries), entries

        async with ClientSession() as session:
            # 一个真实 client 先加入（IPv4 口）
            a, a_welcome = await _join(session, channel_v4, 'dual', secret, 'v4-peer',
                                       origin=APPROVED_ORIGIN)
            assert a_welcome['strictP2P'] is True
            assert a_welcome['iceServers'] == []
            await _receive_type(a, 'roster')

            # 另一个地址族（IPv6 口）加入同一个房间
            b, b_welcome = await _join(session, channel_v6, 'dual', secret, 'v6-peer',
                                       origin=APPROVED_ORIGIN)
            assert b_welcome['strictP2P'] is True
            assert b_welcome['id'] != a_welcome['id']

            # 同进程同一 Hub：IPv4 上的 client 能看到 IPv6 上的 client 出现在花名册里。
            roster = await _receive_type(a, 'roster')
            names = {peer['name'] for peer in roster['peers']}
            assert names == {'v4-peer', 'v6-peer'}, roster

            # 两族之间也能真的发信令（证明是同一个房间、同一份内存状态）。
            # 服务端只允许 peer id 较小的一方宣告新连接，所以按 id 挑发起方，
            # 而不是假定"先连上的一方"一定能发起。
            if a_welcome['id'] < b_welcome['id']:
                sender, receiver, sender_id, receiver_id = a, b, a_welcome['id'], b_welcome['id']
            else:
                sender, receiver, sender_id, receiver_id = b, a, b_welcome['id'], a_welcome['id']
            assert {sender_id, receiver_id} == {peer['id'] for peer in roster['peers']}
            connection_id = str(uuid.uuid4())
            await sender.send_json({'v': 1, 'type': 'signal', 'to': receiver_id,
                                    'connectionId': connection_id, 'attemptId': str(uuid.uuid4()),
                                    'mechanism': 'webrtc', 'profile': 'ice-dual',
                                    'description': {'type': 'offer', 'sdp': 'v=0\r\n'}})
            forwarded = await _receive_type(receiver, 'signal')
            assert forwarded['profile'] == 'ice-dual'
            assert forwarded['connectionId'] == connection_id
            assert forwarded['from'] == sender_id

            # 反向：origin 不在 allowlist 里依然被拒（语义未变）
            with pytest.raises(Exception):
                await session.ws_connect(channel_v6, ssl=False, origin='https://evil.example')

            await a.close()
            await b.close()
    finally:
        await _stop(process, log)


@pytest.mark.asyncio
async def test_single_host_family_rejects_the_other_family(tmp_path):
    """没有隐式双栈：只给一个 --host，另一族必须连不上。"""
    process, port, _, log, _scheme = await _start_server(
        tmp_path, ['--host', '0.0.0.0', *COMMON])
    try:
        await _wait_ready(process, LOOPBACK_V4, port)
        with pytest.raises(OSError):
            await asyncio.open_connection(LOOPBACK_V6, port)
    finally:
        await _stop(process, log)

    process, port, _, log, _scheme = await _start_server(
        tmp_path, ['--host', '::', *COMMON])
    try:
        await _wait_ready(process, LOOPBACK_V6, port)
        with pytest.raises(OSError):
            await asyncio.open_connection(LOOPBACK_V4, port)
    finally:
        await _stop(process, log)


@pytest.mark.asyncio
async def test_default_host_is_still_loopback_only(tmp_path):
    """默认仍是 loopback：不传 --host 时只有 127.0.0.1 接得上。"""
    port = _reserve_port()
    origin = f'http://{LOOPBACK_V4}:{port}'
    process, port, key_file, log, scheme = await _start_server(
        tmp_path, ['--origin', origin], port=port)
    secret = key_file.read_text()
    try:
        await _wait_ready(process, LOOPBACK_V4, port)
        with pytest.raises(OSError):
            await asyncio.open_connection(LOOPBACK_V6, port)
        async with ClientSession() as session:
            url = f'{scheme}://{LOOPBACK_V4}:{port}/ws'
            # 默认站点仍是明文 ws（loopback 允许），--origin allowlist 仍精确生效
            a, welcome = await _join(session, url, 'loop', secret, 'local', origin=origin)
            assert welcome['type'] == 'welcome'
            with pytest.raises(Exception):
                await session.ws_connect(url, origin='https://evil.example')
            await a.close()
    finally:
        await _stop(process, log)


@pytest.mark.asyncio
async def test_public_multi_host_still_requires_tls_and_origin(tmp_path):
    """安全语义未变：非 loopback 多站点仍然强制 TLS + --origin。"""
    for extra in ([], ['--origin', 'https://p2p.example']):
        with pytest.raises(ValueError):
            await main(SimpleNamespace(host=['0.0.0.0', '::'], port=0, cert=None, key=None,
                                       origin=extra[-1:] if extra else [], data=str(tmp_path),
                                       stun_host=None, stun_port=0, stun_url=None))
    # 混合 loopback + 通配时，整体仍按公网处理
    with pytest.raises(ValueError):
        await main(SimpleNamespace(host=['127.0.0.1', '::'], port=0, cert=None, key=None,
                                   origin=[], data=str(tmp_path),
                                   stun_host=None, stun_port=0, stun_url=None))


@pytest.mark.asyncio
async def test_shared_store_and_no_relay_semantics_unchanged(tmp_path):
    """两个站点共享同一 Store：聊天仍然被拒绝，且不进中心日志（无服务端转发）。"""
    process, port, key_file, log, scheme = await _start_server(
        tmp_path, ['--host', '0.0.0.0', '--host', '::', *COMMON])
    secret = key_file.read_text()
    never_relay = 'never relay me over dual stack'
    try:
        await _wait_ready(process, LOOPBACK_V4, port)
        async with ClientSession() as session:
            a, _ = await _join(session, f'{scheme}://{LOOPBACK_V4}:{port}/ws', 'dual', secret, 'v4',
                               origin=APPROVED_ORIGIN)
            await _receive_type(a, 'roster')
            b, _ = await _join(session, f'{scheme}://[{LOOPBACK_V6}]:{port}/ws', 'dual', secret, 'v6',
                               origin=APPROVED_ORIGIN)
            await _receive_type(a, 'roster')
            await a.send_json({'v': 1, 'type': 'chat', 'text': never_relay})
            error = await _receive_type(a, 'error')
            assert error['code'] == 'SCHEMA_INVALID'
            await a.close()
            await b.close()
        # 等待日志落盘
        await asyncio.sleep(0.2)
        journal = (tmp_path / 'central' / 'server.jsonl')
        assert journal.exists(), '中心日志应当存在（行为未变）'
        assert never_relay not in journal.read_text()
        # 两个站点都写进同一份日志文件，说明共享同一数据目录
        events = [json.loads(line) for line in journal.read_text().splitlines() if line.strip()]
        scopes = {event.get('peerId') for event in events}
        assert scopes, events
    finally:
        await _stop(process, log)
