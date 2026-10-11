"""Model the CPython IOCP tuple-length contract on every platform, using real sockets."""
import asyncio
import errno
import socket
import time
import uuid

import pytest
from p2pchat.native.adapter import NativeAdapter
from p2pchat.native.gateway import GatewayPolicy, PCP, NATPMP
from p2pchat.native.stun import socket_address, canonical_endpoint, binding, udp_unreachable, receive_udp_retry
from .test_transport import pair, wait_states, params
from .test_windows_endpoints import IPv6StunResponder
from .test_gateway import MockGateway


def require_form(sock, address):
    assert isinstance(address, tuple)
    assert len(address) == (4 if sock.family == socket.AF_INET6 else 2)
    if sock.family == socket.AF_INET6:
        assert address[2:] == (0, 0)
    assert canonical_endpoint(address, sock.family) == address[:2]


def test_forms_identity_and_security():
    assert socket_address(('0:0:0:0:0:0:0:1', 99), socket.AF_INET6) == ('::1', 99, 0, 0)
    assert socket_address(('127.0.0.1', 99), socket.AF_INET) == ('127.0.0.1', 99)
    assert canonical_endpoint(('::1', 99)) == canonical_endpoint(('::1', 99, 0, 0))
    for endpoint, family in [(('::1', 99, 0, 2), socket.AF_INET6), (('::1%2', 99), socket.AF_INET6),
                             (('::ffff:127.0.0.1', 99), socket.AF_INET), (('ff02::1', 99), socket.AF_INET6)]:
        with pytest.raises(ValueError):
            socket_address(endpoint, family)
    assert not udp_unreachable(OSError(errno.EINVAL, 'invalid'))
    assert not udp_unreachable(PermissionError(errno.EACCES, 'denied'))
    # POSIX reports a UDP ICMP port-unreachable as ECONNREFUSED, Windows as
    # WSAECONNRESET: the same bounded no-response predicate must cover both.
    assert udp_unreachable(ConnectionRefusedError(errno.ECONNREFUSED, 'icmp'))
    assert udp_unreachable(ConnectionResetError(errno.ECONNRESET, 'icmp'))


@pytest.mark.asyncio
@pytest.mark.parametrize('host', ['127.0.0.1', '::1'])
@pytest.mark.parametrize('mechanism', ['udp-probe', 'quic', 'tcp', 'tcp-simopen'])
async def test_real_adapter_socket_call_forms(monkeypatch, host, mechanism):
    loop = asyncio.get_running_loop()
    send, connect = loop.sock_sendto, loop.sock_connect
    calls = []
    async def sendto(sock, data, address):
        require_form(sock, address)
        calls.append(('send', address))
        return await send(sock, data, address)
    async def connectto(sock, address):
        require_form(sock, address)
        calls.append(('connect', address))
        return await connect(sock, address)
    monkeypatch.setattr(loop, 'sock_sendto', sendto)
    monkeypatch.setattr(loop, 'sock_connect', connectto)
    a, b, aid, _, _ = await pair(mechanism, host)
    try:
        states = await wait_states(a, b, aid)
        if mechanism == 'tcp-simopen' and states != ['direct', 'direct']:
            assert states == ['failed', 'failed']  # same existing loopback race, no listen fallback
            assert all(x.attempts[aid].failure == 'TCP_SIMOPEN_UNAVAILABLE' for x in [a, b])
        else:
            assert states == ['direct', 'direct']
        assert calls
        assert all(len(x.attempts[aid].stats()['remoteTuple']) == 2 for x in [a, b])
        if mechanism == 'quic':
            # Require both pre-QUIC probe and QUIC packet sends on the same API.
            assert len(calls) > 6
    finally:
        await a.shutdown()
        await b.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize('host', ['127.0.0.1', '::1'])
async def test_stun_and_gateway_send_forms(monkeypatch, host):
    loop = asyncio.get_running_loop()
    send = loop.sock_sendto
    calls = []
    async def checked(sock, data, address):
        require_form(sock, address)
        calls.append(address)
        return await send(sock, data, address)
    monkeypatch.setattr(loop, 'sock_sendto', checked)
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    transport, _ = await loop.create_datagram_endpoint(
        IPv6StunResponder if family == socket.AF_INET6 else lambda: MockGateway('stun'), local_addr=(host, 0))
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind((host, 0))
    try:
        result = await binding(sock, (host, transport.get_extra_info('sockname')[1]))
        assert result['port'] == sock.getsockname()[1]
    finally:
        sock.close()
        transport.close()
    transport, _ = await loop.create_datagram_endpoint(lambda: MockGateway('pcp'), local_addr=(host, 0))
    gateway = PCP(GatewayPolicy(host, host, enabled=True, mock_loopback=True,
                               port=transport.get_extra_info('sockname')[1], timeout=.05))
    async def validate_mock(lease):
        return lease.external_port == 45678
    try:
        lease = await gateway.map(12345, validator=validate_mock)
        assert lease.verified
        assert await gateway.close() == []
        assert calls
    finally:
        transport.close()


def reset_error(kind):
    if kind == 'subclass':
        return ConnectionResetError(errno.ECONNRESET, 'controlled ICMP reset')
    if kind == 'refused':
        return ConnectionRefusedError(errno.ECONNREFUSED, 'controlled POSIX ICMP unreachable')
    error = OSError('controlled Windows ICMP')
    error.winerror = 10054
    return error


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['subclass', 'winerror', 'refused'])
@pytest.mark.parametrize('stage', ['send', 'receive'])
async def test_unreachable_gateway_no_lease_bounded(monkeypatch, kind, stage):
    loop = asyncio.get_running_loop()
    sent, received = [], []
    async def send(sock, data, address):
        require_form(sock, address)
        sent.append(address)
        if stage == 'send':
            raise reset_error(kind)
    async def receive(sock, size):
        received.append(1)
        raise reset_error(kind)
    monkeypatch.setattr(loop, 'sock_sendto', send)
    monkeypatch.setattr(loop, 'sock_recvfrom', receive)
    for cls in [PCP, NATPMP]:
        gateway = cls(GatewayPolicy('127.0.0.1', '127.0.0.1', enabled=True, mock_loopback=True, timeout=.01))
        async def validator(lease):
            pytest.fail('No ICMP reset may produce a lease for external validation')
        started = time.monotonic()
        with pytest.raises(TimeoutError, match='GATEWAY_TIMEOUT'):
            await asyncio.wait_for(gateway.map(12345, validator=validator), 1)
        assert .05 <= time.monotonic()-started < 1
        assert not gateway.leases
    assert len(sent) == 6  # three existing retries each, no unbounded sends
    assert 1 <= len(received) <= 30  # 10ms paced receive retries, not a busy loop


@pytest.mark.asyncio
@pytest.mark.parametrize('mechanism', ['udp-probe', 'quic'])
@pytest.mark.parametrize('kind', ['winerror', 'refused'])
async def test_unreachable_probe_keeps_deadline(monkeypatch, mechanism, kind):
    loop = asyncio.get_running_loop()
    counts = {'send': 0, 'receive': 0}
    async def send(sock, data, addr):
        require_form(sock, addr)
        counts['send'] += 1
        raise reset_error(kind)
    async def receive(sock, size):
        counts['receive'] += 1
        raise reset_error(kind)
    monkeypatch.setattr(loop, 'sock_sendto', send)
    monkeypatch.setattr(loop, 'sock_recvfrom', receive)
    a, b, aid, ea, eb = await pair(mechanism)
    try:
        a.attempts[aid].timeout = b.attempts[aid].timeout = .2
        assert await wait_states(a, b, aid) == ['timeout', 'timeout']
        assert all(x.attempts[aid].failure == 'PROBE_TIMEOUT' for x in [a, b])
        assert not any(k == 'data' for events in [ea, eb] for k, _ in events)
        assert counts['send'] <= 8 and counts['receive'] <= 60
    finally:
        await a.shutdown()
        await b.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['winerror', 'refused'])
async def test_stun_reset_times_out_other_errors_propagate(monkeypatch, kind):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('::1', 0))
    async def send(sock, data, addr):
        require_form(sock, addr)
    async def reset(sock, size):
        raise reset_error(kind)
    monkeypatch.setattr(loop, 'sock_sendto', send)
    monkeypatch.setattr(loop, 'sock_recvfrom', reset)
    try:
        with pytest.raises(TimeoutError, match='STUN_TIMEOUT'):
            await binding(sock, ('::1', 3478), timeout=.04)
        async def invalid(sock, size):
            raise OSError(errno.EINVAL, 'must not hide programmer error')
        monkeypatch.setattr(loop, 'sock_recvfrom', invalid)
        with pytest.raises(OSError) as exc:
            await receive_udp_retry(sock, 10)
        assert exc.value.errno == errno.EINVAL
    finally:
        sock.close()
