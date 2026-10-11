"""server_preflight 的纯本地单元测试：临时目录 + 自签证书，不访问外部网络。

覆盖：证书过期 / 域名不匹配 / 私钥不配对 / 证书不可读、--origin 不匹配、
数据目录不可写、缺全局 IPv6 地址的判定，以及只读边界（不写数据目录以外的东西）。
"""
import datetime
import ipaddress
import os
import socket
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from p2pchat.tools import server_preflight as pre


# ---------------------------------------------------------------------------
# 自签证书工具（全部在 tmp_path 里生成，不联网）
# ---------------------------------------------------------------------------

NOW = datetime.datetime.now(datetime.timezone.utc)


def _write_cert(directory, name='cert', cn='p2p.example', dns_names=('p2p.example',),
                not_before=None, not_after=None, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    not_before = not_before or (NOW - datetime.timedelta(days=1))
    not_after = not_after or (NOW + datetime.timedelta(days=90))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(not_before).not_valid_after(not_after))
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), critical=False)
    certificate = builder.sign(key, hashes.SHA256())
    cert_path = Path(directory) / f'{name}.pem'
    key_path = Path(directory) / f'{name}.key'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert_path, key_path


def _ok():
    return pre.Result.make('probe', pre.PASS, 'ok')


def _unreadable(path):
    path.chmod(0o000)
    if os.access(path, os.R_OK):  # root 会绕过权限位，那就跳过这条断言
        pytest.skip('当前用户无视文件权限位（例如 root），无法构造不可读文件')


# ---------------------------------------------------------------------------
# (1) Python 与依赖
# ---------------------------------------------------------------------------

def test_python_and_deps_pass(monkeypatch):
    result = pre.check_python_and_deps()
    assert result.status == pre.PASS
    assert result.facts['missing'] == []
    assert result.facts['python'].startswith('3.')


def test_python_too_old_is_blocking():
    result = pre.check_python_and_deps(min_python=(99, 0))
    assert result.status == pre.FAIL
    assert result.code == 'PYTHON_TOO_OLD'


def test_missing_dependency_is_blocking(monkeypatch):
    real_import = __builtins__['__import__'] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == 'aiortc':
            raise ImportError('not installed')
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr('builtins.__import__', fake_import)
    result = pre.check_python_and_deps()
    assert result.status == pre.FAIL
    assert result.code == 'DEPS_MISSING'
    assert any('aiortc' in item for item in result.facts['missing'])


# ---------------------------------------------------------------------------
# (2)(3) 地址判定
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('address,expected', [
    ('240e:1f:2:3::4', True), ('2a02:26f0:1::1', True), ('2606:4700::1111', True),
    ('::1', False), ('fe80::1', False), ('fd00::1', False), ('fc00::1234', False),
    ('ff02::1', False), ('::', False), ('192.0.2.1', False), ('not-an-ip', False),
])
def test_is_global_ipv6(address, expected):
    assert pre.is_global_ipv6(address) is expected


def test_missing_global_ipv6_is_warning_not_blocking():
    result = pre.check_global_ipv6(['127.0.0.1', '::1', 'fe80::abc', 'fd00::1'])
    assert result.status == pre.WARN
    assert result.code == 'NO_GLOBAL_IPV6'
    assert result.facts['globalIPv6'] == []
    assert result.facts['sawAnyIPv6']  # 看到了 IPv6，只是都不是全局


def test_global_ipv6_present():
    result = pre.check_global_ipv6(['2606:4700::1111', 'fe80::1'])
    assert result.status == pre.PASS
    assert result.facts['globalIPv6'] == ['2606:4700::1111']


def test_ipv4_egress_logic():
    assert pre.check_ipv4_egress(['10.0.0.5']).status == pre.PASS
    missing = pre.check_ipv4_egress(['::1', 'fe80::1'])
    assert missing.status == pre.WARN and missing.code == 'NO_IPV4_EGRESS'
    assert pre.is_usable_ipv4('127.0.0.1') is False
    assert pre.is_usable_ipv4('169.254.1.1') is False


# ---------------------------------------------------------------------------
# (4) 证书与私钥
# ---------------------------------------------------------------------------

def test_certificate_ok_reports_days_and_domain(tmp_path):
    cert, key = _write_cert(tmp_path, not_after=NOW + datetime.timedelta(days=77))
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.PASS
    assert result.facts['daysRemaining'] == 76
    assert result.facts['domainMatched'] is True
    assert result.facts['keyMatchesCert'] is True


def test_expired_certificate_blocks(tmp_path):
    cert, key = _write_cert(tmp_path, not_before=NOW - datetime.timedelta(days=30),
                            not_after=NOW - datetime.timedelta(days=3))
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.FAIL
    assert result.code == 'CERT_EXPIRED'
    assert result.facts['expired'] is True
    assert result.facts['daysRemaining'] < 0


def test_not_yet_valid_certificate_blocks(tmp_path):
    cert, key = _write_cert(tmp_path, not_before=NOW + datetime.timedelta(days=2),
                            not_after=NOW + datetime.timedelta(days=30))
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.FAIL and result.code == 'CERT_NOT_YET_VALID'


def test_domain_mismatch_blocks(tmp_path):
    cert, key = _write_cert(tmp_path, cn='other.example', dns_names=('other.example',))
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.FAIL
    assert result.code == 'CERT_DOMAIN_MISMATCH'
    assert result.facts['domainMatched'] is False


def test_domain_match_accepts_wildcard_and_is_case_insensitive():
    assert pre.domain_matches('*.p2p.example', 'a.p2p.example') is True
    assert pre.domain_matches('*.p2p.example', 'p2p.example') is False
    assert pre.domain_matches('*.p2p.example', 'a.b.p2p.example') is False
    assert pre.domain_matches('P2P.Example.', 'p2p.example') is True
    assert pre.domain_matches('p2p.example', 'other.example') is False


def test_wildcard_certificate_matches_subdomain(tmp_path):
    cert, key = _write_cert(tmp_path, cn='*.p2p.example', dns_names=('*.p2p.example',))
    assert pre.check_tls(cert, key, 'a.p2p.example').status == pre.PASS
    assert pre.check_tls(cert, key, 'p2p.example').code == 'CERT_DOMAIN_MISMATCH'


def test_expiring_soon_is_warning(tmp_path):
    cert, key = _write_cert(tmp_path, not_after=NOW + datetime.timedelta(days=5))
    assert pre.check_tls(cert, key, 'p2p.example').facts['daysRemaining'] == 4
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.WARN and result.code == 'CERT_EXPIRING_SOON'


def test_key_cert_mismatch_blocks(tmp_path):
    cert, _ = _write_cert(tmp_path, name='a')
    _, other_key = _write_cert(tmp_path, name='b', cn='b.example', dns_names=('b.example',))
    result = pre.check_tls(cert, other_key, 'p2p.example')
    assert result.status == pre.FAIL and result.code == 'KEY_CERT_MISMATCH'


def test_missing_domain_is_warning(tmp_path):
    cert, key = _write_cert(tmp_path)
    result = pre.check_tls(cert, key)
    assert result.status == pre.WARN and result.code == 'CERT_DOMAIN_NOT_CHECKED'


def test_tls_not_provided_or_half_pair(tmp_path):
    assert pre.check_tls().status == pre.SKIP
    cert, key = _write_cert(tmp_path)
    assert pre.check_tls(cert, None).code == 'TLS_HALF_PAIR'


def test_unreadable_files_block(tmp_path):
    cert, key = _write_cert(tmp_path)
    _unreadable(cert)
    assert pre.check_tls(cert, key, 'p2p.example').code == 'CERT_UNREADABLE'
    cert.chmod(0o600)
    _unreadable(key)
    assert pre.check_tls(cert, key, 'p2p.example').code == 'KEY_UNREADABLE'


def test_encrypted_private_key_is_rejected(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, _ = _write_cert(tmp_path, key=key)
    encrypted = tmp_path / 'enc.key'
    encrypted.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b'passphrase')))
    result = pre.check_tls(cert, encrypted, 'p2p.example')
    assert result.status == pre.FAIL and result.code == 'KEY_PARSE_FAILED_OR_ENCRYPTED'


def test_garbage_certificate_is_rejected(tmp_path):
    cert = tmp_path / 'bad.pem'
    cert.write_text('this is not a certificate')
    _, key = _write_cert(tmp_path)
    result = pre.check_tls(cert, key, 'p2p.example')
    assert result.status == pre.FAIL and result.code == 'CERT_PARSE_FAILED'


# ---------------------------------------------------------------------------
# (5) --origin
# ---------------------------------------------------------------------------

def test_origin_currently_verified_is_not_a_remote_check(tmp_path):
    # 不注入探针时不联网：只断言"没有核对来源"是一条提醒，不是阻断。
    result = pre.check_origin(['https://p2p.example'], host='0.0.0.0')
    assert result.status == pre.WARN and result.code == 'ORIGIN_UNVERIFIED'


def test_origin_probe_matching_origin_passes(monkeypatch):
    monkeypatch.setattr(pre, '_probe_origin', lambda url, timeout: (True, {'status': 200, 'origin': url}))
    result = pre.check_origin(['https://p2p.example'], host='0.0.0.0',
                              probe_url='https://p2p.example/')
    assert result.status == pre.PASS and result.facts['servedOrigin'] == 'https://p2p.example'


def test_origin_mismatch_is_blocking(monkeypatch):
    monkeypatch.setattr(pre, '_probe_origin',
                        lambda url, timeout: (True, {'status': 200, 'origin': 'https://other.example'}))
    result = pre.check_origin(['https://p2p.example'], host='0.0.0.0',
                              probe_url='http://127.0.0.1:8088/')
    assert result.status == pre.FAIL
    assert result.code == 'ORIGIN_MISMATCH'
    assert 'other.example' in result.human


def test_origin_unreachable_is_blocking(monkeypatch):
    monkeypatch.setattr(pre, '_probe_origin', lambda url, timeout: (False, {'error': 'URLError'}))
    result = pre.check_origin(['https://p2p.example'], host='0.0.0.0', probe_url='https://p2p.example/')
    assert result.status == pre.FAIL and result.code == 'ORIGIN_UNREACHABLE'


def test_origin_required_on_public_bind():
    result = pre.check_origin([], host='0.0.0.0')
    assert result.status == pre.FAIL and result.code == 'ORIGIN_REQUIRED'


def test_origin_empty_on_loopback_is_warning():
    assert pre.check_origin([], host='127.0.0.1').status == pre.WARN


def test_origin_http_on_public_bind_blocks():
    result = pre.check_origin(['http://p2p.example'], host='0.0.0.0')
    assert result.status == pre.FAIL and result.code == 'PUBLIC_BUT_HTTP'
    assert 'PUBLIC_BUT_HTTP' in result.facts['problems'][0]


def test_origin_malformed_and_wrong_scheme_block():
    assert pre.check_origin(['p2p.example'], host='0.0.0.0').code == 'NOT_HTTPS_ORIGIN'
    assert pre.check_origin(['null'], host='0.0.0.0').code == 'MALFORMED'
    assert pre.check_origin(['https://p2p.example:8443/'], host='0.0.0.0').status != pre.FAIL


def test_origin_normalization():
    assert pre.normalize_origin('HTTPS://P2P.example:8443/') == 'https://p2p.example:8443'
    assert pre.normalize_origin('null') is None
    assert pre.normalize_origin('') is None


def test_probe_url_must_be_local():
    assert pre.localhost_only('http://127.0.0.1:8088/') is True
    assert pre.localhost_only('http://localhost:8088/') is True
    assert pre.localhost_only('http://[::1]:8088/') is True
    assert pre.localhost_only('https://p2p.example/') is False
    assert pre.localhost_only('https://evil.example/') is False


# ---------------------------------------------------------------------------
# (6) 数据目录
# ---------------------------------------------------------------------------

def test_data_dir_missing_is_warning(tmp_path):
    result = pre.check_data_dir(tmp_path / 'not-yet')
    assert result.status == pre.WARN and result.code == 'DATA_DIR_MISSING'


def test_data_dir_writable_passes_and_leaves_no_residue(tmp_path):
    target = tmp_path / 'data'
    target.mkdir(mode=0o700)
    before = set(os.listdir(target))
    result = pre.check_data_dir(target)
    assert result.status == pre.PASS
    assert result.facts['writable'] is True
    assert set(os.listdir(target)) == before  # 只读：不留下任何探针文件


def test_data_dir_not_writable_blocks(tmp_path):
    target = tmp_path / 'data'
    target.mkdir(mode=0o500)
    try:
        result = pre.check_data_dir(target)
    finally:
        target.chmod(0o700)
    assert result.status == pre.FAIL
    assert result.code == 'DATA_DIR_NOT_WRITABLE'
    assert result.facts['writable'] is False


def test_dir_writable_probe_controls_verdict(tmp_path):
    target = tmp_path / 'data'
    target.mkdir()
    target.chmod(0o700)
    blocked = pre.check_data_dir(target, probe=lambda p: False)
    assert blocked.status == pre.FAIL and blocked.facts['writable'] is False
    allowed = pre.check_data_dir(target, probe=lambda p: True)
    assert allowed.status == pre.PASS and allowed.facts['writable'] is True


def test_data_dir_world_readable_is_warning(tmp_path):
    target = tmp_path / 'data'
    target.mkdir()
    target.chmod(0o707)
    try:
        result = pre.check_data_dir(target)
    finally:
        target.chmod(0o700)
    assert result.status == pre.WARN and result.code == 'DATA_DIR_WORLD_ACCESSIBLE'


def test_data_dir_file_instead_of_directory_blocks(tmp_path):
    target = tmp_path / 'data'
    target.write_text('x')
    assert pre.check_data_dir(target).code == 'DATA_DIR_NOT_DIRECTORY'


# ---------------------------------------------------------------------------
# (7) 端口
# ---------------------------------------------------------------------------

def test_free_port_is_bindable_and_occupied_port_is_not():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        sock.listen(1)
        host, port = sock.getsockname()
        busy = pre.check_tcp_port(host, port)
        assert busy.status == pre.FAIL and busy.code == 'PORT_IN_USE'
    free = pre.check_tcp_port('127.0.0.1', port)
    assert free.status == pre.PASS


def test_udp_port_bindability_uses_real_socket_when_not_injected():
    result = pre.check_udp_port('127.0.0.1', 0)
    assert result.status == pre.PASS and result.facts['bindable'] is True


def test_udp_port_advertised_but_loopback_only_is_warning():
    result = pre.check_udp_port('127.0.0.1', 0, advertised=True)
    assert result.status == pre.WARN and result.code == 'STUN_ONLY_LOOPBACK'
    assert result.facts['onlyLoopback'] is True
    assert pre.check_udp_port('0.0.0.0', 0, advertised=True).status == pre.PASS


def test_family_coverage_single_family_still_warns():
    """只请求一族时，另一族确实没人服务——必须如实提醒，不能一律报通过。"""
    probes = {'ipv4-tcp': _ok(), 'ipv6-tcp': _ok(), 'ipv4-udp': _ok(), 'ipv6-udp': _ok()}
    v6 = pre.check_family_coverage(['::'], probes=probes)
    assert v6.status == pre.WARN and v6.code == 'FAMILY_COVERAGE_LIMITED'
    assert v6.facts['families'] == ['ipv6']
    assert v6.facts['missingFamilies'] == ['ipv4']
    assert 'IPv4 客户端连不上' in v6.human
    assert '--host 0.0.0.0' in v6.human
    v4 = pre.check_family_coverage(['0.0.0.0'], probes=probes)
    assert v4.status == pre.WARN and v4.facts['missingFamilies'] == ['ipv6']
    assert 'IPv6 客户端连不上' in v4.human


def test_family_coverage_dual_stack_is_pass_and_has_no_stale_advice():
    """同时请求两族：单进程就是真双栈，不得再出现"两个实例/socat"这类过时结论。"""
    probes = {'ipv4-tcp': _ok(), 'ipv6-tcp': _ok(), 'ipv4-udp': _ok(), 'ipv6-udp': _ok()}
    result = pre.check_family_coverage(['0.0.0.0', '::'], probes=probes)
    assert result.status == pre.PASS
    assert result.facts['families'] == ['ipv4', 'ipv6']
    assert result.facts['missingFamilies'] == []
    assert '真双栈' in result.human
    assert '同一端口' in result.human and '同一个数据目录' in result.human
    for stale in ('socat', '两个实例', '再起一个实例', '第二个实例'):
        assert stale not in result.human


def test_family_coverage_unknown_host_is_skip():
    probes = {'ipv4-tcp': _ok(), 'ipv6-tcp': _ok(), 'ipv4-udp': _ok(), 'ipv6-udp': _ok()}
    unknown = pre.check_family_coverage(['p2p.example'], probes=probes)
    assert unknown.status == pre.SKIP and unknown.code == 'BIND_FAMILY_UNKNOWN'
    assert unknown.facts['unknownHosts'] == ['p2p.example']


def test_requested_hosts_and_families_helpers():
    assert pre.requested_hosts(None) == ['127.0.0.1']
    assert pre.requested_hosts('::') == ['::']
    assert pre.requested_hosts(['0.0.0.0', '::']) == ['0.0.0.0', '::']
    assert pre.listening_families(['0.0.0.0', '::']) == {'ipv4', 'ipv6'}
    assert pre.listening_families(['::']) == {'ipv6'}
    assert pre.listening_families(['p2p.example']) == set()


# ---------------------------------------------------------------------------
# 实际监听核对：与请求的站点是否一致、有没有隐式回退
# ---------------------------------------------------------------------------

SS_DUAL = [
    'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
    'LISTEN 0      128          0.0.0.0:8088      0.0.0.0:*',
    'LISTEN 0      128             [::]:8088         [::]:*',
]
SS_V4_ONLY = [
    'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
    'LISTEN 0      128          0.0.0.0:8088      0.0.0.0:*',
]
SS_STAR_ONLY = [
    'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
    'LISTEN 0      128                *:8088            *:*',
]


def test_parse_listening_and_families():
    parsed = pre.parse_listening(SS_DUAL)
    assert [(item['family'], item['address'], item['port']) for item in parsed] == [
        ('ipv4', '0.0.0.0', '8088'), ('ipv6', '::', '8088')]
    families, wildcard = pre.listener_families(SS_DUAL)
    assert families == set() and wildcard == {'ipv4', 'ipv6'}  # 通配监听单列，不算明确站点
    loopback_raw = ['LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*', 'LISTEN 0 128 [::1]:8088 [::]:*']
    assert pre.listener_families(loopback_raw) == ({'ipv4', 'ipv6'}, set())
    assert pre.parse_listening(['garbage line']) == []


def test_implicit_fallback_detection_only_when_not_requested():
    assert pre.implicit_fallback_listeners(['0.0.0.0', '::'], SS_DUAL) == []
    assert pre.implicit_fallback_listeners(['127.0.0.1', '::1'], SS_DUAL) == []  # 同族已有明确地址
    # 只请求 IPv6，却只看到 IPv4 通配监听 —— 与请求的族无法对应，按隐式回退报出来
    found = pre.implicit_fallback_listeners(['::'], SS_V4_ONLY)
    assert len(found) == 1 and found[0]['family'] == 'ipv4'
    star = pre.implicit_fallback_listeners(['::'], SS_STAR_ONLY)
    assert len(star) == 1 and star[0]['address'] == '*'


def test_check_listeners_dual_stack_matches():
    result = pre.check_listeners(['0.0.0.0', '::'], 8088, entries=SS_DUAL)
    assert result.status == pre.PASS
    assert result.facts['verdict'] == 'MATCH'
    assert result.facts['source'] == 'injected'
    assert result.facts['wildcardListeners'] == ['ipv4', 'ipv6']
    assert result.facts['implicitFallback'] == []


def test_check_listeners_dual_stack_with_loopback_only_passes():
    entries = ['LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*', 'LISTEN 0 128 [::1]:8088 [::]:*']
    result = pre.check_listeners(['0.0.0.0', '::'], 8088, entries=entries)
    assert result.status == pre.PASS and result.facts['verdict'] == 'MATCH'


def test_check_listeners_missing_family_warns():
    result = pre.check_listeners(['0.0.0.0', '::'], 8088, entries=SS_V4_ONLY)
    assert result.status == pre.WARN and result.code == 'LISTEN_MISSING'
    assert 'IPv6' in result.human


def test_check_listeners_implicit_fallback_warns():
    result = pre.check_listeners(['::'], 8088, entries=SS_V4_ONLY)
    assert result.status == pre.WARN and result.code == 'IMPLICIT_FALLBACK_LISTENER'
    assert '通配' in result.human and 'V6ONLY' in result.human


def test_check_listeners_star_listener_is_reported_as_fallback():
    result = pre.check_listeners(['::'], 8088, entries=SS_STAR_ONLY)
    assert result.status == pre.WARN and result.code == 'IMPLICIT_FALLBACK_LISTENER'
    assert any(item['address'] == '*' for item in result.facts['implicitFallback'])


def test_check_listeners_not_started_yet_is_skip():
    result = pre.check_listeners(['0.0.0.0', '::'], 8088, entries=[])
    assert result.status == pre.SKIP and result.code == 'NOT_LISTENING_YET'


def test_check_listeners_uses_injected_probe_when_proc_unreadable(tmp_path):
    """Windows/macOS 没有 /proc：退化为回环弱探测，并且必须在结论里说清来源与平台限制。"""
    result = pre.check_listeners(['0.0.0.0', '::'], 8088, probe={'ipv4'},
                                 proc_net={'ipv4': str(tmp_path / 'nope'),
                                           'ipv6': str(tmp_path / 'nope6')})
    assert result.facts['source'] == 'loopback-connect'
    assert result.status == pre.WARN and result.code == 'LISTEN_MISSING'
    assert '/proc' in result.human and 'Windows/macOS' in result.human


def test_check_listeners_skips_with_platform_note_when_nothing_known():
    result = pre.check_listeners(['0.0.0.0', '::'], 8088,
                                 proc_net={'ipv4': '/nowhere', 'ipv6': '/nowhere6'},
                                 probe=set())
    assert result.facts['source'] == 'loopback-connect'
    assert result.status == pre.SKIP and result.code == 'NOT_LISTENING_YET'


def test_check_listeners_unknown_host_is_skip():
    result = pre.check_listeners(['p2p.example'], 8088, entries=SS_DUAL)
    assert result.status == pre.SKIP and result.code == 'LISTEN_FAMILY_UNKNOWN'


def test_build_parser_accepts_repeated_host_and_keeps_default():
    parser = pre.build_parser()
    dual = parser.parse_args(['--host', '0.0.0.0', '--host', '::'])
    assert pre.requested_hosts(dual.host) == ['0.0.0.0', '::']
    assert pre.requested_hosts(parser.parse_args([]).host) == ['127.0.0.1']


def test_listen_entry_lines_reads_files(tmp_path):
    listing = tmp_path / 'ss.txt'
    listing.write_text('\n'.join(SS_DUAL) + '\n', encoding='utf8')
    assert pre._listen_entry_lines(['@%s' % listing]) == SS_DUAL
    assert pre._listen_entry_lines(['LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*']) == [
        'LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*']
    assert pre._listen_entry_lines(['@%s' % (tmp_path / 'missing')])[0].startswith('--listen-entries 读不到')
    assert pre._listen_entries_for_port(SS_DUAL, 8088) == SS_DUAL[1:]
    assert pre._listen_entries_for_port(['LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*'], 8088) is None


def _proc_line(address, port, family):
    """把地址+端口编码成 /proc/net/tcp{,6} 的 local_address 字段。"""
    import socket as _socket
    if family == 'ipv4':
        packed = _socket.inet_pton(_socket.AF_INET, address)[::-1]
    else:
        raw = _socket.inet_pton(_socket.AF_INET6, address)
        packed = b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    shown = address if ':' not in address else '[' + address + ']'
    return '0: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1 1 0 0 0 10 0' % (
        packed.hex().upper(), port)


def _proc_file(tmp_path, name, family, entries):
    path = tmp_path / name
    header = ' sl  local_address rem_address st tx_queue rx_queue' if family == 'ipv4' else \
             ' sl  local_address                         remote_address st'
    path.write_text('\n'.join([header] + [_proc_line(address, port, family) for address, port in entries]) + '\n',
                    encoding='utf8')
    return str(path)


def test_proc_net_parsing_reads_real_kernel_encoding(tmp_path):
    proc = {'ipv4': _proc_file(tmp_path, 'tcp', 'ipv4', [('0.0.0.0', 8088), ('127.0.0.1', 9999)]),
            'ipv6': _proc_file(tmp_path, 'tcp6', 'ipv6', [('::', 8088), ('::1', 9999)])}
    lines = pre._proc_listen_lines(8088, proc)
    assert sorted(lines) == ['LISTEN 0 128 0.0.0.0:8088 0.0.0.0:*', 'LISTEN 0 128 [::]:8088 [::]:*']
    assert pre._proc_listen_lines(9999, proc) is not None
    # 头部行与其它端口不能混进来
    assert all('9999' not in line for line in lines)
    assert pre.listener_families(lines) == (set(), {'ipv4', 'ipv6'})


def test_check_listeners_via_proc_reports_match_and_mismatch(tmp_path):
    proc = {'ipv4': _proc_file(tmp_path, 'tcp', 'ipv4', [('0.0.0.0', 8088)]),
            'ipv6': _proc_file(tmp_path, 'tcp6', 'ipv6', [('::', 8088)])}
    ok = pre.check_listeners(['0.0.0.0', '::'], 8088, proc_net=proc)
    assert ok.status == pre.PASS and ok.facts['source'] == '/proc/net/tcp'
    only_v4 = {'ipv4': proc['ipv4'], 'ipv6': _proc_file(tmp_path, 'tcp6-empty', 'ipv6', [])}
    missing = pre.check_listeners(['0.0.0.0', '::'], 8088, proc_net=only_v4)
    assert missing.status == pre.WARN and missing.code == 'LISTEN_MISSING'


def test_proc_unreadable_returns_none():
    assert pre._proc_listen_lines(8088, {'ipv4': '/nowhere/tcp', 'ipv6': '/nowhere/tcp6'}) is None


def test_address_family_of():
    assert pre.address_family_of('::') == 'ipv6'
    assert pre.address_family_of('0.0.0.0') == 'ipv4'
    assert pre.address_family_of('p2p.example') is None


def test_udp_port_in_use_blocks():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        result = pre.check_udp_port('127.0.0.1', port)
    assert result.status == pre.FAIL and result.code == 'UDP_PORT_IN_USE'


def test_port_probe_injection_and_low_port_hint():
    blocked = pre.check_tcp_port('0.0.0.0', 80, probe=lambda h, p: (False, 'PermissionError(errno=13)'))
    assert blocked.status == pre.FAIL and blocked.code == 'PORT_BIND_FAILED'


# ---------------------------------------------------------------------------
# (8) 本机闭环自检 / 编排 / 只读边界
# ---------------------------------------------------------------------------

def test_self_check_skipped_without_data_dir():
    assert pre.check_self_check(None).status == pre.SKIP


def test_self_check_tries_each_loopback_until_one_works(monkeypatch, tmp_path):
    """回环地址逐个试，第一个失败也要继续试第二个（不会误报"代码跑不通"）。"""
    calls = []

    async def fake_run(data_dir, origin, hosts, timeout):
        for host in hosts:
            calls.append(host)
            if host == '::1':
                return {'ok': True, 'reason': None, 'host': host, 'profile': 'ice-v6',
                        'profilesAttempted': ['ice-v4', 'ice-v6'], 'hmacVerified': True,
                        'actual': {'family': 6, 'protocol': 'udp', 'candidateType': 'host'},
                        'attempts': [{'host': '127.0.0.1', 'ok': False, 'reason': 'TIMEOUT'},
                                     {'host': '::1', 'ok': True, 'reason': None}]}
        return {'ok': False, 'reason': 'TIMEOUT', 'host': hosts[-1], 'attempts': []}

    monkeypatch.setattr(pre, '_self_check_async', fake_run)
    result = pre.check_self_check(tmp_path, None, hosts=('127.0.0.1', '::1'))
    assert calls == ['127.0.0.1', '::1']
    assert result.status == pre.PASS
    assert result.facts['host'] == '::1'
    assert '::1' in result.human
    assert result.facts['loopbackTried'] == ['127.0.0.1', '::1']


def test_self_check_all_hosts_failing_is_blocking(monkeypatch, tmp_path):
    async def fake_run(data_dir, origin, hosts, timeout):
        return {'ok': False, 'reason': 'TIMEOUT', 'host': hosts[-1], 'attempts': []}

    monkeypatch.setattr(pre, '_self_check_async', fake_run)
    result = pre.check_self_check(tmp_path, None, hosts=('127.0.0.1', '::1'))
    assert result.status == pre.FAIL and result.code == 'TIMEOUT'


def test_self_check_reports_unavailable_dependency(monkeypatch):
    def boom(coro, *args, **kwargs):
        coro.close()
        raise pre.SelfCheckUnavailable('ImportError: no aiortc')

    monkeypatch.setattr(pre.asyncio, 'run', boom)
    result = pre.check_self_check('/tmp/never-touched', timeout=1)
    assert result.status == pre.SKIP and result.code == 'SELF_CHECK_DEP_UNAVAILABLE'


def test_stun_url_shapes():
    assert pre.check_stun_url('turn:p2p.example:3478', None, 3478).code == 'STUN_URL_INVALID'
    assert pre.check_stun_url('https://p2p.example', None, 3478).code == 'STUN_URL_INVALID'


def test_stun_url_advertised_with_public_hosts_passes():
    result = pre.check_stun_url('stun:p2p.example:3478', ['0.0.0.0', '::'], 3478)
    assert result.status == pre.PASS


def test_stun_url_advertised_while_bound_loopback_warns():
    result = pre.check_stun_url('stun:p2p.example:3478', None, 3478)
    assert result.status == pre.WARN and result.code == 'STUN_BOUND_LOOPBACK_ONLY'
    assert '不保证打洞成功' in result.human


def test_run_checks_covers_every_required_area(tmp_path, monkeypatch):
    monkeypatch.setattr(pre, '_local_addresses', lambda: [('192.0.2.7', 'test'), ('2606:4700::1111', 'test')])
    cert, key = _write_cert(tmp_path)
    data = tmp_path / 'data'
    data.mkdir(mode=0o700)
    args = pre.build_parser().parse_args([
        '--host', '0.0.0.0', '--host', '::', '--port', '18088', '--stun-port', '0',
        '--cert', str(cert), '--key', str(key), '--domain', 'p2p.example',
        '--origin', 'https://p2p.example', '--data', str(data)])
    results = pre.run_checks(args)
    names = [r.name for r in results]
    assert 'Python 与依赖' in names
    assert '全局 IPv6 地址' in names and 'IPv4 出口' in names
    assert 'TLS 证书' in names and '--origin 配置' in names
    assert '数据目录' in names
    assert names.count('信令端口') == 2, names          # 每个 --host 一个站点
    assert '监听地址族' in names and '实际监听核对' in names
    assert any('STUN' in n for n in names)
    assert not [r for r in results if r.status == pre.FAIL]
    assert pre.overall_status(results) in {pre.PASS, pre.WARN}
    coverage = next(r for r in results if r.name == '监听地址族')
    assert coverage.status == pre.PASS and coverage.facts['families'] == ['ipv4', 'ipv6']


def test_cli_json_output_redacts_paths_and_exits_nonzero_on_block(tmp_path, capsys):
    cert, key = _write_cert(tmp_path, not_before=NOW - datetime.timedelta(days=30),
                            not_after=NOW - datetime.timedelta(days=1))
    base = ['--host', '0.0.0.0', '--cert', str(cert), '--key', str(key),
            '--domain', 'p2p.example', '--origin', 'https://p2p.example',
            '--data', str(tmp_path / 'data'), '--json']
    code = pre.main(base)
    payload = capsys.readouterr().out
    assert code == 1
    assert 'CERT_EXPIRED' in payload
    assert str(tmp_path) not in payload          # 默认不输出完整路径（含人话结论）
    assert 'BEGIN' not in payload                # 不输出任何密钥/证书正文
    assert 'disclaimer' in payload
    assert pre.main(base + ['--json-paths']) == 1
    assert str(tmp_path) in capsys.readouterr().out


def test_cli_text_output_is_human_readable(tmp_path, capsys):
    code = pre.main(['--host', '127.0.0.1', '--port', '18088', '--stun-port', '13478',
                     '--data', str(tmp_path)])
    text = capsys.readouterr().out
    assert code == 0
    assert '结论：' in text and '统计：' in text
    assert '未在你家宽服务器上部署过' in text
    assert 'STUN 只观测映射' in text


def test_text_output_never_contains_key_material(tmp_path, capsys):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, key_path = _write_cert(tmp_path, key=key)
    key_body = key_path.read_text().splitlines()[1][:24]  # 私钥正文的一小段
    pre.main(['--host', '0.0.0.0', '--port', '18088', '--stun-port', '13478',
              '--cert', str(cert), '--key', str(key_path), '--domain', 'p2p.example',
              '--origin', 'https://p2p.example', '--data', str(tmp_path)])
    text = capsys.readouterr().out
    assert 'BEGIN' not in text
    assert key_body not in text
    assert 'PRIVATE KEY' not in text


def test_portrait_hides_home_prefix():
    home_file = Path.home() / 'p2p-data'
    assert pre.portrait(home_file).startswith('~')
    assert pre.portrait('/etc/letsencrypt/live/x/fullchain.pem') == '/etc/letsencrypt/live/x/fullchain.pem'


def test_no_root_required_and_read_only_source_scan():
    """源码里不允许出现改防火墙/路由或提权的调用（静态只读边界）。"""
    source = Path(pre.__file__).read_text(encoding='utf8')
    for forbidden in ('iptables', 'nft ', 'ufw ', 'firewall-cmd', 'sysctl -w',
                      'os.system', 'subprocess', 'sudo ', 'chmod('):
        assert forbidden not in source, forbidden
    assert 'os.remove' not in source and 'unlink(' in source  # 只删自己的探针文件
