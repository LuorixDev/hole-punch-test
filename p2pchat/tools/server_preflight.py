#!/usr/bin/env python3
"""家宽服务器部署前只读体检（server preflight, read-only）。

在你自己的服务器上跑一条命令，得到一份人话结论：这台机器现在能不能启动
P2P 信令 + STUN 服务端，以及还差什么。

严格只读边界（本工具的设计约束，不是可选项）：
  * 只读取本机信息；不写系统文件，不改防火墙 / 路由 / 网卡 / DNS，不装依赖。
  * 不需要 root。所有检查以当前用户身份完成。
  * 不替你开放任何端口；只报告端口现在能不能绑定。
  * 除用户显式传入的 ``--stun-url`` / ``--probe-url`` 之外，不主动访问任何外部服务。
  * 输出与日志不含房间密钥、私钥内容；证书私钥只被读取用于"能不能读 / 是否配对"。

用法::

    python -m p2pchat.tools.server_preflight \\
        --host 0.0.0.0 --host :: --port 8088 \\
        --stun-host 0.0.0.0 --stun-host :: --stun-url stun:stun.p2p.example:3478 \\
        --cert /etc/letsencrypt/live/p2p.example/fullchain.pem \\
        --key  /etc/letsencrypt/live/p2p.example/privkey.pem \\
        --origin https://p2p.example --data ~/p2p-data --self-check

``--host`` 与 server.py 一样可重复：服务端是**单进程多站点**（每个 ``--host`` 一个
``V6ONLY`` 监听站点、两族共用同一端口与同一个数据目录），所以
``--host 0.0.0.0 --host ::`` 就是真双栈，一个服务进程即可。只写一族时，体检会如实提醒
另一族没人服务；并且会只读 /proc/net/tcp{,6} 核对机器上实际在听的套接字，
出现未指定地址（``*``）的隐式回退就报提醒。

退出码：0 = 没有阻断项（可能有提醒）；1 = 有阻断项；2 = 参数用法错误。

唯一的写操作：数据目录检查会在 ``--data`` 目录里建一个临时空文件并立即删除；
``--self-check`` 会在该目录下建 ``_selfcheck/`` 放临时日志，跑完删除。除此之外
不写任何东西，不碰系统配置。

诚实标注：本仓库未在用户家宽服务器上部署过。体检通过只代表"本机条件看起来
具备"，不代表家宽双 NAT / CGNAT 一定能打通；STUN 只观测地址映射，不保证成功。
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

# ============================================================================
# 结果模型
# ============================================================================

PASS, WARN, FAIL, SKIP = 'PASS', 'WARN', 'FAIL', 'SKIP'
_TAG = {PASS: '[通过]', WARN: '[提醒]', FAIL: '[阻断]', SKIP: '[跳过]'}


class Result:
    """一条体检结论：机器可读的状态/代码，加一句人话解释。"""

    def __init__(self, name, status, human, code=None, facts=None, paths=()):
        self.name = name
        self.status = status
        self.human = human
        self.code = code
        self.facts = facts or {}
        self.paths = tuple(paths)

    def to_dict(self, include_paths=True):
        facts = self.facts if include_paths else _strip_paths(self.facts, self.paths)
        return {'check': self.name, 'status': self.status, 'conclusion': self.human,
                'code': self.code, 'facts': facts}

    @classmethod
    def make(cls, name, status, human, code=None, facts=None, paths=()):
        return cls(name, status, human, code, facts, paths)


def _strip_paths(facts, paths):
    """把 JSON 明细里的绝对路径替换成基础文件名，避免外泄目录结构。"""
    if not paths:
        return facts
    text = json.dumps(facts, ensure_ascii=False)
    for path in paths:
        if path:
            text = text.replace(str(path), os.path.basename(str(path)) or '<path>')
    return json.loads(text)


def portrait(path):
    """路径在终端里只显示 ~ 形式；/home/user 这种前缀不打印。"""
    if path is None:
        return None
    home = os.path.expanduser('~')
    text = str(path)
    if home and text.startswith(home + os.sep):
        return '~' + text[len(home):]
    return text


def status_counts(results):
    counts = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for item in results:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts


def overall_status(results):
    counts = status_counts(results)
    if counts[FAIL]:
        return FAIL
    if counts[WARN]:
        return WARN
    return PASS


def verdict_human(results):
    """一句人话结论。"""
    blocking = [r for r in results if r.status == FAIL]
    warnings = [r for r in results if r.status == WARN]
    skipped = [r for r in results if r.status == SKIP]
    if blocking:
        return ('还不能启动：有 %d 项阻断问题需要先解决 —— %s。'
                % (len(blocking), '、'.join(r.name for r in blocking[:4])))
    if warnings:
        return ('本机条件看起来具备，但有 %d 项提醒需要自己确认（%s）。'
                '提醒项通常不影响启动，只影响外网可达性或兼容性。'
                % (len(warnings), '、'.join(r.name for r in warnings[:4])))
    if skipped:
        return '本机条件看起来具备（有 %d 项被跳过，如需确认请补上对应参数）。' % len(skipped)
    return '本机条件看起来具备。注意：这只说明本机能启动服务端，不等于家宽能打通。'


# ============================================================================
# (1) Python 与依赖版本
# ============================================================================

MIN_PYTHON = (3, 10)
DEPENDENCIES = (('aiohttp', 'aiohttp>=3.11,<4'), ('aiortc', 'aiortc>=1.13,<2'),
                ('aioquic', 'aioquic>=1.2,<2'), ('cryptography', 'cryptography'), ('pytest', 'pytest>=8,<9'))


def _package_version(name):
    try:
        from importlib.metadata import version
    except ImportError:  # pragma: no cover - Python 3.10+ 总有 importlib.metadata
        return None
    try:
        return version(name)
    except Exception:
        return None


def check_python_and_deps(min_python=MIN_PYTHON):
    """(1) 解释器版本与运行时依赖。不联网，不装包。"""
    facts = {'executable': os.path.basename(sys.executable or 'python'),
             'python': '.'.join(str(x) for x in sys.version_info[:3]),
             'requiredPython': '.'.join(str(x) for x in min_python)}
    missing, versions = [], {}
    for module, spec in DEPENDENCIES:
        try:
            __import__(module)
            present = True
        except Exception:
            present = False
        if not present:
            missing.append(spec)
            continue
        value = _package_version(module)
        versions[module] = value or '已安装（版本未知）'
    facts['installed'] = versions
    facts['missing'] = missing
    if sys.version_info[:2] < min_python:
        return Result.make('Python 与依赖', FAIL,
                           'Python 版本太低（%s），服务端需要 %s 或更高；请先升级解释器。'
                           % (facts['python'], facts['requiredPython']),
                           code='PYTHON_TOO_OLD', facts=facts)
    if missing:
        return Result.make('Python 与依赖', FAIL,
                           '缺少运行时依赖：%s。请在项目目录执行 pip install -r p2pchat/requirements.txt（体检工具本身不会替你安装）。'
                           % '、'.join(missing), code='DEPS_MISSING', facts=facts)
    return Result.make('Python 与依赖', PASS,
                       'Python %s 正常，运行时依赖齐全（%s）。' % (facts['python'], '、'.join(versions)),
                       facts=facts)


# ============================================================================
# (2)(3) 地址可用性：全局 IPv6 / IPv4 出口
# ============================================================================

def is_global_ipv6(address):
    """可用的全局 IPv6：排除回环、链路本地、组播、未指定，以及 fc00::/7（ULA）。"""
    try:
        ip = ipaddress.ip_address(str(address).split('%')[0])
    except ValueError:
        return False
    if ip.version != 6:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_private:  # 覆盖 fc00::/7 ULA
        return False
    return True


def is_usable_ipv4(address):
    """可用的 IPv4 出口地址：排除回环、组播、未指定、链路本地、保留段。"""
    try:
        ip = ipaddress.ip_address(str(address).split('%')[0])
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local:
        return False
    return True


def _local_addresses():
    """本机地址表（只查本机，不发包）。返回 [(ip, ifname)]。"""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.append((info[4][0], 'hostname'))
    except OSError:
        pass
    # 只读查询：绑定一个未连接的 UDP 套接字看内核对默认出口选哪张网卡，不发任何包。
    for family, probe in ((socket.AF_INET, ('192.0.2.1', 9)), (socket.AF_INET6, ('2001:db8::1', 9))):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect(probe)
                found.append((sock.getsockname()[0], 'default-route'))
        except OSError:
            pass
    return found


def check_global_ipv6(addresses=None):
    """(2) 是否有可用的全局 IPv6 地址。"""
    addresses = _local_addresses() if addresses is None else [(a, 'injected') for a in addresses]
    globals_v6 = sorted({a for a, _ in addresses if is_global_ipv6(a)})
    facts = {'globalIPv6': globals_v6,
             'sawAnyIPv6': sorted({a for a, _ in addresses if ':' in str(a)})}
    if globals_v6:
        return Result.make('全局 IPv6 地址', PASS,
                           '找到全局 IPv6 地址：%s。IPv6 直连有戏，但还需要路由器/运营商放行入站。'
                           % '、'.join(globals_v6[:3]), facts=facts)
    return Result.make('全局 IPv6 地址', WARN,
                       '没有找到可用的全局 IPv6 地址（只有回环/链路本地或干脆没有）。'
                       '这不影响启动：服务端仍可用 IPv4 直连。若想要 IPv6 直连，'
                       '需要在路由器上开启 IPv6 并由运营商下发（常见 CGNAT 家宽可能只有 IPv4）。',
                       code='NO_GLOBAL_IPV6', facts=facts)


def check_ipv4_egress(addresses=None):
    """(3) 是否有 IPv4 出口。"""
    addresses = _local_addresses() if addresses is None else [(a, 'injected') for a in addresses]
    usable = sorted({a for a, _ in addresses if is_usable_ipv4(a)})
    facts = {'ipv4Egress': usable}
    if usable:
        return Result.make('IPv4 出口', PASS,
                           '有 IPv4 出口地址：%s。' % '、'.join(usable[:3]), facts=facts)
    return Result.make('IPv4 出口', WARN,
                       '没有找到可用的 IPv4 出口地址。如果服务器只做 IPv6，这是正常的；'
                       '否则请检查网卡与路由（本工具不会去改网络配置）。',
                       code='NO_IPV4_EGRESS', facts=facts)


# ============================================================================
# (4) TLS 证书与私钥
# ============================================================================

def domain_matches(name, domain):
    """证书名字（CN 或 SAN）是否匹配域名：支持 *.example.com 通配。"""
    if not name or not domain:
        return False
    name, domain = name.strip().lower().rstrip('.'), domain.strip().lower().rstrip('.')
    if name == domain:
        return True
    if name.startswith('*.'):
        suffix = name[2:]
        if not suffix or not domain.endswith('.' + suffix):
            return False
        return '.' not in domain[: -len(suffix) - 1]
    return False


def certificate_facts(cert_path, key_path, domain=None, api_probe=None):
    """读取证书与私钥，返回机器可读事实。api_probe 注入用，默认使用 cryptography。"""
    facts = {'certReadable': False, 'keyReadable': False}
    cert_file, key_file = Path(cert_path), Path(key_path)
    try:
        cert_bytes = cert_file.read_bytes()
        facts['certReadable'] = True
    except OSError as exc:
        facts['certError'] = type(exc).__name__
        return facts
    try:
        key_bytes = key_file.read_bytes()
        facts['keyReadable'] = True
    except OSError as exc:
        facts['keyError'] = type(exc).__name__
        return facts

    if api_probe is not None:
        facts.update(api_probe(cert_bytes, key_bytes, domain) or {})
        return facts

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        facts['certError'] = 'CERT_PARSE_FAILED'
        return facts
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except (ValueError, TypeError):
        facts['keyError'] = 'KEY_PARSE_FAILED_OR_ENCRYPTED'
        return facts

    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:  # pragma: no cover - 兼容旧版 cryptography
        not_after = cert.not_valid_after
        not_before = cert.not_valid_before
    now = time.time()
    facts['notBefore'] = not_before.strftime('%Y-%m-%d %H:%M:%S %Z').strip()
    facts['notAfter'] = not_after.strftime('%Y-%m-%d %H:%M:%S %Z').strip()
    facts['notBeforeMs'] = not_before.timestamp() * 1000
    facts['notAfterMs'] = not_after.timestamp() * 1000
    facts['daysRemaining'] = int((not_after.timestamp() - now) // 86400)
    facts['expired'] = not_after.timestamp() <= now
    facts['notYetValid'] = not_before.timestamp() > now

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = []
    try:
        common = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_names = [a.value for a in common]
    except Exception:  # pragma: no cover - 极老版本 OID 差异
        common_names = []
    facts['dnsNames'] = dns_names
    facts['commonNames'] = common_names
    facts['coversThoseNames'] = False
    if domain:
        facts['domain'] = domain
        candidates = dns_names or common_names
        facts['domainMatched'] = any(domain_matches(name, domain) for name in candidates)
    try:
        cert_public = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        facts['keyMatchesCert'] = cert_public == key_public
    except Exception:  # pragma: no cover - 不支持的密钥类型
        facts['keyMatchesCert'] = None
    return facts


def check_tls(cert_path=None, key_path=None, domain=None, warn_days=14, api_probe=None):
    """(4) 证书与私钥可读、域名匹配、剩余有效期天数。"""
    if not cert_path and not key_path:
        return Result.make('TLS 证书', SKIP,
                           '没有传 --cert/--key：按明文 WebSocket 体检。公网必须用 TLS，'
                           '部署时请带上证书参数重新体检。',
                           code='TLS_NOT_PROVIDED')
    name = 'TLS 证书'
    if bool(cert_path) != bool(key_path):
        return Result.make(name, FAIL, '--cert 与 --key 必须成对提供，只给了一个。',
                           code='TLS_HALF_PAIR')
    facts_in = {'cert': str(cert_path), 'key': str(key_path)}
    paths = (str(cert_path), str(key_path))
    facts = certificate_facts(cert_path, key_path, domain, api_probe=api_probe)
    facts.update({k: v for k, v in facts_in.items() if k not in facts})
    make = lambda status, human, code=None: Result.make(name, status, human, code, facts, paths)  # noqa: E731
    label = os.path.basename(str(cert_path))
    if not facts.get('certReadable'):
        return make(FAIL, '读不到证书文件 %s（%s）。请检查路径与文件权限——体检工具只会读，不会改。'
                    % (label, facts.get('certError')), 'CERT_UNREADABLE')
    if not facts.get('keyReadable'):
        return make(FAIL, '读不到私钥文件 %s（%s）。systemd 以非 root 用户运行时，'
                    '私钥权限必须让该用户可读。' % (os.path.basename(str(key_path)), facts.get('keyError')),
                    'KEY_UNREADABLE')
    if facts.get('certError'):
        return make(FAIL, '证书解析失败（%s）。fullchain.pem 必须是 PEM 格式。' % facts['certError'],
                    'CERT_PARSE_FAILED')
    if facts.get('keyError'):
        return make(FAIL, '私钥解析失败（%s）。加密私钥（有口令）服务端无法启动，请用无口令私钥。'
                    % facts['keyError'], 'KEY_PARSE_FAILED_OR_ENCRYPTED')
    if facts.get('keyMatchesCert') is False:
        return make(FAIL, '私钥与证书不配对：TLS 握手会失败。请用同一套证书的 privkey.pem。',
                    'KEY_CERT_MISMATCH')
    if facts.get('expired'):
        return make(FAIL, '证书已过期（到期时间 %s）。请先续期再启动服务端。'
                    % facts.get('notAfter'), 'CERT_EXPIRED')
    if facts.get('notYetValid'):
        return make(FAIL, '证书还没生效（生效时间 %s）。请检查服务器时钟。'
                    % facts.get('notBefore'), 'CERT_NOT_YET_VALID')
    days = facts.get('daysRemaining')
    names = facts.get('dnsNames') or facts.get('commonNames') or []
    if domain and facts.get('domainMatched') is False:
        return make(FAIL, '证书不包含域名 %s（证书里的名字：%s）。客户端会报证书错误。'
                    % (domain, '、'.join(names[:5]) or '无'),
                    'CERT_DOMAIN_MISMATCH')
    if not domain:
        return make(WARN, '证书可读且未过期（剩余 %s 天），但没有传 --domain，'
                    '无法判断域名是否匹配。请带上 --domain 重新体检。' % days,
                    'CERT_DOMAIN_NOT_CHECKED')
    if isinstance(days, int) and days <= warn_days:
        return make(WARN, '证书 %s 匹配、可读，但只剩 %s 天（到期 %s）。请尽快续期。'
                    % (domain, days, facts.get('notAfter')), 'CERT_EXPIRING_SOON')
    return make(PASS, '证书 %s 匹配域名 %s，私钥可读且配对，剩余 %s 天（到期 %s）。'
                % (label, domain, days, facts.get('notAfter')))


# ============================================================================
# (5) --origin 与客户端实际来源
# ============================================================================

_ORIGIN_RE = re.compile(r'^(https|wss)://[A-Za-z0-9.\-]+(:\d{1,5})?$')


def normalize_origin(value):
    """把 https://host:port/ 之类的写法规整成 Origin 头的比较形式。"""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text == 'null':
        return None
    while text.endswith('/'):
        text = text[:-1]
    return text.lower() or None


def origin_problems(origins, host='127.0.0.1', port=8088):
    """--origin 配置本身的形状问题（不联网）。"""
    problems = []
    if not origins:
        problems.append('EMPTY_ORIGIN')
        return problems
    try:
        loopback = ipaddress.ip_address(host).is_loopback or host == 'localhost'
    except ValueError:
        loopback = host == 'localhost'
    for value in origins:
        normalized = normalize_origin(value)
        if normalized is None:
            problems.append('MALFORMED:%s' % value)
        elif normalized.startswith(('http://', 'ws://')):
            if not loopback:
                problems.append('PUBLIC_BUT_HTTP:%s' % value)
            else:
                problems.append('NOT_HTTPS_ORIGIN:%s' % value)
        elif not _ORIGIN_RE.match(normalized):
            problems.append('NOT_HTTPS_ORIGIN:%s' % value)
    return problems


def check_origin(origins, host='127.0.0.1', port=8088, probe_url=None, timeout=5.0):
    """(5) --origin 配置与客户端实际来源（浏览器 Origin 头）是否一致。"""
    names = list(origins or [])
    facts = {'configured': names, 'compareTo': f'http://{host}:{port}/' if ':' not in host else f'http://[{host}]:{port}/'}
    try:
        loopback = ipaddress.ip_address(host).is_loopback or host == 'localhost'
    except ValueError:
        loopback = host == 'localhost'
    if not names:
        if loopback:
            return Result.make('--origin 配置', WARN,
                               '没有配置 --origin（只监听本机回环时允许）。若要让局域网/公网客户端连接，'
                               '必须配置 --origin，值要等于客户端网页的实际来源，例如 https://p2p.example。',
                               code='ORIGIN_EMPTY_LOOPBACK', facts=facts)
        return Result.make('--origin 配置', FAIL,
                           '监听非回环地址却没有配置 --origin，服务端会直接拒绝启动。'
                           '请加上 --origin https://<客户端的网页来源>。',
                           code='ORIGIN_REQUIRED', facts=facts)

    problems = origin_problems(names, host, port)
    facts['problems'] = problems
    if problems:
        human = {
            'EMPTY_ORIGIN': '--origin 列表为空。',
            'PUBLIC_BUT_HTTP': '监听公网地址却把 --origin 配成了 http://。公网必须 https://。',
            'NOT_HTTPS_ORIGIN': '写法不是 https:// 来源。',
        }
        first = problems[0]
        head = first.split(':', 1)[0]
        detail = '；'.join('%s：%s' % (human.get(p.split(':', 1)[0], '写法有问题'), p.split(':', 1)[-1])
                          if ':' in p else human.get(p, p) for p in problems)
        return Result.make('--origin 配置', FAIL,
                           '--origin 写法有问题（%s）。它必须与浏览器地址栏的来源完全一致，'
                           '公网还必须是 https，包括端口、不带结尾斜杠。' % detail,
                           code=head, facts=facts)

    if probe_url:
        ok, info = _probe_origin(probe_url, timeout)
        facts['probe'] = info
        if not ok:
            return Result.make('--origin 配置', FAIL,
                               '无法探测客户端实际来源 %s（%s）。请确认客户端能打开这个地址，'
                               '并且它就是访问服务端的那个来源（协议 + 主机 + 端口都要一致）。'
                               % (probe_url, info.get('error') or info.get('status')),
                               code='ORIGIN_UNREACHABLE', facts=facts)
        served = normalize_origin(info.get('origin') or '')
        facts['servedOrigin'] = served
        if facts.get('probe', {}).get('redirected'):
            facts['note'] = '探测发生过跳转，比较的是跳转后的地址'
        if served and served not in {normalize_origin(o) for o in names}:
            return Result.make('--origin 配置', FAIL,
                               '客户端实际来源是 %s，但 --origin 配的是 %s，两者不一致：'
                               '浏览器会因 Origin 不匹配被服务端拒绝（403）。'
                               % (served, '、'.join(names)), code='ORIGIN_MISMATCH', facts=facts)
        return Result.make('--origin 配置', PASS,
                           '客户端实际来源 %s 与 --origin 一致。' % served, facts=facts)

    return Result.make('--origin 配置', WARN,
                       '--origin 写法合法（%s），但没有传 --probe-url，没法核对客户端实际来源。'
                       '部署后用浏览器打开客户端页面，确认地址栏来源与这里完全一致（含端口）。'
                       % '、'.join(names), code='ORIGIN_UNVERIFIED', facts=facts)


def _probe_origin(url, timeout):
    import urllib.error
    import urllib.request
    request = urllib.request.Request(url, headers={'User-Agent': 'p2pchat-preflight/1'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 用户显式指定
            # 用最终地址：如果发生过跳转，"客户端实际来源"是跳转后的那个。
            return True, {'status': response.status, 'origin': response.geturl() or url,
                          'requested': url, 'redirected': bool(response.geturl() and response.geturl() != url),
                          'server': response.headers.get('Server', '')}
    except urllib.error.HTTPError as exc:
        # HTTP 错误码也算"这个地址活着"；Origin 头是浏览器发的，和状态码无关。
        return True, {'status': exc.code, 'origin': exc.geturl() or url, 'requested': url}
    except Exception as exc:
        return False, {'error': type(exc).__name__, 'origin': url}


# ============================================================================
# (6) 数据目录可写与权限
# ============================================================================

def check_data_dir(path, probe=None):
    """(6) 数据目录可写。默认建一个随机空文件再立刻删掉。"""
    facts = {'path': str(path)}
    target = Path(path)
    if not target.exists():
        facts['exists'] = False
        return Result.make('数据目录', WARN,
                           '数据目录 %s 还不存在。Store 启动时会自动创建（父目录要可写）。'
                           '建议先手工建好并让 systemd 的运行用户拥有它。' % portrait(target),
                           code='DATA_DIR_MISSING', facts=facts, paths=(str(target),))
    facts['exists'] = True
    if not target.is_dir():
        return Result.make('数据目录', FAIL,
                           '%s 存在但不是目录。请换一个 --data 路径。' % portrait(target),
                           code='DATA_DIR_NOT_DIRECTORY', facts=facts, paths=(str(target),))
    try:
        stat = target.stat()
    except OSError as exc:
        return Result.make('数据目录', FAIL, '无法读取 %s 的属性（%s）。'
                           % (portrait(target), type(exc).__name__), code='DATA_DIR_STAT_FAILED',
                           facts=facts, paths=(str(target),))
    facts['mode'] = oct(stat.st_mode & 0o777)
    facts['ownerMine'] = stat.st_uid == os.getuid()
    if probe is not None:
        writable = bool(probe(target))
    else:
        writable = _dir_writable(target)
    facts['writable'] = writable
    if not writable:
        return Result.make('数据目录', FAIL,
                           '数据目录 %s 当前用户写不进去（权限 %s）。请把 --data 指向一个本用户可写的目录，'
                           '或用 systemd 的运行用户建好它。' % (portrait(target), facts['mode']),
                           code='DATA_DIR_NOT_WRITABLE', facts=facts, paths=(str(target),))
    if stat.st_mode & 0o007:
        return Result.make('数据目录', WARN,
                           '数据目录 %s 可写，但权限是 %s：其他用户也能读中心日志。建议 chmod 700。'
                           % (portrait(target), facts['mode']),
                           code='DATA_DIR_WORLD_ACCESSIBLE', facts=facts, paths=(str(target),))
    return Result.make('数据目录', PASS,
                       '数据目录 %s 可写（权限 %s，属主是本用户）。'
                       % (portrait(target), facts['mode']), facts=facts, paths=(str(target),))


def _dir_writable(target):
    """在数据目录里建一个随机命名的空文件再立刻删掉；不改动任何已有文件。"""
    if not os.access(target, os.W_OK | os.X_OK):
        return False
    try:
        descriptor, probe = tempfile.mkstemp(prefix='.preflight-write-', dir=str(target))
    except OSError:
        return False
    try:
        os.close(descriptor)
    finally:
        try:
            os.unlink(probe)
        except OSError:  # pragma: no cover - 极端竞态
            pass
    return True


# ============================================================================
# (7) 端口可绑定
# ============================================================================

def check_tcp_port(host, port, probe=None, name='信令端口'):
    """(7a) 信令 TCP 端口本地可绑定。"""
    facts = {'host': host, 'port': port}
    if probe is not None:
        bound, code = probe(host, port)
    else:
        bound, code = _try_bind(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM, host, port)
    facts['bindable'] = bound
    if not bound:
        if code == 'IN_USE':
            return Result.make(name, FAIL,
                               '%s:%s 已经被占用，服务端会启动失败。请先停掉占用它的进程（或改 --port）。'
                               % (host, port), code='PORT_IN_USE', facts=facts)
        return Result.make(name, FAIL,
                           '%s:%s 绑定失败（%s）。低于 1024 的端口通常需要额外权限。'
                           % (host, port, code), code='PORT_BIND_FAILED', facts=facts)
    return Result.make(name, PASS, '%s:%s 现在可以绑定。' % (host, port), facts=facts)


def address_family_of(value):
    """把 host 参数归类成 ipv4 / ipv6；域名等未知值返回 None。"""
    try:
        return 'ipv6' if ipaddress.ip_address(str(value)).version == 6 else 'ipv4'
    except ValueError:
        return None


def requested_hosts(raw):
    """--host is repeatable (same semantics as the server's action='append')."""
    if isinstance(raw,str):return [raw] if raw else ['127.0.0.1']
    hosts=[str(h) for h in raw or () if str(h)]
    return hosts or ['127.0.0.1']


def listening_families(hosts):
    """请求的站点头里覆盖了哪些地址族（并集）；域名等未知值不计入。"""
    families = {address_family_of(host) for host in requested_hosts(hosts)}
    return {family for family in families if family}


def _family_label(family):
    return {'ipv4': 'IPv4', 'ipv6': 'IPv6'}.get(family, str(family))


def _join_labels(families):
    return '、'.join(_family_label(family) for family in sorted(families))


def check_family_coverage(hosts, probes=None):
    """按**所有** --host 的并集判定覆盖（服务端单进程多站点，不是"一个 --host 一族"）。

    每个站点的监听套接字仍然是 V6ONLY，所以覆盖范围完全由"你写了几个 --host"决定：
    两族都写才算双栈，只写一族时另一族确实没人服务——这要如实提醒，不要一律报通过。
    """
    hosts = requested_hosts(hosts)
    probes = probes if probes is not None else {
        'ipv4-tcp': check_tcp_port('127.0.0.1', 0, name='ipv4-probe'),
        'ipv6-tcp': check_tcp_port('::1', 0, name='ipv6-probe'),
        'ipv4-udp': check_udp_port('127.0.0.1', 0, name='ipv4-probe'),
        'ipv6-udp': check_udp_port('::1', 0, name='ipv6-probe'),
    }
    families = listening_families(hosts)
    unknown = [host for host in hosts if address_family_of(host) is None]
    facts = {'hosts': hosts, 'families': sorted(families),
             'unknownHosts': unknown,
             'tcp': {'ipv4': probes['ipv4-tcp'].status, 'ipv6': probes['ipv6-tcp'].status},
             'udp': {'ipv4': probes['ipv4-udp'].status, 'ipv6': probes['ipv6-udp'].status}}
    if not families:
        return Result.make('监听地址族', SKIP,
                           '--host 里没有 IP 字面量（%s），没法判断覆盖哪个地址族；'
                           '服务端会按你给的值各建一个站点，请自行确认。' % '、'.join(unknown),
                           code='BIND_FAMILY_UNKNOWN', facts=facts)
    facts['missingFamilies'] = sorted({'ipv4', 'ipv6'} - families)
    if families == {'ipv4', 'ipv6'}:
        note = ''
        if len(hosts) > 2:
            note = '（你给了 %d 个 --host，其中 %d 个不是 IPv4/IPv6 字面量，请自行确认它们是同一个地址族的不同地址）' % (
                len(hosts), len(unknown))
        return Result.make('监听地址族', PASS,
                           '你同时请求了 IPv4 与 IPv6 两个站点（%s）：这就是单进程真双栈——'
                           '每个 --host 一个 V6ONLY 监听站点，两族共用同一端口与同一个数据目录，'
                           '一个服务进程即可。%s' % ('、'.join(hosts), note),
                           facts=facts)
    serving = _join_labels(families)
    missing = _join_labels({'ipv4', 'ipv6'} - families)
    human = ('你只请求了 %s 站点（%s），所以只有 %s 客户端能连上信令；'
             '%s 客户端连不上。要两族都收，就按部署文档再加一个 --host（例如 '
             '--host 0.0.0.0 --host ::）：同一个服务进程里多一个站点，端口与数据目录都不用变。'
             % (serving, '、'.join(hosts), serving, missing))
    if probes['ipv6-tcp'].status == FAIL and 'ipv6' in families:
        facts['note'] = '本机连 IPv6 回环都绑定不了，IPv6 站点可能起不来'
    return Result.make('监听地址族', WARN, human, code='FAMILY_COVERAGE_LIMITED', facts=facts)


# ---------------------------------------------------------------------------
# 实际监听情况：有没有出现与请求不一致的隐式回退（例如 * 监听）
# ---------------------------------------------------------------------------

_WILDCARD_ADDRESSES = {'*', '', '0.0.0.0', '::', '::0', '0:0:0:0:0:0:0:0'}


def parse_listening(entries):
    """解析 ss -lnt 风格的行，返回 [{'family','address','port','raw'}]。

    只做纯文本解析，便于用固定样例测试；不调用 ss。
    """
    parsed = []
    for entry in entries:
        parts = str(entry).split()
        if len(parts) < 4 or parts[0] != 'LISTEN':
            continue  # 表头或非监听行直接跳过
        local = parts[3]
        address, _, port = local.rpartition(':')
        if address.startswith('[') and address.endswith(']'):
            address = address[1:-1]
        family = 'ipv6' if ':' in address else 'ipv4'
        parsed.append({'family': family, 'address': address, 'port': port, 'raw': str(entry)})
    return parsed


def implicit_fallback_listeners(hosts, entries):
    """找出"未指定地址"监听（* / 通配）：请求里没写通配却出现，就是隐式回退。"""
    requested = requested_hosts(hosts)
    wildcard_requested = {host for host in requested if host in _WILDCARD_ADDRESSES}
    found = []
    for item in parse_listening(entries):
        if item['address'] not in _WILDCARD_ADDRESSES:
            continue
        if item['address'] in wildcard_requested:
            continue
        if any(address_family_of(host) == item['family'] for host in requested if host not in _WILDCARD_ADDRESSES):
            continue  # 请求里已有同族的明确地址，通配监听不算"隐式回退"
        found.append(item)
    return found


def listener_families(entries):
    """实际监听的地址族集合；通配监听按"未指定"单列。"""
    families, wildcard = set(), set()
    for item in parse_listening(entries):
        if item['address'] in _WILDCARD_ADDRESSES:
            wildcard.add(item['family'])
        else:
            families.add(item['family'])
    return families, wildcard


PROC_NET = {'ipv4': '/proc/net/tcp', 'ipv6': '/proc/net/tcp6'}
PROC_NET_NOTE = ('/proc/net/tcp{,6} 只有 Linux 有；Windows/macOS 上读不到，本项会退化为'
                 '"连一下回环"的弱探测，并在结论里注明来源')
LISTEN_STATE = '0A'


def _proc_net_listeners(path, family, port):
    """读 /proc/net/tcp{,6}，按端口返回该族的 LISTEN 套接字（ss -lnt 风格的单行）。

    严格只读：只读内核暴露的套接字表，不跑命令、不建连接、不需要 root。
    文件读不到返回 None（表示"不知道"），读出空列表表示"这个族确实没有监听"。
    """
    try:
        lines = Path(path).read_text(encoding='utf8', errors='replace').splitlines()
    except OSError:
        return None
    if not lines:
        return None
    found = []
    peer = '0.0.0.0:*' if family == 'ipv4' else '[::]:*'
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != LISTEN_STATE:
            continue
        try:
            address_hex, port_hex = parts[1].rsplit(':', 1)
            local_port = int(port_hex, 16)
            if local_port != port:
                continue
            packed = bytes.fromhex(address_hex)
            if family == 'ipv4':
                address = socket.inet_ntop(socket.AF_INET, packed[::-1])
                local = '%s:%d' % (address, local_port)
            else:
                # /proc 里每个 32 位组是主机字节序，按组反转后才是网络序。
                address = socket.inet_ntop(socket.AF_INET6, b''.join(packed[i:i + 4][::-1] for i in range(0, 16, 4)))
                local = '[%s]:%d' % (address, local_port)
        except (ValueError, OSError):
            continue
        found.append('LISTEN 0 128 %s %s' % (local, peer))
    return found


def _proc_listen_lines(port, proc_net=None):
    """该端口上的 LISTEN 套接字（两个地址族合并）；两个文件都读不到才返回 None。"""
    proc_net = proc_net or PROC_NET
    collected, read_any = [], False
    for family in ('ipv4', 'ipv6'):
        entries = _proc_net_listeners(proc_net[family], family, port)
        if entries is None:
            continue
        read_any = True
        collected.extend(entries)
    if not read_any:
        return None
    return collected


def check_listeners(hosts, port, entries=None, probe=None, proc_net=None):
    """核对"请求的站点"与"机器上实际在听的套接字"，重点抓隐式回退。

    数据来源依次是：注入的 entries > `/proc/net/tcp{,6}` > 回环连通性探测。
    拿不到任何真实信息时返回 SKIP，不冒充结论。
    """
    hosts = requested_hosts(hosts)
    families = listening_families(hosts)
    facts = {'hosts': hosts, 'port': port}
    if not families:
        return Result.make('实际监听核对', SKIP,
                           '--host 不是 IP 字面量，没法核对实际监听是否与请求一致。',
                           code='LISTEN_FAMILY_UNKNOWN', facts=facts)
    source = None
    if entries is not None:
        source, raw = 'injected', entries
    else:
        raw = _proc_listen_lines(port, proc_net)
        if raw is not None:
            source = '/proc/net/tcp'
    if raw is None and probe is None and source is None:
        probe = _probe_listening_families(hosts, port)
    if raw is None:
        if probe is None:
            return Result.make('实际监听核对', SKIP,
                               '读不到 /proc/net/tcp{,6}（只有 Linux 有），也没有可用的连通性探测，'
                               '无法核对实际监听。请手工执行 `ss -lnt | grep %d`（Windows/macOS 用等价的'
                               '`netstat -an`）对照。' % port,
                               code='LISTEN_STATE_UNKNOWN', facts=facts)
        facts['source'] = 'loopback-connect'
        facts['listeningFamilies'] = sorted(probe)
        return _listener_verdict(hosts, families, set(probe), set(), facts)
    facts['source'] = source
    observed, wildcard = listener_families(raw)
    facts['listeningFamilies'] = sorted(observed)
    facts['wildcardListeners'] = sorted(wildcard)
    facts['listenEntries'] = [item['raw'].strip() for item in parse_listening(raw)][:10]
    fallbacks = implicit_fallback_listeners(hosts, raw)
    facts['implicitFallback'] = [{'family': item['family'], 'address': item['address']} for item in fallbacks]
    return _listener_verdict(hosts, families, observed, wildcard, facts, fallbacks)


def _probe_listening_families(hosts, port):
    """只连回环判断有没有人在听；连不上就代表没人服务。"""
    unique = []
    for host in ['127.0.0.1', '::1'] + [h for h in hosts if h not in {'127.0.0.1', '::1'}]:
        if host not in unique and address_family_of(host) is not None:
            unique.append(host)
    found = set()
    for host in unique:
        family = address_family_of(host)
        if family in found:
            continue
        try:
            sock = socket.socket(socket.AF_INET6 if family == 'ipv6' else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            try:
                sock.connect((host, port))
            finally:
                sock.close()
            found.add(family)
        except OSError:
            continue
    return found


def _listener_verdict(hosts, families, observed, wildcard, facts, fallbacks=()):
    if fallbacks:
        facts['verdict'] = 'IMPLICIT_FALLBACK'
        return Result.make('实际监听核对', WARN,
                           '实际监听里出现了未指定地址的通配监听（%s），而你请求的是 %s：'
                           '信令服务端的每个站点都是 V6ONLY 的明确地址，出现 `*` 通配说明监听方式与 '
                           '`--host 0.0.0.0 --host ::` 的期望不一致，请核对启动参数与实际站点。'
                           % ('、'.join('%s %s' % (_family_label(item['family']), item['address'])
                                       for item in fallbacks), '、'.join(hosts)),
                           code='IMPLICIT_FALLBACK_LISTENER', facts=facts)
    if not observed and not wildcard:
        # 端口上什么都没有：通常只是还没启动服务端，不算问题，也不冒充结论。
        facts['verdict'] = 'NOT_STARTED'
        return Result.make('实际监听核对', SKIP,
                           '端口 %d 上目前没有任何监听：如果你还没启动服务端，这是正常的（部署前体检的常见状态）。'
                           '启动之后再跑一次本项，或手工 `ss -lnt | grep %d`，就能看到每个 --host 一个监听项。'
                           % (facts['port'], facts['port']), code='NOT_LISTENING_YET', facts=facts)
    for family in sorted(families):
        if family not in observed and family not in wildcard:
            facts['verdict'] = 'NOT_LISTENING'
            human = ('实际监听里没有你请求的 %s 站点' % _family_label(family))
            if facts.get('source') == 'loopback-connect':
                human += ('：读不到 /proc/net/tcp{,6}（非 Linux 或被隔离），改为在 %s:%d 上连回环，没人应答'
                          '（端口没在听，或只绑了别的地址）；这一项在 Windows/macOS 上只是弱探测'
                          % ('、'.join(hosts), facts['port']))
            else:
                human += ('（/proc/net/tcp 与 tcp6 在端口 %d 上都没看到）' % facts['port'])
            if wildcard:
                human += '；但能看到未指定地址的监听（%s）' % _join_labels(wildcard)
            return Result.make('实际监听核对', WARN,
                               human + '。服务端启动后应当每个 --host 都有一个监听项（两族站点共用同一端口），'
                               '请核对启动参数：`ss -lnt | grep %d`。' % facts['port'],
                               code='LISTEN_MISSING', facts=facts)
    facts['verdict'] = 'MATCH'
    return Result.make('实际监听核对', PASS,
                       '实际监听的地址族与请求的站点一致（%s），未发现未指定地址的隐式回退监听。'
                       % '、'.join(hosts), facts=facts)


def check_udp_port(host, port, probe=None, name='STUN 端口(UDP)', advertised=False):
    """(7b) STUN 的 UDP 端口本地可绑定。

    advertised=True 表示 --stun-url 已经把外网地址下发给客户端；此时只绑回环地址
    说明外网客户端根本够不着，要提醒而不是给通过。
    """
    facts = {'host': host, 'port': port, 'advertisedToClients': advertised}
    if probe is not None:
        bound, code = probe(host, port)
    else:
        bound, code = _try_bind(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM, host, port)
    facts['bindable'] = bound
    if not bound:
        if code == 'IN_USE':
            return Result.make(name, FAIL,
                               'UDP %s:%s 已被占用，STUN 起不来。请释放该端口（或改 --stun-port）。'
                               % (host, port), code='UDP_PORT_IN_USE', facts=facts)
        return Result.make(name, FAIL, 'UDP %s:%s 绑定失败（%s）。' % (host, port, code),
                           code='UDP_PORT_BIND_FAILED', facts=facts)
    loopback = address_family_of(host) is not None and _is_loopback_literal(host)
    if advertised and loopback:
        facts['onlyLoopback'] = True
        return Result.make(name, WARN,
                           'UDP %s:%s 能绑定，但它只有回环地址：你已经把 --stun-url 下发给客户端了，'
                           '外网客户端却够不着这个 STUN。要让外网观测，请在路由器放行 UDP %s 并加上'
                           ' --stun-host 0.0.0.0 --stun-host ::（两者都要，缺一个就少一个地址族）。'
                           % (host, port, port),
                           code='STUN_ONLY_LOOPBACK', facts=facts)
    return Result.make(name, PASS, 'UDP %s:%s 现在可以绑定。' % (host, port), facts=facts)


def _is_loopback_literal(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == 'localhost'


def _try_bind(family, kind, host, port):
    """用一次性套接字试绑：绑完立刻关，不改宿主的任何状态。

    SO_REUSEADDR 只影响 TIME_WAIT 的残留绑定，不会掩盖"已经有进程在监听"——
    那种情况下 bind 仍然报 EADDRINUSE。
    """
    try:
        with socket.socket(family, kind) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
        return True, None
    except OSError as exc:
        if exc.errno == 98:  # EADDRINUSE
            return False, 'IN_USE'
        return False, '%s(errno=%s)' % (type(exc).__name__, exc.errno)


# ============================================================================
# (8) 本机闭环自检：真实 HMAC + ICE 握手
# ============================================================================

class SelfCheckUnavailable(RuntimeError):
    """环境缺少自检所需的依赖（例如没装 aiortc）。"""


SELF_CHECK_HOSTS = ('127.0.0.1', '::1')


def _free_tcp_port(host):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


async def _self_check_once(data_dir, origin, host, timeout):
    """在给定的回环地址上跑一次真实握手。"""
    from aiohttp import web
    from p2pchat.peer import Peer
    from p2pchat.server import make_app

    port = _free_tcp_port(host)
    app = make_app(str(data_dir), None, [origin] if origin else [])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    url = 'ws://%s:%d/ws' % ('[%s]' % host if ':' in host else host, port)
    room = 'preflight-selfcheck'
    secret = 'preflight-local-only-%s' % os.urandom(16).hex()
    workdir = Path(data_dir) / '_selfcheck'
    workdir.mkdir(parents=True, exist_ok=True)
    peers, tasks, outcome = [], [], {'ok': False, 'reason': None, 'host': host}
    try:
        client = Peer(url, room, secret, 'preflight-client', workdir / 'client', echo=False, origin=origin or None)
        echo = Peer(url, room, secret, 'preflight-echo', workdir / 'echo', echo=True, origin=origin or None)
        peers = [client, echo]
        tasks = [asyncio.create_task(client.run()), asyncio.create_task(echo.run())]
        async with asyncio.timeout(timeout):
            await client.ready.wait()
        path = next((p for p in client.paths.values() if p.get('hello') and p.get('actual')), None)
        if path is None:
            outcome['reason'] = 'NO_AUTHENTICATED_PATH'
        else:
            actual = dict(path['actual'])
            outcome = {'ok': True, 'reason': None, 'host': host, 'profile': path['profile'],
                       'mechanism': 'webrtc', 'actual': actual,
                       'profilesAttempted': sorted({p['profile'] for p in client.paths.values()}),
                       'hmacVerified': True}
    except asyncio.TimeoutError:
        outcome['reason'] = 'TIMEOUT'
    finally:
        for peer in peers:
            try:
                await peer.close()
            except Exception:
                pass
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await runner.cleanup()
        shutil.rmtree(workdir, ignore_errors=True)
    return outcome


async def _self_check_async(data_dir, origin, hosts=SELF_CHECK_HOSTS, timeout=60.0):
    """逐个回环地址尝试，直到有一次真的握上手。

    不要先按 --host 去连：`--host ::` 在部分环境里 ICE 走不通，而这不是部署事故。
    自检只回答"这套代码在本机能不能完成一次真实握手"，所以两种回环都试。
    """
    try:
        from p2pchat.peer import Peer  # noqa: F401 - 早失败，给出可读的缺依赖提示
        from p2pchat.server import make_app  # noqa: F401
    except Exception as exc:
        raise SelfCheckUnavailable('%s: %s' % (type(exc).__name__, exc)) from exc
    attempts, last = [], None
    for host in hosts:
        last = await _self_check_once(Path(data_dir), origin, host, timeout)
        attempts.append({'host': host, 'ok': last['ok'], 'reason': last.get('reason')})
        if last['ok']:
            break
    last['attempts'] = attempts
    return last


def check_self_check(data_dir, origin=None, hosts=SELF_CHECK_HOSTS, timeout=60.0):
    """(8) 可选的本机闭环自检。"""
    facts = {'scope': '本机同机闭环；不是真实家宽证据',
             'needs': 'aiortc + aiohttp（本机回环 UDP/TCP）',
             'loopbackTried': list(hosts)}
    if not data_dir:
        return Result.make('本机闭环自检', SKIP, '未提供 --data 目录，跳过闭环自检。',
                           code='SELF_CHECK_NO_DATA_DIR', facts=facts)
    try:
        outcome = asyncio.run(_self_check_async(Path(data_dir), origin, hosts, timeout))
    except SelfCheckUnavailable as exc:
        facts['error'] = str(exc)
        return Result.make('本机闭环自检', SKIP,
                           '本机缺依赖，无法做闭环自检（%s）。装好 requirements.txt 后重跑。' % exc,
                           code='SELF_CHECK_DEP_UNAVAILABLE', facts=facts)
    except Exception as exc:  # noqa: BLE001 - 自检失败要变成结论而不是崩掉体检
        facts['error'] = '%s: %s' % (type(exc).__name__, exc)
        return Result.make('本机闭环自检', FAIL,
                           '闭环自检异常退出（%s）。这通常意味着代码在本机就跑不通，'
                           '先解决它再谈公网部署。' % facts['error'],
                           code='SELF_CHECK_ERROR', facts=facts)
    facts.update(outcome)
    facts['noSecrets'] = '临时房间密钥只存在于内存与 hold 变量，不写入输出/日志'
    if not outcome.get('ok'):
        return Result.make('本机闭环自检', FAIL,
                           '闭环自检没有完成一次真实握手（原因 %s，回环地址试过 %s）。'
                           '信令/HMAC/ICE 至少有一环在本机就不通，先解决它再谈公网部署。'
                           % (outcome.get('reason'), '、'.join(hosts)),
                           code=outcome.get('reason') or 'SELF_CHECK_FAILED', facts=facts)
    actual = outcome.get('actual') or {}
    family = actual.get('family')
    human = ('闭环自检通过：两个本机 Peer 完成 HMAC 身份校验，ICE 协商成功，'
             '实际使用的方式是 %s（地址族 IPv%s，传输 %s，候选类型 %s），前面还试过 %s；'
             '这次握手用的是回环地址 %s。'
             % (outcome.get('profile'), family, actual.get('protocol'),
                actual.get('candidateType'), '、'.join(outcome.get('profilesAttempted') or []),
                outcome.get('host')))
    return Result.make('本机闭环自检', PASS, human, facts=facts)


# ============================================================================
# 编排与输出
# ============================================================================

def localhost_only(url):
    """只允许探测本机 —— 守边界：体检不替你访问第三方服务。"""
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
    except Exception:
        return False
    if not hostname:
        return False
    if hostname == 'localhost':
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def run_checks(args):
    results = [check_python_and_deps()]
    hosts = requested_hosts(args.host)
    results.append(check_global_ipv6())
    results.append(check_ipv4_egress())
    results.append(check_tls(args.cert, args.key, args.domain))
    if args.probe_url and not localhost_only(args.probe_url):
        results.append(Result.make('--origin 配置', SKIP,
                                   '--probe-url 指向非本机地址，体检工具不会替你访问第三方服务；'
                                   '核对来源请改成从本机执行，或用浏览器自己看地址栏。',
                                   code='PROBE_REFUSED_REMOTE'))
    else:
        results.append(check_origin(args.origin, hosts[0], args.port, args.probe_url))
    if args.data:
        results.append(check_data_dir(args.data))
    for host in hosts:
        results.append(check_tcp_port(host, args.port))
    results.append(check_family_coverage(hosts))
    results.append(check_listeners(hosts, args.port, entries=args.listen_entries))
    for host in args.stun_host or ['127.0.0.1', '::1']:
        results.append(check_udp_port(host, args.stun_port, advertised=bool(args.stun_url)))
    if args.stun_url:
        results.append(check_stun_url(args.stun_url, args.stun_host, args.stun_port))
    if args.self_check:
        results.append(check_self_check(args.data, (args.origin or [None])[0],
                                        SELF_CHECK_HOSTS, args.timeout))
    return results


def check_stun_url(stun_url, stun_hosts, stun_port):
    """用户显式传入的 --stun-url：只检查写法，不主动访问第三方。"""
    facts = {'stunUrl': stun_url, 'advertised': True}
    if not stun_url.startswith('stun:'):
        return Result.make('STUN 地址配置', FAIL,
                           '--stun-url 必须以 stun: 开头（例如 stun:stun.p2p.example:3478）。'
                           'TURN/中继在本产品里是被禁止的。', code='STUN_URL_INVALID', facts=facts)
    if stun_url.startswith('turn:') or stun_url.startswith('turns:'):
        return Result.make('STUN 地址配置', FAIL, 'TURN 中继被禁止，本产品只允许 stun:。',
                           code='RELAY_FORBIDDEN', facts=facts)
    facts['localUdpPort'] = stun_port
    names = stun_hosts or ['127.0.0.1', '::1']
    facts['localUdpHosts'] = names
    if all(_is_loopback_literal(h) for h in names):
        facts['problem'] = 'STUN_BOUND_LOOPBACK_ONLY'
        return Result.make('STUN 地址配置', WARN,
                           '--stun-url 写法合法（%s），但它会把客户端指向你自己；而你现在的 --stun-host'
                           ' 只有回环地址，外网客户端够不着。要么去掉 --stun-url，要么放行 UDP %s 并加上'
                           ' --stun-host 0.0.0.0 --stun-host ::。STUN 只观测映射，不保证打洞成功，'
                           '也不中继数据。' % (stun_url, stun_port),
                           code='STUN_BOUND_LOOPBACK_ONLY', facts=facts)
    return Result.make('STUN 地址配置', PASS,
                       '--stun-url 写法合法（%s）。它会作为客户端要观测的 STUN 地址下发。'
                       '注意：STUN 只观测映射，不保证打洞成功，也不中继数据；本体检不主动去访问它。'
                       % stun_url, facts=facts)


def _listen_entry_lines(raw):
    """--listen-entries 的值：@文件 读文件，其余按一行处理。"""
    lines = []
    for item in raw or ():
        text = str(item)
        if text.startswith('@'):
            try:
                text = Path(text[1:]).read_text(encoding='utf8', errors='replace')
            except OSError as exc:
                lines.append('--listen-entries 读不到 %s（%s）' % (text[1:], type(exc).__name__))
                continue
        lines.extend(part for part in text.splitlines() if part.strip())
    return lines


def _listen_entries_for_port(entries, port):
    """只保留目标端口的行；用户贴了其它端口的行也不要误报。"""
    kept = [line for line in entries if str(line).split()[3:4] and str(line).split()[3].rsplit(':', 1)[-1] == str(port)]
    return kept or None


def render_text(results, args):
    counts = status_counts(results)
    lines = ['', 'P2P 家宽服务器部署前体检（只读，未修改任何系统配置）', '=' * 52]
    for index, item in enumerate(results, 1):
        lines.append('%s %d. %s' % (_TAG.get(item.status, '[?]'), index, item.name))
        for chunk in _wrap(item.human, 2):
            lines.append('   ' + chunk)
    lines.append('-' * 52)
    lines.append('结论：%s' % verdict_human(results))
    lines.append('统计：通过 %d / 提醒 %d / 阻断 %d / 跳过 %d'
                 % (counts[PASS], counts[WARN], counts[FAIL], counts[SKIP]))
    lines.append('边界：本工具只读；不改防火墙/路由/网络，不需要 root，不替你开端口；'
                 '除你显式传入的 --stun-url/--probe-url 外不访问外部服务；'
                 '核对实际监听只读 Linux 的 /proc/net/tcp{,6}（其他平台退化为连一下回环，结论里会注明来源）。')
    lines.append('诚实标注：本仓库未在你家宽服务器上部署过；双 NAT/CGNAT 能否打通必须实测；'
                 'STUN 只观测映射，不保证成功。')
    lines.append('')
    return '\n'.join(lines)


def _wrap(text, indent):
    width = max(40, shutil.get_terminal_size((88, 24)).columns - indent - 2)
    out, line = [], ''
    for token in str(text).split(' '):
        if len(line) + len(token) + 1 > width and line:
            out.append(line)
            line = token
        else:
            line = (line + ' ' + token).strip()
    if line:
        out.append(line)
    return out


def render_json(results, args, include_paths=False):
    payload = {'tool': 'p2pchat.tools.server_preflight', 'generatedAtMs': time.time() * 1000,
               'mode': 'read-only', 'overall': overall_status(results),
               'conclusion': verdict_human(results), 'counts': status_counts(results),
               'checks': [r.to_dict(True) for r in results],
               'disclaimer': '本仓库未在用户家宽服务器上部署过；双 NAT/CGNAT 能否打通必须实测；'
                             'STUN 只观测映射，不保证成功。'}
    if include_paths:
        payload['target'] = {'host': args.host, 'port': args.port, 'stunPort': args.stun_port,
                             'domain': args.domain, 'origins': list(args.origin or [])}
        return json.dumps(payload, ensure_ascii=False, indent=2)
    # 默认脱敏：整个 JSON（含人话结论）里的完整路径都只留文件名。
    paths = {path for result in results for path in result.paths}
    return json.dumps(_strip_paths(payload, paths), ensure_ascii=False, indent=2)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='python -m p2pchat.tools.server_preflight',
        description=(__doc__ or '').splitlines()[0],
        epilog='示例：python -m p2pchat.tools.server_preflight --host 0.0.0.0 --host :: --port 8088 '
               '--cert fullchain.pem --key privkey.pem --origin https://p2p.example '
               '--data ~/p2p-data --self-check')
    parser.add_argument('--host', action='append',
                        help='服务端将监听的地址，可重复（与 server.py 的 --host 一致）：'
                             '--host 0.0.0.0 --host :: 就是单进程真双栈；默认 127.0.0.1')
    parser.add_argument('--port', type=int, default=8088,
                        help='信令/控制 TCP 端口（默认 8088）；所有 --host 站点共用这一个端口')
    parser.add_argument('--stun-port', type=int, default=3478, help='STUN UDP 端口（默认 3478）')
    parser.add_argument('--stun-host', action='append',
                        help='STUN 监听地址，可重复；默认同时试 127.0.0.1 与 ::1')
    parser.add_argument('--stun-url', help='下发给客户端的 STUN 地址（stun:host:port），仅检查写法')
    parser.add_argument('--cert', help='TLS 证书链（fullchain.pem）')
    parser.add_argument('--key', help='TLS 私钥（privkey.pem），只读')
    parser.add_argument('--domain', help='客户端访问用的域名，用于证书匹配检查')
    parser.add_argument('--origin', action='append', default=[],
                        help='服务端 --origin 允许来源，可重复；例如 https://p2p.example')
    parser.add_argument('--probe-url', help='客户端实际来源地址，用于核对 Origin；只允许本机地址')
    parser.add_argument('--data', default=str(Path.home() / 'p2p-data'),
                        help='服务端 --data 数据目录（默认 ~/p2p-data）')
    parser.add_argument('--self-check', action='store_true',
                        help='额外做一次本机闭环自检（临时启动 server+echo+client，真实 HMAC+ICE 握手）')
    parser.add_argument('--timeout', type=float, default=60.0,
                        help='自检每个回环地址的超时秒数（默认 60，先试 127.0.0.1 再试 ::1）')
    parser.add_argument('--json', action='store_true', help='输出机器可读 JSON')
    parser.add_argument('--json-paths', action='store_true',
                        help='JSON 里保留完整路径（默认只保留文件名，避免外泄目录结构）')
    parser.add_argument('--listen-entries', action='append', metavar='LINE',
                        help='高级用法/测试：直接提供 ss -lnt 风格的行（可重复，或用 @文件）。'
                             '默认只读 /proc/net/tcp{,6} 核对实际监听，不修改任何东西')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 1 <= args.stun_port <= 65535:
        parser.error('端口必须在 1..65535 之间')
    args.listen_entries = _listen_entries_for_port(_listen_entry_lines(args.listen_entries), args.port)
    results = run_checks(args)
    if args.json:
        print(render_json(results, args, args.json_paths))
    else:
        print(render_text(results, args))
    return 1 if overall_status(results) == FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
