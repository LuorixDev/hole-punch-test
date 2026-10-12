"""能力词表守卫：任何客户端声明的 capabilities 必须 ⊆ 服务器 MECHANISMS。

真实事故（t46）：安卓原生曾声明 `capabilities=["webrtc","stun"]`，而服务器
`p2pchat/backend/protocol.py` 的 `MECHANISMS` 里没有 `stun`（stun 是协议/服务，不是打洞
机制）⇒ `protocol.join()` 判 `SCHEMA_INVALID` ⇒ **客户端根本加不进房间**。症状是"连不上"，
不是"少功能"，所以从日志里几乎看不出来——只有把口径钉住才防复发。

这个文件不写文档式检查，而是**真的从各声明点取值**：
* `native/adapter.py`：真跑一遍 `NativeAdapter().capabilities()`（可上报的机制集合）+ 静态
  解析它的 `METHODS` / `GATEWAY_METHODS` 字面量；
* `web/app.js`：解析 `capabilitiesList()`——'webrtc' 字面量 + 桥接里 status==='available'
  的机制（后者的来源就是上面那个适配器，所以这里断言它的形状没被改掉）；
* `android-native/**/*.kt`：正则解析 Kotlin 源码里 `capabilities = listOf(...)` 的字面量；
* `peer.py`：解析 `join_v2(... capabilities=('webrtc',))` 的默认形参；
* `python_desktop/engine.py`：解析 `room_capabilities = ["webrtc"] + [...]` 的字面量与形状。

权威只有一处：`protocol.py` 的 `MECHANISMS`。本文件**不动**协议校验（它是对的），
也不新增 skip；找不到任何声明点时直接失败，而不是跳过。
"""
import asyncio
import re
from pathlib import Path

import pytest

from p2pchat.backend import protocol
from p2pchat.native.adapter import METHODS as ADAPTER_METHODS
from p2pchat.native.adapter import NativeAdapter

ROOT = Path(__file__).resolve().parents[2]              # …/p2pchat
MECHANISMS = protocol.MECHANISMS
# 文档（docs/PROTOCOL.md）与 t54 契约里写死的那 8 个：只作为**下限**钉住，防止误删；
# 将来真要加机制，改 protocol.py 即可（客户端并集会立刻要求同步改，见下方断言）。
DOCUMENTED = {'webrtc', 'udp-probe', 'quic', 'tcp', 'tcp-simopen', 'upnp', 'pcp', 'natpmp'}
CAP_MAX = 8                                             # 协议里 capabilities ≤ 8
DECLARATION_NOT_FOUND = ('没有在 %s 里找到 capabilities 声明：守卫不能空转。'
                         '如果声明点被重命名/搬家，请同步更新本文件的解析，不要删掉这条断言。')


def _string_literals(text, quote):
    """取出字面量；同时兼容两种引号，避免因为格式调整而漏掉声明。"""
    return re.findall(r'%s([A-Za-z0-9_\-]+)%s' % (quote, quote), text)


def kotlin_capability_lists(root=None):
    """(文件, [机制…])：安卓 Kotlin 源码里所有 capabilities 列表字面量（root 可换成注入副本）。"""
    found = []
    for path in sorted(((root or ROOT) / 'android-native').rglob('*.kt')):
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r'capabilities\s*(?::\s*List<String>\s*)?=\s*listOf\(([^)]*)\)', text):
            found.append((str(path.relative_to(root or ROOT)), _string_literals(match.group(1), '"')))
    assert found, DECLARATION_NOT_FOUND % 'android-native/**/*.kt'
    return found


def peer_default_capabilities():
    """peer.py 里 join_v2 的 capabilities 默认形参。"""
    text = (ROOT / 'peer.py').read_text(encoding='utf-8')
    match = re.search(r'capabilities\s*=\s*\(([^)]*)\)', text)
    assert match, DECLARATION_NOT_FOUND % 'peer.py（join_v2 默认形参）'
    values = _string_literals(match.group(1), "'") + _string_literals(match.group(1), '"')
    assert values, DECLARATION_NOT_FOUND % 'peer.py（join_v2 默认形参）'
    return values


def web_capabilities_list():
    """web/app.js 的 capabilitiesList()：返回 (字面量机制, 函数体)。"""
    text = (ROOT / 'web' / 'app.js').read_text(encoding='utf-8')
    match = re.search(r'function capabilitiesList\(\)\{(.*?)\}', text, re.S)
    assert match, DECLARATION_NOT_FOUND % 'web/app.js（capabilitiesList）'
    body = match.group(1)
    hard = re.search(r"window\.RTCPeerConnection\?\[([^\]]*)\]", body)
    assert hard, 'capabilitiesList() 里"浏览器直连"那半的数组字面量不见了，请同步本守卫'
    literals = _string_literals(hard.group(1), "'") + _string_literals(hard.group(1), '"')
    # 形状守卫：动态那半必须仍然只取"桥接里 status==='available' 的机制"，且排除伪机制
    # 'native'（它不是打洞机制）。改掉这段逻辑就得改这里，别让守卫悄悄失效。
    for required in ("m.mechanism!=='native'", "m.status==='available'", '.map(m=>m.mechanism)'):
        assert required in body.replace(' ', ''), ('capabilitiesList() 的构造逻辑变了：%s 不见了。'
                                                   '请确认新逻辑仍只取服务器认识的机制，并同步本守卫。' % required)
    assert "caps.methods" in text or 'caps.methods' in text, 'web 桥接方法表的来源变了（原本来自 caps.methods）'
    return literals, body


def engine_capabilities():
    """python_desktop/engine.py 组装 room_capabilities 那一行的字面量。"""
    text = (ROOT / 'python_desktop' / 'engine.py').read_text(encoding='utf-8')
    match = re.search(r'room_capabilities\s*=\s*\[([^\]]*)\](.*)', text)
    assert match, DECLARATION_NOT_FOUND % 'python_desktop/engine.py（room_capabilities）'
    literals = _string_literals(match.group(1), '"') + _string_literals(match.group(1), "'")
    assert literals, DECLARATION_NOT_FOUND % 'python_desktop/engine.py（room_capabilities）'
    assert 'status") == "available"' in match.group(2) or "status') == 'available'" in match.group(2), \
        'engine.py 里"只加 available 的原生方法"这个条件不见了，请同步确认并更新守卫'
    return literals


def adapter_reported_mechanisms():
    """真跑一遍原生适配器：它现在对外可上报的机制集合（状态无关，名字才是词表）。"""
    entries = asyncio.run(NativeAdapter().capabilities())['methods']
    assert entries, '适配器报告了空的方法表？守卫不能空转'
    return [entry['mechanism'] for entry in entries]


def all_declarations():
    """各客户端真正会声明出去的机制（客户端名 → 机制列表）。"""
    declarations = {}
    for path, values in kotlin_capability_lists():
        declarations['android-native/%s' % Path(path).name] = values
    declarations['peer.py（join_v2 默认）'] = peer_default_capabilities()
    declarations['web/app.js（capabilitiesList 字面量）'] = web_capabilities_list()[0]
    declarations['python_desktop/engine.py（room_capabilities 字面量）'] = engine_capabilities()
    declarations['native/adapter.py（真跑 capabilities()）'] = adapter_reported_mechanisms()
    declarations['native/adapter.py（METHODS 静态）'] = list(ADAPTER_METHODS)
    return declarations


def assert_known(client, mechanisms):
    """核心口径：客户端只许声明服务器认识的机制。"""
    unknown = sorted(set(mechanisms) - MECHANISMS)
    assert not unknown, (
        '%s 声明了服务器不认识的机制 %s —— 服务器会判 SCHEMA_INVALID，客户端**加不进房间**。'
        '要加机制必须同时改 p2pchat/backend/protocol.py 的 MECHANISMS（或从这个客户端的声明里去掉）。'
        % (client, unknown))
    assert len(mechanisms) <= CAP_MAX, ('%s 声明了 %d 个机制，超过协议上限 %d（protocol.join 会拒）'
                                        % (client, len(mechanisms), CAP_MAX))


# ---------------------------------------------------------------------------
# 权威词表
# ---------------------------------------------------------------------------

def test_server_vocabulary_is_the_authority_and_never_loses_a_mechanism():
    assert isinstance(MECHANISMS, set) and len(MECHANISMS) >= 8
    assert DOCUMENTED <= MECHANISMS, '服务器词表少了已发布的机制：%s' % sorted(DOCUMENTED - MECHANISMS)
    assert all(isinstance(name, str) and re.fullmatch(r'[a-z0-9\-]+', name) for name in MECHANISMS), MECHANISMS
    # `stun` 是协议/服务，不是打洞机制：t46 把它写进 capabilities 就是这个事故的根因
    assert 'stun' not in MECHANISMS


def test_protocol_rejects_unknown_mechanism_and_overlong_list():
    """服务端校验本身是对的：未知机制、超长列表都被拒（这是 SCHEMA_INVALID 的真实来源）。"""
    def join(caps):
        return protocol.join({'v': 1, 'type': 'join', 'room': 'r', 'secret': 'abcdefgh', 'name': 'n',
                              'clientSessionId': '11111111-1111-1111-1111-111111111111',
                              'capabilities': caps})
    known = ['webrtc', 'udp-probe', 'quic', 'tcp', 'tcp-simopen', 'upnp', 'pcp', 'natpmp']
    assert join(known[:CAP_MAX]) is None                          # 正好 8 个：可以
    with pytest.raises(ValueError) as too_long:
        join(known + ['webrtc'])
    assert str(too_long.value) == 'SCHEMA_INVALID'
    with pytest.raises(ValueError) as unknown:
        join(['webrtc', 'stun'])                                  # t46 的真缺陷
    assert str(unknown.value) == 'SCHEMA_INVALID'


# ---------------------------------------------------------------------------
# 四端（+ 桌面/适配器）守卫
# ---------------------------------------------------------------------------

def test_every_client_declares_only_known_mechanisms():
    declarations = all_declarations()
    assert declarations, '没有取到任何声明点'
    for client, mechanisms in declarations.items():
        assert_known(client, mechanisms)
        if client.startswith(('android-native', 'peer.py', 'web/', 'python_desktop/')):
            assert mechanisms, '%s 的声明列表是空的？' % client


def test_declared_lists_stay_inside_the_protocol_cap():
    """上限不是注释：每个客户端声明的条数、以及"最坏情况并集"都不能越过 ≤8。"""
    for client, mechanisms in all_declarations().items():
        assert len(mechanisms) <= CAP_MAX, '%s 声明了 %d 条（上限 %d）' % (client, len(mechanisms), CAP_MAX)
    # 桌面/网页的最坏情况 = webrtc + 适配器所有可上报机制（适配器再加一个就顶破上限）
    worst = {'webrtc'} | set(adapter_reported_mechanisms())
    assert len(worst) <= CAP_MAX, ('适配器可上报机制加上 webrtc 会到 %d 条，超过协议上限 %d：'
                                   '新机制要么不进 capabilities，要么先改协议上限'
                                   % (len(worst), CAP_MAX))
    assert worst <= MECHANISMS, '适配器可上报机制里有服务器不认识的：%s' % sorted(worst - MECHANISMS)


def test_adapter_gateway_display_list_is_not_a_join_declaration():
    """`gateway_capability()['mechanisms']` 里有 `upnp-pinhole`，那是给界面/同意的展示项，
    不是加入房间的 capabilities；这里把这条边界钉住，防止有人把它接进 join 列表。"""
    display = set(NativeAdapter().gateway_capability()['mechanisms'])
    assert 'upnp-pinhole' in display                     # 展示项确实含它
    assert display - MECHANISMS == {'upnp-pinhole'}      # 唯一越界项就是它
    assert not (display & set(adapter_reported_mechanisms()) - MECHANISMS), '展示项混进了可上报机制'
    join_lists = [values for client, values in all_declarations().items() if not client.endswith('静态）')]
    assert all('upnp-pinhole' not in values for values in join_lists), 'upnp-pinhole 不该出现在任何加入声明里'


def test_extraction_is_not_vacuous_for_each_client_kind():
    """守卫必须真取到值：任何一端取不到就失败（而不是跳过）。"""
    assert [v for _, v in kotlin_capability_lists()]
    assert peer_default_capabilities() == ['webrtc'] or set(peer_default_capabilities()) <= MECHANISMS
    literals, _ = web_capabilities_list()
    assert 'webrtc' in literals
    assert 'webrtc' in engine_capabilities()
    assert 'webrtc' not in adapter_reported_mechanisms()      # webrtc 由各端自己加，不在适配器方法表里
    assert set(adapter_reported_mechanisms()) <= set(ADAPTER_METHODS)


# ---------------------------------------------------------------------------
# 反向验证：把安卓声明改回 ["webrtc","stun"]（t46 的真缺陷）→ 守卫必须点名
# ---------------------------------------------------------------------------

def test_reverse_verification_flags_the_android_stun_regression(tmp_path):
    """把安卓声明改回 t46 的缺陷形态（追加 "stun"）→ 守卫必须点名客户端与机制。

    这里始终针对**注入副本**跑同一套解析（不动真源码），所以无论当前源码是什么状态，
    这条用例都在证明"守卫拦得住"，而不是在证明"现在恰好是对的"。
    """
    source = (ROOT / 'android-native' / 'app' / 'src' / 'main' / 'java' / 'dev' / 'p2pobservatory' /
              'nativeprobe' / 'SignalingClient.kt')
    assert source.exists(), '找不到安卓声明点：%s' % source
    original = source.read_text(encoding='utf-8')
    declaration = next(re.finditer(r'capabilities\s*(?::\s*List<String>\s*)?=\s*listOf\(([^)]*)\)',
                                   original))
    current = _string_literals(declaration.group(1), '"')
    assert current, '安卓声明里没有机制字面量'
    broken_line = 'capabilities: List<String> = listOf(%s)' % ', '.join(
        ['"%s"' % name for name in current] + ['"stun"'])
    broken = (original[:declaration.start()] + broken_line + original[declaration.end():])
    fake_root = tmp_path / 'p2pchat'
    broken_path = fake_root / 'android-native' / source.relative_to(ROOT / 'android-native')
    broken_path.parent.mkdir(parents=True)
    broken_path.write_text(broken, encoding='utf-8')
    found = kotlin_capability_lists(fake_root)             # 同一套解析，换成注入副本
    assert len(found) == 1, found
    client, mechanisms = found[0]
    assert 'stun' in mechanisms, mechanisms
    with pytest.raises(AssertionError) as failure:
        assert_known('android-native/%s' % Path(client).name, mechanisms)
    message = str(failure.value)
    assert 'stun' in message and 'android' in message.lower(), message
    assert 'MECHANISMS' in message, message
    # 真源码一个字都没动
    assert source.read_text(encoding='utf-8') == original
