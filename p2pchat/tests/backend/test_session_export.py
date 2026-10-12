"""复盘导出：按 session/attempt 合并跨端时间线，默认脱敏、有界、可流式。

全用真实 Store（真 sqlite 行）验证，没有 mock 冒充：客户端上报的事件走
``Store.ingest``（与线上同一条白名单/校验路径），服务端自己的事件走 ``Store.event``，
另外再直接插一行"旧版本/外来数据"来验证导出端的第二道脱敏（不能只靠入库白名单）。

会话解析规则：`diagnostics` 里客户端上报的行 session 列是 clientSessionId，服务端自己记的
行 session 列是零 uuid、靠 peer（服务端 pid）关联回来；两者按服务端接收时间 + rowid 合并。
"""
import asyncio
import io
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from aiohttp import ClientSession, web

from p2pchat.backend import telemetry
from p2pchat.backend.telemetry import (ENUMS, EVENTS, LIST_KEYS, LOCAL_ONLY_KEYS, NET_ENV_ADDRESS_STABILITY,
                                       NET_ENV_COMPONENTS, NET_ENV_NAT_BEHAVIOR, NET_ENV_RECOMMENDATION,
                                       NET_ENV_STATUS, NET_ENV_UNMEASURED, EXPORT_EVENT, Store, export_session,
                                       mask_address, safe_data, sanitize_event_data, validate_event)
# t49 的真产出：环境体检的真实报告/事件/消息都由它自己生成，测试不手写 telemetry 字典。
from p2pchat.native import nat_behavior as nat
from p2pchat.native import net_env as env
from p2pchat.server import make_app

ROOM_SCOPE = 'scope-room-1'
PEER = 'peer-server-pid-1'
SECRET_TEXT = 'room-secret-hunter2'
TOKEN_TEXT = 'a' * 48
BODY_TEXT = '这是一段不应该被导出的聊天正文'
FILE_TEXT = '私人照片.png'
V6_FULL = '2001:db8:1:2::5'
V4_FULL = '203.0.113.9'


# ---------------------------------------------------------------------------
# 造数据：与线上同路径 + 一行"外来数据"
# ---------------------------------------------------------------------------

def client_event(session, seq, event, data=None, *, connection_id=None, attempt_id=None, ts_wall=None):
    return {'v': 1, 'id': str(uuid.uuid4()), 'clientSessionId': session, 'seq': seq,
            'tsWallMs': time.time() * 1000 if ts_wall is None else ts_wall,
            'monoMs': 100.0 + seq, 'connectionId': connection_id, 'attemptId': attempt_id,
            'event': event, 'data': data or {}}


def seed_session(store, session, *, attempt_id=None, peer=PEER):
    """一条真实感的会话：环境体检 → 各方式尝试/候选 → 结果 → IPv6 回连结论。"""
    connection_id = str(uuid.uuid4())
    attempt_id = attempt_id or str(uuid.uuid4())
    peer_used = peer
    rows = [
        client_event(session, 1, 'client.boot', {'family': 6}),
        client_event(session, 2, 'path.stats', {'mechanism': 'udp-probe', 'family': 6, 'packets': 8},
                     connection_id=connection_id, attempt_id=attempt_id),
        client_event(session, 3, 'path.state', {'state': 'failed', 'reason': 'TIMEOUT',
                                                'mechanism': 'udp-probe', 'family': 6},
                     connection_id=connection_id, attempt_id=attempt_id),
    ]
    store.ingest(ROOM_SCOPE, peer_used, session, rows)
    store.event(ROOM_SCOPE, peer_used, 'signal.candidate',
                {'mechanism': 'webrtc', 'candidateType': 'host', 'family': 6},
                connection_id=connection_id, attempt_id=attempt_id)
    store.event(ROOM_SCOPE, peer_used, 'path.state',
                {'state': 'completed', 'ok': True, 'mechanism': 'tcp', 'protocol': 'tcp',
                 'family': 6, 'rttMs': 12.5},
                connection_id=connection_id, attempt_id=attempt_id)
    return connection_id, attempt_id


def inject_raw_row(store, body, *, session, peer='legacy-peer', received=None):
    """绕过入库白名单直接写一行（模拟旧版本/外来数据），导出端必须自己脱敏。"""
    store.db.execute('INSERT INTO diagnostics VALUES(?,?,?,?,?,?)',
                     (ROOM_SCOPE, session, str(uuid.uuid4()), received or time.time(), peer,
                      json.dumps(body, sort_keys=True, separators=(',', ':'))))
    store.db.commit()


WS_ROOM = 'export-ws-room'
WS_SECRET = 'export-ws-secret'


async def start_hub(directory):
    """真 aiohttp 服务端（只为把 t49 的真消息走一遍真信令链路）。"""
    app = make_app(directory)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    return app, runner, 'ws://127.0.0.1:%d/ws' % site._server.sockets[0].getsockname()[1]


async def connect(session, url):
    """真 join；返回 (ws, pid, clientSessionId)。上报事件必须用这个 clientSessionId。"""
    client_session = str(uuid.uuid4())
    ws = await session.ws_connect(url)
    await ws.send_json({'v': 1, 'type': 'join', 'room': WS_ROOM, 'secret': WS_SECRET, 'name': 'export',
                        'clientSessionId': client_session, 'capabilities': ['webrtc']})
    welcome = await ws.receive_json()
    assert welcome['type'] == 'welcome'
    await ws.receive_json()                       # roster
    return ws, welcome['id'], client_session


async def receive_kind(ws, kind, timeout=10.0):
    async with asyncio.timeout(timeout):
        while True:
            message = await ws.receive_json()
            if message['type'] == kind:
                return message


def parse_jsonl(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def audit_rows(store, kind=EXPORT_EVENT):
    """扫出审计行（Python 侧过滤，不依赖 sqlite 的 JSON1）：返回 (peer, record)。"""
    found = []
    for peer, body in store.db.execute('SELECT peer,body FROM diagnostics'):
        record = json.loads(body)
        if record.get('event') == kind:
            found.append((peer, record))
    return found


# ---------------------------------------------------------------------------
# 合并顺序
# ---------------------------------------------------------------------------

def test_merges_server_and_client_events_with_stable_order(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    # 故意把自报时间戳拧成倒序：合并顺序不能被跨端时钟带偏
    connection_id, attempt_id = seed_session(store, session)
    store.ingest(ROOM_SCOPE, PEER, session, [
        client_event(session, 4, 'client.error', {'reason': 'INTERNAL_ERROR'}, ts_wall=1.0),
        client_event(session, 5, 'path.state', {'state': 'timeout', 'reason': 'TIMEOUT',
                                                'mechanism': 'quic', 'family': 6}, ts_wall=0.5),
    ])
    out = io.StringIO()
    summary = export_session(store, out, session=session)
    entries = [row for row in parse_jsonl(out.getvalue()) if 'kind' not in row]
    assert summary['rows'] == len(entries) == 7
    # 两端事件都在：客户端上报的行（clientSessionId=session）与服务端自己记的行（peer=PEER）
    assert any(row['event'] == 'client.boot' and row['peer'] == PEER for row in entries)
    assert any(row['event'] == 'signal.candidate' and row['peer'] == PEER for row in entries)
    # 环境体检(client.boot/path.stats) 与 IPv6 回连结论(path.state+tcp+rttMs) 都在时间线里
    assert any(row['event'] == 'path.stats' and row['data'].get('mechanism') == 'udp-probe'
               for row in entries)
    assert any(row['event'] == 'path.state' and row['data'].get('mechanism') == 'tcp'
               and row['data'].get('ok') is True and row['data'].get('rttMs') == 12.5 for row in entries)
    assert any(row['data'].get('reason') == 'TIMEOUT' for row in entries)      # 原因码保留
    # 同一来源的 seq 顺序必须保持（自报时间戳乱序也不影响）
    client_seqs = [row['seq'] for row in entries if row['clientSessionId'] == session]
    assert client_seqs == sorted(client_seqs) == [1, 2, 3, 4, 5]
    # 合并基准是服务端接收时间：单调不减
    received = [row['received'] for row in entries]
    assert received == sorted(received)
    # 可重复：再导一次逐字节一致
    # 可重复：固定时钟 + 不写审计（写审计会让时间线合理地多一行）⇒ 逐字节一致
    again = io.StringIO()
    export_session(store, again, session=session, clock=lambda: 1.0, record=False)
    fixed = io.StringIO()
    export_session(store, fixed, session=session, clock=lambda: 1.0, record=False)
    assert again.getvalue() == fixed.getvalue()
    assert (connection_id, attempt_id)  # 两个关联 id 都真用上了


def test_export_by_attempt_covers_both_sides(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    connection_id, attempt_id = seed_session(store, session)
    other = str(uuid.uuid4())
    store.ingest(ROOM_SCOPE, 'other-peer', other, [client_event(other, 1, 'client.boot',
                                                                attempt_id=str(uuid.uuid4()))])
    out = io.StringIO()
    summary = export_session(store, out, attempt=attempt_id)
    entries = [row for row in parse_jsonl(out.getvalue()) if 'kind' not in row]
    assert summary['rows'] == 4          # 该 attempt 下：2 条客户端 + 2 条服务端
    assert {row['attemptId'] for row in entries} == {attempt_id}
    assert all(row['peer'] != 'other-peer' for row in entries)      # 只导出该 attempt


# ---------------------------------------------------------------------------
# 默认脱敏
# ---------------------------------------------------------------------------

def test_default_redaction_covers_secrets_chat_content_and_addresses(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    seed_session(store, session)
    inject_raw_row(store, {'event': 'path.state', 'clientSessionId': session, 'seq': 9,
                           'data': {'state': 'completed', 'secret': SECRET_TEXT, 'token': TOKEN_TEXT,
                                    'proof': 'proof-value', 'privateKey': 'PRIVATE-KEY', 'password': 'pw',
                                    'filename': FILE_TEXT, 'text': BODY_TEXT, 'address': V6_FULL,
                                    'endpoint': '203.0.113.9:443'}},
                    session=session)
    out = io.StringIO()
    export_session(store, out, session=session)
    text = out.getvalue()
    for leaked in (SECRET_TEXT, TOKEN_TEXT, 'proof-value', 'PRIVATE-KEY', 'pw', FILE_TEXT, BODY_TEXT,
                   V6_FULL, V4_FULL):
        assert leaked not in text, leaked
    assert '[redacted]' in text                       # 显式标记而不是默默删掉
    assert '2001:db8::/32' in text and '203.0.113.0/24' in text    # 地址只留前缀
    # 显式同意才保留完整地址
    full = io.StringIO()
    export_session(store, full, session=session, include_addresses=True)
    assert V6_FULL in full.getvalue() and V4_FULL in full.getvalue()
    # 脱敏函数本身也可单测：键保留、值替换
    assert sanitize_event_data({'token': 'x', 'state': 'completed'}) == {'token': '[redacted]',
                                                                        'state': 'completed'}
    # 值形态兜底：48/64 位裸 hex 换个字段名也照样遮；关联标签 endpointTag 必须保留
    assert sanitize_event_data({'someField': 'd' * 48, 'other': 'e' * 64}) == {
        'someField': '[redacted]', 'other': '[redacted]'}
    assert sanitize_event_data({'endpointTag': 'f' * 64}) == {'endpointTag': 'f' * 64}


def test_masked_prefixes_match_client_side_policy():
    import ipaddress
    assert mask_address(ipaddress.ip_address(V6_FULL)) == '2001:db8::/32'
    assert mask_address(ipaddress.ip_address(V4_FULL)) == '203.0.113.0/24'


# ---------------------------------------------------------------------------
# 有界 / 截断 / 流式
# ---------------------------------------------------------------------------

def test_limits_truncate_and_annotate(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    for batch in range(5):
        store.ingest(ROOM_SCOPE, PEER, session,
                     [client_event(session, batch * 10 + i, 'path.stats',
                                   {'mechanism': 'udp-probe', 'family': 6, 'packets': i})
                      for i in range(1, 11)])
    out = io.StringIO()
    summary = export_session(store, out, session=session, limit=7, record=False)
    rows = parse_jsonl(out.getvalue())
    assert summary['rows'] == 7 and summary['totalRows'] == 50 and summary['truncated'] is True
    assert summary['dropped'] == 43
    assert rows[-1]['kind'] == 'export-summary' and rows[-1]['truncated'] is True
    assert len([row for row in rows if 'kind' not in row]) == 7
    # 字节上限：头/尾元信息（几百字节）总写出，正文条目受上限约束并在尾部标注
    tiny = io.StringIO()
    small = export_session(store, tiny, session=session, max_bytes=64, record=False)
    assert small['rows'] == 0 and small['truncated'] is True and small['totalRows'] == 50
    assert json.loads(tiny.getvalue().splitlines()[-1])['kind'] == 'export-summary'
    bounded = io.StringIO()
    medium = export_session(store, bounded, session=session, max_bytes=1500, record=False)
    assert 0 < medium['rows'] < 50 and medium['truncated'] is True
    assert medium['writtenBytes'] <= 1500 + 800          # 正文受 max_bytes 约束，元信息固定少量
    assert all(len(line) < 1500 for line in bounded.getvalue().splitlines())


def test_export_stops_early_instead_of_serializing_everything(tmp_path, monkeypatch):
    """流式+上限的证据：只对写出去的那些行做脱敏/序列化，不会走完整个会话。"""
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    for batch in range(10):
        store.ingest(ROOM_SCOPE, PEER, session,
                     [client_event(session, batch * 10 + i, 'path.stats',
                                   {'mechanism': 'quic', 'family': 6, 'packets': i}) for i in range(1, 11)])
    calls = {'n': 0}
    original = telemetry.sanitize_entry

    def counted(item, include_addresses=False):
        calls['n'] += 1
        return original(item, include_addresses)

    monkeypatch.setattr(telemetry, 'sanitize_entry', counted)
    out = io.StringIO()
    summary = export_session(store, out, session=session, limit=3)
    assert summary['rows'] == 3 and summary['truncated'] is True
    assert calls['n'] <= 4                      # 3 行 + 触界那次就停


# ---------------------------------------------------------------------------
# 失败原因 / 审计 / 入口安全
# ---------------------------------------------------------------------------

def test_missing_target_has_explicit_reason_and_is_audited(tmp_path):
    store = Store(str(tmp_path))
    with pytest.raises(ValueError) as info:
        export_session(store, io.StringIO(), session=str(uuid.uuid4()))
    assert str(info.value) == 'NO_SUCH_SESSION'
    with pytest.raises(ValueError) as info:
        export_session(store, io.StringIO(), attempt=str(uuid.uuid4()))
    assert str(info.value) == 'NO_SUCH_ATTEMPT'
    with pytest.raises(ValueError) as info:
        export_session(store, io.StringIO())
    assert str(info.value) == 'EXPORT_TARGET_REQUIRED'
    with pytest.raises(ValueError) as info:
        export_session(store, io.StringIO(), session='x', format='csv')
    assert str(info.value) == 'EXPORT_FORMAT_INVALID'
    # 失败的导出同样留痕（谁在何时试过导出什么）
    failed = [record for _, record in audit_rows(store)]
    assert failed and all(record['data']['ok'] is False for record in failed)


def test_export_action_is_recorded_and_correlatable(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    seed_session(store, session)
    export_session(store, io.StringIO(), session=session, actor='local-cli:tester')
    audit = audit_rows(store)
    assert len(audit) == 1
    peer, record = audit[0]
    assert record['data']['ok'] is True and record['data']['state'] == 'completed'
    assert record['data']['receivedBytes'] > 0 and record['data']['packets'] == 5
    assert record['data']['messageId'] == session          # 导的是哪个会话
    assert peer == 'local-cli:tester'                      # 谁
    assert record['tsWallMs'] > 0 and record['monoMs'] > 0  # 何时
    # 审计行就在该会话的时间线里：再导一次能看到它
    out = io.StringIO()
    export_session(store, out, session=session)
    entries = [row for row in parse_jsonl(out.getvalue()) if 'kind' not in row]
    assert any(row['event'] == EXPORT_EVENT and row['peer'] == 'local-cli:tester' for row in entries)


def test_other_sessions_export_records_do_not_leak_into_this_timeline(tmp_path):
    """审计行不串会话：导出 A、再导出 B，A 的时间线里不能冒出 B 的导出记录。"""
    store = Store(str(tmp_path))
    session_a, session_b = str(uuid.uuid4()), str(uuid.uuid4())
    seed_session(store, session_a, peer='peer-a')      # 每个会话自己的服务端 pid
    seed_session(store, session_b, peer='peer-b')
    export_session(store, io.StringIO(), session=session_a, actor='local-cli:tester')
    export_session(store, io.StringIO(), session=session_b, actor='local-cli:tester')
    out = io.StringIO()
    summary = export_session(store, out, session=session_a, actor='local-cli:tester')
    entries = [row for row in parse_jsonl(out.getvalue()) if 'kind' not in row]
    audits = [row for row in entries if row['event'] == EXPORT_EVENT]
    assert len(audits) == 1                      # 只有 A 自己的那条（B 的不能串进来）
    assert audits[0]['clientSessionId'] == session_a
    assert not [row for row in entries if (row['data'] or {}).get('messageId') == session_b]
    assert all(row['peer'] in ('peer-a', 'local-cli:tester') for row in entries)
    assert summary['rows'] == len(entries) == 6  # 3 客户端 + 2 服务端 + A 的一条审计


def test_cli_reports_unwritable_output_with_explicit_reason(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    seed_session(store, session)
    store.close()
    proc = subprocess.run([sys.executable, '-m', 'p2pchat.server', '--export-session', session,
                           '--data', str(tmp_path), '--export-out', str(tmp_path / 'nope' / 'out.txt')],
                          capture_output=True, text=True, encoding='utf-8', errors='replace')
    assert proc.returncode == 2 and 'EXPORT_OUTPUT_UNAVAILABLE' in proc.stderr


def test_cli_is_local_only_and_never_binds_or_adds_routes(tmp_path):
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    seed_session(store, session)
    store.close()
    out_file = tmp_path / 'timeline.txt'
    proc = subprocess.run([sys.executable, '-m', 'p2pchat.server', '--export-session', session,
                           '--data', str(tmp_path), '--export-out', str(out_file),
                           '--export-format', 'text'],
                          capture_output=True, text=True, encoding='utf-8', errors='replace')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'exported session=' in proc.stderr and 'signaling listening on' not in proc.stderr
    body = out_file.read_text(encoding='utf-8')
    assert body.startswith('# export-header') and 'path.state' in body
    assert SECRET_TEXT not in body
    # 找不到会话：明确原因 + 非零退出
    missing = subprocess.run([sys.executable, '-m', 'p2pchat.server', '--export-session',
                              str(uuid.uuid4()), '--data', str(tmp_path)],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
    assert missing.returncode == 2 and 'NO_SUCH_SESSION' in missing.stderr
    # 导出不引入任何新路由（更不是中继）
    from p2pchat.server import make_app
    app = make_app(str(tmp_path))
    names = {getattr(resource, 'canonical', '') for resource in app.router.resources()}
    assert not [name for name in names if 'export' in name.lower() or 'relay' in name.lower()]


# ---------------------------------------------------------------------------
# t49 环境体检汇总结论：真产出 → 白名单 → store → 导出时间线
# ---------------------------------------------------------------------------

def netenv_report():
    """跑一次 t49 的真实体检（默认配置：没配观测点 ⇒ 不向任何外部地址发包）。"""
    return asyncio.run(env.health_check(env.NetEnvConfig()))


def project_center_report(report):
    """把 t49 的**真实** center_report()/local_report() 投影成那 10 个白名单键。

    投影只做"搬值"，不发明任何词：状态取自 report，mapping/filtering 取本机观测到的
    NAT 行为词（与 nat_behavior 常量一致），稳定性词取自 AddressRecord.stability() 的真取值，
    未测项清单取自 report['unmeasured']。
    """
    center, local = report.center_report(), report.local_report()
    nat_detail = local['components']['natBehavior']['detail']
    comps = list(center['components'])
    first = 'addresses' if 'addresses' in comps else comps[0]
    stability = sorted({env.AddressRecord(family=6, address='2001:db8::1', scope=scope, is_global=True,
                                          temporary=temp).stability()
                        for scope in ('global', 'host', 'link', 'multicast', 'ula', 'unspecified')
                        for temp in (True, False, None)})
    data = {
        'netEnvOverall': center['overall']['status'],
        'netEnvComponent': first,
        'netEnvStatus': center['components'][first]['status'],
        'netEnvReason': (center['overall']['reasons'] or [center['components'][first]['reason']])[:4],
        'netEnvAddressStability': stability[0],
        'netEnvNat64': center['components']['nat64']['reason'],
        'netEnvRecommendation': center['recommendations'][0]['method'],
        'netEnvUnmeasured': list(center['unmeasured']),
    }
    if nat_detail.get('mapping') in NET_ENV_NAT_BEHAVIOR:
        data['netEnvMapping'] = nat_detail['mapping']
    if nat_detail.get('filtering') in NET_ENV_NAT_BEHAVIOR:
        data['netEnvFiltering'] = nat_detail['filtering']
    return data


def test_netenv_keys_cover_t49_allowlist_and_vocabulary_matches_its_constants():
    """t49 自己列的 allowlistFieldsNeeded 一个不缺；词表与它模块里的常量逐字对齐。"""
    assert set(env.ALLOWLIST_FIELDS_NEEDED) <= set(ENUMS) | set(LIST_KEYS)
    assert set(env.STATUSES) <= NET_ENV_STATUS                      # 组件状态
    assert set(env.RECOMMENDATION_STATUSES) <= NET_ENV_STATUS       # 推荐状态（同一键、两套真词表）
    assert set(env.COMPONENTS) == NET_ENV_COMPONENTS
    assert set(env.METHOD_ORDER) == NET_ENV_RECOMMENDATION
    assert {code for code, _ in env.UNMEASURED} == NET_ENV_UNMEASURED
    assert {nat.MAPPING_ENDPOINT_INDEPENDENT, nat.MAPPING_ADDRESS_DEPENDENT,
            nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT, nat.FILTERING_ENDPOINT_INDEPENDENT,
            nat.FILTERING_ADDRESS_DEPENDENT, nat.FILTERING_ADDRESS_AND_PORT_DEPENDENT,
            nat.UNDETERMINED} == NET_ENV_NAT_BEHAVIOR
    real_stability = {env.AddressRecord(family=6, address='2001:db8::1', scope=scope, is_global=True,
                                        temporary=temp).stability()
                      for scope in ('global', 'host', 'link', 'multicast', 'ula', 'unspecified')
                      for temp in (True, False, None)}
    assert real_stability <= NET_ENV_ADDRESS_STABILITY
    # 没放宽既有语义：老键的越界值照旧被拒
    for bad in ({'state': 'teleporting'}, {'family': 5}, {'ok': 'yes'}, {'rttMs': 'fast'},
                {'mechanism': 'turn'}):
        with pytest.raises(ValueError):
            safe_data(bad, True)


def test_netenv_conclusion_lands_in_store_and_export_verbatim(tmp_path):
    """真报告投影出的结论真的能入库，且值一字不差；导出时间线里也能看到。"""
    report = netenv_report()
    session = str(uuid.uuid4())
    data = project_center_report(report)
    assert set(data) <= set(env.ALLOWLIST_FIELDS_NEEDED)            # 只用了 t49 自己点名的键
    # 信封也是 t49 真产出：拿它自己 center_events() 的第一个事件，只把结论并进 data
    events = report.center_events(session=session, connection_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()))
    event = {**events[0], 'data': {**events[0]['data'], **data}}
    validate_event(event, session)                                  # 服务端严格校验必须先过
    store = Store(str(tmp_path))
    store.ingest(ROOM_SCOPE, PEER, session, [event])
    row = [json.loads(body) for (body,) in store.db.execute('SELECT body FROM diagnostics')][0]
    for key, value in data.items():                                 # 完整保真：不是"能塞进去"就算
        assert row['data'][key] == value, key
    out = io.StringIO()
    export_session(store, out, session=session)
    entries = [item for item in parse_jsonl(out.getvalue()) if 'kind' not in item]
    written = next(item for item in entries if item['event'] == events[0]['event'])
    for key, value in data.items():
        assert written['data'][key] == value, key


@pytest.mark.asyncio
async def test_t49_real_center_message_over_the_wire_lands_in_the_store(tmp_path):
    """真信令链路：t49 的 center_message() 经 /ws 上报 → telemetry_ack → 中心库 → 导出。"""
    report = await env.health_check(env.NetEnvConfig())
    app, runner, url = await start_hub(tmp_path)
    try:
        async with ClientSession() as http:
            ws, pid, session = await connect(http, url)        # 上报必须用 join 时的 clientSessionId
            message = report.center_message(session=session, connection_id=str(uuid.uuid4()),
                                            attempt_id=str(uuid.uuid4()))
            assert message['type'] == 'telemetry' and message['clientSessionId'] == session and message['events']
            await ws.send_json(message)
            ack = await receive_kind(ws, 'telemetry_ack')
            assert ack['clientSessionId'] == session and len(ack['ids']) == len(message['events'])
            await ws.close()
        store = Store(str(tmp_path))
        # 客户端上报的行按 session 列落库；导出时再按 peer 把服务端自己的行合进来
        client_rows = store.db.execute('SELECT COUNT(*) FROM diagnostics WHERE session=?',
                                       (session,)).fetchone()[0]
        assert client_rows == len(message['events'])
        assert store.count_session_rows(session=session) > len(message['events'])
        out = io.StringIO()
        summary = export_session(store, out, session=session)
        entries = [item for item in parse_jsonl(out.getvalue()) if 'kind' not in item]
        kinds = [item['event'] for item in entries]
        # 服务端自己的 session.joined/left 与客户端上报的体检事件在同一条时间线上
        assert 'session.joined' in kinds and 'session.left' in kinds
        for event in message['events']:
            assert event['event'] in kinds
        boot = next(item for item in entries if item['event'] == 'client.boot')
        assert boot['data']['ok'] is True and 'canMessage' in boot['data'] and 'protocol' in boot['data']
        assert summary['byEvent'].get('client.boot') == 1
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# localOnly 边界：不入库、也不出现在导出里
# ---------------------------------------------------------------------------

def local_only_markers():
    """t49 的 LOCAL_ONLY_FIELDS 每个叶子名配一个可搜索的标记值。"""
    return {name: 'MARKER-' + name.replace('.', '-') for name in env.LOCAL_ONLY_FIELDS}


def test_localonly_fields_are_denied_at_ingest_and_redacted_in_export(tmp_path):
    markers = local_only_markers()
    assert len(markers) == len(env.LOCAL_ONLY_FIELDS) >= 10
    for name in env.LOCAL_ONLY_FIELDS:
        leaf = name.split('.')[-1]
        assert leaf in LOCAL_ONLY_KEYS                        # 显式边界，不是"恰好不在白名单"
        assert leaf not in ENUMS and leaf not in LIST_KEYS and leaf not in telemetry.BOOLS
        assert leaf not in telemetry.NUMBERS
    # ① 严格入库：带 localOnly 字段的事件整条被拒（不发出去、也不降级收集）
    for name in env.LOCAL_ONLY_FIELDS:
        with pytest.raises(ValueError):
            safe_data({'family': 6, name.split('.')[-1]: markers[name]}, True)
    # ② 非严格（服务端容错路径）：字段被丢掉，其余保留
    dropped = safe_data({'family': 6, 'canMessage': True, 'records': markers['addresses.records']}, False)
    assert dropped == {'family': 6, 'canMessage': True}
    # ③ 旧版本/外来数据行硬塞进库：导出也必须遮掉（值不出现，键保留为 [redacted]）
    store = Store(str(tmp_path))
    session = str(uuid.uuid4())
    seed_session(store, session)
    inject_raw_row(store, {'event': 'path.state', 'seq': 1,
                           'data': {'state': 'completed', **{k.split('.')[-1]: v for k, v in markers.items()},
                                    'records': markers['addresses.records']}},
                    session=session)
    out = io.StringIO()
    export_session(store, out, session=session)
    text = out.getvalue()
    for name, marker in markers.items():
        assert marker not in text, name
    assert '[redacted]' in text


def test_reverse_verification_without_netenv_overall_the_event_is_rejected(tmp_path, monkeypatch):
    """反向验证：把 `netEnvOverall` 从白名单拿掉，体检结论必须入不了库（白名单是承重的）。"""
    report = netenv_report()
    session = str(uuid.uuid4())
    data = project_center_report(report)
    events = report.center_events(session=session)
    event = {**events[0], 'data': {**events[0]['data'], **data}}
    store = Store(str(tmp_path))
    store.ingest(ROOM_SCOPE, PEER, session, [event])                 # 有键：正常入库
    assert store.count_session_rows(session=session) == 1
    monkeypatch.delitem(ENUMS, 'netEnvOverall')                      # 临时抽掉这一个键
    assert 'netEnvOverall' not in ENUMS
    with pytest.raises(ValueError):
        validate_event(event, session)                               # 严格校验：整条被拒
    with pytest.raises(ValueError):
        Store(str(tmp_path / 'rejected')).ingest(ROOM_SCOPE, PEER, session, [event])
    # 非严格路径也不允许降级收集：字段被丢掉，别的字段还在
    assert 'netEnvOverall' not in safe_data({'state': 'completed', 'netEnvOverall': 'determined'}, False)
    monkeypatch.undo()                                               # 复原
    assert 'netEnvOverall' in ENUMS
    restored = Store(str(tmp_path / 'restored'))
    restored.ingest(ROOM_SCOPE, PEER, session, [event])
    assert restored.count_session_rows(session=session) == 1
