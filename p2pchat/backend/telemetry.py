"""Allowlisted diagnostics. No data retrieval route on the control plane.

客户端环境体检（t49）的汇总结论有一组**专属白名单键**（`netEnv*`，见文件下方
`NET_ENV_*`），每个键只承载它自己那一件事、闭词表或严格形态；t49 标为 localOnly 的字段
（原始地址/网关地址/接口名/mapping·filtering 证据/入站 verdict·note/NAT64 signs/UDP bindings/
errors）**显式拒绝入库**，导出时也一律 [redacted]。

复盘导出（`export_session`）只在本地 CLI 上跑：给定 session/attempt 把服务端与各客户端上报的
事件合并成一条时间线，默认脱敏、有界、流式；不新增任何 HTTP 路由，也不引入中继/转发路径。
"""
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

EVENTS = {'probe.ack','transfer.complete','client.error','client.boot','path.state','path.stats','session.joined','session.error','session.left','signal.sdp','signal.candidate','stun.binding','transfer.sent','transfer.received','chat.received','chat.echo','peer.ack','task.error','receive.error','receive.queue_overflow','datachannel.open','datachannel.closed','rtc.connection','peer.authenticated_channel','server.error','diagnostic.dropped','export.session'}
ENUMS = {
 'state': {'unsupported','gathering','probing','authenticating','direct','failed','timeout','closed','new','connecting','connected','disconnected','completed','checking'},
 'mechanism': {'webrtc','udp-probe','quic','tcp','tcp-simopen','upnp','pcp','natpmp','stun'},
 'profile': {'ice-v6','ice-v4','ice-dual','default'},
 'protocol': {'udp','tcp','quic','sctp','dtls'},
 'candidateType': {'host','srflx','prflx','mapped','relay','unknown'},
 'reason': {'AUTH_FAILED','SCHEMA_INVALID','LIMIT_EXCEEDED','RELAY_FORBIDDEN','PEER_UNAVAILABLE','EVENT_CONFLICT','UNSUPPORTED_VERSION','TIMEOUT','CLOSED','INTEGRITY_FAILED','UNSUPPORTED','INTERNAL_ERROR','ROOM_EXPIRED','ATTEMPT_CONFLICT','ENDPOINT_UNOBSERVABLE'},
 'error': {'AUTH_FAILED','SCHEMA_INVALID','LIMIT_EXCEEDED','RELAY_FORBIDDEN','TIMEOUT','CLOSED','INTEGRITY_FAILED','INTERNAL_ERROR'},
 'family': {4,6,'unknown'},
}
NUMBERS = {'bytes','txBytes','rxBytes','rttMs','goodput','loss','lostPackets','packets','elapsedMs','requestBytes','responseBytes','droppedCount','queuedBytes','receivedBytes','nextSequence','rateBps'}
BOOLS = {'ok','echo','integrityOk','canMessage'}

# ---------------------------------------------------------------------------
# 客户端环境体检（t49）汇总结论的专属键 —— 净新增，不改动上面任何一项
# ---------------------------------------------------------------------------
# 词汇表逐字对齐来源（不发明新词）：
#   p2pchat/native/net_env.py : STATUSES / RECOMMENDATION_STATUSES / COMPONENTS /
#                               METHOD_ORDER / UNMEASURED / AddressRecord.stability()
#   p2pchat/native/nat_behavior.py : MAPPING_* / FILTERING_* / UNDETERMINED
# 每个键只装它自己那一件事，闭词表或严格形态，**不允许把结论塞进无关字段**。
NET_ENV_STATUS = ({'determined', 'insufficient-evidence', 'not-tested', 'unavailable', 'not-applicable'} |
                  # 推荐项的状态词表（net_env.RECOMMENDATION_STATUSES）
                  {'recommended', 'possible', 'unknown'})
# 原因码形态（t49 的组件/推荐项原因码，以及 overall 的 `组件:状态:码` 复合形式）：
# 每段必须字母开头、≤48 字符、最多 3 段。
#   长度上限是从 t49 **真实词表**量出来的，不是拍的：net_env/nat_behavior/ipv6_reach 里所有
#   原因码最长 40（ALTERNATE_ADDRESS_MUST_DIFFER_IN_ADDRESS），紧随其后的是
#   INSUFFICIENT_ADDRESS_OR_ROUTE_EVIDENCE(38) / NAT64_SYNTHESIZED_PROBE_NO_RESPONSE(35) /
#   ROUTE_TABLE_UNREADABLE_ON_PLATFORM(34，**只有非 Linux 路径才会出现**，Windows 上必现)。
#   2026-10 的 Windows CI 就是被这些 >32 的码判成 SCHEMA_INVALID 的，所以这里留 8 个字符余量。
# 形态上装不下地址（数字开头/点号/空段都不行）、装不下密钥赋值（没有 '='），
# 纯 hex（≥32 位裸 token 那种）也被单独挡掉；导出还有 ≥32 位 hex 与 localOnly 兜底。
NET_ENV_TOKEN = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,47}(?::[A-Za-z][A-Za-z0-9_-]{0,47}){0,2}$')
NET_ENV_PURE_HEX = re.compile(r'^[0-9a-f]{8,}$')          # 形态像 token 的整段一律不算原因码
NET_ENV_COMPONENTS = {'addresses', 'routes', 'udpEgress', 'natBehavior', 'inboundReachability',
                      'ipv6Only', 'nat64'}
NET_ENV_NAT_BEHAVIOR = {'endpoint-independent', 'address-dependent', 'address-and-port-dependent',
                        'undetermined'}
NET_ENV_ADDRESS_STABILITY = {'stable', 'temporary', 'unverified', 'not-global'}   # net_env.AddressRecord.stability()
NET_ENV_RECOMMENDATION = {'ipv6-direct', 'gateway-mapping', 'port-prediction'}
NET_ENV_UNMEASURED = {'REAL_NAT_TYPE', 'REAL_IPV6_INBOUND_ALLOWED', 'REAL_PORT_PREDICTION_SUCCESS',
                      'REAL_MULTIPLE_PATHS'}
ENUMS.update({
    'netEnvOverall': NET_ENV_STATUS,
    'netEnvStatus': NET_ENV_STATUS,
    'netEnvComponent': NET_ENV_COMPONENTS,
    'netEnvMapping': NET_ENV_NAT_BEHAVIOR,
    'netEnvFiltering': NET_ENV_NAT_BEHAVIOR,
    'netEnvAddressStability': NET_ENV_ADDRESS_STABILITY,
    'netEnvRecommendation': NET_ENV_RECOMMENDATION,
    'netEnvUnmeasured': NET_ENV_UNMEASURED,
})
# 有界列表 / 单值 token：元素仍受闭词表或严格形态约束（上限 1 = 只收单值、不收数组）。
#   netEnvReason     —— 组件/推荐项的原因码（大写 token，最多 4 条）
#   netEnvUnmeasured —— 未测项清单（闭词表，最多 8 条）
#   netEnvNat64      —— NAT64 结论 token（t49 的 nat64 原因码，单值）
LIST_KEYS = {
    'netEnvReason': (8, None, NET_ENV_TOKEN),          # 最多 7 条（每组件一条）+ 余量
    'netEnvUnmeasured': (8, NET_ENV_UNMEASURED, None),
    'netEnvNat64': (1, None, NET_ENV_TOKEN),
}
# t49 `LOCAL_ONLY_FIELDS` 的叶子名（+ 原样点号形式）：显式拒绝，不做任何降级收集。
LOCAL_ONLY_KEYS = frozenset({
    'records', 'gatewayAddress', 'interfaceNames', 'mapping', 'filtering', 'mappingEvidence',
    'filteringEvidence', 'verdict', 'note', 'signs', 'bindings', 'errors',
    'addresses.records', 'routes.gatewayAddress', 'routes.interfaceNames',
    'natBehavior.mapping', 'natBehavior.filtering', 'natBehavior.mappingEvidence',
    'natBehavior.filteringEvidence', 'inboundReachability.verdict', 'inboundReachability.note',
    'nat64.signs', 'udpEgress.bindings', 'errors',
})

def uid(value):
    if not isinstance(value,str): raise ValueError('SCHEMA_INVALID')
    try: uuid.UUID(value)
    except (ValueError,AttributeError): raise ValueError('SCHEMA_INVALID') from None
    return value

def _not_pure_hex(value):
    """纯 hex 的整串不是原因码（那是 token/哈希的形态）：形态正则放行的长度里再挡一次。"""
    return not NET_ENV_PURE_HEX.match(value)


def safe_data(data, strict=True):
    if not isinstance(data,dict): raise ValueError('SCHEMA_INVALID')
    result={}
    for key,value in data.items():
        if str(key) in LOCAL_ONLY_KEYS:
            # t49 标为 localOnly 的字段：显式拒绝（严格）或丢弃（非严格），绝不入库。
            if strict: raise ValueError('SCHEMA_INVALID')
            continue
        good = value is None and key in ENUMS | {k:set() for k in NUMBERS}
        if key in LIST_KEYS:
            limit,vocab,pattern = LIST_KEYS[key]
            values = value if isinstance(value,list) else [value]
            # 上限 1 的键只收单值：避免把一个结论塞成数组混进去。
            good = (not (limit == 1 and isinstance(value,list)) and 0 < len(values) <= limit and all(
                isinstance(item,str) and not isinstance(item,bool) and _not_pure_hex(item) and
                ((vocab is not None and item in vocab) or (pattern is not None and pattern.match(item)))
                for item in values))
        elif key in ENUMS:
            good = value is None or isinstance(value,(str,int)) and not isinstance(value,bool) and value in ENUMS[key]
        elif key in NUMBERS:
            good = value is None or type(value) in (int,float) and math.isfinite(value) and 0 <= value <= 1e15
        elif key in BOOLS: good = type(value) is bool
        elif key in {'messageId','endpointTag'}:
            good = isinstance(value,str) and ((key=='endpointTag' and len(value)==64 and all(c in '0123456789abcdef' for c in value)) or (key=='messageId' and _is_uuid(value)))
        if not good:
            if strict: raise ValueError('SCHEMA_INVALID')
            continue
        result[key]=value
    return result

def _is_uuid(value):
    try: uid(value); return True
    except ValueError: return False

def validate_event(event,session):
    keys={'v','id','clientSessionId','seq','tsWallMs','monoMs','connectionId','attemptId','event','data'}
    if not isinstance(event,dict) or set(event)!=keys or event['v']!=1 or event['clientSessionId']!=session: raise ValueError('SCHEMA_INVALID')
    uid(session); uid(event['id'])
    for k in ('connectionId','attemptId'):
        if event[k] is not None: uid(event[k])
    for k in ('seq','tsWallMs','monoMs'):
        if type(event[k]) not in (int,float) or not math.isfinite(event[k]) or not 0<=event[k]<=1e15: raise ValueError('SCHEMA_INVALID')
    if type(event['seq']) is not int or event['event'] not in EVENTS: raise ValueError('SCHEMA_INVALID')
    safe_data(event['data'])
    if len(json.dumps(event).encode())>2048: raise ValueError('LIMIT_EXCEEDED')
    return event

# ---------------------------------------------------------------------------
# 房间数据目录命名
# ---------------------------------------------------------------------------
# 取舍（可读性 vs 碰撞）：目录名 = 可读的 ASCII 安全片段 + 房间名的稳定哈希。
#   * 片段只保留 [A-Za-z0-9_-]（其余折叠成 '-'，长度上限 32）：给人眼看，不承担唯一性；
#     两个不同的房间名可能得到同一个片段（例如"房间A"/"房间B"都变成"room"）。
#   * 唯一性由 sha256 前 16 hex（64 bit）承担：**不同房间名绝不同目录**（碰撞概率 2^-64），
#     且与文件系统编码无关——这正是非 UTF-8 编码下也能建目录的原因。
#   * 房间名里可能带 '/'、'..' 之类字符，片段化顺带把它们变成 '-'，不会形成路径穿越。
# 路径里只有房间名与它的哈希，不含密钥/凭据；同一房间名无论 secret 是什么都映射到同一目录。
# 输入归一化也在这里做（room_text）：非 UTF-8 文件系统/语言环境（LC_ALL=C 的容器/CI）下，
# 命令行/环境变量/文件系统交回来的名字是 surrogateescape 形式，调用方不需要也不应该各自处理——
# 归一化只有这一处，未来新增调用方直接传房间名即可。
# **不变量**：正常解码的 `'房间'` 与代理转义形式（`b'房间'.decode('utf-8','surrogateescape')`）
# 必须得到同一个目录名；否则同一个房间会按 locale 分裂成两份历史，比原缺陷更糟。
ROOM_DIR_SLUG_MAX=32
ROOM_DIR_HASH_CHARS=16
ROOM_DIR_INFO=b'p2pchat/room-dir/v1\0'
_UNSAFE_SLUG=re.compile(r'[^A-Za-z0-9_-]+')


def room_text(room):
    """把 locale 交回来的房间名还原成 UTF-8 文本——命名与哈希的**唯一**归一化点。

    非 UTF-8 文件系统/语言环境（LC_ALL=C 的容器/CI）下，`--room 中文` 经 argv、环境变量或
    文件系统交到 Python 手里是 surrogateescape 字符串（每个字节一个代理码位）。这里按
    **原始字节**还原：正常解码的 str 与代理转义形式得到同一串字节 ⇒ 同一目录
    （否则同一个房间会按 locale 分裂成两份历史）。
    还原不出来的字节（不是合法 UTF-8）用 replacement 字符代替，绝不把编码错冒给调用方。
    """
    raw=str(room).encode('utf-8','surrogateescape')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('utf-8','replace')


def directory_slug(label,limit=ROOM_DIR_SLUG_MAX):
    """把任意标签压成 ASCII 安全且可读的片段；全被过滤掉时用 'room' 兜底。"""
    text=_UNSAFE_SLUG.sub('-',str(label)).strip('-_')
    return text[:limit].strip('-_') or 'room'


def room_directory_name(room):
    """房间数据目录的**目录名**（不含父目录）：可读片段 + 稳定哈希，ASCII 安全且不碰撞。

    先经 :func:`room_text` 归一化（代理转义形式与正常解码形式同名同哈希），再算片段与哈希。
    """
    text=room_text(room)
    digest=hashlib.sha256(ROOM_DIR_INFO+text.encode('utf-8')).hexdigest()[:ROOM_DIR_HASH_CHARS]
    return '%s-%s' % (directory_slug(text),digest)


def legacy_room_directory(base,room):
    """旧规则的目录（房间名直接当目录名）——只有里面有数据时才算数。

    两种形式都试，谁先命中算谁（顺序固定，结果确定）：`str(room)` 原样（在非 UTF-8
    文件系统编码下，代理转义形式经 surrogateescape 正好落回磁盘上的真实字节，能认出旧目录）
    与 `room_text(room)` 归一化后的名字（在 UTF-8 文件系统上正常解码的名字）。
    探测与返回都必须编码安全：任何编码错误按"旧目录不存在"处理，绝不因此崩溃；
    命中后只要本机编码放得下就返回归一化形式的路径，使返回值与输入的解码形式无关。
    """
    base=Path(base)
    hit=None
    for text in dict.fromkeys((str(room),room_text(room))):
        try:
            candidate=base/text
            if candidate.is_dir() and any(candidate.iterdir()):
                hit=candidate
                break
        except (UnicodeError,OSError,ValueError):
            continue
    if hit is None:
        return None
    # 两种解码形式可能指向同一个目录：统一返回归一化形式的路径（本机编码放得下时），
    # 使返回值与输入形式无关——否则同一房间会因为 locale 不同而看起来像两个目录。
    canonical=base/room_text(room)
    try:
        os.fsencode(str(canonical))
    except UnicodeEncodeError:
        return hit
    return canonical


def room_directory(base,room,*,prefer_legacy=True):
    """房间数据目录：**优先沿用旧目录**（有数据时），否则用新规则。

    向后兼容策略：
    1. 升级前已有 `base/<房间名>` 且里面有数据 ⇒ 继续用它。历史日志/队列不丢，
       也不会出现"两个目录互相看不到"。
    2. 旧目录不存在、或存在但是空的 ⇒ 用 `base/<片段>-<哈希>` 新规则。
    3. 两种目录同时存在且旧目录有数据 ⇒ 仍然选旧目录（只保留一份历史）。
    调用方把返回值交给 Store/LocalQueue 即可；Store 自己不会静默改名，遇到放不下的
    目录名会明确报 DATA_DIR_NOT_ENCODABLE。
    """
    base=Path(base)
    if prefer_legacy:
        legacy=legacy_room_directory(base,room)
        if legacy is not None:
            return legacy
    return base/room_directory_name(room)


class Store:
    def __init__(self,directory,max_bytes=100*1024*1024,retention_days=7):
        self.directory=Path(directory)
        try:
            self.directory.mkdir(parents=True,exist_ok=True)
        except UnicodeEncodeError as exc:
            # 非 UTF-8 文件系统编码（例如 LC_ALL=C 的容器/CI）放不下这个目录名。
            # 这里不静默改名——那可能把历史拆成两个目录——而是明确失败并指向命名工具。
            raise ValueError('DATA_DIR_NOT_ENCODABLE') from exc
        self.path=self.directory/'server.jsonl'
        self.max_bytes=max_bytes; self.retention=retention_days*86400
        self.db=sqlite3.connect(self.directory/'events.sqlite3')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA auto_vacuum=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS diagnostics(scope TEXT,session TEXT,id TEXT,received REAL,peer TEXT,body TEXT,PRIMARY KEY(scope,session,id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT)')
        self.db.commit()
        self.salt=self.meta('salt',secrets.token_hex(32))
        self._trim()
    def meta(self,key,default):
        self.db.execute('INSERT OR IGNORE INTO metadata VALUES(?,?)',(key,default)); self.db.commit()
        return self.db.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()[0]
    def _trim(self):
        self.db.execute('DELETE FROM diagnostics WHERE received<?',(time.time()-self.retention,))
        # Reserve half the budget for SQLite pages and half for two JSONL segments.
        rows=self.db.execute('SELECT rowid,length(body)+256 FROM diagnostics ORDER BY received DESC').fetchall()
        total=0
        for row,size in rows:
            total+=size
            if total>max(1024,self.max_bytes//8): self.db.execute('DELETE FROM diagnostics WHERE rowid=?',(row,))
        self.db.commit(); self.db.execute('VACUUM')
        for path in (self.path,self.path.with_suffix('.jsonl.1')):
            if path.exists() and path.stat().st_mtime < time.time()-self.retention: path.unlink()
    def _append(self,row):
        if self.path.exists() and self.path.stat().st_size>self.max_bytes//8:
            self.path.replace(self.path.with_suffix('.jsonl.1'))
        with self.path.open('a',encoding='utf8') as f: f.write(json.dumps(row,separators=(',',':'))+'\n')
    def ingest(self,scope,peer,session,events):
        if not isinstance(events,list) or len(events)>30: raise ValueError('LIMIT_EXCEEDED')
        rows=[]
        try:
            for event in events:
                validate_event(event,session)
                body=json.dumps(event,sort_keys=True,separators=(',',':'))
                old=self.db.execute('SELECT body FROM diagnostics WHERE scope=? AND session=? AND id=?',(scope,session,event['id'])).fetchone()
                if old and old[0]!=body: raise ValueError('EVENT_CONFLICT')
                if not old:
                    now=time.time()
                    self.db.execute('INSERT INTO diagnostics VALUES(?,?,?,?,?,?)',(scope,session,event['id'],now,peer,body))
                    rows.append({**event,'peerId':peer,'receivedAtMs':now*1000})
            self.db.commit()
        except Exception:
            self.db.rollback(); raise
        for row in rows: self._append(row)
        self._trim()
        return [e['id'] for e in events]
    def event(self,scope,peer,kind,data,event_id=None,connection_id=None,attempt_id=None,session=None):
        # Server-generated records undergo the same payload allowlist.
        # session=None ⇒ 服务端行的常规归属（零 uuid，靠 peer 关联）；显式传 clientSessionId
        # 时把这条服务端记录直接挂到那个会话上（复盘导出要能一眼看到"谁导出过它"）。
        session=session or '00000000-0000-0000-0000-000000000000'
        event={'v':1,'id':event_id or str(uuid.uuid4()),'clientSessionId':session,'seq':0,'tsWallMs':time.time()*1000,'monoMs':time.monotonic()*1000,'connectionId':connection_id,'attemptId':attempt_id,'event':kind if kind in EVENTS else 'session.error','data':safe_data(data,False)}
        self.ingest(scope,peer,session,[event]); return event['id']
    SERVER_SESSION='00000000-0000-0000-0000-000000000000'
    def session_query(self,session=None,attempt=None):
        """会话/attempt 的行过滤条件（不解包 body：能用列就用列）。

        会话导出 = 该 clientSessionId 上报的行 + 同一 peer（服务端 pid）自己记的行；
        服务端行在 diagnostics 里 session 列是零 uuid，靠 peer 关联回来。
        attempt 过滤用 body 里的 "attemptId":"…"（json 是 sort_keys 序列化的，稳定），
        拿到行之后还会用解析结果复核一次。
        """
        clauses=[];params=[]
        peers=()
        if session:
            # 只把**会话自己上报的行**的 peer 当成服务端 pid 展开；审计行（export.session）
            # 的 peer 是操作者，不能当 pid 用，否则别的会话的导出记录会被串进这条时间线。
            peers=tuple(row[0] for row in self.db.execute(
                "SELECT DISTINCT peer FROM diagnostics WHERE session=? AND body NOT LIKE ?",
                (session,'%"event":"' + EXPORT_EVENT + '"%')))
            marks=','.join('?'*len(peers)) if peers else "''"
            clauses.append('(session=? OR (session=? AND peer IN (%s)))'%marks)
            params.extend([session,self.SERVER_SESSION,*peers])
        if attempt:
            clauses.append("body LIKE ?")
            params.append('%"attemptId":"' + attempt + '"%')
        return (' AND '.join(clauses) if clauses else '1=1'),params,peers
    def count_session_rows(self,session=None,attempt=None):
        where,params,_=self.session_query(session,attempt)
        return int(self.db.execute('SELECT COUNT(*) FROM diagnostics WHERE %s'%where,params).fetchone()[0])
    def iter_session_rows(self,session=None,attempt=None):
        """流式迭代（sqlite 游标逐行）：接收时间 + rowid 稳定序；不把整个会话读进内存。"""
        where,params,_=self.session_query(session,attempt)
        cursor=self.db.execute('SELECT received,peer,session,body FROM diagnostics WHERE %s ORDER BY received,rowid'%where,params)
        for received,peer,session_id,body in cursor:
            try:record=json.loads(body)
            except ValueError:continue
            if attempt and record.get('attemptId')!=attempt:continue     # LIKE 复核
            yield {'received':received,'peer':peer,'session':session_id,'record':record}
    def record_export(self,*,state,actor,rows,bytes_written,dropped,scope='',session=None):
        """导出动作本身入中心日志：谁（peer=actor）何时导出了哪个会话（messageId）/多少。"""
        data={'state':state,'ok':state=='completed','receivedBytes':int(bytes_written),
              'droppedCount':int(dropped),'packets':int(rows)}
        owner=None
        if session:
            try:uid(session)
            except ValueError:pass
            else:
                owner=session;data['messageId']=session
        return self.event(scope or 'export',actor or 'local-cli',EXPORT_EVENT,data,session=owner)
    def close(self): self.db.close()

# ---------------------------------------------------------------------------
# 复盘导出：把服务端自己与各客户端上报的事件按时间合并成一条时间线，默认脱敏
# ---------------------------------------------------------------------------
# 设计要点（为什么这样而不是"读全量再排序"）：
#   * 只读：只用 SELECT，不在导出过程中改任何事件；导出动作本身另记一条 export.session。
#   * 流式：用 sqlite 游标逐行吐，先按服务端**接收时间**（单调，只有它可流式），
#     再按 rowid 稳定排序；事件自报的 tsWallMs/monoMs/seq 原样保留在行里。
#     跨端时钟可能乱序，所以不拿自报时间去排全局顺序，而是保证：同一来源的 seq 顺序
#     一定保持、整个导出可重复（两次导出逐字节一致）。会话级条数/字节数上限内截断并标注。
#   * 默认脱敏：密钥/token/proof/凭据/证书私钥一律替换为 [redacted]（键保留，显式标记），
#     聊天正文/文件名/显示名等隐私字段同样替换；IPv6/IPv4 只保留前缀（IPv6 /32、IPv4 /24），
#     要完整地址必须调用方显式 include_addresses=True（对应客户端的 fullAddressShared 同意）。
EXPORT_EVENT='export.session'
EXPORT_LIMIT_DEFAULT=5000
EXPORT_MAX_BYTES_DEFAULT=2*1024*1024
EXPORT_REDACTED='[redacted]'
EXPORT_FORMATS=('jsonl','text')
# 机密类：任何情况下都不出现在导出里
EXPORT_SECRET_KEYS=frozenset({'secret','roomsecret','room_secret','token','tokens','proof','key','keys',
                              'password','passwd','credential','credentials','authorization','auth',
                              'privatekey','private_key','psk','cert','certificate','certificates',
                              'sessionkey','join_key','joinKey'})
# 隐私类：聊天正文/文件名/显示名——显式标记并默认排除（键保留为 [redacted]）
EXPORT_PRIVATE_KEYS=frozenset({'text','body','content','payload','message','messages','transcript',
                               'filename','file_name','name','mime','sdp','candidate','blob'})
_IPV6_TOKEN=re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z_.\-]+)?(?![0-9A-Fa-f:])')
_IPV4_TOKEN=re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_ADDRESS_TOKEN=re.compile(r'[0-9A-Fa-f:.]{2,45}')
_HEXISH_SECRET=re.compile(r'^[0-9a-fA-F]{32,}$')
# t49 的 localOnly 字段即使来自旧版本/外来数据行，导出也一律遮掉（值不出现，键保留=显式标记）。
EXPORT_LOCAL_ONLY_KEYS=frozenset(name.lower() for name in LOCAL_ONLY_KEYS)   # 导出侧按小写键名比对
# 允许保留的长 hex 值（这些是**关联用的标签/哈希**，不是凭据；token 一定不在其中）
EXPORT_HEX_OK_KEYS=frozenset({'endpointtag'})


def mask_address(value):
    """只保留前缀：IPv6 → /32，IPv4 → /24（与客户端默认不记全地址的口径一致）。"""
    prefix=32 if value.version==6 else 24
    return str(ipaddress.ip_network('%s/%d'%(value,prefix),strict=False))


def mask_text_addresses(text):
    """把字符串里的 IP 字面量换成前缀形式（best effort：IPv4/IPv6 分开匹配，带端口也不漏）。

    先按 IPv6/IPv4 正则替换；再用宽松候选串兜一层（例如 `203.0.113.9:443` 这种被整体
    匹配到的形态，试着去掉尾部的 :port 再解析）。遮蔽失败时**原样保留**，但下面的
    候选兜底会把"看起来像地址"的串交出来，绝不静默通过。
    """
    def masked(token):
        for candidate in (token,token.split('%',1)[0],token.rsplit(':',1)[0] if token.count(':')==1 else token):
            try:return mask_address(ipaddress.ip_address(candidate))
            except ValueError:continue
        return None
    def replace(match):
        return masked(match.group(0)) or match.group(0)
    text=_IPV6_TOKEN.sub(replace,text)
    text=_IPV4_TOKEN.sub(replace,text)
    def fallback(match):
        token=match.group(0)
        return masked(token) or token
    return _ADDRESS_TOKEN.sub(fallback,text)


def _sanitize_value(value,include_addresses,depth=0,key=None):
    if depth>6:return EXPORT_REDACTED
    if value is None or isinstance(value,(bool,int,float)):return value
    if isinstance(value,str):
        # 值形态兜底：48/64 位裸 hex 看着就是 token/proof，除非它是显式放行的关联标签。
        if _HEXISH_SECRET.match(value) and str(key or '').lower() not in EXPORT_HEX_OK_KEYS:
            return EXPORT_REDACTED
        if include_addresses:return value[:2048]
        return mask_text_addresses(value)[:2048]
    if isinstance(value,list):return [_sanitize_value(v,include_addresses,depth+1) for v in value[:64]]
    if isinstance(value,dict):
        out={}
        for key,item in list(value.items())[:64]:
            low=str(key).lower()
            if low in EXPORT_SECRET_KEYS or low in EXPORT_PRIVATE_KEYS or low in EXPORT_LOCAL_ONLY_KEYS:
                out[key]=EXPORT_REDACTED
            else:out[key]=_sanitize_value(item,include_addresses,depth+1,low)
        return out
    return EXPORT_REDACTED


def sanitize_event_data(data,include_addresses=False):
    """按默认策略脱敏一份事件 data（键保留、值替换，便于复盘时知道"这里被遮了"）。

    两道：敏感/隐私键名一律 [redacted]；32 位以上裸 hex 值也一律 [redacted]（换个字段名
    也躲不掉），只有 EXPORT_HEX_OK_KEYS 里的关联标签（endpointTag）保留。
    """
    return _sanitize_value(data if isinstance(data,dict) else {},include_addresses,key='data')


def sanitize_entry(item,include_addresses=False):
    """一行时间线条目：只带可关联字段 + 脱敏后的 data。"""
    record=item.get('record') or {}
    return {'received':round(float(item.get('received',0.0)),3),'peer':item.get('peer'),
            'event':record.get('event'),'id':record.get('id'),'seq':record.get('seq'),
            'tsWallMs':record.get('tsWallMs'),'monoMs':record.get('monoMs'),
            'clientSessionId':record.get('clientSessionId'),
            'connectionId':record.get('connectionId'),'attemptId':record.get('attemptId'),
            'data':sanitize_event_data(record.get('data'),include_addresses)}


def render_entry(entry,format='jsonl'):
    if format=='jsonl':return json.dumps(entry,ensure_ascii=False,separators=(',',':'))+'\n'
    data=entry.get('data') or {}
    pairs=' '.join('%s=%s'%(k,data[k]) for k in sorted(data) if k in
                   {'state','reason','error','mechanism','profile','protocol','family','ok','rttMs',
                    'elapsedMs','droppedCount','receivedBytes','requestBytes','responseBytes',
                    'lostPackets','packets','loss','goodput','candidateType','address','port'})
    # text 视图显示**服务端接收时间**（与排序一致）；事件自报的 tsWallMs/monoMs 在 jsonl 里
    when=time.strftime('%Y-%m-%dT%H:%M:%S',time.gmtime(entry.get('received',0))) if entry.get('received') else '-'
    return '%s peer=%-24s %-24s %s\n'%(when,entry.get('peer') or '-',entry.get('event') or '-',pairs)


def render_note(payload,format='jsonl'):
    """头/尾（元信息与统计）：jsonl 用带 kind 的对象，text 用 # 注释行。"""
    if format=='jsonl':return json.dumps(payload,ensure_ascii=False,separators=(',',':'))+'\n'
    kind=payload.get('kind','note')
    body=' '.join('%s=%s'%(k,v) for k,v in payload.items() if k!='kind')
    return '# %s %s\n'%(kind,body)


class SessionExport:
    """复盘导出的共享外壳：既给 CLI 用，也给测试直接调用（纯只读 + 脱敏 + 有界）。"""
    @staticmethod
    def store_defaults():return {'limit':EXPORT_LIMIT_DEFAULT,'max_bytes':EXPORT_MAX_BYTES_DEFAULT}


def export_session(store,out,*,session=None,attempt=None,limit=EXPORT_LIMIT_DEFAULT,
                   max_bytes=EXPORT_MAX_BYTES_DEFAULT,format='jsonl',include_addresses=False,
                   actor='local-cli',clock=time.time,record=True):
    """把 session/attempt 的跨端事件导出成一条**脱敏、有界、可流式**的时间线。

    * `session`：客户端 clientSessionId（服务端自己记的行按 peer 关联回来）
    * `attempt`：attemptId（可单独用，两个都给就是交集）
    * `format`：'jsonl'（一行一个对象，头尾各一条 kind=export-header/export-summary）
      或 'text'（人读）
    * `limit`/`max_bytes`：条数与字节数上限，超出就截断并在尾部标注（附精确 totalRows）
    * `include_addresses`：默认 False ⇒ IPv6 /32、IPv4 /24；True 才保留完整地址
      （对应客户端 fullAddressShared 的显式同意）
    失败给稳定原因码：EXPORT_TARGET_REQUIRED / EXPORT_FORMAT_INVALID / NO_SUCH_SESSION /
    NO_SUCH_ATTEMPT。无论成败都记一条 export.session（可审计）。返回统计 dict。
    """
    if not session and not attempt:raise ValueError('EXPORT_TARGET_REQUIRED')
    if format not in EXPORT_FORMATS:raise ValueError('EXPORT_FORMAT_INVALID')
    limit=int(limit);max_bytes=int(max_bytes)
    if limit<1 or max_bytes<1:raise ValueError('EXPORT_LIMIT_INVALID')
    total=store.count_session_rows(session,attempt)
    if total==0:
        store.record_export(state='failed',actor=actor,rows=0,bytes_written=0,dropped=0,
                            session=session,scope='')
        raise ValueError('NO_SUCH_SESSION' if session else 'NO_SUCH_ATTEMPT')
    header={'v':1,'kind':'export-header','session':session,'attempt':attempt,'actor':actor,
            'generatedAtMs':round(clock()*1000,3),'includeAddresses':bool(include_addresses),
            'limit':limit,'maxBytes':max_bytes,'order':'received,rowid',
            'redaction':'secrets/credentials/chat-content replaced by [redacted]; addresses masked to prefix',
            'note':'时间线条目按服务端接收时间排序；事件自报 tsWallMs/monoMs/seq 原样保留'}
    out.write(render_note(header,format))
    written=len(render_note(header,format))
    emitted=0;truncated=False;by_event={}
    for item in store.iter_session_rows(session,attempt):
        entry=sanitize_entry(item,include_addresses)
        line=render_entry(entry,format)
        if emitted>=limit or written+len(line)>max_bytes:
            truncated=True
            break
        out.write(line);written+=len(line);emitted+=1
        kind=str(entry.get('event'))
        by_event[kind]=by_event.get(kind,0)+1
    summary={'v':1,'kind':'export-summary','session':session,'attempt':attempt,'rows':emitted,
             'bytes':written,'totalRows':total,'truncated':truncated,
             'dropped':max(0,total-emitted),'byEvent':by_event}
    out.write(render_note(summary,format))
    written+=len(render_note(summary,format))
    if record:
        store.record_export(state='completed',actor=actor,rows=emitted,bytes_written=written,
                            dropped=max(0,total-emitted),session=session)
    return {**summary,'rows':emitted,'writtenBytes':written,'byEvent':by_event}


class LocalQueue(Store):
    def __init__(self,directory,max_events=2000,max_bytes=20*1024*1024):
        super().__init__(directory,max_bytes)
        self.session=self.meta('clientSessionId',str(uuid.uuid4())); self.max_events=max_events
        self.seq=int(self.meta('seq','0')); self.dropped=0
    def emit(self,kind,data,connection_id=None,attempt_id=None):
        self.seq+=1
        event={'v':1,'id':str(uuid.uuid4()),'clientSessionId':self.session,'seq':self.seq,'tsWallMs':time.time()*1000,'monoMs':time.monotonic()*1000,'connectionId':connection_id,'attemptId':attempt_id,'event':kind if kind in EVENTS else 'session.error','data':safe_data(data,False)}
        self.ingest('local','local',self.session,[event])
        self.db.execute("UPDATE metadata SET value=? WHERE key='seq'",(str(self.seq),))
        rows=self.db.execute('SELECT rowid FROM diagnostics ORDER BY received DESC LIMIT -1 OFFSET ?',(self.max_events,)).fetchall()
        self.dropped+=len(rows)
        self.db.executemany('DELETE FROM diagnostics WHERE rowid=?',rows)
        if rows:
            total=int(self.meta('droppedCount','0'))+len(rows)
            self.db.execute("UPDATE metadata SET value=? WHERE key='droppedCount'",(str(total),))
            self._append({**event,'id':str(uuid.uuid4()),'event':'diagnostic.dropped','data':{'droppedCount':total}})
        self.db.commit()
        return event
    def pending(self,limit=30):
        return [json.loads(r[0]) for r in self.db.execute('SELECT body FROM diagnostics ORDER BY received LIMIT ?',(min(limit,30),))]
    def ack(self,session,ids):
        if session!=self.session: return
        self.db.executemany('DELETE FROM diagnostics WHERE scope=? AND session=? AND id=?',[('local',session,i) for i in ids]); self.db.commit()
