"""Allowlisted diagnostics. No data retrieval route exists on the control plane."""
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

EVENTS = {'probe.ack','transfer.complete','client.error','client.boot','path.state','path.stats','session.joined','session.error','session.left','signal.sdp','signal.candidate','stun.binding','transfer.sent','transfer.received','chat.received','chat.echo','peer.ack','task.error','receive.error','receive.queue_overflow','datachannel.open','datachannel.closed','rtc.connection','peer.authenticated_channel','server.error','diagnostic.dropped'}
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

def uid(value):
    if not isinstance(value,str): raise ValueError('SCHEMA_INVALID')
    try: uuid.UUID(value)
    except (ValueError,AttributeError): raise ValueError('SCHEMA_INVALID') from None
    return value

def safe_data(data, strict=True):
    if not isinstance(data,dict): raise ValueError('SCHEMA_INVALID')
    result={}
    for key,value in data.items():
        good = value is None and key in ENUMS | {k:set() for k in NUMBERS}
        if key in ENUMS:
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
ROOM_DIR_SLUG_MAX=32
ROOM_DIR_HASH_CHARS=16
ROOM_DIR_INFO=b'p2pchat/room-dir/v1\0'
_UNSAFE_SLUG=re.compile(r'[^A-Za-z0-9_-]+')


def directory_slug(label,limit=ROOM_DIR_SLUG_MAX):
    """把任意标签压成 ASCII 安全且可读的片段；全被过滤掉时用 'room' 兜底。"""
    text=_UNSAFE_SLUG.sub('-',str(label)).strip('-_')
    return text[:limit].strip('-_') or 'room'


def room_directory_name(room):
    """房间数据目录的**目录名**（不含父目录）：可读片段 + 稳定哈希，ASCII 安全且不碰撞。"""
    digest=hashlib.sha256(ROOM_DIR_INFO+str(room).encode('utf-8')).hexdigest()[:ROOM_DIR_HASH_CHARS]
    return '%s-%s' % (directory_slug(room),digest)


def legacy_room_directory(base,room):
    """旧规则的目录（房间名直接当目录名）——只有里面有数据时才算数。

    非 UTF-8 文件系统编码下，这个名字根本不可能存在于磁盘上（也就无从创建）；
    探测本身也必须是有编码安全的：`os.stat` 在这种平台上会抛 UnicodeEncodeError，
    这里按"旧目录不存在"处理，绝不因此崩溃。
    """
    try:
        candidate=Path(base)/str(room)
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate
    except (UnicodeError,OSError,ValueError):
        return None
    return None


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
    def event(self,scope,peer,kind,data,event_id=None,connection_id=None,attempt_id=None):
        # Server-generated records undergo the same payload allowlist.
        session='00000000-0000-0000-0000-000000000000'
        event={'v':1,'id':event_id or str(uuid.uuid4()),'clientSessionId':session,'seq':0,'tsWallMs':time.time()*1000,'monoMs':time.monotonic()*1000,'connectionId':connection_id,'attemptId':attempt_id,'event':kind if kind in EVENTS else 'session.error','data':safe_data(data,False)}
        self.ingest(scope,peer,session,[event]); return event['id']
    def close(self): self.db.close()

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
