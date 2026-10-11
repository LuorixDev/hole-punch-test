"""Allowlisted diagnostics. No data retrieval route exists on the control plane."""
import json
import math
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

class Store:
    def __init__(self,directory,max_bytes=100*1024*1024,retention_days=7):
        self.directory=Path(directory); self.directory.mkdir(parents=True,exist_ok=True)
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
