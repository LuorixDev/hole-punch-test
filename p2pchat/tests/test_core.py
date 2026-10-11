import asyncio
import hashlib
import json
import socket
import struct
import uuid
import pytest
from aiohttp import web, ClientSession
from p2pchat.server import make_app, stun_binding, redact
from p2pchat.peer import Peer, frame, unframe, filter_sdp


def test_stun_v4_v6():
    tx=b'0123456789ab'
    req=struct.pack('!HHI',1,0,0x2112a442)+tx
    for address,family,size in [('192.0.2.9',1,32),('2001:db8::9',2,44)]:
        reply=stun_binding(req,(address,47000))
        assert len(reply)==size and reply[8:20]==tx
        assert reply[25]==family
        assert struct.unpack('!H',reply[26:28])[0] ^ 0x2112 ==47000
    assert stun_binding(b'x',('127.0.0.1',1)) is None
    assert stun_binding(req+b'x',('127.0.0.1',1)) is None


def test_redaction_and_frames():
    assert redact({'payload':'hello','nested':{'password':'secret'}})=={'payload':'[redacted]','nested':{'password':'[redacted]'}}
    assert unframe(frame('abc',b'hello'))==('abc',0,b'hello')
    with pytest.raises(ValueError):unframe(b'\0\xffx')
    s='a=candidate:1 1 udp 100 192.0.2.1 4000 typ host\r\na=candidate:2 1 udp 90 2001:db8::1 5000 typ host\r\na=candidate:3 1 udp 10 192.0.2.2 5001 typ relay\r\n'
    assert '192.0.2.1' not in filter_sdp(s,'ice-v6')
    assert 'relay' not in filter_sdp(s,'ice-dual')


@pytest.mark.asyncio
async def test_signaling_rejects_chat_and_bad_room_key(tmp_path):
    app=make_app(tmp_path)
    runner=web.AppRunner(app);await runner.setup()
    site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
    port=site._server.sockets[0].getsockname()[1]
    async with ClientSession() as s:
        a=await s.ws_connect(f'http://127.0.0.1:{port}/ws')
        await a.send_json({'v':1,'type':'join','room':'r','secret':'abcdefgh','name':'a','clientSessionId':str(uuid.uuid4()),'capabilities':['webrtc']})
        assert (await a.receive_json())['type']=='welcome'
        await a.receive_json()
        b=await s.ws_connect(f'http://127.0.0.1:{port}/ws')
        await b.send_json({'v':1,'type':'join','room':'r','secret':'xxxxxxxx','name':'b','clientSessionId':str(uuid.uuid4()),'capabilities':['webrtc']})
        assert (await b.receive_json())['type']=='error'
        await b.close()
        await a.send_json({'v':1,'type':'chat','text':'never relay me'})
        while True:
            m=await a.receive_json()
            if m['type']=='error':break
        assert m['code']=='SCHEMA_INVALID'
        await a.close()
    await runner.cleanup()
    assert 'never relay me' not in (tmp_path/'server.jsonl').read_text()


async def wait_for_message(peer, predicate, timeout=30):
    async with asyncio.timeout(timeout):
        while True:
            source, m=await peer.received.get()
            if predicate(m):return source,m


@pytest.mark.asyncio
async def test_real_webrtc_echo_text_file_and_parallel_paths(tmp_path):
    app=make_app(tmp_path/'hub')
    runner=web.AppRunner(app);await runner.setup()
    site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
    port=site._server.sockets[0].getsockname()[1]
    url=f'ws://127.0.0.1:{port}/ws'
    a=Peer(url,'test','long-secret','Alice',tmp_path/'a',echo=False)
    b=Peer(url,'test','long-secret','Echo',tmp_path/'b',echo=True)
    tasks=[asyncio.create_task(a.run()),asyncio.create_task(b.run())]
    try:
        await asyncio.wait_for(a.ready.wait(),30)
        await asyncio.sleep(.5)
        paths=[p for p in a.paths.values() if p.get('hello') and p.get('dc') and p['dc'].readyState=='open']
        assert paths
        assert {p['profile'] for p in a.paths.values()}=={'ice-v4','ice-v6','ice-dual'}
        path=paths[0]
        identifier=str(uuid.uuid4())
        a.send(path,{'kind':'text','id':identifier,'text':'hello P2P 世界'})
        _,echo=await wait_for_message(a,lambda m:m.get('echoOf')==identifier)
        assert echo['text']=='hello P2P 世界'
        payload=b'P2P binary payload\x00'*4096
        fid=await a.send_file(path,payload,'test.bin','application/octet-stream')
        _,ack=await wait_for_message(a,lambda m:m.get('kind')=='file-ack' and m.get('id')==fid)
        assert ack['ok'] and ack['sha256']==hashlib.sha256(payload).hexdigest()
        _,file=await wait_for_message(a,lambda m:m.get('kind')=='file' and m.get('echoOf')==fid)
        assert file['ok'] and file['sha256']==ack['sha256']
        # Echoing a response must not create another echo.
        a.send(path,{'kind':'text','id':str(uuid.uuid4()),'text':'do not echo','echoOf':identifier})
        await asyncio.sleep(.3)
        assert 'hello P2P 世界' not in (tmp_path/'hub'/'server.jsonl').read_text()
    finally:
        await a.close();await b.close()
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await runner.cleanup()
