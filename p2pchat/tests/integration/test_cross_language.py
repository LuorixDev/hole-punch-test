"""JavaScript WebCrypto HMAC compared with actual Python proof and early ACK."""
import asyncio
import json
import secrets
import subprocess
import uuid
import pytest
from p2pchat.peer import Peer, proof

@pytest.mark.asyncio
async def test_unicode_js_python_hmac_and_python_early_ack(tmp_path):
    room='联调房间🌏';secret='随机🔐'+secrets.token_hex(16);cid,aid=str(uuid.uuid4()),str(uuid.uuid4())
    script="const C=require('./p2pchat/web/core.js'); const o=JSON.parse(process.argv[1]); (async()=>{const h=new C.Handshake(o);console.log(JSON.stringify(await h.hello()));})();"
    config=dict(room=room,secret=secret,connectionId=cid,attemptId=aid,localPeerId='js',peerId='py')
    result=subprocess.run(['node','-e',script,json.dumps(config)],capture_output=True,text=True,encoding='utf-8',check=True)
    hello=json.loads(result.stdout);assert hello['proof']==proof(secret,room,cid,aid,'js','py',hello['nonce'])
    peer=Peer('ws://127.0.0.1:1',room,secret,log_dir=tmp_path);peer.id='py'
    p=peer.new_path('js','ice-dual',aid,cid);sent=[];peer.send=lambda path,m:sent.append(m);peer.selected_pair=lambda path:{'family':4,'protocol':'udp','candidateType':'host'}
    ack={**hello,'kind':'hello-ack','echoNonce':p['nonce'],'proof':proof(secret,room,cid,aid,'js','py',hello['nonce'],p['nonce'])}
    try:
        await peer.receive(p,json.dumps(ack));assert not p['hello']
        await peer.receive(p,json.dumps(hello));assert p['hello'] and sent[-1]['kind']=='hello-ack'
        with pytest.raises(ValueError):await peer.receive(p,json.dumps(ack))
    finally:await peer.close()
