"""Reproducible independent-process LOCAL test, not residential NAT evidence.

python -m pytest p2pchat/tests/backend/test_process_echo.py -q --basetemp=/tmp/p2p-unique-run
Retains test logs and evidence.json beneath basetemp; never writes outputs/.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import uuid
import pytest
from aiohttp import ClientSession
from p2pchat.peer import Peer

def reserve_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
async def until(peer,predicate):
    async with asyncio.timeout(30):
        while True:
            _,message=await peer.received.get()
            if predicate(message):return message

@pytest.mark.asyncio
async def test_separate_signaling_and_echo_processes(tmp_path):
    port=reserve_port();key=tmp_path/'room.key';key.write_text('process-test-room-secret');key.chmod(0o600)
    server_log=(tmp_path/'server.stderr').open('wb');echo_log=(tmp_path/'echo.stderr').open('wb')
    server=await asyncio.create_subprocess_exec(sys.executable,'-m','p2pchat.server','--port',str(port),'--stun-port','0','--data',str(tmp_path/'central'),'--origin','https://p2p.example',stdout=server_log,stderr=server_log)
    echo=None;peer=None;task=None
    try:
        async with asyncio.timeout(10):
            async with ClientSession() as session:
                while True:
                    try:
                        async with session.get(f'http://127.0.0.1:{port}/health') as r:
                            if r.status==200:assert (await r.json())['role']=='signaling-stun';break
                    except OSError:pass
                    await asyncio.sleep(.05)
        echo=await asyncio.create_subprocess_exec(sys.executable,'-m','p2pchat.peer','--server',f'ws://127.0.0.1:{port}/ws','--secret-file',str(key),'--room','process-test','--logs',str(tmp_path/'echo'),'--origin','https://p2p.example',stdout=echo_log,stderr=echo_log)
        peer=Peer(f'ws://127.0.0.1:{port}/ws','process-test',key.read_text(),'client',tmp_path/'client',False,origin='https://p2p.example')
        task=asyncio.create_task(peer.run());await asyncio.wait_for(peer.ready.wait(),30)
        path=next(p for p in peer.paths.values() if p['hello'])
        text='independent local process P2P';mid=str(uuid.uuid4());peer.send(path,{'kind':'text','id':mid,'text':text})
        assert (await until(peer,lambda m:m.get('echoOf')==mid))['text']==text
        results=[]
        for mime,name,data in [('image/png','test.png',b'\x89PNG\r\n'+os.urandom(32000)),('audio/ogg','recording.ogg',b'OggS'+os.urandom(16000)),('application/octet-stream','test.bin',os.urandom(65000))]:
            fid=await peer.send_file(path,data,name,mime)
            answer=await until(peer,lambda m:m.get('kind')=='file' and m.get('echoOf')==fid)
            assert answer['ok'] and answer['sha256']==hashlib.sha256(data).hexdigest()
            results.append({'mime':mime,'bytes':len(data),'integrityOk':True})
        assert server.pid!=echo.pid!=os.getpid()
        assert text not in (tmp_path/'central'/'server.jsonl').read_text()
        (tmp_path/'evidence.json').write_text(json.dumps({'scope':'same-host independent processes; NOT residential/NAT evidence','serverPid':server.pid,'echoPid':echo.pid,'clientPid':os.getpid(),'actual':path['actual'],'textEcho':True,'fileEcho':results},indent=2))
    finally:
        if peer:await peer.close()
        if task:task.cancel();await asyncio.gather(task,return_exceptions=True)
        for process in (echo,server):
            if process and process.returncode is None:
                process.terminate()
                try:await asyncio.wait_for(process.wait(),5)
                except TimeoutError:process.kill();await process.wait()
        server_log.close();echo_log.close()
