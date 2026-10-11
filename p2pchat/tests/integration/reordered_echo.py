"""Test-only Python echo injecting valid early ACK and trickle before SDP."""
import argparse
import asyncio
from pathlib import Path
from p2pchat.peer import Peer

class ReorderedSocket:
    def __init__(self,ws):self.ws=ws
    def __getattr__(self,name):return getattr(self.ws,name)
    async def send_json(self,m):
        if m.get('type')=='signal' and m.get('description'):
            for line in m['description']['sdp'].splitlines():
                if line.startswith('a=candidate:'):
                    early={k:v for k,v in m.items() if k!='description'}
                    early['candidate']={'candidate':line[2:],'sdpMid':'0','sdpMLineIndex':0}
                    await self.ws.send_json(early)
        return await self.ws.send_json(m)

class ReorderedPeer(Peer):
    async def initiate(self,peer):
        if not isinstance(self.ws,ReorderedSocket):self.ws=ReorderedSocket(self.ws)
        await super().initiate(peer)
    async def on_signal(self,m):
        if not isinstance(self.ws,ReorderedSocket):self.ws=ReorderedSocket(self.ws)
        await super().on_signal(m)
    def auth_send(self,path,kind,echo=None):
        if kind=='hello':path['test_held_hello']=True;return
        super().auth_send(path,kind,echo)
        if kind=='hello-ack' and path.pop('test_held_hello',False):
            super().auth_send(path,'hello')

async def main(a):
    peer=ReorderedPeer(a.server,a.room,Path(a.secret_file).read_text(),log_dir=a.logs,origin=a.origin)
    try:await peer.run()
    finally:await peer.close()
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('server','room','secret-file','logs','origin'):p.add_argument('--'+n,required=True)
    asyncio.run(main(p.parse_args()))
