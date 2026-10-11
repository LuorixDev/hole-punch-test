import asyncio
from types import SimpleNamespace
import pytest
from aiohttp import ClientSession,WSServerHandshakeError
from p2pchat.server import main
from p2pchat.tests.backend.test_security import start,join_message

@pytest.mark.asyncio
async def test_exact_origin_and_independent_room_auth(tmp_path):
    _,runner,url=await start(tmp_path,origins=['https://p2p.example'])
    try:
        async with ClientSession() as s:
            for origin in (None,'null','https://evil.example'):
                with pytest.raises(WSServerHandshakeError):await s.ws_connect(url,origin=origin)
            a=await s.ws_connect(url,origin='https://p2p.example');await a.send_json(join_message());assert (await a.receive_json())['type']=='welcome';await a.receive_json()
            b=await s.ws_connect(url,origin='https://p2p.example');join=join_message();join['secret']='WRONG-ROOM-SECRET';await b.send_json(join)
            assert (await b.receive_json())['code']=='AUTH_FAILED'
            await a.close();await b.close()
    finally:await runner.cleanup()

@pytest.mark.asyncio
async def test_public_bind_requires_tls_and_origins():
    for cert,key,origins in [(None,None,[]),(None,None,['https://p2p.example']),('cert','key',[])]:
        with pytest.raises(ValueError):await main(SimpleNamespace(host='0.0.0.0',cert=cert,key=key,origin=origins))
