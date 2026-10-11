"""Local-only manual Agent Window integration fixture, never a production route.
Run .venv/bin/python -m p2pchat.tests.integration.browser_lab --port 8098
Open /integration and click connect, then Run real cross-language checks.
Runtime keys/logs stay in ignored p2pchat/data; no committed key or media.
"""
import argparse
import asyncio
import json
from pathlib import Path
import secrets
import sys
import tempfile
from aiohttp import web
from p2pchat.server import make_app

async def main(port):
    root=Path(__file__).resolve().parents[2]
    (root/'data').mkdir(exist_ok=True)
    runtime=Path(tempfile.mkdtemp(prefix='integration-',dir=root/'data'))
    room='联调房间🌏';secret='随机密钥🔐'+secrets.token_hex(16)
    key=runtime/'room.key';key.write_text(secret);key.chmod(0o600)
    blocked={'value':False}
    @web.middleware
    async def pause_control(request,handler):
        if request.path=='/ws' and blocked['value']:raise web.HTTPServiceUnavailable()
        return await handler(request)
    app=make_app(runtime/'central',origins=[f'http://127.0.0.1:{port}'])
    app.middlewares.append(pause_control)
    async def offline(request):
        blocked['value']=True
        peers=list(app['hub'].peers.values())
        for peer in peers:
            if request.query.get('mode')=='all' or peer['name']=='Explorer':await peer['ws'].close()
        return web.json_response({'controlBlocked':True})
    async def restore(request):
        blocked['value']=False
        return web.json_response({'controlBlocked':False})
    app.router.add_post('/integration/offline',offline)
    app.router.add_post('/integration/restore',restore)
    async def page(request):
        html=(root/'web/index.html').read_text()
        setup=json.dumps({'room':room,'secret':secret},ensure_ascii=False)
        extra='<button id="integration-run">Run real cross-language checks</button><pre id="integration-result">NOT RUN — real loopback browser/Python, not home NAT</pre><button id="offline-one">Test one-end signaling outage 60s</button><button id="offline-all">Test both-end signaling outage 60s</button><pre id="offline-result">NOT RUN</pre><button id="retry-check">Test high-ID retry timeout</button><pre id="retry-result">NOT RUN</pre>'
        script=f'<script>const labConfig={setup};document.getElementById("room").value=labConfig.room;document.getElementById("secret").value=labConfig.secret;</script><script src="/integration.js"></script>'
        return web.Response(text=html.replace('</body>',extra+script+'</body>'),content_type='text/html')
    app.router.add_get('/integration',page)
    app.router.add_get('/integration.js',lambda r:web.FileResponse(Path(__file__).with_name('browser_checks.js')))
    runner=web.AppRunner(app);await runner.setup();await web.TCPSite(runner,'127.0.0.1',port).start()
    log=(runtime/'echo.stderr').open('wb')
    echo=await asyncio.create_subprocess_exec(sys.executable,'-m','p2pchat.tests.integration.reordered_echo','--server',f'ws://127.0.0.1:{port}/ws','--room',room,'--secret-file',str(key),'--logs',str(runtime/'echo'),'--origin',f'http://127.0.0.1:{port}',stdout=log,stderr=log)
    print(f'Agent Window URL http://127.0.0.1:{port}/integration | runtime {runtime} | echo PID {echo.pid}',flush=True)
    try:await asyncio.Event().wait()
    finally:
        echo.terminate();await echo.wait();log.close();await runner.cleanup()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8098);asyncio.run(main(p.parse_args().port))
