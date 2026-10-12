"""房间目录命名接线：服务端与桌面客户端都调用同一实现，旧目录优先，非 UTF-8 编码可用。

被测点是**调用方**（server.py / python_desktop/）而不是命名实现本身（那由
test_telemetry_dir.py 覆盖）。所有导入 aiohttp/aiortc 的产品模块都在**子进程**里跑，
并且子进程一律用 LC_ALL=C + PYTHONUTF8=0 + PYTHONCOERCECLOCALE=0（fs encoding=ascii），
所以在 UTF-8 与 C locale 两种验证跑法下结论一致、可复现。

子进程用 ASCII 符号链接包一层 python/cwd：本机仓库路径含中文时，非 UTF-8 locale 下
第三方扩展的路径编码会变成噪声（CI 的检出路径是 ASCII，不会遇到）。这不是 skip：
两种环境都真跑，脚本里还会打印 fs encoding 供断言。
"""
import contextlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from p2pchat.backend.telemetry import room_directory, room_directory_name

ROOT = Path(__file__).resolve().parents[3]
ROOM = '离线-测试🌏'
LIBRARY_ROOM = 'lab'
SECRET = 'wiring-room-secret'
ROOM_HEX = ROOM.encode('utf-8').hex()          # 子进程跑 C locale：非 ASCII 参数用 hex 传，避免命令行解码
ROOM_NAME = room_directory_name(ROOM)
C_LOCALE = {'LC_ALL': 'C', 'PYTHONUTF8': '0', 'PYTHONCOERCECLOCALE': '0',
            'PYTHONIOENCODING': 'utf-8:backslashreplace'}
DEADLINE = 40.0


def _ascii_path(path):
    """子进程一律跑 C locale（fs encoding=ascii），所以只有纯 ASCII 路径才不会踩到第三方扩展。"""
    try:
        str(path).encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


@contextlib.contextmanager
def _ascii_wrapper():
    """(python, cwd)：路径已经是 ASCII 就原样用，否则用临时目录里的 ASCII 符号链接。"""
    if _ascii_path(ROOT) and _ascii_path(sys.prefix):
        yield sys.executable, str(ROOT)
        return
    sandbox = Path(tempfile.mkdtemp(prefix='p2pwrap-'))
    repo, venv = sandbox / 'repo', sandbox / 'venv'
    repo.symlink_to(ROOT, target_is_directory=True)
    venv.symlink_to(Path(sys.prefix), target_is_directory=True)
    yield str(venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')), str(repo)


def _child_env(cwd, **extra):
    env = dict(os.environ)
    env.update(C_LOCALE)
    env['PYTHONPATH'] = cwd
    env.update(extra)
    return env


def run_script(script, *args, timeout=120):
    with _ascii_wrapper() as (python, cwd):
        return subprocess.run([python, '-c', script, *[str(a) for a in args]], cwd=cwd,
                              env=_child_env(cwd), capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=timeout)


def assert_ok(proc, marker):
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert marker in proc.stdout, proc.stdout + proc.stderr


def as_argv(text):
    """按原始 UTF-8 字节交给子进程的 argv：C locale 的 shell 给的就是这串字节。

    直接传中文在 C-locale 的**父进程**里本身就是 UnicodeEncodeError（父进程 fs encoding=ascii），
    所以先 surrogateescape 成 ASCII 字符，os.fsencode 会把它还原成同一串 UTF-8 字节。
    """
    return text.encode('utf-8').decode('ascii', 'surrogateescape')


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------
# 服务端：data_directory() 用共享实现 + 旧目录优先 + 不静默改名
# ---------------------------------------------------------------------------

SERVER_SCRIPT = r'''
# Child source must stay ASCII-only: a C-locale interpreter cannot run a -c command
# that contains non-ASCII bytes, and the room name is passed as hex anyway.
import os, sys
from pathlib import Path
from p2pchat.backend.telemetry import Store, room_directory, room_directory_name
from p2pchat.server import data_directory

base = Path(sys.argv[1])
room = bytes.fromhex(sys.argv[2]).decode('utf-8')
surrogate = bytes.fromhex(sys.argv[2]).decode('ascii', 'surrogateescape')
expected_name = sys.argv[3]
print('fs encoding =', sys.getfilesystemencoding())
assert sys.getfilesystemencoding() in ('ascii', 'ANSI_X3.4-1968'), sys.getfilesystemencoding()
print('fs encoding is ascii')

# (1) same implementation, ASCII safe, stable per room name
assert data_directory(base, room) == room_directory(base, room)
assert data_directory(base, room).name == room_directory_name(room) == expected_name
# (1b) the same room name maps to the same directory however the locale decoded it:
# the wired entry point normalises the surrogate-escaped argv form back to the same bytes.
assert room_directory_name(room) == expected_name
assert data_directory(base, surrogate).name == expected_name
assert os.fsencode(str(data_directory(base, room)))
# (2) no room => base itself (multi-room deployments keep the old behaviour)
assert data_directory(base) == base
# (3) legacy base/<room> holding data is reused
legacy = base / 'lab'
legacy.mkdir(parents=True); (legacy / 'events.sqlite3').write_bytes(b'legacy')
assert data_directory(base, 'lab') == legacy
# (4) legacy AND the new-rule directory both exist => legacy wins, nothing is migrated
new_by_rule = base / room_directory_name('lab')
new_by_rule.mkdir(); (new_by_rule / 'events.sqlite3').write_bytes(b'new')
assert data_directory(base, 'lab') == legacy
assert (new_by_rule / 'events.sqlite3').read_bytes() == b'new'
# (5) an empty legacy directory does not win
empty = base / 'empty-room'; empty.mkdir()
assert data_directory(base, 'empty-room') == base / room_directory_name('empty-room')
# (6) never rename silently: an unencodable directory name must fail with the explicit code
raw = base / room
try:
    Store(raw)
except ValueError as exc:
    assert str(exc) == 'DATA_DIR_NOT_ENCODABLE', exc
    assert isinstance(exc.__cause__, UnicodeEncodeError), exc.__cause__
else:
    raise AssertionError('raw non-ASCII directory name was created under an ASCII filesystem encoding')
assert not raw.exists()
print('WIRING-SERVER-OK')
'''


def test_server_data_directory_uses_shared_rule_and_keeps_legacy(tmp_path):
    proc = run_script(SERVER_SCRIPT, tmp_path, ROOM_HEX, ROOM_NAME)
    assert_ok(proc, 'WIRING-SERVER-OK')
    assert proc.stdout.isascii()                                           # 子进程只打 ASCII，便于任何 locale 下读日志
    assert not (tmp_path / ROOM).exists()                                  # 原名目录从未建立


# ---------------------------------------------------------------------------
# 桌面：records_directory() 用共享实现，引擎把 <records>/webRTC 交给 Peer
# ---------------------------------------------------------------------------

DESKTOP_SCRIPT = r'''
import asyncio, os, sys
from pathlib import Path
from types import SimpleNamespace
from p2pchat.backend.telemetry import room_directory, room_directory_name
from p2pchat.python_desktop import engine
from p2pchat.python_desktop.engine import EngineConfig, DesktopEngine, records_directory
from p2pchat.python_desktop.selftest import SelfTestLab

base = Path(sys.argv[1])
room = bytes.fromhex(sys.argv[2]).decode('utf-8')
surrogate = bytes.fromhex(sys.argv[2]).decode('ascii', 'surrogateescape')
expected_name = sys.argv[3]
print('desktop fs encoding =', sys.getfilesystemencoding())
assert sys.getfilesystemencoding() in ('ascii', 'ANSI_X3.4-1968')

# (1) same implementation as the server side, ASCII safe
assert records_directory(base, room) == room_directory(base, room)
assert records_directory(base, surrogate).name == expected_name
assert os.fsencode(str(records_directory(base, room)))
# (2) pre-existing flat layout (<data_dir>/webRTC or /voice with data) keeps working
for legacy_name in ('webRTC', 'voice'):
    (base / legacy_name).mkdir(parents=True)
    (base / legacy_name / 'record').write_bytes(b'x')
    assert records_directory(base, room) == base, legacy_name
    (base / legacy_name / 'record').unlink()
assert records_directory(base, room) == room_directory(base, room)
# (3) real call site: the log dir handed to Peer is <records>/webRTC
seen = {}
def fake_peer(url, room_name, secret, name, log_dir, **kwargs):
    seen['log_dir'] = log_dir
    return SimpleNamespace(store=SimpleNamespace(), log_dir=log_dir)
engine.Peer = fake_peer
config = EngineConfig(url='ws://127.0.0.1:1/ws', room=room, secret='secretsecret123', name='x',
                      data_dir=str(base / 'desktop'), allow_native=False)
desktop = DesktopEngine(config)
try:
    asyncio.run(desktop.start())   # offline: Peer construction happens before any network work
except Exception:
    pass                           # later wiring needs a live peer; the log dir was already built
expected = Path(records_directory(config.data_dir, room)) / 'webRTC'
assert 'log_dir' in seen, 'DesktopEngine.start() did not construct a Peer'
assert Path(seen['log_dir']) == expected, (seen.get('log_dir'), expected)
assert os.fsencode(str(expected))
# (4) the self-test lab no longer puts the operator supplied node name into the path
node_name = '\u7f51\u5173\u56de\u58f0'          # ASCII-escaped node name (gateway echo) for this child source
lab = SelfTestLab.__new__(SelfTestLab)
lab.root = base / 'selftest'; lab.root.mkdir()
lab.room = 'selftest-room'; lab.secret = 's' * 24; lab.with_stun = False; lab.native = False
lab.http_port = 1; lab.stun_url = None
cfg = lab.config(node_name)
assert cfg.data_dir == str(room_directory(lab.root, node_name))
assert os.fsencode(cfg.data_dir) and Path(cfg.data_dir).name == room_directory_name(node_name)
print('WIRING-DESKTOP-OK')
'''


def test_desktop_records_directory_and_call_sites(tmp_path):
    proc = run_script(DESKTOP_SCRIPT, tmp_path, ROOM_HEX, ROOM_NAME)
    assert_ok(proc, 'WIRING-DESKTOP-OK')


# ---------------------------------------------------------------------------
# 端到端：C locale 下用中文房间名真启动服务端 → 建目录 → 写入 → 回读
# ---------------------------------------------------------------------------

def test_server_cli_with_unicode_room_under_ascii_fs(tmp_path):
    base = tmp_path / 'data'
    expected = room_directory(base, ROOM)
    port = free_port()
    with _ascii_wrapper() as (python, cwd):
        proc = subprocess.Popen([python, '-m', 'p2pchat.server', '--data', str(base),
                                 '--room', as_argv(ROOM), '--port', str(port)],
                                cwd=cwd, env=_child_env(cwd), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    stderr = ''
    try:
        deadline = time.monotonic() + DEADLINE
        while time.monotonic() < deadline and not (expected / 'events.sqlite3').exists():
            if proc.poll() is not None:
                raise AssertionError('服务器提前退出：\n' + proc.communicate()[1])
            time.sleep(0.2)
        assert (expected / 'events.sqlite3').exists(), '中文房间名没建出数据目录'
        # 子进程的 fs encoding 是 ascii，--room 是父进程按 UTF-8 编码传过去的真 argv；
        # 这里断言子进程算出的目录名与父进程（UTF-8）算出的完全一致。
        assert expected.name == ROOM_NAME and os.fsencode(str(expected))
        assert not (base / ROOM).exists()                       # 没有按房间名原样建目录

        # 真实健康检查 + 真实旧式 join（loopback 默认允许）→ 产生 session.joined
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=10) as response:
            assert json.loads(response.read().decode())['ok'] is True
        body = {'v': 1, 'type': 'join', 'room': ROOM, 'secret': SECRET, 'name': 'wiring',
                'clientSessionId': str(uuid.uuid4()), 'capabilities': ['webrtc']}
        request = urllib.request.Request(f'http://127.0.0.1:{port}/signal/join',
                                         data=json.dumps(body).encode(),
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 200, response.status

        # 写入 → 回读：jsonl 有那条事件，sqlite 能打开且表在
        deadline = time.monotonic() + DEADLINE
        while time.monotonic() < deadline and not (expected / 'server.jsonl').exists():
            time.sleep(0.2)
        lines = (expected / 'server.jsonl').read_text(encoding='utf-8').splitlines()
        assert any('session.joined' in line for line in lines), lines
        assert all(json.loads(line) for line in lines)
        with sqlite3.connect(str(expected / 'events.sqlite3')) as db:
            tables = {row[0] for row in db.execute('SELECT name FROM sqlite_master')}
        assert 'diagnostics' in tables, tables
    finally:
        proc.terminate()
        try:
            _, stderr = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, stderr = proc.communicate(timeout=20)
    assert 'UnicodeEncodeError' not in stderr, stderr
    assert 'Traceback' not in stderr, stderr


# ---------------------------------------------------------------------------
# 名字与 locale 无关（同一房间名在任何编码下都是同一个目录名）
# ---------------------------------------------------------------------------

def test_room_directory_name_is_locale_independent_and_pinned():
    # 规则一旦改动就要显式更新这个常量：它是"同一房间名始终同一目录"的稳定锚点。
    assert room_directory_name(ROOM) == 'room-73aaaabac6dc91af'
    assert room_directory(Path('/tmp'), ROOM) == Path('/tmp/room-73aaaabac6dc91af')
