"""房间目录命名接线：服务端与桌面客户端都调用同一实现，旧目录优先，编码安全。

被测点是**调用方**（server.py / python_desktop/）而不是命名实现本身（那由
test_telemetry_dir.py 覆盖）。导入 aiohttp/aiortc 的产品模块都在**子进程**里跑。

两个分支（都不 skip，两种都会在每次跑里真执行）：
* **unicode 分支**：文件系统编码支持 Unicode（Windows 的 NTFS+Unicode API、POSIX UTF-8）。
  断言：同一房间名在正常形式与代理转义形式下同一目录名；旧目录 `base/<房间名>` 有数据时优先
  且不迁移；新旧并存仍选旧；空旧目录不选中；非 ASCII 房间名建出 `room-<hash>` 目录并可写读。
  **注意**：`DATA_DIR_NOT_ENCODABLE` 在这个分支里不可能发生（不存在"放不下的目录名"，
  见本文件 ascii 分支的断言），所以这里没有那条断言，而不是把它当通过。
* **ascii 分支**：POSIX + 非 UTF-8 文件系统编码（LC_ALL=C 的容器/CI）。保留完整 ASCII 安全集：
  只建 ASCII 目录、原名目录不被创建、`Store(原名)` 报 `DATA_DIR_NOT_ENCODABLE`
  （cause 是 UnicodeEncodeError）、跨 locale 同目录不变量。

子进程环境由用例显式给出：`PYTHONUTF8=1` ⇒ 任何平台/语言环境都是 utf-8（unicode 分支）；
`PYTHONUTF8=0 + LC_ALL=C` ⇒ POSIX 上是 ascii，Windows 上仍是 utf-8（NTFS 走 Unicode API）
——所以 Windows 跑两次都落在 unicode 分支，这正是修掉的那条平台假设。
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
SECRET = 'wiring-room-secret'
ROOM_HEX = ROOM.encode('utf-8').hex()          # 非 ASCII 参数用 hex 传，避免命令行解码差异
ROOM_NAME = room_directory_name(ROOM)
# 两个子进程语言环境：unicode 分支用 UTF-8 模式强制 utf-8；ascii 分支是 POSIX C locale。
UNICODE_FS_LOCALE = {'LC_ALL': 'C', 'PYTHONUTF8': '1', 'PYTHONCOERCECLOCALE': '0',
                     'PYTHONIOENCODING': 'utf-8:backslashreplace'}
ASCII_FS_LOCALE = {'LC_ALL': 'C', 'PYTHONUTF8': '0', 'PYTHONCOERCECLOCALE': '0',
                   'PYTHONIOENCODING': 'utf-8:backslashreplace'}
DEADLINE = 40.0
BRANCHES = [pytest.param(True, id='unicode-fs'), pytest.param(False, id='non-utf8-fs')]


def expected_branch(unicode_fs):
    """子进程应当落在哪个分支。

    unicode_fs=True：PYTHONUTF8=1 在任何平台/语言环境都给出 utf-8 文件系统编码 ⇒ unicode。
    unicode_fs=False：POSIX + C locale ⇒ ascii；Windows 的文件系统编码本来就是 utf-8
    （NTFS + Unicode API，locale 改变不了）⇒ 同样是 unicode 分支。
    """
    if unicode_fs or os.name == 'nt':
        return 'unicode'
    return 'ascii'


def _ascii_path(path):
    try:
        str(path).encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


@contextlib.contextmanager
def _subprocess_target():
    """(python, cwd)：Windows 直接用；POSIX 上路径不是纯 ASCII 时用 ASCII 符号链接包一层。

    非 UTF-8 locale 下，仓库/venv 路径里的非 ASCII 字符会让第三方扩展（multidict 等）报
    surrogates not allowed——那是环境噪声，CI 的检出路径是 ASCII 不会遇到。Windows 走 UTF-16
    宽字符 API，不受这个约束，也不需要符号链接（还避免开发者模式权限问题）。
    """
    if os.name == 'nt' or (_ascii_path(ROOT) and _ascii_path(sys.prefix)):
        yield sys.executable, str(ROOT)
        return
    sandbox = Path(tempfile.mkdtemp(prefix='p2pwrap-'))
    repo, venv = sandbox / 'repo', sandbox / 'venv'
    repo.symlink_to(ROOT, target_is_directory=True)
    venv.symlink_to(Path(sys.prefix), target_is_directory=True)
    yield str(venv / 'bin' / 'python'), str(repo)


def _child_env(cwd, unicode_fs):
    env = dict(os.environ)
    env.update(UNICODE_FS_LOCALE if unicode_fs else ASCII_FS_LOCALE)
    env['PYTHONPATH'] = cwd
    return env


def run_script(script, *args, unicode_fs, timeout=120):
    with _subprocess_target() as (python, cwd):
        return subprocess.run([python, '-c', script, *[str(a) for a in args]], cwd=cwd,
                              env=_child_env(cwd, unicode_fs), capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=timeout)


def assert_ok(proc, marker, unicode_fs):
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert marker in proc.stdout, proc.stdout + proc.stderr
    branch = expected_branch(unicode_fs)
    assert 'FS-BRANCH=' + branch in proc.stdout, proc.stdout + proc.stderr


def as_argv(text):
    """给子进程的 `--room` argv 值（按平台选最忠实的形式）。

    父进程自己能把名字按本机文件系统编码写出去（UTF-8 POSIX、Windows）就**直接传字符串**：
    真实用户就是这么敲的，也避免把代理字符交给 Windows 的 CreateProcessW。
    父进程是 POSIX C locale（fs encoding=ascii）时，直接传中文在父进程里就 UnicodeEncodeError，
    所以退成 surrogateescape 形式——os.fsencode 会把它还原成同一串 UTF-8 字节，
    与 C-locale shell 交给进程的字节完全一致。
    """
    try:
        os.fsencode(text)
        return text
    except UnicodeEncodeError:
        return text.encode('utf-8').decode('ascii', 'surrogateescape')


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------
# 服务端：data_directory() 用共享实现 + 旧目录优先 + 分支真实断言
# ---------------------------------------------------------------------------

SERVER_SCRIPT = r'''
# Child source must stay ASCII-only: a C-locale interpreter cannot run a -c command that
# contains non-ASCII bytes, and the room name arrives as hex anyway.
import os, sys
from pathlib import Path
from p2pchat.backend.telemetry import Store, room_directory, room_directory_name
from p2pchat.server import data_directory

base = Path(sys.argv[1])
room = bytes.fromhex(sys.argv[2]).decode('utf-8')
surrogate = bytes.fromhex(sys.argv[2]).decode('ascii', 'surrogateescape')
expected_name = sys.argv[3]
try:
    os.fsencode(room)
    branch = 'unicode'
except UnicodeEncodeError:
    branch = 'ascii'
print('FS-BRANCH=' + branch)
print('fs encoding = ' + sys.getfilesystemencoding())

# (1) shared implementation, stable per room name, same name in both decoded forms
assert data_directory(base, room) == room_directory(base, room)
assert data_directory(base, room).name == room_directory_name(room) == expected_name
assert room_directory_name(room) == room_directory_name(surrogate) == expected_name
assert data_directory(base, surrogate).name == expected_name
# (2) no room => base itself (multi-room deployments keep the old behaviour)
assert data_directory(base) == base
# (3) legacy base/<room> holding data is reused (ASCII room name: works on any filesystem)
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

if branch == 'ascii':
    # POSIX + non-UTF-8 filesystem encoding: the raw room name cannot even be created,
    # and a caller that tries gets the explicit code instead of a silent rename.
    assert os.fsencode(str(data_directory(base, room)))
    raw = base / room
    try:
        Store(raw)
    except ValueError as exc:
        assert str(exc) == 'DATA_DIR_NOT_ENCODABLE', exc
        assert isinstance(exc.__cause__, UnicodeEncodeError), exc.__cause__
    else:
        raise AssertionError('raw non-ASCII directory name was created on an ASCII filesystem')
    assert not raw.exists()
else:
    # Unicode filesystem (Windows NTFS + Unicode API, POSIX UTF-8): "unencodable directory
    # name" simply does not exist here, so there is no DATA_DIR_NOT_ENCODABLE assertion.
    target = data_directory(base, room)
    assert target.name == expected_name and target.name.isascii()   # we still only choose ASCII names
    Store(target).close()
    assert (target / 'events.sqlite3').exists()                     # directory created, writable/readable
    # legacy <base>/<raw room name> (really creatable here) with data wins, for both decoded forms
    unicode_base = base / 'unicode-base'; unicode_base.mkdir()
    unicode_legacy = unicode_base / room
    unicode_legacy.mkdir(); (unicode_legacy / 'events.sqlite3').write_bytes(b'legacy-unicode')
    assert data_directory(unicode_base, room) == unicode_legacy
    assert data_directory(unicode_base, surrogate) == unicode_legacy
    # both present => legacy still wins and the new-rule directory is untouched (no migration)
    other = unicode_base / room_directory_name(room)
    other.mkdir(); (other / 'events.sqlite3').write_bytes(b'new')
    assert data_directory(unicode_base, room) == unicode_legacy
    assert (other / 'events.sqlite3').read_bytes() == b'new'
print('WIRING-SERVER-OK')
'''


@pytest.mark.parametrize('unicode_fs', BRANCHES)
def test_server_data_directory_uses_shared_rule_and_keeps_legacy(tmp_path, unicode_fs):
    proc = run_script(SERVER_SCRIPT, tmp_path, ROOM_HEX, ROOM_NAME, unicode_fs=unicode_fs)
    assert_ok(proc, 'WIRING-SERVER-OK', unicode_fs)
    assert proc.stdout.isascii()                              # 子进程只打 ASCII，任何 locale 下都好读
    assert not (tmp_path / ROOM).exists()                     # 主 base 上从未按原名建目录


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
try:
    os.fsencode(room)
    branch = 'unicode'
except UnicodeEncodeError:
    branch = 'ascii'
print('FS-BRANCH=' + branch)
print('fs encoding = ' + sys.getfilesystemencoding())

# (1) same implementation as the server side; both decoded forms give the same directory name
assert records_directory(base, room) == room_directory(base, room)
assert records_directory(base, surrogate).name == expected_name
if branch == 'ascii':
    assert os.fsencode(str(records_directory(base, room)))
else:
    assert records_directory(base, room).name == expected_name and expected_name.isascii()
# (2) pre-existing flat layout (<data_dir>/webRTC or /voice with data) keeps working
for legacy_name in ('webRTC', 'voice'):
    (base / legacy_name).mkdir(parents=True)
    (base / legacy_name / 'record').write_bytes(b'x')
    assert records_directory(base, room) == base, legacy_name
    (base / legacy_name / 'record').unlink()
assert records_directory(base, room) == room_directory(base, room)
if branch == 'unicode':
    # legacy <data_dir>/<raw room name> (really creatable here) wins too, for both decoded forms
    unicode_base = base / 'unicode-base'; unicode_base.mkdir()
    legacy = unicode_base / room
    legacy.mkdir(); (legacy / 'record').write_bytes(b'x')
    assert records_directory(unicode_base, room) == legacy
    assert records_directory(unicode_base, surrogate) == legacy
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
# (4) the self-test lab no longer puts the operator supplied node name into the path
node_name = '\u7f51\u5173\u56de\u58f0'          # ASCII-escaped node name (gateway echo) for this child source
lab = SelfTestLab.__new__(SelfTestLab)
lab.root = base / 'selftest'; lab.root.mkdir()
lab.room = 'selftest-room'; lab.secret = 's' * 24; lab.with_stun = False; lab.native = False
lab.http_port = 1; lab.stun_url = None
cfg = lab.config(node_name)
assert cfg.data_dir == str(room_directory(lab.root, node_name))
assert Path(cfg.data_dir).name == room_directory_name(node_name)
if branch == 'ascii':
    assert os.fsencode(cfg.data_dir)
print('WIRING-DESKTOP-OK')
'''


@pytest.mark.parametrize('unicode_fs', BRANCHES)
def test_desktop_records_directory_and_call_sites(tmp_path, unicode_fs):
    proc = run_script(DESKTOP_SCRIPT, tmp_path, ROOM_HEX, ROOM_NAME, unicode_fs=unicode_fs)
    assert_ok(proc, 'WIRING-DESKTOP-OK', unicode_fs)


# ---------------------------------------------------------------------------
# 端到端：真启动服务端（中文房间名）→ 建目录 → 写入 → 回读，两个分支都跑
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('unicode_fs', BRANCHES)
def test_server_cli_with_unicode_room(tmp_path, unicode_fs):
    base = tmp_path / 'data'
    expected = room_directory(base, ROOM)          # 父进程算出的目录名（与子进程的 locale 无关）
    assert expected.name == ROOM_NAME
    port = free_port()
    with _subprocess_target() as (python, cwd):
        proc = subprocess.Popen([python, '-m', 'p2pchat.server', '--data', str(base),
                                 '--room', as_argv(ROOM), '--port', str(port)],
                                cwd=cwd, env=_child_env(cwd, unicode_fs), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    stderr = ''
    try:
        deadline = time.monotonic() + DEADLINE
        while time.monotonic() < deadline and not (expected / 'events.sqlite3').exists():
            if proc.poll() is not None:
                raise AssertionError('服务器提前退出：\n' + proc.communicate()[1])
            time.sleep(0.2)
        assert (expected / 'events.sqlite3').exists(), '中文房间名没建出数据目录'
        assert expected.name == ROOM_NAME and expected.name.isascii()
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
    assert 'Traceback' not in stderr, stderr
    if expected_branch(unicode_fs) == 'ascii':
        assert 'UnicodeEncodeError' not in stderr, stderr       # 非 UTF-8 编码下的原始缺陷不再出现


# ---------------------------------------------------------------------------
# 名字与 locale 无关（同一房间名在任何编码下都是同一个目录名）
# ---------------------------------------------------------------------------

def test_room_directory_name_is_locale_independent_and_pinned():
    # 规则一旦改动就要显式更新这个常量：它是"同一房间名始终同一目录"的稳定锚点。
    assert room_directory_name(ROOM) == 'room-73aaaabac6dc91af'
    assert room_directory(Path('/tmp'), ROOM) == Path('/tmp/room-73aaaabac6dc91af')
