"""房间数据目录命名：ASCII 安全、不碰撞、旧目录兼容。

缺陷复现（非 UTF-8 文件系统编码，例如容器/CI 里的 LC_ALL=C）：
`Store(base + '/房间-测试🌏')` 在 telemetry.py 的 `directory.mkdir()` 抛
`UnicodeEncodeError: 'ascii' codec can't encode characters ...`。现代桌面多为 UTF-8
所以不常触发；Windows 用 Unicode API，不受影响。修法：目录名 = 可读 ASCII 片段 +
房间名稳定哈希（`room_directory()`），并优先沿用旧目录。

本文件在 UTF-8 与 ASCII 两种文件系统编码下都必须通过（验证命令会跑两次）。
"""
import hashlib
import inspect
import os
import re
from pathlib import Path

import pytest

from p2pchat.backend import telemetry
from p2pchat.backend.telemetry import LocalQueue, Store

UNICODE_ROOM = '房间-测试🌏'
SAFE_NAME = re.compile(r'^[A-Za-z0-9_-]+$')


def _fs_can_encode(text):
    """当前文件系统编码能不能表示这个名字（UTF-8 上恒真，LC_ALL=C 上为假）。"""
    try:
        os.fsencode(text)
        return True
    except UnicodeEncodeError:
        return False


# ---------------------------------------------------------------------------
# 命名规则：ASCII 安全 + 不碰撞
# ---------------------------------------------------------------------------

def test_room_directory_name_is_ascii_safe_and_bounded():
    name = telemetry.room_directory_name(UNICODE_ROOM)
    assert SAFE_NAME.match(name)                     # 全是 ASCII 安全字符
    assert name == name.encode('ascii').decode()     # 可直接编码，任何文件系统都放得下
    assert len(name) <= telemetry.ROOM_DIR_SLUG_MAX + 1 + telemetry.ROOM_DIR_HASH_CHARS
    assert name.startswith('room-')                  # 非 ASCII 全部折叠后由 'room' 兜底
    assert telemetry.room_directory_name('lab').startswith('lab-')   # 可读片段保留下来


@pytest.mark.parametrize('first,second', [
    (UNICODE_ROOM, '通道-测试🌏'),
    ('房间A', '房间B'),                # 片段相同（都被折叠成 room/A/B），只有哈希能区分
    ('🌏', '🌍'),
    ('lab', 'lab '),
    ('', '.'),
    ('../../etc/passwd', 'etc-passwd'),
])
def test_different_rooms_never_share_a_directory(first, second):
    assert telemetry.room_directory_name(first) != telemetry.room_directory_name(second)


def test_same_room_is_stable_and_hash_carries_uniqueness():
    assert telemetry.room_directory_name(UNICODE_ROOM) == telemetry.room_directory_name(UNICODE_ROOM)
    # 片段相同也绝不同目录：唯一性来自哈希，不是"非 ASCII 都变成同一个 room"的静默退化。
    assert telemetry.directory_slug('🌏A') == telemetry.directory_slug('房间A') == 'A'
    assert telemetry.room_directory_name('🌏A') != telemetry.room_directory_name('房间A')
    # 哈希输入只有房间名（+固定标签），不含任何密钥/凭据。
    expected = hashlib.sha256(telemetry.ROOM_DIR_INFO + UNICODE_ROOM.encode('utf-8')).hexdigest()[:16]
    assert telemetry.room_directory_name(UNICODE_ROOM).endswith(expected)


def test_room_directory_takes_no_secret_and_needs_no_unicode_fs(tmp_path):
    assert list(inspect.signature(telemetry.room_directory).parameters) == ['base', 'room', 'prefer_legacy']
    path = telemetry.room_directory(tmp_path, UNICODE_ROOM)
    assert os.fsencode(str(path))                    # 路径本身在任何文件系统编码下都成立
    assert 'SECRET' not in str(path) and 'key' not in str(path)


@pytest.mark.parametrize('room', [UNICODE_ROOM, '房间', '🌏🌍', 'a' * 200, '../../escape', ''])
def test_new_scheme_path_is_always_encodable(tmp_path, room):
    assert os.fsencode(str(telemetry.room_directory(tmp_path, room)))


# ---------------------------------------------------------------------------
# 兼容与迁移：优先沿用旧目录（有数据时）
# ---------------------------------------------------------------------------

def test_room_directory_prefers_legacy_dir_with_data(tmp_path):
    legacy = tmp_path / UNICODE_ROOM
    if not _fs_can_encode(str(legacy)):
        # 非 UTF-8 编码下这个旧目录在磁盘上不可能存在：探测必须安全返回"没有旧目录"。
        assert telemetry.legacy_room_directory(tmp_path, UNICODE_ROOM) is None
        assert telemetry.room_directory(tmp_path, UNICODE_ROOM) == tmp_path / telemetry.room_directory_name(UNICODE_ROOM)
        return
    legacy.mkdir()
    (legacy / 'events.sqlite3').write_bytes(b'x')            # 有历史数据
    assert telemetry.room_directory(tmp_path, UNICODE_ROOM) == legacy
    assert telemetry.room_directory(tmp_path, UNICODE_ROOM, prefer_legacy=False) != legacy


def test_new_scheme_when_legacy_absent_or_empty(tmp_path):
    new_path = tmp_path / telemetry.room_directory_name(UNICODE_ROOM)
    assert telemetry.room_directory(tmp_path, UNICODE_ROOM) == new_path
    if _fs_can_encode(str(tmp_path / UNICODE_ROOM)):
        (tmp_path / UNICODE_ROOM).mkdir()                    # 旧目录存在但是空的
        assert telemetry.room_directory(tmp_path, UNICODE_ROOM) == new_path


def test_legacy_probe_never_raises_and_ignores_files(tmp_path):
    probe = tmp_path / UNICODE_ROOM
    assert telemetry.legacy_room_directory(tmp_path, UNICODE_ROOM) in (None, probe)
    if _fs_can_encode(str(probe)):
        probe.write_bytes(b'not a directory')                # 同名但是文件：不算旧目录
        assert telemetry.legacy_room_directory(tmp_path, UNICODE_ROOM) is None


# ---------------------------------------------------------------------------
# 真实读写：新目录里 Store / LocalQueue 可建可读写
# ---------------------------------------------------------------------------

def test_store_and_local_queue_round_trip_in_new_room_dir(tmp_path):
    directory = telemetry.room_directory(tmp_path, UNICODE_ROOM)
    store = Store(directory)
    store.event('scope', 'peer', 'session.joined', {})
    store.close()
    assert (directory / 'server.jsonl').exists() and (directory / 'events.sqlite3').exists()
    assert 'session.joined' in (directory / 'server.jsonl').read_text(encoding='utf8')

    queue = LocalQueue(telemetry.room_directory(tmp_path, '另一个房间🌏'))
    queue.emit('client.boot', {})
    pending = queue.pending()
    assert len(pending) == 1 and pending[0]['event'] == 'client.boot'
    queue.close()


def test_store_reports_clear_code_for_non_encodable_directory_name(tmp_path):
    raw = tmp_path / UNICODE_ROOM
    if not _fs_can_encode(str(raw)):
        with pytest.raises(ValueError) as info:
            Store(raw)
        assert str(info.value) == 'DATA_DIR_NOT_ENCODABLE'          # 明确失败码，不是裸编码错
        assert isinstance(info.value.__cause__, UnicodeEncodeError)
        return
    # UTF-8 系统：原名目录照旧可建（行为不退化），只是新代码走 room_directory()。
    Store(raw).close()
    assert raw.is_dir()
