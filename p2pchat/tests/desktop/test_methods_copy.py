"""The desktop interface copy must match docs/METHODS-PLAIN.md exactly.

This is the machine check behind the product rule "文案严格取自
docs/METHODS-PLAIN.md，不得使用内部代号作为标题". The test parses the Markdown
table rather than hard-coding a second copy, so the document stays the single
source of truth.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from p2pchat.python_desktop import methods as plain

DOC = Path(__file__).resolve().parents[2] / "docs" / "METHODS-PLAIN.md"


def strip_bold(text: str) -> str:
    """Markdown emphasis is presentation only: ``**同时**`` reads as ``同时``."""
    return re.sub(r"\*\*(.+?)\*\*", r"\1", text)


def doc_rows() -> list[dict]:
    """Parse the nine-row method table out of METHODS-PLAIN.md."""
    text = DOC.read_text(encoding="utf-8")
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 6 or not cells[0].isdigit():
            continue
        index, title, what, when, why = cells[0], cells[1], cells[2], cells[3], cells[4]
        can_message = cells[5]
        rows.append(
            {
                "index": int(index),
                "name": strip_bold(title),
                "what": strip_bold(what),
                "when": strip_bold(when),
                "why": strip_bold(why),
                "canMessage": can_message,
            }
        )
    return rows


def test_document_is_the_catalogue() -> None:
    rows = doc_rows()
    assert [row["index"] for row in rows] == list(range(1, 10)), rows
    assert len(plain.METHODS) == 9
    # The interface wording must come from the table, not from a second copy.
    assert [row["name"] for row in rows] == [method["title"] for method in plain.METHODS]


@pytest.mark.parametrize("row", doc_rows(), ids=lambda row: row["name"])
def test_each_documented_method_matches_the_table_word_for_word(row) -> None:
    """Column 3 → ``explain``, column 4 → ``works``, column 5 → ``failure``.

    Compared with exact equality (after removing Markdown emphasis), so a
    paraphrase cannot silently drift away from the document. Mirrors the web
    suite's ``assert.equal``-style checks.
    """
    match = next((method for method in plain.METHODS if method["title"] == row["name"]), None)
    assert match is not None, f"缺少文档里的方式：{row['name']}"
    assert match["explain"] == row["what"], f"{row['name']} 的 explain 与文档第 3 列不一致"
    assert match["works"] == row["when"], f"{row['name']} 的 works 与文档第 4 列不一致"
    assert match["failure"] == row["why"], f"{row['name']} 的 failure 与文档第 5 列不一致"
    assert row["what"] and row["when"] and row["why"]


def test_documented_order_is_the_attempt_order() -> None:
    assert [method["title"] for method in plain.METHODS] == [row["name"] for row in doc_rows()]


def test_no_internal_codenames_are_visible_to_users() -> None:
    forbidden = ["ice-v6", "ice-v4", "ice-dual", "tcp-simopen", "udp-probe", "natpmp", "upnp", "ntp"]
    for method in plain.METHODS:
        for field in ("title", "explain"):
            text = method[field].lower()
            for codename in forbidden:
                assert codename not in text, f"{method['title']} 的 {field} 出现了内部代号 {codename}"


def test_ids_are_internal_only_and_unique() -> None:
    ids = [method["id"] for method in plain.METHODS]
    assert len(ids) == len(set(ids))
    # The legacy profile names stay engine-side identifiers, never titles.
    assert "ice-v6" in ids and plain.METHOD_BY_ID["ice-v6"]["title"] == "IPv6 直连"


def test_status_and_availability_vocabulary() -> None:
    # METHODS-PLAIN.md 状态用词表：6 个状态，「已观测」专用于只探测/观测成功的方式。
    assert set(plain.STATUS.values()) == {"等待中", "尝试中", "已打通", "已观测", "不可用", "不支持"}
    assert plain.STATUS["observed"] == "已观测"
    assert set(plain.AVAILABILITY.values()) == {"可用", "不可用", "不支持"}


def test_probe_only_rows_match_the_documented_can_message_column() -> None:
    for row in doc_rows():
        method = next(m for m in plain.METHODS if m["title"] == row["name"])
        documented = row["canMessage"].startswith("是")
        assert (not plain.probe_only(method)) == documented, row["name"]


def test_only_message_capable_paths_use_the_direct_wording() -> None:
    # 已打通 is reserved for paths that can carry a message; a successful probe
    # reads 已观测 instead of overstating success.
    assert plain.MESSAGING_STATES == {"direct"}
    assert plain.STATUS["observed"] == "已观测"
    for method_id in ("udp-probe", "stun-observation"):
        assert plain.probe_only(plain.METHOD_BY_ID[method_id]) is True
        assert "仅探测" not in plain.METHOD_BY_ID[method_id]["title"]


def test_reason_never_returns_a_bare_token() -> None:
    assert plain.reason("") == ""
    assert "身份校验" in plain.reason("AUTH_FAILED")
    unknown = plain.reason("SOME_UNKNOWN_CODE")
    assert "SOME_UNKNOWN_CODE" not in unknown
    assert unknown.endswith("。")
    passthrough = plain.reason("对方拒绝了这次申请。")
    assert passthrough == "对方拒绝了这次申请。"


def test_describe_address_is_plain_language() -> None:
    assert "IPv4" in plain.describe_address("192.168.1.2")
    assert "IPv6" in plain.describe_address("2001:db8::1")
    assert "IPv4" in plain.describe_address("127.0.0.1")
    assert plain.describe_address("not-an-address") == "地址不合法"
    assert ipaddress.ip_address("127.0.0.1").is_loopback


def test_stun_row_itself_says_it_is_not_a_relay() -> None:
    # METHODS-PLAIN.md limitation 2: STUN 不是中继，只观察地址，不转发任何数据。
    stun = plain.METHOD_BY_ID["stun-observation"]
    assert "不是中继" in stun["explain"]
    assert "不转发" in stun["explain"]
    row = next(row for row in doc_rows() if row["name"] == "STUN 映射观测")
    assert "不是中继" in row["what"], "文档第 8 行本身必须写明不是中继"


def test_three_address_selections_are_one_protocol() -> None:
    # The three ICE rows are address-family selections of one WebRTC protocol.
    assert plain.WEBRTC_PROFILE_NOTE == "是同一个 WebRTC 直连的三种地址选择，不是三个独立协议"
    assert tuple(plain.WEBRTC_PROFILE_IDS) == ("ice-dual", "ice-v6", "ice-v4")
    for method_id in plain.WEBRTC_PROFILE_IDS:
        assert plain.METHOD_BY_ID[method_id]["mechanism"] == "webrtc"


def test_document_has_a_trailing_newline_and_no_zero_width_characters() -> None:
    raw = DOC.read_bytes().decode("utf-8")
    assert raw.endswith("\n"), "METHODS-PLAIN.md 缺少末尾换行"
    for bad in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        assert bad not in raw, f"METHODS-PLAIN.md 出现不可见零宽字符 {bad!r}"
