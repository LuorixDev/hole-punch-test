from __future__ import annotations

import asyncio
import datetime as dt
import json
import shlex
import sqlite3
import time
from collections import deque
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.geometry import Size
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    DirectoryTree,
    Footer,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from .client import NETWORK_TEST_NOTICE, Client, normalize_server_address
from .experiments import scheme_explanation, scheme_nickname
from .journal import redact
from .network import address_rejection, remaining_lifetime
from .performance import bottleneck_assessment
from .status import public_ip_evidence, speed_assessment, timestamp_age
from .udp import PROFILES

STATES = {
    "success": "成功",
    "failed": "失败",
    "cancelled": "已取消",
    "not-applicable": "不适用",
    "connected-without-local-gateway-lease": "已连接／本端无网关租约",
    "connected-without-icmp-association": "已连接／未证实 ICMP 关联",
    "pending": "待尝试",
    "offered": "等待接收",
    "sending": "发送中",
    "receiving": "接收中",
    "running": "进行中",
    "completed": "已完成",
    "measured": "已测得",
    "not-measured": "未测量",
    "timeout": "超时",
    "preferred": "可用",
    "deprecated": "已弃用",
    "tentative": "DAD 检测中",
    "dadfailed": "DAD 失败",
    "invalid": "已失效",
    "unverified": "未验证",
    "stable": "稳定",
    "temporary": "临时",
    "baseline": "基线",
    "gateway": "网关放行",
    "balanced": "均衡",
    "fast": "快速",
    "staggered": "错峰",
    "dual": "双栈",
    "unavailable": "不可用",
    "not-tested": "未测试",
    "lease-created": "租约已创建",
    "INFO": "信息",
    "WARNING": "警告",
    "ERROR": "错误",
    "DEBUG": "调试",
    "CRITICAL": "严重",
}
REASONS = {
    "PEER_FILE_TRANSFER_UNSUPPORTED": "对端版本不支持附件传输",
    "FILE_SEND_BUSY": "发送任务已满，请等待或取消已有传输",
    "FILE_RECEIVE_BUSY": "对端接收任务已满",
    "FILE_PATH_REQUIRED": "请选择文件或填写文件路径",
    "FILE_TRANSFER_ID_REQUIRED": "请指定传输 ID",
    "FILE_TRANSFER_NOT_ACTIVE": "该传输已经结束或不存在",
    "FILE_NOT_WAITING_FOR_ACCEPT": "该传输不在等待接收",
    "FILE_REJECTED": "对端拒绝了文件",
    "FILE_CANCELLED": "文件传输已取消",
    "FILE_CHECKSUM_MISMATCH": "文件完整性校验失败，未保留文件",
    "FILE_NOT_ENOUGH_SPACE": "接收目录磁盘空间不足",
    "FILE_CHANGED_DURING_SEND": "发送期间源文件发生变化",
    "FILE_READY_TIMEOUT": "等待对端接受文件超时",
    "FILE_ACK_TIMEOUT": "等待对端确认文件进度超时",
    "FILE_RECEIPT_TIMEOUT": "等待文件校验回执超时",
    "FILE_NOT_REGULAR": "仅能发送普通文件，不能发送目录或管道",
    "FILE_SIZE_LIMIT": "文件超过单文件大小限制",
    "IMAGE_FORMAT_UNSUPPORTED": "图片格式不支持或图片标识无效",
    "IMAGE_NOT_RECEIVED": "请选择已经接收完成的图片",
    "DESKTOP_OPEN_FAILED": "系统图片查看器或文件管理器打开失败",
    "REACHABLE": "HTTP 入站可达",
    "TIMEOUT_INCONCLUSIVE": "超时，原因未确定",
    "CONNECTION_REFUSED_INCONCLUSIVE": "连接被拒绝，原因未确定",
    "NO_IPV6_ROUTE": "观察端无 IPv6 路由",
    "OBSERVER_NO_ROUTE": "服务端无可用路由，无法判断入站",
    "OBSERVER_SOURCE_UNAVAILABLE": "服务端源地址不可用，无法判断入站",
    "REJECTED_BY_POLICY": "服务端策略或探测额度拒绝，未测试入站",
    "NOT_TESTED": "未测试",
    "AUTHENTICATED_PROBE_ONLY_NO_CHAT_CHANNEL": "认证探测成功，未建立聊天通道",
    "UDP_AUTHENTICATED_PUNCH_TIMEOUT": "UDP 打洞认证超时",
    "LOCAL_PUBLIC_UDP_MAPPING_MISSING": "本端未获取公网 UDP 映射",
    "PEER_PUBLIC_UDP_CANDIDATE_MISSING": "对端未提供公网 UDP 候选",
    "PUBLIC_UDP_CANDIDATES_PRESENT": "双方已有公网 UDP 候选",
    "DIRECT_ADDRESS_CANDIDATES": "直接地址候选",
    "TCP_CONNECT_FAILED": "TCP 连接失败",
    "TCP_CANDIDATES_TIMEOUT": "等待对端 TCP 候选地址超时",
    "TCP_LISTEN_ACCEPT_TIMEOUT": "监听端未在期限内接受 TCP 连接；不能单独确定是防火墙拦截",
    "DATA_PATH_READY_TIMEOUT": "数据通道未就绪",
    "NO_AUTHENTICATED_P2P_DATA_PATH_YET": "尚无已认证 P2P 通道",
    "NO_STABLE_DESTINATION_DEPENDENT_PORT_PATTERN": "未发现可用的稳定端口预测规律",
    "RETRY_MUST_BE_REQUESTED_ON_COORDINATOR": "需由协调端发起重试",
    "WAIT_FOR_CURRENT_MATRIX_TO_FINISH_BEFORE_RETRY": "当前矩阵未完成",
    "NO_SIGNALING_PAIR": "尚未配对",
    "ROOM_FULL": "房间已满",
    "AUTH_FAILED": "认证失败",
    "LOCAL_ADDRESS_NOT_AVAILABLE": "本地地址不可用",
    "WAN_TEST_ALREADY_RUNNING": "公网测速仍在进行",
    "WAN_TEST_RUNNING_SPEED_DEFERRED": "一端正在公网测速，请稍后进行链路测速",
    "WAIT_FOR_CURRENT_MATRIX_TO_FINISH_BEFORE_WAN": "请等待打洞矩阵完成再重测公网带宽",
    "P2P_BENCH_RECEIVER_BUSY": "正在接收对端测速数据，请稍后进行公网测速",
    "P2P_BENCH_SENDER_BUSY": "已有链路测速正在运行，请等待完成",
    "FILE_TRANSFER_BUSY": "文件传输正在进行，请等待完成后再测公网带宽",
    "BENCH_RECEIVE_TIMEOUT": "测速接收超时，本次测量已清理",
    "BENCH_READY_TIMEOUT": "等待对端准备测速超时",
    "BENCH_SEND_TIMEOUT": "发送测速数据超时，已请求终止本次测速",
    "BENCH_PROGRESS_TIMEOUT": "等待测速进度确认超时，已请求终止本次测速",
    "BENCH_DRAIN_TIMEOUT": "等待已发测速数据确认超时，已请求终止本次测速",
    "BENCH_RESULT_TIMEOUT": "等待最终测速结果超时",
    "BENCH_TOTAL_TIMEOUT": "测速超过总时限，已请求终止本次测速",
    "PEER_BENCH_BUSY": "对端已有测速正在运行",
    "LIBRESPEED_CLI_MISSING": "缺少 LibreSpeed 可执行文件",
    "NO_REACHABLE_WAN_TARGET": "未找到可用测速节点，请检查网络或配置区域节点列表",
    "BEST_OBSERVED_NOT_ISP_THEORETICAL_LIMIT": "多节点最佳实测参考，不是运营商理论上限",
    "PEER_WAN_TEST_RUNNING": "对端正在公网测速",
    "SPEED_SIZE_MUST_BE_1_TO_1024_MIB": "测速大小须为 1–1024 MiB",
    "INTERFACE_DOWN": "网卡未启用",
    "ADDRESS_TENTATIVE": "地址仍在 DAD 检测",
    "ADDRESS_DADFAILED": "地址冲突检测失败",
    "ADDRESS_EXPIRED": "有效期已过",
    "ADDRESS_DEPRECATED": "地址已弃用",
    "IPV6_STATE_UNVERIFIED": "IPv6 状态未验证",
    "RAW_EXPERIMENT_DISABLED": "原始报文实验未启用（可在实验参数中启用）",
    "RAW_PERMISSION_UNAVAILABLE_CAP_NET_RAW": "无原始套接字权限：需要 Linux CAP_NET_RAW",
    "RAW_BACKEND_UNAVAILABLE_ON_THIS_PLATFORM": "原始报文后端仅支持 Linux",
    "LIBUTP_BACKEND_UNAVAILABLE": "缺少可选 libutp 后端",
    "LIBNICE_BACKEND_UNAVAILABLE": "缺少可选 libnice 后端",
    "NAT64_PREFIX_UNAVAILABLE": "未发现或配置 NAT64 前缀，不能猜测 /96",
    "NAT64_IPV4_MAPPING_UNAVAILABLE": "未观察到 IPv6 转换后的 IPv4 映射",
    "POOL_NO_AUTHENTICATED_WINNER": "有限端口搜索未找到双方认证的共同获胜 socket",
    "AUTHENTICATED_HAIRPIN_PROBE_ONLY": "仅证实本机映射回环，不计作对端聊天通道",
    "ADDRESS_LIFETIME_TOO_SHORT": "剩余有效期过短",
    "ADDRESS_SKIP_AS_SOURCE": "系统禁止作为出站源地址",
    "ADDRESS_CANDIDATE_BUDGET": "候选名额限制",
}
EVENTS = {
    "client.started": "客户端启动",
    "signaling.connected": "信令已连接",
    "signaling.offline": "信令离线",
    "room.waiting": "等待另一台设备",
    "room.paired": "双方已配对",
    "room.peer_signaling_left": "对端信令离线",
    "network.completed": "网络诊断完成",
    "network.auto_retry": "切网后自动协调重打洞",
    "network.retry_requested": "已请求协调端重打洞",
    "network.retry_deferred": "自动重试暂不执行",
    "experiment.replaced": "旧矩阵停止，保留可用通道",
    "nat64.prefix": "NAT64 转换前缀证据",
    "nat64.mapping": "NAT64 IPv4 映射观察",
    "nat.filtering": "独立 socket 过滤诊断",
    "nat.hairpin": "本机 NAT 回环证据",
    "pool.prepared": "socket 阵列就绪",
    "pool.round": "端口搜索轮次",
    "pool.winner": "已协商共同获胜端点",
    "raw.icmp_association": "ICMP 引用报文关联结果",
    "raw.natblaster_handshake": "原始 SYNACK 注入后连接完成",
    "native.utp_connected": "原生 uTP 流连接完成",
    "native.ice_selected": "原生 ICE 候选对已选定",
    "native.tls_verified": "原生流 TLS 证书验证通过",
    "tcp.race_selected": "同端口监听竞争连接已选定",
    "tcp.stunt_warmup": "低 TTL TCP 预热后重新绑定",
    "experiment.plan": "打洞矩阵已生成",
    "experiment.started": "开始尝试",
    "experiment.result": "尝试结果",
    "experiment.completed": "矩阵完成",
    "path.opened": "P2P 通道已认证",
    "path.verified": "数据通道验证通过",
    "path.closed": "通道关闭",
    "ipv6.inbound_result": "IPv6 HTTP 回连结果",
    "ipv4.inbound_result": "IPv4 HTTP 回连结果",
    "ipv6.inbound_not_tested": "IPv6 回连未测试",
    "stun.observed": "STUN 映射观察",
    "stun.failed": "STUN 观察失败",
    "stun.target_failed": "STUN 目标失败",
    "stun.health": "STUN 出口可达性",
    "stun.selected": "ICE 选用的 STUN",
    "nat.mapping": "NAT 映射证据",
    "mtu.directional": "方向性 MTU 证据",
    "quic.mtu_avoidance": "QUIC 报文降级",
    "gateway.unavailable": "网关控制不可用",
    "gateway.lease_created": "网关租约已创建",
    "webrtc.signal_ignored": "忽略已关闭尝试的迟到信令",
    "ping.result": "延迟测试结果",
    "speed.result": "测速结果",
    "speed.failed": "测速阶段失败",
    "speed.post_rtt": "测后延迟",
    "speed.post_rtt_failed": "测后延迟未取得",
    "network.auto_retry_deferred": "网络重测等待当前测速或传输结束",
    "quic.runtime": "QUIC运行后端与缓冲区",
    "quic.buffer_tuning_failed": "QUIC缓冲区调整失败",
    "quic.transmit_failed": "QUIC批量发送失败",
    "speed.batch_started": "开始批量测速",
    "speed.batch_path_failed": "批量测速中一条链路失败",
    "speed.batch_finished": "批量测速结束",
    "chat.delivered": "消息已确认送达",
    "chat.received": "收到 P2P 消息",
    "terminal.command_failed": "操作失败",
    "network.peer_status": "对端网络状态已更新",
    "wan.started": "公网测速开始",
    "wan.test_started": "公网测速节点",
    "wan.sample": "公网测速样本",
    "wan.completed": "公网测速结束",
    "wan.not_tested": "公网测速未执行",
    "wan.deferred": "公网测速等待空闲",
    "file.offered": "发送附件",
    "file.incoming": "收到附件请求",
    "file.progress": "附件传输进度",
    "file.delivered": "附件已确认送达",
    "file.received": "附件已保存",
    "file.failed": "附件传输失败 / 取消",
    "file.rejected": "附件未接收",
    "file.cleanup_failed": "附件清理失败",
}
FIELDS = {
    "transfer_id": "传输标识",
    "download_dir": "接收目录",
    "max_bytes": "单文件最大字节数",
    "auto_accept": "自动接收",
    "media": "附件类型",
    "completed": "已传输字节",
    "total_bytes": "总字节数",
    "received_at": "接收完成时间 UTC",
    "receiver_seconds": "接收耗时（秒）",
    "saved_path": "已保存文件路径",
    "sha256": "文件 SHA-256 校验值",
    "receipt": "接收端回执",
    "attempt": "尝试编号",
    "method": "打洞方案",
    "mechanism": "通道机制",
    "profile": "重试档位",
    "trial": "新套接字重试轮次",
    "phase": "实验阶段",
    "a_host": "协调端网卡绑定地址（非公网映射）",
    "b_host": "参与端网卡绑定地址（非公网映射）",
    "candidate_evidence": "实际候选与网络证据",
    "local_candidates": "本端套接字候选 IP 与端口",
    "remote_candidates": "对端提供的候选 IP 与端口",
    "stun_observations": "本套接字 STUN 映射记录",
    "stun_failures": "STUN 失败记录",
    "diagnosis": "候选诊断（非 NAT 等级）",
    "socket_error": "套接字错误",
    "probe_sends": "探测发包调用数（不代表已送达）",
    "received_probes": "收到的探测包数",
    "rejected_probes": "拒绝的探测包数",
    "host": "本端绑定地址",
    "leader_initiator": "协调端主动发起",
    "initiator": "本端主动发起",
    "tls_client": "本端为 TLS 客户端",
    "datagram_size": "请求 UDP 载荷（字节）",
    "effective_datagram_size": "实际 UDP 载荷（字节）",
    "offset": "发送偏移（秒）",
    "initial": "初次重试间隔（秒）",
    "ceiling": "重试间隔上限（秒）",
    "state": "状态",
    "reason": "原因",
    "scheme_explanation": "方案解释",
    "elapsed_ms": "耗时（毫秒）",
    "data_path": "已验证聊天通道",
    "rtt_ms": "往返延迟（毫秒）",
    "rtt_state": "延迟采样状态",
    "rtt_age_seconds": "延迟样本距今（秒）",
    "speed_results": "各方向测速结果",
    "speed_bottlenecks": "各方向瓶颈判断",
    "bottleneck": "速度瓶颈",
    "sender_runtime": "发送端运行时采样",
    "receiver_runtime": "接收端运行时采样",
    "socket_buffers": "套接字实际缓冲区大小",
    "backend_version": "传输库版本",
    "event_loop_core_fraction": "事件循环线程单核占用比例",
    "event_loop_lag_p95_ms": "事件循环延迟P95毫秒",
    "process_cpu_seconds": "进程CPU时间秒",
    "timer_backend": "定时器后端",
    "pacing_fires": "QUIC节奏唤醒次数",
    "pacing_requested_seconds": "QUIC节奏请求等待秒",
    "pacing_late_seconds": "QUIC节奏唤醒延误秒",
    "cwnd_rtt_mbps_median": "拥塞窗口除RTT中位参考Mbps",
    "inflight_fraction_median": "在途数据占拥塞窗口中位比例",
    "congestion_reductions_observed": "观测到的拥塞恢复次数下界",
    "udp_buffer_errors": "命名空间UDP缓冲错误增量",
    "competing_work": "采样期间同时有打洞或文件传输",
    "measurement_contended": "采样时本端矩阵未完成",
    "confidence": "判断可信级别",
    "format": "测速数据格式",
    "chunk_bytes": "测速分块（字节）",
    "window_bytes": "最大未确认测速载荷（字节）",
    "window_peak_bytes": "本轮发送窗口峰值（字节）",
    "window_mode": "发送窗口模式",
    "requested_bytes": "本轮流量上限（字节）",
    "sample_limited": "本轮结束条件",
    "target_seconds": "目标采样时长（秒）",
    "bytes_sent": "已发送字节",
    "bytes_confirmed": "对端确认字节",
    "sender_cpu_seconds": "发送端进程 CPU 耗时（秒）",
    "short_sample": "样本时长不足一秒",
    "mtu_evidence": "方向性 MTU 证据",
    "udp_remote": "UDP 实际对端",
    "gateway_action": "网关控制结果",
    "gateway_reason": "网关控制原因",
    "mapping_endpoint": "映射端点",
    "address": "地址",
    "family": "地址族",
    "interface": "网卡",
    "interface_up": "网卡已启用",
    "type": "地址类型",
    "temporary": "临时地址",
    "prefix": "网段",
    "prefixlen": "前缀长度",
    "scope": "作用范围",
    "mtu": "网卡 MTU",
    "preferred_lifetime": "采集时首选期（秒）",
    "valid_lifetime": "采集时有效期（秒）",
    "tentative": "仍在 DAD 检测",
    "dadfailed": "DAD 检测失败",
    "deprecated": "已弃用",
    "source": "证据来源",
    "observed_monotonic": "采集单调时钟",
    "code": "结果代码",
    "firewall_assessment": "入站评估",
    "listener_received": "本端收到回连",
    "address_record": "回连地址记录",
    "observer_elapsed_ms": "观察端耗时（毫秒）",
    "observer_code": "观察端代码",
    "os_errno": "操作系统错误码",
    "protocol": "协议",
    "provider": "查询来源",
    "gateway": "网关",
    "local": "本端地址",
    "mapped": "观察到的映射",
    "observer": "观察端",
    "evidence": "证据",
    "bytes": "确认字节数",
    "mbps": "确认吞吐（Mbps）",
    "seconds": "耗时（秒）",
    "direction": "传输方向",
    "matrix_in_progress": "矩阵仍在运行",
    "min_ms": "最小延迟（毫秒）",
    "mean_ms": "平均延迟（毫秒）",
    "max_ms": "最大延迟（毫秒）",
    "samples_ms": "延迟样本（毫秒）",
    "server": "服务器",
    "room": "房间",
    "name": "设备名",
    "timeout": "每项超时（秒）",
    "profiles": "重试档位",
    "max_addresses": "候选地址上限",
    "max_pairs": "地址配对上限",
    "expanded": "扩展矩阵",
    "comprehensive": "完整实验矩阵",
    "raw_probes": "原始 ICMP/TCP 实验",
    "auto_retry": "切网自动协调重试",
    "nat64_prefixes": "配置的 NAT64 前缀",
    "ttl": "TTL / Hop Limit",
    "synchronized": "RTT 同步",
    "socket_count": "socket 阵列数量",
    "target_count": "每轮随机目标端口数",
    "rounds": "端口搜索轮数",
    "hard_side": "多 socket 端",
    "gateway_side": "网关申请端",
    "prediction_window": "预测窗口",
    "prediction_radius": "预测半径",
    "stun": "STUN 观察点",
    "port_prediction": "端口预测",
    "diagnostics": "外部网络诊断",
    "index": "索引",
    "peer": "对端",
    "cursor": "日志游标",
    "id": "记录标识",
    "client": "设备标识",
    "run": "运行标识",
    "time": "UTC 时间",
    "level": "日志级别",
    "event": "事件",
    "message": "消息",
    "fields": "详细字段",
    "exception": "异常类型",
    "traceback": "完整堆栈",
    "ready": "已认证",
    "closed": "已关闭",
    "configuration": "原始配置",
    "data_dir": "数据目录",
    "retry_parameters": "全部重试参数",
}


def readable_fields(value):
    if isinstance(value, dict):
        return {f"{FIELDS[k]} ({k})" if k in FIELDS else k: readable_fields(v) for k, v in value.items()}
    if isinstance(value, list):
        return [readable_fields(v) for v in value]
    return value


def translated(value):
    if value is None:
        return "—"
    raw = str(value)
    if raw in STATES or raw in REASONS:
        return STATES.get(raw, REASONS.get(raw))
    if ":" in raw and raw.split(":", 1)[1] in REASONS:
        return REASONS[raw.split(":", 1)[1]] + " · " + raw
    return raw


def safe_text(value):
    return "".join(c if c in "\n\t" or ord(c) >= 32 and ord(c) != 127 else "?" for c in str(value))


def json_text(value):
    return Text(safe_text(json.dumps(redact(value), ensure_ascii=False, indent=2, default=str)))


def number(value, suffix=""):
    return "—" if value is None else f"{value:.2f}{suffix}"


class HistoryLog(RichLog):
    """Keep renderables, not width-dependent strips produced while a tab is hidden."""

    def __init__(self, *, history_limit=None, **kwargs):
        super().__init__(**kwargs)
        self.history = deque(maxlen=history_limit)
        self.serial = 0
        self.rendered_serial = 0
        self.rendered_width = None
        self.rendered_entries = deque()

    def append_entry(self, content):
        self.serial += 1
        self.history.append((self.serial, content.copy()))

    def on_show(self):
        self.call_after_refresh(self.flush_history)

    def on_resize(self, event):
        super().on_resize(event)
        self.call_after_refresh(self.flush_history)

    def flush_history(self):
        width = self.scrollable_content_region.width
        if not self.is_on_screen or width < 2 or not self._size_known:
            return
        first = self.history[0][0] if self.history else None
        rebuild = width != self.rendered_width
        follow = not self.lines or self.is_vertical_scroll_end
        position = self.scroll_y
        if rebuild:
            self.clear()
            self.rendered_serial = 0
            self.rendered_entries.clear()
        removed_lines = 0
        while self.rendered_entries and (first is None or self.rendered_entries[0][0] < first):
            _, count = self.rendered_entries.popleft()
            removed_lines += count
        if removed_lines:
            # Match RichLog's line eviction without rendering retained entries again.
            del self.lines[:removed_lines]
            self._start_line += removed_lines
            self.virtual_size = Size(self.virtual_size.width, len(self.lines))
            self.refresh()
        new_entries = []
        for serial, content in reversed(self.history):
            if serial <= self.rendered_serial:
                break
            new_entries.append((serial, content))
        for serial, content in reversed(new_entries):
            previous_lines = len(self.lines)
            self.write(content, width=width, scroll_end=False)
            self.rendered_entries.append((serial, len(self.lines) - previous_lines))
            self.rendered_serial = serial
        self.rendered_width = width
        if follow and (rebuild or removed_lines or new_entries):
            # Deferred per-entry scrolling can override a later manual scroll.
            self.scroll_end(animate=False, immediate=True, x_axis=False)
        elif not follow and (rebuild or removed_lines):
            self.scroll_to(y=max(0, position - removed_lines), animate=False, immediate=True)


class LogReader:
    """A separate read-only connection remains usable after the backend journal closes."""

    def __init__(self, path):
        from .logcodec import document_text

        self.db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
        self.db.execute("PRAGMA query_only=ON")
        self.db.create_function("journal_json", 1, document_text, deterministic=True)
        self.indexed = "run" in {row[1] for row in self.db.execute("PRAGMA table_info(events)")}

    def stats(self):
        count, pending, cursor = self.db.execute(
            "SELECT COUNT(*),COALESCE(SUM(acked=0),0),COALESCE(MAX(seq),0) FROM events"
        ).fetchone()
        return {"total": count, "pending": pending, "cursor": cursor}

    def browse(self, *, before=None, after=None, run=None, search="", level="", limit=100):
        where, args = ["1=1"], []
        for clause, value in (
            ("seq<?", before),
            ("seq>?", after),
            ("run=?" if self.indexed else "json_extract(journal_json(document),'$.run')=?", run),
            ("instr(journal_json(document),?)>0", search or None),
            ("level=?" if self.indexed else "json_extract(journal_json(document),'$.level')=?", level or None),
        ):
            if value is not None:
                where.append(clause)
                args.append(value)
        order = "ASC" if after is not None else "DESC"
        rows = self.db.execute(
            "SELECT seq,journal_json(document) FROM events WHERE "
            + " AND ".join(where) + f" ORDER BY seq {order} LIMIT ?",
            [*args, min(max(limit, 1), 1000)],
        )
        return [{"cursor": seq, **json.loads(doc)} for seq, doc in rows]

    def detail(self, cursor):
        row = self.db.execute("SELECT journal_json(document) FROM events WHERE seq=?", (cursor,)).fetchone()
        if not row:
            return {"error": "记录不存在", "cursor": cursor}
        record = json.loads(row[0])
        if record["event"] != "journal.fragment":
            return {"cursor": cursor, **record}
        fields = record["fields"]
        sql = (
            "SELECT journal_json(document) FROM events WHERE original_id=? ORDER BY fragment_index"
            if self.indexed else
            "SELECT journal_json(document) FROM events "
            "WHERE json_extract(journal_json(document),'$.event')='journal.fragment' "
            "AND json_extract(journal_json(document),'$.fields.original_id')=? "
            "ORDER BY json_extract(journal_json(document),'$.fields.index')"
        )
        fragments = [
            json.loads(doc)["fields"]
            for (doc,) in self.db.execute(
                sql,
                (fields["original_id"],),
            )
        ]
        if [p["index"] for p in fragments] == list(range(fields["parts"])):
            return {
                "cursor": cursor,
                "reassembled_fragments": len(fragments),
                **json.loads("".join(p["json_part"] for p in fragments)),
            }
        return {"cursor": cursor, "fragment_state": "分片不完整", **record}

    def close(self):
        self.db.close()


class DetailScreen(ModalScreen):
    BINDINGS = [Binding("escape", "close", "关闭")]

    def __init__(self, title, document):
        super().__init__()
        self.heading, self.document = title, document

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-dialog"):
            yield Label(Text(self.heading), id="detail-title")
            with TabbedContent(initial="detail-readable"):
                with TabPane("中文字段", id="detail-readable"):
                    with VerticalScroll():
                        yield Static(json_text(readable_fields(self.document)), markup=False)
                with TabPane("原始 JSON", id="detail-raw"):
                    with VerticalScroll(id="detail-scroll"):
                        yield Static(json_text(self.document), id="detail-body", markup=False)
            yield Button("关闭", id="close-detail")

    @on(Button.Pressed, "#close-detail")
    def action_close(self):
        self.dismiss()


class JoinScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss(None)", "取消")]

    def __init__(self, config):
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        with Vertical(id="join-dialog"):
            yield Label("加入房间", id="join-title")
            yield Label("服务器地址")
            yield Input(value=str(self.config.get("server", "")), placeholder="服务器 IP:8443", id="server")
            yield Label("房间号")
            yield Input(id="room", max_length=64)
            yield Static("", id="join-security", markup=False)
            yield Static(NETWORK_TEST_NOTICE, id="join-network-notice", markup=False)
            yield Static("", id="join-error")
            with Horizontal():
                yield Button("加入", variant="primary", id="join")
                yield Button("取消", id="cancel-join")

    def on_mount(self):
        self.query_one("#room" if self.config.get("server") else "#server", Input).focus()
        self.update_security()

    @on(Input.Changed, "#server")
    def update_security(self):
        try:
            server = normalize_server_address(self.query_one("#server", Input).value)
        except ValueError:
            warning = ""
        else:
            warning = "明文信令：服务器地址和诊断日志不加密" if server.startswith("ws://") else ""
        self.query_one("#join-security", Static).update(warning)

    @on(Input.Submitted, "#server")
    def next_field(self):
        self.query_one("#room", Input).focus()

    @on(Input.Submitted, "#room")
    @on(Button.Pressed, "#join")
    def join(self):
        room = self.query_one("#room", Input).value.strip()
        if not room or len(room) > 64 or any(ord(char) < 32 for char in room):
            self.query_one("#join-error", Static).update("房间号须为 1–64 个字符")
            return
        try:
            server = normalize_server_address(self.query_one("#server", Input).value)
        except ValueError as exc:
            self.query_one("#join-error", Static).update(str(exc))
            return
        self.dismiss({"server": server, "room": room})

    @on(Button.Pressed, "#cancel-join")
    def cancel(self):
        self.dismiss(None)


class AttachmentScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss(None)", "取消")]

    def __init__(self, *, image=False):
        super().__init__()
        self.image = image

    def compose(self) -> ComposeResult:
        with Vertical(id="attachment-dialog"):
            yield Static("发送图片" if self.image else "发送文件", id="attachment-title")
            yield DirectoryTree(Path.home(), id="attachment-tree")
            yield Input(placeholder="文件的完整路径", id="attachment-path")
            with Horizontal():
                yield Button("发送", variant="primary", id="attachment-confirm")
                yield Button("取消", id="attachment-dismiss")

    @on(DirectoryTree.FileSelected, "#attachment-tree")
    def select_file(self, event):
        self.query_one("#attachment-path", Input).value = str(event.path)

    @on(Input.Submitted, "#attachment-path")
    @on(Button.Pressed, "#attachment-confirm")
    def confirm(self):
        path = self.query_one("#attachment-path", Input).value.strip()
        if path:
            self.dismiss(path)

    @on(Button.Pressed, "#attachment-dismiss")
    def cancel(self):
        self.dismiss(None)


def message_metrics_text(metrics):
    line = Text(style="italic #859096")
    line.append("  接收 ")
    try:
        stamp = dt.datetime.fromisoformat(metrics["received_at"]).astimezone()
        value = stamp.strftime("%m-%d %H:%M:%S.%f")[:-3]
    except (TypeError, ValueError, KeyError):
        value = "未确认"
    line.append(value, style="italic #79b8ff")
    line.append("  ·  均速 ")
    speed = metrics.get("mbps")
    line.append(f"{speed:.3f}" if speed is not None else "未测", style="italic #e5c46d")
    if speed is not None:
        line.append(" Mbps")
    duration = metrics.get("receiver_seconds")
    if duration is not None:
        line.append("  ·  耗时 ")
        line.append(f"{duration * 1000:.2f}", style="italic #7dd7bc")
        line.append(" ms")
    return line


class P2PApp(App):
    TITLE = "P2P 网络实验室"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+1", "tab('chat')", "聊天"),
        Binding("ctrl+2", "tab('matrix')", "矩阵"),
        Binding("ctrl+3", "tab('network')", "网络"),
        Binding("ctrl+4", "tab('paths')", "链路"),
        Binding("ctrl+5", "tab('logs')", "日志"),
        Binding("ctrl+6", "tab('settings')", "参数"),
        Binding("ctrl+7", "tab('transfers')", "传输"),
        Binding("ctrl+l", "focus_message", "输入"),
        Binding("ctrl+q,ctrl+c", "quit", "退出", priority=True),
    ]
    CSS = """
    Screen { background: #101416; color: #e0e6e9; }
    #brand { height: 1; background: #263332; color: #e1e9e8; padding: 0 1; }
    #status { height: 2; padding: 0 1; background: #192123; }
    #network-banner { height: 4; padding: 0 1; background: #172420; overflow-y: auto; }
    #wan-summary { height: 2; color: #7dd7bc; overflow-y: auto; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 0 1; }
    ContentSwitcher { height: 1fr; }
    #chat-layout { height: 1fr; }
    #chat-log { width: 2fr; height: 1fr; padding: 0 1; }
    #activity { width: 1fr; min-width: 32; height: 1fr; border-left: solid #354345; padding: 0 1; }
    .compact #activity { display: none; }
    .compact #toolbar Button { min-width: 6; width: 10; margin-right: 0; padding: 0; }
    .compact #speed-size { width: 12; }
    .narrow #toolbar { layout: grid; grid-size: 3 2; grid-columns: 1fr 1fr 1fr; grid-rows: 3 3; height: 6; }
    .narrow #toolbar Button, .narrow #speed-size { width: 1fr; }
    RichLog { background: #101416; }
    #measurements { height: 2; color: #7dd7bc; }
    #toolbar { height: 3; padding: 0 1; }
    #toolbar Button { min-width: 8; width: auto; margin-right: 1; }
    #speed-size { width: 13; }
    #path-tools { height: 3; }
    #path-tools Button { min-width: 8; width: auto; margin-right: 1; }
    #path-speed-size { width: 13; }
    #batch-status { height: 1; color: #7dd7bc; }
    #path-monitor-tools { height: 3; }
    #path-rtt-monitor { width: 25; }
    #path-monitor-tools #batch-status { width: 1fr; height: 3; content-align: left middle; }
    #command-row { height: 3; padding: 0 1; }
    #message { width: 1fr; }
    #send { min-width: 8; width: 8; }
    #attach-file, #attach-image { min-width: 6; width: 6; }
    #transfer-progress { height: 1; color: #7dd7bc; }
    #transfer-selection { height: 2; overflow-y: auto; }
    #transfer-tools { height: 3; }
    #transfer-tools Button { min-width: 6; width: auto; margin-right: 1; }
    #attachment-dialog { width: 90%; height: 85%; background: #192123; border: solid #638f80; padding: 1; }
    #attachment-title { height: 2; color: #7dd7bc; }
    #attachment-tree { height: 1fr; }
    #attachment-dialog Horizontal { height: 3; }
    Button { border: none; height: 3; background: #293436; }
    Button:hover { background: #3b4b4d; }
    Button.-primary { background: #21634f; }
    Button.-error { background: #703b42; }
    DataTable { height: 1fr; background: #101416; }
    DataTable > .datatable--header { background: #273335; color: #d8e5e4; }
    #matrix-selection { height: 5; padding: 0 1; background: #192123; }
    #path-selection { height: 3; padding: 0 1; background: #192123; }
    .section-title { height: 1; margin-top: 1; color: #7dd7bc; }
    #addresses { height: 12; } #callbacks { height: 7; }
    #public-ips, #gateways { height: 7; }
    #network-full { width: 20; margin-top: 1; }
    #log-controls { height: 3; }
    #log-search { width: 1fr; } #log-level { width: 13; } #log-run { width: 15; }
    #log-pager { height: 3; } #log-pager Button { min-width: 8; }
    #log-count { width: 1fr; height: 3; content-align: right middle; }
    #settings-table { height: 1fr; }
    #detail-dialog { width: 94%; height: 90%; background: #192123; border: solid #638f80; padding: 1; }
    #detail-title { height: 2; color: #7dd7bc; }
    #detail-scroll { height: 1fr; } #detail-body { width: 1fr; height: auto; }
    #close-detail { width: 10; margin-top: 1; }
    #join-dialog { width: 72; max-width: 95%; height: auto; background: #192123; border: solid #638f80; padding: 1 2; }
    #join-dialog Static { height: auto; margin: 0; }
    #join-dialog Horizontal { height: 3; } #join-dialog Button { margin-right: 1; }
    #join-title { height: 2; color: #7dd7bc; }
    Footer { background: #263332; }
    """

    def __init__(self, config=None, *, room=None, client=None, start_backend=True):
        super().__init__()
        self.config = config if config is not None else (client.config if client else {})
        self.room, self.client, self.start_backend = room, client, start_backend
        self.reader = None
        self.backend_task = None
        self.latest = {}
        self.inbound = {}
        self.cursor = 0
        self.page_before = None
        self.page_stack = []
        self.log_rows = []
        self.details = {}
        self.table_cache = {}
        self.busy = set()
        self.closing = False
        self.disposing = False
        self.main_screen = None

    def query_ui(self, selector, expect_type=None):
        return self.main_screen.query_one(selector, expect_type)

    def table(self, name):
        return DataTable(id=name, cursor_type="row", zebra_stripes=True)

    def compose(self) -> ComposeResult:
        yield Static("P2P 网络实验室", id="brand")
        yield Static("尚未加入房间", id="status", markup=False)
        yield Static(
            "本机 IPv4 / IPv6：采集中\n对端 IPv4 / IPv6：等待配对", id="network-banner", markup=False
        )
        with TabbedContent(initial="chat", id="views"):
            with TabPane("聊天", id="chat"):
                yield Static("延迟  —    上行  —    下行  —", id="measurements", markup=False)
                with Horizontal(id="chat-layout"):
                    yield HistoryLog(id="chat-log", wrap=True, min_width=1)
                    yield HistoryLog(id="activity", wrap=True, min_width=1, history_limit=1000)
                yield Static("", id="transfer-progress", markup=False)
                with Horizontal(id="toolbar"):
                    yield Button("测延迟", id="ping")
                    yield Select(
                        [(f"≤{n}MiB", n) for n in (1, 4, 16, 64, 128, 256, 1024)],
                        value=128,
                        allow_blank=False,
                        id="speed-size",
                    )
                    yield Button("双向测速", id="speed")
                    yield Button("网络重测", id="net")
                    yield Button("重新打洞", id="retry")
                    yield Button("退出", id="quit")
                with Horizontal(id="command-row"):
                    yield Input(placeholder="消息或命令", id="message")
                    yield Button("文件", id="attach-file", tooltip="选择要发送的文件")
                    yield Button("图片", id="attach-image", tooltip="选择要发送的图片")
                    yield Button("发送", variant="primary", id="send")
            with TabPane("传输", id="transfers"):
                yield self.table("transfer-table")
                yield Static("", id="transfer-selection", markup=False)
                with Horizontal(id="transfer-tools"):
                    yield Button("接收", id="transfer-accept")
                    yield Button("拒绝", id="transfer-reject")
                    yield Button("取消", id="transfer-cancel")
                    yield Button("查看图片", id="transfer-view")
                    yield Button("接收目录", id="transfer-directory")
            with TabPane("打洞矩阵", id="matrix"):
                yield self.table("attempts")
                yield Static("", id="matrix-selection", markup=False)
            with TabPane("网络", id="network"):
                with VerticalScroll():
                    yield Static("网卡与完整地址清单", classes="section-title")
                    yield self.table("addresses")
                    yield Static("IPv4 / IPv6 HTTP 入站基线", classes="section-title")
                    yield self.table("callbacks")
                    yield Static("多源公网 IP 观察", classes="section-title")
                    yield self.table("public-ips")
                    yield Static("路由与网关", classes="section-title")
                    yield self.table("gateways")
                    yield Button("完整网络证据", id="network-full")
            with TabPane("链路", id="paths"):
                yield Static("", id="wan-summary", markup=False)
                yield self.table("path-table")
                yield Static("", id="path-selection", markup=False)
                with Horizontal(id="path-monitor-tools"):
                    yield Checkbox("当前链路实时 RTT", value=False, id="path-rtt-monitor")
                    yield Static("", id="batch-status", markup=False)
                with Horizontal(id="path-tools"):
                    yield Button("切换链路", id="use-path")
                    yield Select(
                        [(f"≤{n}MiB", n) for n in (1, 16, 64, 128, 256, 1024)],
                        value=128,
                        allow_blank=False,
                        id="path-speed-size",
                    )
                    yield Button("批量测速", id="speed-all")
                    yield Button("公网测速", id="wan-test")
            with TabPane("完整日志", id="logs"):
                with Horizontal(id="log-controls"):
                    yield Input(placeholder="搜索事件、参数或原因", id="log-search")
                    yield Select(
                        [
                            ("全部级别", ""),
                            ("信息", "INFO"),
                            ("警告", "WARNING"),
                            ("错误", "ERROR"),
                            ("严重", "CRITICAL"),
                            ("调试", "DEBUG"),
                        ],
                        value="",
                        allow_blank=False,
                        id="log-level",
                    )
                    yield Select(
                        [("本次运行", "current"), ("全部历史", "all")],
                        value="current",
                        allow_blank=False,
                        id="log-run",
                    )
                yield self.table("log-table")
                with Horizontal(id="log-pager"):
                    yield Button("较早", id="log-older")
                    yield Button("较新", id="log-newer")
                    yield Button("实时", id="log-live")
                    yield Static("", id="log-count", markup=False)
            with TabPane("参数", id="settings"):
                yield self.table("settings-table")
                yield Button("完整有效配置", id="config-full")
        yield Footer()

    def on_mount(self):
        self.main_screen = self.screen
        schemas = {
            "attempts": [
                "序号",
                "方案",
                "IP",
                "重试档",
                "请求/实际",
                "本端",
                "对端",
                "通道",
                "耗时 ms",
                "方案解释",
                "原因",
            ],
            "addresses": ["网卡", "IP", "地址", "类型", "状态", "入选", "MTU", "首选期 / 有效期", "排除原因"],
            "callbacks": ["地址", "类型", "结果", "耗时 ms", "原始代码"],
            "public-ips": ["来源", "IP", "观察地址", "状态", "原因"],
            "gateways": ["IP", "网卡", "本地地址", "网关"],
            "path-table": [
                "索引",
                "当前",
                "机制",
                "IP",
                "状态",
                "RTT ms",
                "更新距今",
                "上行 Mbps",
                "下行 Mbps",
                "速度瓶颈 ↑ / ↓",
                "测速",
                "尝试 ID",
            ],
            "log-table": ["序号", "时间 UTC", "级别", "事件", "消息"],
            "settings-table": ["参数", "当前值"],
            "transfer-table": ["方向", "类型", "文件名", "状态", "进度", "实时 Mbps", "均速 Mbps",
                               "耗时 s", "开始时间", "接收时间", "ID"],
        }
        for name, columns in schemas.items():
            table = self.query_ui("#" + name, DataTable)
            for index, title in enumerate(columns):
                table.add_column(title, key=str(index), width=52 if title == "方案解释" else None)
        self.set_class(self.size.width < 100, "compact")
        self.set_class(self.size.width < 75, "narrow")
        self.set_interval(0.5, self.refresh_state)
        if self.client:
            self.attach_client()
        elif self.room:
            self.join_room(self.room)
        else:
            self.push_screen(JoinScreen(self.config), self.join_room)

    def join_room(self, room):
        if room is None:
            self.exit()
            return
        if isinstance(room, dict):
            self.config = {**self.config, "server": room["server"],
                           "allow_insecure": room["server"].startswith("ws://")}
            room = room["room"]
        self.room = room
        try:
            self.client = Client(self.config, room, console=False)
            self.attach_client()
        except Exception as exc:
            self.notify(safe_text(str(exc)), title="客户端配置错误", severity="error", timeout=10)
            self.push_screen(JoinScreen(self.config), self.join_room)

    def attach_client(self):
        self.client.log.console = False
        self.client.chat_display = self.receive_chat
        self.reader = LogReader(self.client.data / "client.sqlite3")
        self.cursor = 0
        if self.start_backend:
            self.client.log.event(
                "terminal.tui_started",
                "中文 TUI 已启动",
                views=["聊天", "传输", "打洞矩阵", "网络", "链路", "完整日志", "参数"],
            )
        if self.start_backend:
            self.backend_task = asyncio.create_task(self.run_backend(), name="tui-client")
        self.query_ui("#message", Input).focus()
        self.refresh_state()

    async def run_backend(self):
        try:
            await self.client.run(interactive=False, signal_stop=self.action_quit)
        except Exception as exc:
            self.notify(safe_text(str(exc)), title="客户端异常", severity="error", timeout=10)
        finally:
            self.refresh_state()
            if self.closing:
                self.exit()

    async def on_unmount(self):
        self.disposing = True
        if self.backend_task and not self.backend_task.done():
            self.client.stop.set()
            await self.backend_task
        if self.client:
            self.client.chat_display = None
            self.client.link_monitor_active = False
        if self.reader:
            self.reader.close()
            self.reader = None

    def on_resize(self, event):
        self.set_class(event.size.width < 100, "compact")
        self.set_class(event.size.width < 75, "narrow")
        self.call_after_refresh(self.flush_chat_logs)

    def action_tab(self, name):
        self.main_screen.set_focus(None)
        self.query_ui("#views", TabbedContent).active = name
        target = {
            "chat": "message",
            "matrix": "attempts",
            "network": "addresses",
            "paths": "path-table",
            "logs": "log-search",
            "settings": "settings-table",
            "transfers": "transfer-table",
        }[name]
        self.query_ui("#" + target).focus()
        self.refresh_state()

    def action_focus_message(self):
        self.action_tab("chat")
        self.query_ui("#message", Input).focus()

    @on(TabbedContent.TabActivated, "#views")
    def view_changed(self, event):
        if self.client:
            self.client.link_monitor_active = event.pane.id == "paths"
        self.call_after_refresh(self.flush_chat_logs)

    @on(Checkbox.Changed, "#path-rtt-monitor")
    def rtt_monitor_changed(self, event):
        if self.client:
            self.client.rtt_monitor_enabled = event.value
            self.client.log.event("path.rtt_monitor_changed", enabled=event.value,
                                  scope="current-path-only;paused-during-benchmarks-and-hidden-tab")

    def flush_chat_logs(self):
        if self.disposing or not self.main_screen:
            return
        if self.query_ui("#views", TabbedContent).active == "chat":
            for name in ("chat-log", "activity"):
                self.query_ui("#" + name, HistoryLog).flush_history()

    def action_quit(self):
        if self.closing:
            return
        self.closing = True
        if self.client and self.backend_task and not self.backend_task.done():
            self.client.stop.set()
            self.query_ui("#status", Static).update("正在关闭链路并等待日志上传确认…")
        else:
            self.exit()

    def receive_chat(self, name, text, metrics=None):
        if self.disposing:
            return
        line = Text(f"{dt.datetime.now().strftime('%H:%M:%S')}  {safe_text(name)}\n", style="bold #8bcdb6")
        line.append(safe_text(text) + "\n", style="#e0e6e9")
        if metrics:
            line.append_text(message_metrics_text(metrics))
            line.append("\n")
        self.query_ui("#chat-log", HistoryLog).append_entry(line)
        self.call_after_refresh(self.flush_chat_logs)

    def submit_command(self, text):
        if not self.client or self.client.closed or self.closing:
            self.notify("客户端未连接或已关闭", severity="warning")
            return False
        text = text.strip()
        if not text:
            return False
        command = text.split()[0] if text.startswith("/") else "chat"
        if command == "/quit":
            self.action_quit()
            return True
        if command in self.busy:
            self.notify("该操作仍在进行中", severity="warning")
            return False
        self.busy.add(command)
        self.client.spawn(self.execute_command(text, command), "tui-command:" + command)
        self.refresh_state()
        return True

    async def execute_command(self, text, command):
        try:
            result = await self.client.command(text)
            if command == "chat":
                self.receive_chat("我 · 已送达", text, result)
            elif isinstance(result, str):
                self.notify(result, severity="warning", timeout=8)
        except Exception as exc:
            self.client.log.exception("terminal.command_failed", exc)
            self.notify(
                translated(str(exc)) + "\n" + safe_text(str(exc)),
                title="操作失败",
                severity="error",
                timeout=8,
            )
            if command == "chat":
                self.receive_chat("我 · 发送失败", text)
        finally:
            self.busy.discard(command)
            self.refresh_state()

    @on(Input.Submitted, "#message")
    @on(Button.Pressed, "#send")
    def send_message(self):
        box = self.query_ui("#message", Input)
        if box.value.strip():
            text = box.value
            if self.submit_command(text):
                box.value = ""

    @on(Button.Pressed)
    def button_pressed(self, event):
        name = event.button.id
        commands = {"ping": "/ping", "net": "/net", "retry": "/retry"}
        if name in commands:
            self.submit_command(commands[name])
        elif name == "speed":
            self.submit_command(f"/speed {self.query_ui('#speed-size', Select).value}")
        elif name == "speed-all":
            self.submit_command(f"/speed-all {self.query_ui('#path-speed-size', Select).value}")
        elif name == "wan-test":
            self.submit_command("/wan")
        elif name == "quit":
            self.action_quit()
        elif name in ("attach-file", "attach-image"):
            image = name == "attach-image"

            def selected(path):
                if path:
                    self.submit_command(("/image " if image else "/file ") + shlex.quote(path))

            self.push_screen(AttachmentScreen(image=image), selected)
        elif name == "transfer-directory":
            self.submit_command("/open-dir")
        elif name in ("transfer-accept", "transfer-reject", "transfer-cancel", "transfer-view"):
            table = self.query_ui("#transfer-table", DataTable)
            if table.row_count:
                tid = str(table.ordered_rows[table.cursor_row].key.value)
                command = {"transfer-accept": "/accept", "transfer-reject": "/reject",
                           "transfer-cancel": "/cancel", "transfer-view": "/view"}[name]
                self.submit_command(command + " " + tid)
        elif name == "network-full" and self.client:
            self.push_screen(DetailScreen("完整网络证据", self.client.network))
        elif name == "config-full" and self.client:
            self.push_screen(DetailScreen("完整有效配置", self.effective_settings()))
        elif name == "use-path":
            table = self.query_ui("#path-table", DataTable)
            if table.row_count:
                key = str(table.ordered_rows[table.cursor_row].key.value)
                self.submit_command("/use " + key)
        elif name == "log-older" and self.log_rows:
            self.page_stack.append(self.page_before)
            self.page_before = min(row["cursor"] for row in self.log_rows)
            self.refresh_logs()
        elif name == "log-newer" and self.page_stack:
            self.page_before = self.page_stack.pop()
            self.refresh_logs()
        elif name == "log-live":
            self.reset_logs()

    @on(Input.Changed, "#log-search")
    @on(Select.Changed, "#log-level")
    @on(Select.Changed, "#log-run")
    def log_filter_changed(self):
        self.reset_logs()

    def reset_logs(self):
        self.page_before = None
        self.page_stack.clear()
        self.refresh_logs()

    def update_table(self, name, rows, documents=None):
        table = self.query_ui("#" + name, DataTable)
        current = self.table_cache.setdefault(name, {})
        incoming = {str(key): tuple(safe_text(v) for v in cells) for key, cells in rows}
        if list(current) != list(incoming):
            selected = str(table.ordered_rows[table.cursor_row].key.value) if table.row_count else None
            if name == "log-table" and self.page_before is None and not table.has_focus:
                selected = None
            table.clear()
            current.clear()
            for key, cells in incoming.items():
                table.add_row(*(Text(cell) for cell in cells), key=key)
                current[key] = cells
            if selected in incoming:
                table.move_cursor(row=list(incoming).index(selected), animate=False)
            self.details[name] = documents or {}
            return
        for key in list(current):
            if key not in incoming:
                table.remove_row(key)
                del current[key]
        for key, cells in incoming.items():
            if key not in current:
                table.add_row(*(Text(cell) for cell in cells), key=key)
            elif current[key] != cells:
                for index, cell in enumerate(cells):
                    if current[key][index] != cell:
                        table.update_cell(key, str(index), Text(cell), update_width=True)
            current[key] = cells
        self.details[name] = documents or {}

    def refresh_state(self):
        if (not self.client or not self.reader or not self.is_mounted or self.disposing
                or not self.main_screen or not self.main_screen.is_running or not self.main_screen.is_attached):
            return
        client = self.client
        refresh_started = time.perf_counter()
        for record in self.reader.browse(after=self.cursor, run=client.log.run, limit=1000):
            self.cursor = record["cursor"]
            if record.get("run") != client.log.run:
                continue
            event, fields = record["event"], record["fields"]
            self.latest[event] = record
            if event == "speed.result":
                self.latest["speed." + fields.get("direction", "unknown")] = record
            if event in ("ipv6.inbound_result", "ipv4.inbound_result", "ipv6.inbound_not_tested"):
                self.inbound[fields.get("address", "未测试")] = record
            if event in EVENTS or record["level"] in ("WARNING", "ERROR", "CRITICAL"):
                heading = EVENTS.get(event, event)
                detail = translated(
                    fields.get("state") or fields.get("code") or fields.get("reason") or record["message"]
                )
                parts = [
                    translated(fields.get(key)) for key in ("state", "code", "reason") if fields.get(key)
                ]
                if record["message"]:
                    parts.append(safe_text(record["message"]))
                if fields.get("mbps") is not None:
                    parts.append(f"{fields.get('direction', '')} {number(fields['mbps'])} Mbps")
                if event.startswith("file.") and fields.get("transfer_id"):
                    tid = fields["transfer_id"]
                    transfer = client.transfers.records.get(tid, {})
                    parts.append(f"{tid[:8]} · {safe_text(transfer.get('name', fields.get('name', '')))}")
                    if event == "file.progress":
                        parts.append(f"{fields['bytes']:,}/{fields['total_bytes']:,} 字节")
                if parts:
                    detail = " · ".join(dict.fromkeys(parts))
                attempt = fields.get("attempt")
                label = self.attempt_label(attempt, fields) if attempt else ""
                if event == "wan.completed":
                    detail = (
                        translated(fields.get("evidence", {}).get("state"))
                        + " · "
                        + translated(fields.get("evidence", {}).get("reason", ""))
                    )
                entry = Text(
                    f"{record['time'][11:19]}  {heading}\n{safe_text(label)}\n{safe_text(detail)}\n"
                    if label
                    else f"{record['time'][11:19]}  {heading}\n{safe_text(detail)}\n",
                    style="#deba75" if record["level"] in ("WARNING", "ERROR") else "#a5b8b9",
                )
                self.query_ui("#activity", HistoryLog).append_entry(entry)
        stats = self.reader.stats()
        paths = [p for p in client.paths if p.ready.is_set() and not p.closed]
        manager = client.manager
        done, total = (len(manager.results), len(manager.plan)) if manager else (0, 0)
        peer = client.peer.get("name", "—") if client.peer else "等待另一台设备"
        signal = "已关闭" if client.closed else "在线" if client.connected.is_set() else "连接中 / 重连中"
        active = client.active_path
        link = f"{active.mechanism} / IPv{active.family or '?'}" if active and active in paths else "暂无"
        self.query_ui("#brand", Static).update(
            Text(f"P2P 网络实验室   {safe_text(client.name)}   房间 {safe_text(client.room)}")
        )
        self.query_ui("#status", Static).update(
            Text(
                f"信令 {signal}   对端 {safe_text(peer)}   可用链路 {len(paths)}   当前 {link}\n"
                f"矩阵 {done}/{total}   角色 {'协调端' if client.leader else '参与端' if client.paired.is_set() else '未配对'}   日志 {stats['total']} 条 / 待上传 {stats['pending']} 条"
            )
        )
        self.refresh_banner()
        ping = self.latest.get("ping.result", {}).get("fields", {})
        up = self.latest.get("speed.local-to-peer", {}).get("fields", {})
        down = self.latest.get("speed.peer-to-local", {}).get("fields", {})
        self.query_ui("#measurements", Static).update(
            Text(
                f"RTT 均值 {number(ping.get('mean_ms'), ' ms')}   最小 {number(ping.get('min_ms'))} / 最大 {number(ping.get('max_ms'))} ms\n"
                f"确认吞吐 上行 {number(up.get('mbps'), ' Mbps')}   下行 {number(down.get('mbps'), ' Mbps')}"
            )
        )
        available = (bool(paths) or any(client.can_reopen(p) for p in client.paths)) and not client.closed and not self.closing
        for name, command in (("ping", "/ping"), ("speed", "/speed")):
            self.query_ui("#" + name, Button).disabled = (
                not available or command in self.busy or (command == "/speed" and "/speed-all" in self.busy)
            )
        self.query_ui("#speed-all", Button).disabled = not available or bool(
            {"/speed", "/speed-all"} & self.busy
        )
        wan_busy = (
            client.wan_lock.locked()
            or client.wan_result.get("state") == "running"
            or client.peer_network.get("wan", {}).get("state") == "running"
        )
        for name in ("speed", "speed-all"):
            self.query_ui("#" + name, Button).disabled |= wan_busy
        self.query_ui("#wan-test", Button).disabled = (
            client.closed
            or wan_busy
            or not client.diagnostics_enabled
            or client.loopback
            or bool({"/speed", "/speed-all", "/wan"} & self.busy)
            or bool(manager and manager.task and not manager.task.done())
        )
        self.query_ui("#net", Button).disabled = client.closed or "/net" in self.busy
        self.query_ui("#retry", Button).disabled = (
            client.closed
            or not client.paired.is_set()
            or not client.leader
            or bool(manager and manager.task and not manager.task.done())
            or "/retry" in self.busy
        )
        self.query_ui("#send", Button).disabled = client.closed or "chat" in self.busy
        self.query_ui("#use-path", Button).disabled = not available
        self.refresh_matrix()
        self.refresh_network()
        self.refresh_paths()
        self.refresh_settings()
        self.refresh_transfers()
        if self.page_before is None or not self.log_rows:
            self.refresh_logs()
        self.call_after_refresh(self.flush_chat_logs)
        client.ui_refresh_max_ms = max(client.ui_refresh_max_ms, (time.perf_counter() - refresh_started) * 1000)

    def refresh_transfers(self):
        manager = self.client.transfers
        states = {"offered": "等待接收", "sending": "发送中", "receiving": "接收中", "verifying": "校验落盘中",
                  "completed": "已完成", "cancelled": "已取消", "failed": "失败"}
        rows = []
        for tid, item in manager.records.items():
            total, done = item["bytes"], item.get("completed", 0)
            progress = f"{done / total * 100:.1f}%" if total else ("100%" if item["state"] == "completed" else "0%")
            metrics = manager.metrics(tid)
            rows.append((tid, ["发送" if item["direction"] == "send" else "接收",
                              "图片" if item["media"] == "image" else "文件", item["name"],
                              states.get(item["state"], item["state"]), f"{progress} · {done:,}/{total:,}",
                              number(metrics["current_mbps"]) if item["state"] in ("sending", "receiving") else "—",
                              number(item.get("mbps") if item["state"] == "completed" else metrics["average_mbps"]),
                              number(item.get("receiver_seconds") if item["state"] == "completed"
                                     else metrics["elapsed_seconds"]),
                              item.get("started_at", "—"), item.get("received_at", "—"), tid]))
        self.update_table("transfer-table", rows, dict(manager.records))
        table = self.query_ui("#transfer-table", DataTable)
        selected = manager.records.get(str(table.ordered_rows[table.cursor_row].key.value), {}) if table.row_count else {}
        self.query_ui("#transfer-selection", Static).update(
            safe_text(selected.get("saved_path") or selected.get("reason") or selected.get("name", ""))
        )
        for name in ("accept", "reject"):
            self.query_ui("#transfer-" + name, Button).disabled = not (
                selected.get("direction") == "receive" and selected.get("state") == "offered"
            )
        self.query_ui("#transfer-cancel", Button).disabled = selected.get("state") not in (
            "offered", "sending", "receiving", "verifying"
        )
        self.query_ui("#transfer-view", Button).disabled = not (
            selected.get("media") == "image" and selected.get("saved_path") and selected.get("state") == "completed"
        )
        available = not self.client.closed and any(p.ready.is_set() and not p.closed for p in self.client.paths)
        for name in ("attach-file", "attach-image"):
            self.query_ui("#" + name, Button).disabled = not available or len(manager.outgoing) >= 2
        active = [item for item in manager.records.values()
                  if item["state"] in ("offered", "sending", "receiving", "verifying")]
        status = self.query_ui("#transfer-progress", Static)
        status.display = bool(active)
        status.update(Text(" · ".join(
            f"{states[i['state']]} {safe_text(i['name'])} {i.get('completed', 0):,}/{i['bytes']:,} "
            f"耗时 {number(manager.metrics(i['id'])['elapsed_seconds'])} s "
            f"实时 {number(manager.metrics(i['id'])['current_mbps'])} Mbps "
            f"均速 {number(manager.metrics(i['id'])['average_mbps'])} Mbps"
            for i in active
        )))

    def attempt_label(self, attempt, fields=None):
        if not attempt:
            return ""
        for manager in self.client.managers + ([self.client.manager] if self.client.manager else []):
            for index, spec in enumerate(manager.plan):
                if spec["attempt"] == attempt:
                    source = spec.get("source_attempt")
                    if source:
                        for original in self.client.managers:
                            for source_index, source_spec in enumerate(original.plan):
                                if source_spec["attempt"] == source:
                                    return f"#{source_index + 1:03d} {scheme_nickname(spec)}（重建）"
                    return f"#{index + 1:03d} {scheme_nickname(spec)}"
        spec = {**(fields or {}), "method": (fields or {}).get("method", attempt.rsplit("-", 1)[-1])}
        return str(attempt) + " · " + scheme_nickname(spec)

    def refresh_banner(self):
        local, peer = self.client.network_status(), self.client.peer_network
        lines = []
        for name, status in (("本机", local), ("对端", peer)):
            addresses = status.get("addresses", [])
            inbound = {r["address"]: r for r in status.get("inbound", [])}
            private = (
                "、".join(dict.fromkeys(r["address"] for r in addresses if r["family"] == 4)) or "待获取"
            )
            ip_evidence = public_ip_evidence(status)
            signaling_label = (
                "信令转发器" if status.get("signaling_source_mode") == "forwarded" else "信令"
            )
            public = "  ".join(
                label + " " + ("、".join(ip_evidence["4"]["sources"][source]) or "未观察")
                for source, label in (("signaling", signaling_label), ("http", "HTTP出口"))
            )
            conflict = " [出口不一致]" if ip_evidence["4"]["state"] == "multiple-observed-addresses" else ""
            if ip_evidence["4"]["non_global_sources"]["signaling"]:
                conflict += " [信令非公网/可能经转发]"
            elif status.get("signaling_source_mode") == "forwarded":
                conflict += " [转发器地址不参与出口比较]"
            v4_probes = [r for r in inbound.values() if ":" not in r["address"]]
            v6_probes = [r for r in inbound.values() if ":" in r["address"]]

            def family_verdict(probes):
                if not probes:
                    return "未测"
                fresh = [
                    r for r in probes
                    if (age := timestamp_age(r.get("tested_at"))) is not None and age <= 1800
                ]
                if not fresh:
                    return "探测过期"
                if any(r["code"] == "REACHABLE" and r["listener_received"] for r in fresh):
                    return "HTTP可达"
                if all(r["code"] in ("OBSERVER_NO_ROUTE", "OBSERVER_SOURCE_UNAVAILABLE") for r in fresh):
                    return "服务端网络不可用"
                if any(r["code"] != "NOT_TESTED" for r in fresh):
                    return "已探测·未确认"
                return "未测"

            verdict4 = family_verdict(v4_probes)
            verdict6 = family_verdict(v6_probes)
            nat = status.get("nat", {})
            nat_label = nat.get("label", "未测")
            nat_age = timestamp_age(nat.get("tested_at"))
            if nat.get("tested_at") and (nat_age is None or nat_age > 1800):
                nat_label = "探测过期"
            lines.append(
                f"{name} {nat_label}  IPv4{conflict} {private}  {public}  "
                f"入站：IPv4 {verdict4} / IPv6 {verdict6}"
            )
            v6 = []
            stale = timestamp_age(status.get("updated_at"))
            for row in addresses:
                if row["family"] != 6:
                    continue
                observation = inbound.get(row["address"], {})
                code = observation.get("code")
                verdict = (
                    "HTTP可达"
                    if code == "REACHABLE" and observation.get("listener_received")
                    else (
                        "收到回连/响应未确认"
                        if observation.get("listener_received")
                        else "未确认"
                        if code and code != "NOT_TESTED"
                        else "未测"
                    )
                )
                if stale is None or stale > 1800:
                    verdict = "状态过期"
                tested_age = timestamp_age(observation.get("tested_at"))
                if observation and (tested_age is None or tested_age > 1800):
                    verdict = "探测过期"
                kind = (
                    "临时"
                    if row.get("type") == "temporary"
                    else "稳定"
                    if row.get("type") == "stable"
                    else "类型未确认"
                )
                v6.append(f"{row['address']}({kind}·{verdict})")
            http6 = ip_evidence["6"]["sources"]["http"]
            local6 = {r["address"] for r in addresses if r["family"] == 6}
            extra = "  HTTP出口 " + "、".join(http6) if http6 else ""
            if any(a not in local6 for a in http6):
                extra += "（与所示网卡地址不同，非候选）"
            lines.append(f"{name} IPv6 " + ("、".join(v6) or "无可用地址 / 待获取") + extra)
        banner = self.query_ui("#network-banner", Static)
        banner.update(Text(safe_text("\n".join(lines)), no_wrap=True, overflow="ellipsis"))
        banner.tooltip = Text(
            safe_text("\n".join(lines))
            + "\nIPv4 出口是 HTTP/信令观察地址，不代表所有 UDP 映射。入站仅指本次服务端 HTTP/TCP 回连，不能推断所有端口或对端均可入站。"
            + "\n非公网信令来源可能是内网连接或服务端转发器，不参与公网出口比较。"
            + "\n明确的 socat/反向代理模式会将信令来源标记为转发器并排除出口冲突比较；该地址仍保留作来源证据。"
            + "\n公网出口不一致可能来自服务端转发、VPN/代理/TUN、多出口或分流，不按多数票选地址。" + NETWORK_TEST_NOTICE
            + "\nNAT1=公网直连；NAT2=映射/过滤均端点无关；NAT3?=映射端点无关但过滤探测超时后的推测；NAT4=目的相关映射。NAT3? 可能受丢包影响；IPv6 不使用此 IPv4 NAT 等级。"
        )

    def refresh_matrix(self):
        manager = self.client.manager
        rows, documents = [], {}
        if manager:
            results = {r["attempt"]: r for r in manager.results}
            running = self.latest.get("experiment.started", {}).get("fields", {}).get("attempt")
            for index, spec in enumerate(manager.plan):
                attempt = spec["attempt"]
                result = results.get(attempt, {})
                remote = manager.remote_done.get(attempt, {})
                state = result.get("state", "running" if running == attempt else "pending")
                explanation = scheme_explanation(spec)
                reason = translated(result.get("reason", ""))
                diagnosis = result.get("candidate_evidence", {}).get("diagnosis")
                if state == "failed" and diagnosis in ("LOCAL_PUBLIC_UDP_MAPPING_MISSING", "PEER_PUBLIC_UDP_CANDIDATE_MISSING"):
                    reason = translated(diagnosis) + "；" + reason
                family = (
                    "6↔4"
                    if spec.get("method") == "nat64"
                    else
                    "6"
                    if ":" in (spec.get("a_host") or "")
                    else "4"
                    if spec.get("a_host")
                    else translated(spec.get("profile"))
                )
                rows.append(
                    (
                        attempt,
                        [
                            index + 1,
                            scheme_nickname(spec),
                            family,
                            translated(spec.get("profile")),
                            f"{spec.get('datagram_size', '—')}/{result.get('effective_datagram_size', '—')}",
                            translated(state),
                            translated(remote.get("state", "pending")),
                            "是" if result.get("data_path") else "否" if "data_path" in result else "—",
                            number(result.get("elapsed_ms")),
                            explanation,
                            reason,
                        ],
                    )
                )
                documents[attempt] = {
                    "方案解释": explanation,
                    "尝试参数": spec,
                    "本端结果": result,
                    "对端结果": remote,
                }
        self.update_table("attempts", rows, documents)

    def refresh_network(self):
        network = self.client.network
        selected = {(r.get("interface"), r["address"]) for r in network.get("addresses", [])}
        excluded = {
            (r.get("interface"), r["address"]): r.get("reason") for r in network.get("excluded_addresses", [])
        }
        rows, documents = [], {}
        for index, record in enumerate(network.get("address_inventory", [])):
            key = str(index)
            lifetimes = [remaining_lifetime(record, k) for k in ("preferred_lifetime", "valid_lifetime")]
            lifetime = " / ".join(
                ("未知" if record.get("state") == "unverified" else "永久")
                if v is None
                else f"{max(int(v), 0)}s"
                for v in lifetimes
            )
            rows.append(
                (
                    key,
                    [
                        record.get("interface", "—"),
                        record["family"],
                        record["address"],
                        translated(record.get("type")),
                        translated(record.get("state")),
                        "是" if (record.get("interface"), record["address"]) in selected else "否",
                        record.get("mtu", "—"),
                        lifetime,
                        translated(
                            excluded.get((record.get("interface"), record["address"]))
                            or address_rejection(record)
                            or ""
                        ),
                    ],
                )
            )
            documents[key] = record
        self.update_table("addresses", rows, documents)
        self.update_table(
            "callbacks",
            [
                (
                    host,
                    [
                        host,
                        translated(e["fields"].get("address_record", {}).get("type")),
                        translated(e["fields"].get("code", e["fields"].get("firewall_assessment"))),
                        number(e["fields"].get("elapsed_ms")),
                        e["fields"].get("code", e["fields"].get("reason", "—")),
                    ],
                )
                for host, e in self.inbound.items()
            ],
            self.inbound,
        )
        observations = list(network.get("http_observations", []))
        if self.client.server_observed_ipv4:
            observations.insert(0, {
                "provider": "交换服务器（信令转发器）"
                if self.client.signaling_source_mode == "forwarded"
                else "交换服务器（信令）",
                "family": 4, "state": "observed",
                "address": self.client.server_observed_ipv4, "reason": "仅此信令连接；非 UDP 映射",
            })
        self.update_table(
            "public-ips",
            [
                (
                    str(i),
                    [
                        r.get("provider", "—") + ("（国内适用）" if r.get("region") == "domestic" else ""),
                        r.get("family", "—"),
                        r.get("address", r.get("ip", "—")),
                        translated(r.get("state")),
                        translated(r.get("reason", "")),
                    ],
                )
                for i, r in enumerate(observations)
            ],
            {str(i): r for i, r in enumerate(observations)},
        )
        gateways = [
            {"family": version, **r}
            for version in (4, 6)
            for r in network.get("gateways" if version == 4 else "gateways6", [])
        ]
        self.update_table(
            "gateways",
            [
                (str(i), [r["family"], r.get("interface", "—"), r.get("local", "—"), r.get("gateway", "—")])
                for i, r in enumerate(gateways)
            ],
            {str(i): r for i, r in enumerate(gateways)},
        )

    def refresh_paths(self):
        rows, documents = [], {}
        for index, path in enumerate(self.client.paths):
            age = time.monotonic() - path.rtt_measured_at if path.rtt_measured_at is not None else None
            fresh = age is not None and age < 10 and path.rtt_state == "measured" and not path.closed
            speeds = path.latest_speed
            state = getattr(path, "speed_state", "pending")
            if state == "success" and any(r.get("short_sample") for r in speeds.values()):
                state = "短样本"

            def speed_value(direction):
                record = speeds.get(direction, {})
                value = number(record.get("mbps"))
                if record and record.get("measurement_run") != getattr(path, "speed_run", None):
                    value += "（旧）"
                else:
                    verdict = speed_assessment(record, self.client.path_reference(path, direction))
                    if verdict:
                        if verdict["state"] == "above-reference":
                            value += "（超过WAN参考）"
                        elif verdict["state"] == "near-limit":
                            basis = "上限" if verdict["basis"] == "configured" else "参考"
                            value += f"（≥90%{basis}）"
                return value

            def speed_limit(direction):
                record = speeds.get(direction, {})
                if not record:
                    return "未测"
                if record.get("measurement_run") != getattr(path, "speed_run", None):
                    return "旧样本"
                return bottleneck_assessment(
                    record, self.client.path_reference(path, direction),
                    competing=record.get("measurement_contended", False),
                )["label"]

            rows.append(
                (
                    str(index),
                    [
                        index,
                        "当前" if path is self.client.active_path else "",
                        self.attempt_label(path.attempt, {"method": path.mechanism}),
                        path.family or "未确认",
                        "冷备（待重建）" if path.closed and self.client.can_reopen(path)
                        else "已关闭" if path.closed else "已认证" if path.ready.is_set() else "认证中",
                        number(path.last_rtt) if fresh else "超时" if path.rtt_state == "timeout"
                        else number(path.last_rtt) + "（历史）" if path.last_rtt is not None else "—",
                        f"{age:.1f}s" if age is not None else "—",
                        speed_value("local-to-peer"),
                        speed_value("peer-to-local"),
                        " / ".join(speed_limit(d) for d in ("local-to-peer", "peer-to-local")),
                        translated(state),
                        path.attempt,
                    ],
                )
            )
            result = next(
                (r for m in self.client.managers for r in m.results if r["attempt"] == path.attempt), {}
            )
            documents[str(index)] = {
                "index": index,
                "attempt": path.attempt,
                "mechanism": path.mechanism,
                "family": path.family,
                "ready": path.ready.is_set(),
                "closed": path.closed,
                "cold_standby": path.closed and self.client.can_reopen(path),
                "source_attempt": getattr(path, "source_attempt", path.attempt),
                "rtt_policy": "按需；实时监测须手动开启，且只针对当前链路",
                "rtt_ms": path.last_rtt,
                "rtt_state": path.rtt_state,
                "rtt_age_seconds": age,
                "speed_results": speeds,
                "speed_bottlenecks": {
                    d: bottleneck_assessment(r, self.client.path_reference(path, d),
                                            competing=r.get("measurement_contended", False))
                    for d, r in speeds.items()
                },
                "wan_references": {
                    d: self.client.path_reference(path, d) for d in ("local-to-peer", "peer-to-local")
                },
                "peer": redact(path.peer),
                "experiment_result": result,
            }
        self.update_table("path-table", rows, documents)
        summaries = []
        for name, status in (("本机", self.client.network_status()), ("对端", self.client.peer_network)):
            wan = status.get("wan", {})
            rates = " / ".join(
                f"IPv{f} ↑{number(r.get('upload_mbps'))} ↓{number(r.get('download_mbps'))} Mbps"
                for f, r in wan.get("families", {}).items()
            )
            state = {
                "not-tested": "未测试",
                "configured": "配置上限",
                "measured": "WAN实测参考",
                "running": "测速中",
            }.get(wan.get("state"), translated(wan.get("state")))
            summaries.append(f"{name} {state}  {rates}")
        self.query_ui("#wan-summary", Static).update(Text(safe_text("\n".join(summaries))))
        self.query_ui(
            "#wan-test", Button
        ).tooltip = "LibreSpeed 多节点公网测速；会产生大量流量，与 P2P 测速互斥。/wan 可重新采样。"
        table = self.query_ui("#path-table", DataTable)
        if table.row_count:
            selected = documents[str(table.ordered_rows[table.cursor_row].key.value)]
            age = selected["rtt_age_seconds"]
            self.query_ui("#path-selection", Static).update(
                Text(
                    f"尝试 {selected['attempt']}\n对端 {selected['peer'].get('name', '—')} · RTT {number(selected['rtt_ms'], ' ms')} · {translated(selected['rtt_state'])} · 样本 {number(age, ' 秒前')}"
                )
            )
            self.query_ui("#path-selection", Static).tooltip = "\n".join(
                f"{'上行' if d == 'local-to-peer' else '下行'}：{r['label']}；{r['reason']}"
                for d, r in selected["speed_bottlenecks"].items()
            ) or None
        batch = self.client.batch_speed_state
        self.query_ui("#batch-status", Static).update(
            Text(
                f"批量测速 {translated(batch.get('state'))}  {batch.get('completed', 0)}/{batch.get('total', 0)}  失败 {batch.get('failed', 0)}"
                if batch
                else ""
            )
        )

    def effective_settings(self):
        c = self.client
        return {
            "server": c.server_url,
            "room": c.room,
            "name": c.name,
            "data_dir": str(c.data),
            "timeout": c.timeout,
            "profiles": c.profiles,
            "retry_parameters": PROFILES,
            "gateway": c.gateway_enabled,
            "port_prediction": c.prediction_enabled,
            "diagnostics": c.diagnostics_enabled,
            "max_addresses": c.max_addresses,
            "max_pairs": c.max_pairs,
            "expanded": c.expanded,
            "comprehensive": c.research_enabled,
            "raw_probes": c.config.get("experiment", {}).get("raw_probes", False),
            "auto_retry": c.auto_retry,
            "nat64_prefixes": c.config.get("experiment", {}).get("nat64_prefixes", []),
            "loopback": c.loopback,
            "stun": c.observers,
            "extra_stun": c.extra_observers,
            "tcp_observer": c.tcp_observer,
            "inbound_check": c.inbound_supported,
            "configuration": redact(c.config),
            "logs": {"storage": "zlib-dict-v2", "upload_encoding": c.log_encoding or "legacy-json",
                     "upload_interval": c.upload_interval, "retry_interval": c.upload_retry,
                     "batch_events": c.upload_batch_events},
            "wan": c.wan_result,
            "peer_network": c.peer_network,
            "transfer": {"download_dir": str(c.transfers.directory), "max_bytes": c.transfers.max_bytes,
                         "auto_accept": c.transfers.auto_accept},
            "matrix_coverage": getattr(c.manager, "coverage", {}) if c.manager else {},
            "path_lifecycle": {"cold_paths_supported": c.cold_paths_supported,
                               "rtt_monitor_enabled": c.rtt_monitor_enabled,
                               "rtt_scope": "opt-in-current-path-only", "idle_keepalive_seconds": 12},
        }

    def refresh_settings(self):
        c = self.client
        parameters = [
            ("服务器", c.server_url),
            ("房间号", c.room),
            ("设备名", c.name),
            ("数据目录", str(c.data)),
            ("日志落盘压缩", "zlib 无损压缩；保留全部条目"),
            ("日志上传压缩", "zlib 批量压缩" if c.log_encoding else "未协商 / 旧服务端原文兼容"),
            ("日志上传间隔", f"{c.upload_interval:g} 秒"),
            ("日志重传间隔", f"{c.upload_retry:g} 秒"),
            ("日志每批上限", f"{c.upload_batch_events} 条"),
            ("备用链路策略", "按需冷备（须双方支持）" if c.cold_paths_supported else "服务端未协商冷备支持"),
            ("持续 RTT", "手动开启，仅当前链路" if c.rtt_monitor_enabled else "关闭；保留历史验证 RTT"),
            ("主链路闲置保活", "12 秒；不记录 RTT；有业务流量时不额外探测"),
            ("接收目录", str(c.transfers.directory)),
            ("附件自动接收", "启用" if c.transfers.auto_accept else "关闭"),
            ("单文件上限", f"{c.transfers.max_bytes // (1024 * 1024):,} MiB"),
            ("每项超时", f"{c.timeout:g} 秒"),
            ("重试档位", "、".join(translated(p) for p in c.profiles)),
            ("主动网关控制", "启用" if c.gateway_enabled else "关闭"),
            ("端口预测", "启用" if c.prediction_enabled else "关闭"),
            ("外部网络诊断", "启用" if c.diagnostics_enabled else "关闭"),
            (
                "启动公网测速",
                "启用" if c.wan_options.get("enabled", c.diagnostics_enabled) and not c.loopback else "关闭",
            ),
            ("公网测速程序", c.wan_options.get("executable", "librespeed-cli / 项目 .tools")),
            ("公网测速状态", c.wan_result.get("reason", c.wan_result.get("state"))),
            ("双端上限策略", "上行取 min(本机上行, 对端下行)；下行反向；IPv4/IPv6 分别计算"),
            ("候选地址上限", c.max_addresses),
            ("地址配对上限", c.max_pairs),
            ("扩展参数矩阵", "启用" if c.expanded else "关闭"),
            ("回环测试模式", "启用" if c.loopback else "关闭"),
            ("IPv6 HTTP 回连", "服务端启用" if c.inbound_supported else "服务端未启用"),
            ("STUN 观察点", "、".join(c.observers) or "待获取"),
            ("TCP 观察点", str(c.tcp_observer)),
            ("信令加密", "TLS" if c.server_url.startswith("wss:") else "明文 WS"),
            ("尝试策略", "成功后继续全部矩阵；基线完成后尝试网关放行"),
            ("矩阵硬上限", 200),
        ]
        coverage = getattr(c.manager, "coverage", {}) if c.manager else {}
        if coverage:
            parameters += [
                ("预算前生成组合", coverage.get("requested")),
                ("预算内执行组合", coverage.get("selected")),
                ("预算省略组合", coverage.get("omitted_count", len(coverage.get("omitted", [])))),
            ]
        parameters += [
            (f"{translated(name)}重试参数", json.dumps(profile, ensure_ascii=False))
            for name, profile in PROFILES.items()
        ]
        self.update_table(
            "settings-table",
            [(str(i), [key, value]) for i, (key, value) in enumerate(parameters)],
            {str(i): {key: value} for i, (key, value) in enumerate(parameters)},
        )

    def refresh_logs(self):
        if not self.reader or not self.client or not self.is_mounted or self.disposing:
            return
        level = self.query_ui("#log-level", Select).value
        run = self.client.log.run if self.query_ui("#log-run", Select).value == "current" else None
        self.log_rows = self.reader.browse(
            before=self.page_before,
            run=run,
            search=self.query_ui("#log-search", Input).value,
            level=level if isinstance(level, str) else "",
        )
        rows = [
            (
                str(r["cursor"]),
                [
                    r["cursor"],
                    r["time"][11:23],
                    translated(r["level"]),
                    EVENTS.get(r["event"], r["event"]) + " · " + r["event"],
                    r["message"],
                ],
            )
            for r in self.log_rows
        ]
        self.update_table("log-table", rows)
        self.query_ui("#log-older", Button).disabled = len(rows) < 100
        self.query_ui("#log-newer", Button).disabled = not self.page_stack
        stats = self.reader.stats()
        self.query_ui("#log-count", Static).update(
            Text(
                f"{'实时' if self.page_before is None else '历史页'} · 本页 {len(rows)} 条 · 全库 {stats['total']} 条"
            )
        )

    @on(DataTable.RowHighlighted)
    def row_highlighted(self, event):
        name, key = event.data_table.id, str(event.row_key.value)
        document = self.details.get(name, {}).get(key)
        if name == "attempts" and document:
            spec = document["尝试参数"]
            evidence = document["本端结果"].get("candidate_evidence", {})

            def candidates(key):
                if key not in evidence:
                    return "尚未记录"
                endpoints = evidence[key]
                return "、".join(f"[{ip}]:{port}" for ip, port in endpoints[:2]) + (
                    f" 等 {len(endpoints)} 个" if len(endpoints) > 2 else ""
                ) if endpoints else "无候选"

            self.query_ui("#matrix-selection", Static).update(
                Text(
                    f"{spec['attempt']}\n绑定：协调端 {spec.get('a_host') or 'ICE 自动选址'} / 参与端 {spec.get('b_host') or 'ICE 自动选址'}\n"
                    f"本端候选：{candidates('local_candidates')}\n对端候选：{candidates('remote_candidates')}\n"
                    f"阶段 {translated(spec['phase'])} · 协调端{'主动' if spec['leader_initiator'] else '被动'} · 偏移 {spec.get('offset', 0)}s",
                    no_wrap=True, overflow="ellipsis",
                )
            )
            self.query_ui("#matrix-selection", Static).tooltip = self.query_ui("#matrix-selection", Static).content
        elif name == "path-table" and document:
            self.query_ui("#path-selection", Static).update(
                Text(
                    f"尝试 {document['attempt']}\n对端 {document['peer'].get('name', '—')} · RTT {number(document['rtt_ms'], ' ms')}"
                )
            )

    @on(DataTable.RowSelected)
    def row_selected(self, event):
        name, key = event.data_table.id, str(event.row_key.value)
        if name == "log-table" and self.reader:
            document = self.reader.detail(int(key))
        else:
            document = self.details.get(name, {}).get(key)
        if document is not None:
            self.push_screen(DetailScreen("完整记录与参数", document))
