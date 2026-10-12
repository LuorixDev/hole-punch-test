"""User-facing wording for the desktop client.

The names, explanations and status words below come from ``docs/METHODS-PLAIN.md``,
which is the single source of truth for interface copy. Internal codes
(``ice-v6``, ``tcp-simopen``, ...) are identifiers for the engine only and are
never used as a visible title.
"""
from __future__ import annotations

import ipaddress

# Exact status vocabulary required by METHODS-PLAIN.md.
STATUS = {
    "pending": "等待中",
    "trying": "尝试中",
    "direct": "已打通",
    # METHODS-PLAIN.md: probe/observation methods can succeed without ever being
    # able to carry a message, so calling them 已打通 would overstate success.
    "observed": "已观测",
    "unavailable": "不可用",
    "unsupported": "不支持",
    "skipped": "等待中",
}

# Exact availability vocabulary required by METHODS-PLAIN.md.
AVAILABILITY = {
    "available": "可用",
    "unavailable": "不可用",
    "unsupported": "不支持",
}

# Only message-capable paths may ever be reported as 已打通.
MESSAGING_STATES = {"direct"}
OBSERVED_STATES = {"observed"}

# 「能否传消息」列（METHODS-PLAIN.md 的第 6 列）就是这份声明的唯一来源：
#   是                → message     （打通后能聊天）
#   否，只能探测       → probe       （只确认能不能直达，不传内容）
#   否，只能观测       → observation （只观察自己的出口地址，不传内容）
#   否，它只开端口     → action      （只是个开端口动作，不传内容）
MESSAGE, PROBE, OBSERVATION, ACTION = "message", "probe", "observation", "action"
CARRIES = (MESSAGE, PROBE, OBSERVATION, ACTION)

# 非聊天方式的行内提示。界面文案一律由 carries 派生到这里，不允许在渲染端另写字符串：
# 探测和观测本来就都是「只看不传」，所以共用一句话；开端口是动作，必须说清它不开聊天。
NON_CHAT_NOTES = {
    PROBE: "仅探测，不传内容",
    OBSERVATION: "仅探测，不传内容",
    ACTION: "只开端口，不传内容",
}

# Nine methods in the fixed order documented in METHODS-PLAIN.md:
# 1 双栈直连, 2 IPv6 直连, 3 IPv4 直连, 4 UDP 探测, 5 QUIC 加密直连,
# 6 TCP 加密直连, 7 TCP 同时打开, 8 STUN 映射观测, 9 路由器放行
METHODS = [
    {
        "id": "ice-dual",
        "mechanism": "webrtc",
        "title": "双栈直连",
        "explain": "同时用 IPv6 和 IPv4 两种地址去找对方，谁先通就用谁",
        "works": "双方都有可用公网地址（大多数家宽）",
        "failure": "两边 NAT 都严格、或运营商拦截 UDP",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "ice-v6",
        "mechanism": "webrtc",
        "title": "IPv6 直连",
        "explain": "只用 IPv6 地址直连",
        "works": "两台设备都有可用公网 IPv6，且入站防火墙放行",
        "failure": "一方没有 IPv6；或路由器/防火墙挡了入站",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "ice-v4",
        "mechanism": "webrtc",
        "title": "IPv4 直连",
        "explain": "只用 IPv4 地址直连",
        "works": "至少一方有公网 IPv4，或双方 NAT 容易打洞",
        "failure": "双方都在大内网/CGNAT 后面",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "udp-probe",
        "mechanism": "udp-probe",
        "title": "UDP 探测",
        "explain": "互相发加密小包，确认「这个地址端口能不能直达」",
        "works": "只要能出去 UDP 就能探测",
        "failure": "UDP 被运营商限制",
        "carries": PROBE,
        "retryable": True,
    },
    {
        "id": "quic",
        "mechanism": "quic",
        "title": "QUIC 加密直连",
        "explain": "用同一个 UDP 端口建立一条加密通道来传数据",
        "works": "双方 UDP 可达",
        "failure": "UDP 被挡；或中间设备干扰",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "tcp",
        "mechanism": "tcp",
        "title": "TCP 加密直连",
        "explain": "用 TCP 建立一条互相验证身份的加密连接",
        "works": "UDP 被限制但 TCP 能出去的网络",
        "failure": "一方无法被动接受连接",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "tcp-simopen",
        "mechanism": "tcp-simopen",
        "title": "TCP 同时打开",
        "explain": "双方同时主动向对方发起连接，谁都不当「服务器」",
        "works": "只允许主动外连、不允许被动监听的网络",
        "failure": "双方时序错开，或中间设备重置连接",
        "carries": MESSAGE,
        "retryable": True,
    },
    {
        "id": "stun-observation",
        "mechanism": "observation",
        "title": "STUN 映射观测",
        "explain": "问外网「我在你眼里是什么地址和端口」，用来判断能不能直连；它不是中继，只观察地址，不转发任何数据",
        "works": "所有能上网的环境",
        "failure": "服务器不可达；对称 NAT 下观测结果无用",
        "carries": OBSERVATION,
        "retryable": True,
    },
    {
        "id": "gateway",
        "mechanism": "gateway",
        "title": "路由器放行（自动开一个端口）",
        "explain": "向你自己家的路由器申请开一个端口",
        "works": "路由器支持该协议且已开启",
        "failure": "路由器关闭了这类功能；运营商光猫拦截",
        "carries": ACTION,
        "opt_in": True,
        "retryable": False,
    },
]

# The three ICE rows are address-family selections of one protocol, not three
# protocols. Rendered once next to those rows (screen 2 and the settings panel).
WEBRTC_PROFILE_NOTE = "是同一个 WebRTC 直连的三种地址选择，不是三个独立协议"

# Ids that share WEBRTC_PROFILE_NOTE.
WEBRTC_PROFILE_IDS = ("ice-dual", "ice-v6", "ice-v4")

METHOD_BY_ID = {method["id"]: method for method in METHODS}

# Plain-language reasons. Codes come from the reused transports; the wording is
# what a non-specialist can act on. Unknown codes never render a raw token.
REASONS = {
    "AUTH_FAILED": "双方身份校验没通过，请确认房间密码完全一致。",
    "SCHEMA_INVALID": "对方发来的连接信息格式不对，已拒绝。",
    "LIMIT_EXCEEDED": "碰到了本机或对方的安全限额，请稍后再试。",
    "RELAY_FORBIDDEN": "发现了被禁止的转发路径，已拒绝使用。",
    "PEER_UNAVAILABLE": "对方现在不在线，等对方重新加入后再试。",
    "ATTEMPT_CONFLICT": "这次连接的编号和对方的对不上，已放弃这一条。",
    "TIMEOUT": "等待对方回应超时，可能被路由器或防火墙挡住了。",
    "PROBE_TIMEOUT": "对方一段时间没有回应，这条路径不通。",
    "SIGNAL_TIMEOUT": "还没收到对方发来的地址信息就超时了。",
    "ICE_FAILED": "没找到双方都能用的地址，请检查两边的网络和防火墙。",
    "AT_LEAST_ONE_CANDIDATE": "没有收集到可用地址。",
    "BIND_UNAVAILABLE": "本机地址绑定失败，可能是端口被占用或权限不足。",
    "RESOURCE_LIMIT": "同时尝试的方式太多，已到达上限。",
    "SESSION_ATTEMPT_LIMIT": "本次会话的尝试次数已用完，请重新连接。",
    "ATTEMPT_REPLAY": "重复使用了同一个连接编号，已拒绝。",
    "NOT_MESSAGE_CAPABLE": "这条路径只能探测，不能用来传消息。",
    "BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION": "这条连接没有独立测速通道，所以不能测速。",
    "BACKPRESSURE": "发送速度太快，本机积压过多，请稍后再发。",
    "CANDIDATE_LIMIT": "对方给的地址太多，已到达上限。",
    "CANDIDATE_INCOMPATIBLE": "对方给的地址类型和这条方式不匹配。",
    "CANDIDATE_SOCKET_CHANGED": "对方的地址来源变了，已放弃这一条。",
    "CERTIFICATE_FINGERPRINT_MISMATCH": "对方证书和信令里声明的不一致，已拒绝连接。",
    "CERTIFICATE_CHANGED": "对方的证书中途变了，已拒绝连接。",
    "CERTIFICATE_UNVERIFIED": "对方证书没通过校验，已拒绝连接。",
    "TCP_TUPLE_REQUIRES_NEW_ATTEMPT": "TCP 只能连接同一个地址端口，请重新开始一次尝试。",
    "TCP_TLS_OR_CONNECT_FAILED": "TCP 没连上，或加密握手没成功。",
    "TCP_SIMOPEN_UNAVAILABLE": "双方同时发起的时间没对上，或被中间设备重置了。",
    "TCP_IO_FAILED": "TCP 传输中断了。",
    "UDP_IO_FAILED": "UDP 收发中断了。",
    "PROBE_ONLY": "这条方式只用来探测能否直连，不传聊天内容。",
    "OPT_IN_GATEWAY_API_ONLY": "需要操作者单独显式授权才可用；本界面不会自动去改动路由器。",
    "EXPERIMENTAL_PLATFORM_UNVERIFIED": "这种方式的平台支持还没在真实设备上验证过。",
    "UNSUPPORTED_METHOD": "当前系统不支持这种方式。",
    "UNSUPPORTED": "当前系统不支持这种方式。",
    "KEEPALIVE_TIMEOUT": "对方一段时间没有回应，连接可能已经断开。",
    "KEEPALIVE_IO_FAILED": "保活探测出错，连接可能已经断开。",
    "CLOSED": "这条连接已经关闭。",
    "USER_CLOSED": "这条连接已经关闭。",
    "STUN_MAPPING_UNAVAILABLE": "没问到自己的外部地址，可能是 STUN 服务不可达。",
    "NO_STUN_SERVER": "服务器没有提供 STUN 地址，无法观测出口。",
    "UNAVAILABLE": "当前不可用。",
    "TRANSPORT_FAILED": "传输初始化失败。",
    "QUIC_TLS_OR_CONNECTION_FAILED": "QUIC 加密握手没成功，或连接被中断。",
    "UNEXPECTED_STREAM": "收到预期之外的加密流，已断开。",
    "LANE_MISMATCH": "数据发到了与预期不同的通道，已断开。",
    "FRAME_LIMIT": "单条数据超过本机限额，已拒绝。",
    "AUTH_REQUIRED": "还没完成身份校验就先收到了数据，已断开。",
    "UNKNOWN_FRAME": "收到无法识别的数据帧，已断开。",
    "INTEGRITY_FAILED": "收到的文件校验不一致，已拒绝接收。",
    "SAVE_FAILED": "保存失败，请检查保存权限后重试。",
    "FILE_LIMIT_32_MIB": "文件太大，请选择不超过 32 MiB 的文件。",
    "FILE_TOO_LARGE": "文件太大，请选择不超过 32 MiB 的文件。",
    "TEXT_LIMIT": "文字太长，请分成几条发送。",
    "SEND_BUSY": "同时发送的文件太多，请等当前文件发完。",
    "NO_DIRECT_PATH": "还没有能聊天的直连，请等其他方式成功。",
    "NO_PEER": "房间里还没有别人，请让对方加入同一个房间。",
    "PEER_LOST": "和对方的连接中断了。",
    "RECORDING_FAILED": "录音失败，请检查麦克风权限后重试。",
    "RECORDING_LIMIT": "录音已达到大小限制，请缩短录音。",
    "RECORDING_UNAVAILABLE": "本机找不到可用的麦克风采集方式，录音不可用。",
    "INTERNAL_ERROR": "操作没能完成，请重试。",
}


def reason(code) -> str:
    """Human sentence for a transport code; never returns a bare token."""
    if not code:
        return ""
    text = str(code).strip()
    if text in REASONS:
        return REASONS[text]
    key = text.split(" ")[0]
    if key in REASONS:
        return REASONS[key]
    if key.startswith("PCP_RESULT_") or key.startswith("NATPMP_RESULT_") or key.startswith("UPNP_"):
        return "自家路由器拒绝了这次申请。"
    if text and ord(text[0]) > 0x2000:
        # Already a human sentence from a caller.
        return text[:400]
    return "这次尝试没能完成，请检查双方网络后重试。"


def method_for(mechanism: str, profile: str = "") -> dict | None:
    if mechanism == "webrtc":
        return METHOD_BY_ID.get(profile) or METHOD_BY_ID["ice-dual"]
    if mechanism in {"upnp", "pcp", "natpmp", "gateway"}:
        return METHOD_BY_ID["gateway"]
    return METHOD_BY_ID.get(mechanism)


def carries(method: dict) -> str:
    """METHODS-PLAIN.md 的「能否传消息」列，转成界面可以派生的声明。

    返回 message / probe / observation / action 之一；未声明的老数据按 message 处理，
    绝不默认成「探测」——不能传消息必须由声明明说。
    """
    kind = method.get("carries") or MESSAGE
    return kind if kind in CARRIES else MESSAGE


def probe_only(method: dict) -> bool:
    """True when a method can never carry a chat message itself.

    METHODS-PLAIN.md's 能否传消息 column marks UDP 探测, STUN 映射观测 and
    路由器放行 as 否. This stays the "cannot chat" predicate; use
    ``non_chat_note()`` when the interface has to say *why* (a probe/observation
    looks, a port-opening action only opens a port).
    """
    return carries(method) != MESSAGE


def is_probe(method: dict) -> bool:
    """True only for the 探测/观测 kinds (UDP 探测, STUN 映射观测)."""
    return carries(method) in (PROBE, OBSERVATION)


def is_action_only(method: dict) -> bool:
    """True only for the 只开端口 kind (路由器放行)."""
    return carries(method) == ACTION


def non_chat_note(method: dict) -> str:
    """行内提示，由 ``carries`` 派生：探测/观测 →「仅探测，不传内容」；开端口 →「只开端口，不传内容」。"""
    return NON_CHAT_NOTES.get(carries(method), "")


def non_chat_status(method: dict) -> str:
    """非聊天方式成功时显示的整句状态，同样由声明派生。

    * 探测/观测类借状态词「已观测」，因为 METHODS-PLAIN.md 把「已观测」定义成
      「只用于探测或观测的方式成功了」。
    * 开端口类**不借**「已观测」（它不是观测），更不写「已打通」（它不能聊天），
      而是直接说清自己的动作：「只开端口，不传内容」。
    """
    kind = carries(method)
    if kind in (PROBE, OBSERVATION):
        return f"{STATUS['observed']}（{NON_CHAT_NOTES[kind]}）"
    if kind == ACTION:
        return NON_CHAT_NOTES[ACTION]
    return STATUS["direct"]


def availability(mechanism: str, capability: dict | None) -> str:
    """可用 / 不可用 / 不支持 for one capability entry."""
    if capability is None:
        return "unsupported"
    status = capability.get("status")
    if status == "available":
        return "available"
    if status == "unavailable":
        return "unavailable"
    return "unsupported"


def describe_address(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "地址不合法"
    return f"IPv{parsed.version} 地址，{'本机回环' if parsed.is_loopback else '本机接口'}"

# Availability is always one of 可用/不可用/不支持; "no result yet" is a note,
# never a fourth availability word.
AVAILABILITY_NOTE = {
    "pending": "尚未出结果",
    "trying": "尚未出结果",
    "direct": "",
    "observed": "",
    "unavailable": "",
    "unsupported": "",
}

# Shown when the automatic central collection is paused while local diagnostic
# records are still waiting to be uploaded (README: 中心记录不完整).
TELEMETRY_NOTE = "中心记录不完整：自动汇集已暂停，本机仍有诊断记录没有上传到中心。"

# 诊断汇集面板文案。暂停优先：暂停时绝不出现「已开启」。
TELEMETRY_ON_TEXT = "自动汇集已开启：只有中心确认保存后才从本机待传队列移除；不含正文、密码、媒体与完整地址。"
TELEMETRY_PAUSED_TEXT = "自动汇集已暂停：本机仍在本地累积诊断记录，暂停期间不会上传；重新勾选即可继续。"
