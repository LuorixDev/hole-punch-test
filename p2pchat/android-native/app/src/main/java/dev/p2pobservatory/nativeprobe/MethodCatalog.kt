package dev.p2pobservatory.nativeprobe

/**
 * 界面文案的唯一来源是 `p2pchat/docs/METHODS-PLAIN.md`（九条人话名称/解释/什么网络下可行/失败原因）。
 * 这里的字符串必须与那份文档逐字一致；内部代号（ice-v6、tcp-simopen…）只出现在「技术详情」里。
 *
 * 状态与延迟语义与桌面端 `python_desktop/methods.py` 一致：
 * 未测得显示「—」而不是 0；探测/观测 RTT 与聊天延迟分开标注；失败或未测绝不显示成功。
 */
object MethodCatalog {

    /** METHODS-PLAIN.md 的状态词表（界面统一使用）。 */
    const val STATUS_PENDING = "等待中"
    const val STATUS_TRYING = "尝试中"
    const val STATUS_DIRECT = "已打通"
    const val STATUS_OBSERVED = "已观测"
    const val STATUS_UNAVAILABLE = "不可用"
    const val STATUS_UNSUPPORTED = "不支持"

    /** 当前安卓版本的固定能力词表。 */
    const val AVAILABLE = "可用"
    const val UNAVAILABLE = "不可用"
    const val UNSUPPORTED = "不支持"

    /** 只有能聊天的路径才允许显示「已打通」。 */
    val MESSAGING_STATES = setOf(STATUS_DIRECT)
    val OBSERVED_STATES = setOf(STATUS_OBSERVED)

    /** 未测得时必须显示「—」：不允许把没测到写成 0。 */
    const val UNMEASURED = "—"

    class Method(
        val index: Int,
        val id: String,
        val title: String,
        val explain: String,
        val works: String,
        val failure: String,
        val canMessage: Boolean,
        /** 技术详情里才出现的内部代号与说明。 */
        val technical: String,
    )

    /** 与 METHODS-PLAIN.md 表格逐字一致（顺序固定：基础方式在前）。 */
    val METHODS = listOf(
        Method(
            1, "ice-dual", "双栈直连",
            "同时用 IPv6 和 IPv4 两种地址去找对方，谁先通就用谁",
            "双方都有可用公网地址（大多数家宽）",
            "两边 NAT 都严格、或运营商拦截 UDP",
            true, "profile=ice-dual；候选不过滤地址族，仅拒绝 typ relay",
        ),
        Method(
            2, "ice-v6", "IPv6 直连",
            "只用 IPv6 地址直连",
            "两台设备都有可用公网 IPv6，且入站防火墙放行",
            "一方没有 IPv6；或路由器/防火墙挡了入站",
            true, "profile=ice-v6；只保留 IPv6 候选（a=candidate 第 5 列含冒号）",
        ),
        Method(
            3, "ice-v4", "IPv4 直连",
            "只用 IPv4 地址直连",
            "至少一方有公网 IPv4，或双方 NAT 容易打洞",
            "双方都在大内网/CGNAT 后面",
            true, "profile=ice-v4；只保留 IPv4 候选，同样拒绝 typ relay",
        ),
        Method(
            4, "udp-probe", "UDP 探测",
            "互相发加密小包，确认「这个地址端口能不能直达」",
            "只要能出去 UDP 就能探测",
            "UDP 被运营商限制",
            false, "仅探测，不传内容；原生端不做 QUIC/UDP 自定义通道，本阶段如实标「不支持」或「不可用」",
        ),
        Method(
            5, "quic", "QUIC 加密直连",
            "用同一个 UDP 端口建立一条加密通道来传数据",
            "双方 UDP 可达",
            "UDP 被挡；或中间设备干扰",
            true, "原生安卓没有可用 QUIC API（WebRTC 数据通道走 SCTP/DTLS），本阶段标「不支持」，不假装有",
        ),
        Method(
            6, "tcp", "TCP 加密直连",
            "用 TCP 建立一条互相验证身份的加密连接",
            "UDP 被限制但 TCP 能出去的网络",
            "一方无法被动接受连接",
            true, "需要 QUIC/TCP 原生适配器的直连套接字，安卓端本阶段没有，标「不支持」",
        ),
        Method(
            7, "tcp-simopen", "TCP 同时打开",
            "双方**同时**主动向对方发起连接，谁都不当「服务器」",
            "只允许主动外连、不允许被动监听的网络",
            "双方时序错开，或中间设备重置连接",
            true, "tcp-simopen 需要两侧同时外连，安卓端本阶段标「不支持」",
        ),
        Method(
            8, "stun", "STUN 映射观测",
            "问外网「我在你眼里是什么地址和端口」，用来判断能不能直连；它不是中继，只观察地址，不转发任何数据",
            "所有能上网的环境",
            "服务器不可达；对称 NAT 下观测结果无用",
            false, "只观测，不传内容；观测到的出口地址与端口只用于判断候选，不转发任何数据",
        ),
        Method(
            9, "gateway", "路由器放行（自动开一个端口）",
            "向你自己家的路由器申请开一个端口",
            "路由器支持该协议且已开启",
            "路由器关闭了这类功能；运营商光猫拦截",
            false, "安卓端只显示「不支持」：路由器放行目前只有桌面 Python 版支持（UPnP IGD/PCP/NAT-PMP/IPv6 防火墙放行）",
        ),
    )

    /** 前三条是同一个 WebRTC 协议的三种地址族策略，不是三种独立协议。 */
    const val WEBRTC_PROFILE_NOTE =
        "前三条（双栈直连 / IPv6 直连 / IPv4 直连）是同一个 WebRTC 协议的三种地址族策略，不是三种独立协议。"

    /** METHODS-PLAIN.md 的三条限制，界面上必须能讲清楚。 */
    const val NO_RELAY_NOTE =
        "没有中继、没有 TURN：整个产品不通过服务器转发聊天；直连不成功就是失败，不会偷偷改走服务器。"

    fun methodFor(id: String): Method? = METHODS.firstOrNull { it.id == id }

    fun formatLatency(valueMs: Double?): String =
        if (valueMs == null) UNMEASURED else String.format("%.1f ms", valueMs)

    fun statusFor(state: String): String = when (state) {
        "pending", "skipped" -> STATUS_PENDING
        "trying", "connecting", "checking", "gathering", "probing", "authenticating" -> STATUS_TRYING
        "direct", "connected" -> STATUS_DIRECT
        "observed" -> STATUS_OBSERVED
        "unsupported" -> STATUS_UNSUPPORTED
        else -> STATUS_UNAVAILABLE
    }

    /** 只有「能聊天 + 真的打通」才允许把状态写成成功。 */
    fun isHonestSuccess(method: Method, state: String, authenticated: Boolean): Boolean =
        state == "direct" && authenticated && method.canMessage

    fun availabilityFor(method: Method, platformSupported: Boolean): String = when {
        method.id == "gateway" -> UNSUPPORTED
        !platformSupported -> UNSUPPORTED
        else -> AVAILABLE
    }

    /** 探测/观测 RTT 与聊天延迟必须分开标注。 */
    fun latencyLabel(kind: String): String = when (kind) {
        "probe" -> "探测往返"
        "observed" -> "观测往返"
        else -> "聊天延迟"
    }
}
