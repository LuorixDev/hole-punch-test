package dev.p2pobservatory.nativeprobe

import org.json.JSONObject

/**
 * 九条方式的尝试顺序与状态机。与 `docs/METHODS-PLAIN.md` 的顺序一致：
 * 基础方式在前，需要额外条件的在后；任何一条打通后其余仍在后台继续尝试。
 *
 * 本阶段（安卓原生第一阶段）的真实能力边界，必须如实显示而不是假装：
 *  - 1/2/3 双栈、IPv6、IPv4 直连：用 WebRTC 三档 profile 真做（同一个协议，三种地址族策略）；
 *  - 4 UDP 探测 / 5 QUIC / 6 TCP / 7 TCP 同时打开 / 9 路由器放行：原生端本阶段没有对应通道实现 → 显示「不支持」；
 *  - 8 STUN 映射观测：观测本身用服务器下发的 STUN 做（只观察地址、不转发数据），成功时只能显示「已观测」。
 */
class PathRunner(
    private val diagnostics: Diagnostics,
    private val listener: Listener,
) {
    interface Listener {
        fun onPathChanged(state: PathState)
        fun onChatReady(state: PathState)
    }

    class PathState(
        val method: MethodCatalog.Method,
        var state: String = "pending",
        var reason: String? = null,
        var availability: String = MethodCatalog.AVAILABLE,
        /** 探测/观测 RTT 与聊天延迟分开存放，界面上也分开标注。 */
        var probeRttMs: Double? = null,
        var observedRttMs: Double? = null,
        var chatRttMs: Double? = null,
        var profile: String? = null,
        var authenticated: Boolean = false,
    ) {
        fun statusWord(): String = MethodCatalog.statusFor(state)
        fun latencyText(): String = MethodCatalog.formatLatency(probeRttMs ?: observedRttMs ?: chatRttMs)
    }

    val paths: List<PathState> = MethodCatalog.METHODS.map { method -> PathState(method) }
    private var chatReady: PathState? = null

    init {
        for (path in paths) {
            // 「不支持」是当前平台能力的如实标注，不是失败；只有真有通道的方式才进入尝试队列。
            path.availability = when (path.method.id) {
                "ice-dual", "ice-v6", "ice-v4", "stun" -> MethodCatalog.AVAILABLE
                else -> MethodCatalog.UNSUPPORTED
            }
            if (path.availability == MethodCatalog.UNSUPPORTED) path.state = "unsupported"
        }
    }

    fun snapshot(): List<PathState> = paths

    /** 依次尝试：三条 WebRTC 档位真连；不支持的如实标「不支持」；STUN 观测成功也只标「已观测」。 */
    fun begin(localPeerId: String, peerId: String, stunUrls: List<String>, factory: (String) -> RtcSession) {
        diagnostics.emit("path.state", JSONObject().put("state", "probing").put("mechanism", "webrtc"))
        for (path in paths) {
            when (path.method.id) {
                "ice-dual", "ice-v6", "ice-v4" -> {
                    path.profile = path.method.id
                    path.state = "trying"
                    listener.onPathChanged(path)
                    runCatching { factory(path.method.id) }
                        .onFailure {
                            path.state = "unavailable"
                            path.reason = it.message ?: "INTERNAL_ERROR"
                            listener.onPathChanged(path)
                        }
                }
                "stun" -> {
                    // 有服务器下发的 STUN 就说明观测可用；观测不到出口地址时不能写成成功。
                    if (stunUrls.isEmpty()) {
                        path.state = "unavailable"
                        path.reason = "服务器不可达；对称 NAT 下观测结果无用"
                    } else {
                        path.state = "observed"
                        path.observedRttMs = null // 未测到就显示「—」，绝不写 0
                    }
                    listener.onPathChanged(path)
                }
                else -> Unit // 已标「不支持」
            }
        }
        if (localPeerId.isEmpty() || peerId.isEmpty()) return
        diagnostics.emit("path.stats", JSONObject().put("packets", 0))
    }

    fun noteProbe(kind: String, rttMs: Double) {
        val target = paths.firstOrNull { it.method.canMessage && it.profile != null } ?: paths.first()
        if (kind == "probe") target.probeRttMs = rttMs else target.observedRttMs = rttMs
        listener.onPathChanged(target)
    }

    fun noteChatLatency(rttMs: Double) {
        chatReady?.chatRttMs = rttMs
        chatReady?.let { listener.onPathChanged(it) }
    }

    fun markConnected(profile: String, authenticated: Boolean) {
        val path = paths.firstOrNull { it.profile == profile } ?: return
        path.authenticated = authenticated
        path.state = if (MethodCatalog.isHonestSuccess(path.method, "direct", authenticated)) "direct" else "trying"
        listener.onPathChanged(path)
        if (path.state == "direct" && chatReady == null) {
            chatReady = path
            diagnostics.emit("path.state", JSONObject().put("state", "direct")
                .put("mechanism", "webrtc").put("profile", profile))
            listener.onChatReady(path)
        }
    }

    fun markFailed(profile: String, reason: String) {
        val path = paths.firstOrNull { it.profile == profile } ?: return
        // 失败就是失败：不写成功，也不改走服务器。
        path.state = "unavailable"
        path.reason = reason
        path.profile = profile
        listener.onPathChanged(path)
    }

    fun markObserved(rttMs: Double?) {
        val path = paths.firstOrNull { it.method.id == "stun" } ?: return
        path.state = "observed"
        path.observedRttMs = rttMs
        listener.onPathChanged(path)
    }

    fun remaining(): List<MethodCatalog.Method> =
        paths.filter { it.state != "direct" }.map { it.method }

    fun usable(): Boolean = chatReady != null
}
