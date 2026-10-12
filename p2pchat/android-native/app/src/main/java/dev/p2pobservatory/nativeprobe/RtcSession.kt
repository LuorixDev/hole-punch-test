package dev.p2pobservatory.nativeprobe

import android.util.Log
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * 一条 WebRTC 路径（一个 profile = 一种地址族策略）。
 *
 * 无中继硬约束：
 *  - `RTCConfiguration.iceServers` 只由服务器下发的 **STUN** 构造（`Protocol.stunUrls` 已经拒绝 turn:）；
 *  - 本端与对端的 `a=candidate:` 行都过 `Protocol.permitted()`，`typ relay` 一律丢；
 *  - 没有任何“失败就改走服务器”的分支：连不上就是 failed。
 */
class RtcSession(
    private val factory: PeerConnectionFactory,
    private val profile: String,
    private val room: String,
    private val secret: String,
    private val localPeerId: String,
    private val peerId: String,
    private val connectionId: String,
    private val attemptId: String,
    private val stunUrls: List<String>,
    private val diagnostics: Diagnostics,
    private val listener: Listener,
) {
    interface Listener {
        fun onState(state: String, detail: String? = null)
        fun onChatMessage(text: String, id: String)
        fun onFileReceived(id: String, name: String, mime: String, bytes: ByteArray)
        fun onTextDelivered(id: String)
        fun onLatency(kind: String, rttMs: Double)
        fun onBenchmark(goodputBytesPerSecond: Double, bytes: Long, elapsedMs: Double)
        fun onAuthenticated()
    }

    private val sendExecutor = Executors.newSingleThreadExecutor()
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val authenticated = AtomicBoolean(false)
    private var chat: DataChannel? = null
    private var bench: DataChannel? = null
    private var connection: PeerConnection? = null
    private var localNonce: String = run {
        val bytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(bytes)
        Protocol.hex(bytes)
    }
    private var remoteNonce: String? = null
    private var gotAck = false
    private val incoming = HashMap<String, Transfer>()
    private val outgoing = HashMap<String, Transfer>()
    private val benchRuns = HashMap<String, BenchRun>()

    class Transfer(val id: String, val name: String, val mime: String, val size: Long, val sha256: String) {
        val sink = java.io.ByteArrayOutputStream()
        val startNs = System.nanoTime()
        var nextSequence = 0L
        var received = 0L
        var lastProgressAt = 0L
    }

    class BenchRun(val id: String, val totalBytes: Long, val startNs: Long) {
        var sent = 0L
    }

    val isAuthenticated: Boolean get() = authenticated.get()

    fun start() {
        val iceServers = stunUrls.map { PeerConnection.IceServer.builder(it).createIceServer() }
        // 断言：只可能是 STUN；出现中继地址就抛，绝不带着 TURN 配置继续。
        assertNoRelay(stunUrls)
        val config = PeerConnection.RTCConfiguration(iceServers).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            enableCpuOveruseDetection = false
        }
        connection = factory.createPeerConnection(config, observer) ?: run {
            listener.onState("failed", "PEER_CONNECTION_UNAVAILABLE")
            return
        }
        chat = connection!!.createDataChannel(Protocol.LANE_CHAT, DataChannel.Init().apply { ordered = true })
        bench = connection!!.createDataChannel(Protocol.LANE_BENCH, DataChannel.Init().apply { ordered = false; maxRetransmits = 0 })
        chat?.registerObserver(channelObserver(onOpen = { sendHello() }, text = ::onChatText, binary = ::onChatBinary))
        bench?.registerObserver(channelObserver(onOpen = null, text = ::onBenchText, binary = ::onBenchBinary))
        // 发起方：offer
        connection!!.createOffer(sdpObserver("offer"), MediaConstraints())
    }

    /** 服务器下发的 STUN 列表里不允许出现 turn:/relay（静态断言 + 运行时兜底）。 */
    fun assertNoRelay(urls: List<String>) {
        for (url in urls) {
            if (url.startsWith("turn:") || url.startsWith("turns:") || url.contains("relay")) {
                diagnostics.emit("session.error", JSONObject().put("code", "RELAY_FORBIDDEN").put("reason", "RELAY_FORBIDDEN"))
                throw IllegalStateException("RELAY_FORBIDDEN")
            }
        }
    }

    private val observer = object : PeerConnection.Observer {
        override fun onSignalingChange(state: PeerConnection.SignalingState) = Unit
        override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
            val mapped = when (state) {
                PeerConnection.IceConnectionState.CONNECTED, PeerConnection.IceConnectionState.COMPLETED -> "connected"
                PeerConnection.IceConnectionState.CHECKING -> "checking"
                PeerConnection.IceConnectionState.DISCONNECTED -> "disconnected"
                PeerConnection.IceConnectionState.FAILED -> "failed"
                else -> "new"
            }
            diagnostics.emit("rtc.connection", JSONObject().put("state", mapped).put("profile", profile),
                connectionId, attemptId)
            if (mapped == "failed") listener.onState("failed", "ICE_FAILED")
        }

        override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit
        override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) = Unit

        override fun onIceCandidate(candidate: IceCandidate) {
            if (!Protocol.permitted(candidate.sdp, profile)) {
                // relay 或地址族不符：本端直接不发，绝不用中继。
                diagnostics.emit("signal.candidate", JSONObject().put("candidateType", "relay")
                    .put("profile", profile).put("mechanism", "webrtc"), connectionId, attemptId)
                return
            }
            listener.onState("gathering", null)
            onLocalCandidate(candidate)
        }

        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) = Unit
        override fun onAddStream(stream: org.webrtc.MediaStream) = Unit
        override fun onRemoveStream(stream: org.webrtc.MediaStream) = Unit

        override fun onDataChannel(channel: DataChannel) {
            when (channel.label()) {
                Protocol.LANE_CHAT -> { chat = channel; channel.registerObserver(channelObserver(onOpen = { sendHello() }, text = ::onChatText, binary = ::onChatBinary)) }
                Protocol.LANE_BENCH -> { bench = channel; channel.registerObserver(channelObserver(onOpen = null, text = ::onBenchText, binary = ::onBenchBinary)) }
            }
        }

        override fun onRenegotiationNeeded() = Unit
        override fun onAddTrack(receiver: org.webrtc.RtpReceiver, streams: Array<out org.webrtc.MediaStream>) = Unit
    }

    /** 对端候选/描述进来（由信令层转交）。 */
    fun onRemoteDescription(type: String, sdp: String) {
        val filtered = Protocol.filterSdp(sdp, profile)
        val description = SessionDescription(
            if (type == "offer") SessionDescription.Type.OFFER else SessionDescription.Type.ANSWER, filtered)
        val pc = connection ?: return
        pc.setRemoteDescription(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription) = Unit
            override fun onSetSuccess() {
                if (type == "offer") pc.createAnswer(sdpObserver("answer"), MediaConstraints())
            }
            override fun onCreateFailure(error: String) { listener.onState("failed", "SDP_FAILED") }
            override fun onSetFailure(error: String) { listener.onState("failed", "SDP_FAILED") }
        }, description)
    }

    fun onRemoteCandidate(sdpMid: String?, sdpMLineIndex: Int, sdp: String) {
        if (!Protocol.permitted(sdp, profile)) {
            diagnostics.emit("signal.candidate", JSONObject().put("candidateType", "relay").put("profile", profile),
                connectionId, attemptId)
            return
        }
        connection?.addIceCandidate(IceCandidate(sdpMid, sdpMLineIndex, sdp))
    }

    private fun sdpObserver(tag: String) = object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription) {
            val filtered = Protocol.filterSdp(description.description, profile)
            val pc = connection ?: return
            pc.setLocalDescription(object : SdpObserver {
                override fun onCreateSuccess(desc: SessionDescription) = Unit
                override fun onSetSuccess() {
                    listener.onState("gathering", null)
                    onLocalDescription(if (tag == "offer") "offer" else "answer", filtered)
                }
                override fun onCreateFailure(error: String) { listener.onState("failed", "SDP_FAILED") }
                override fun onSetFailure(error: String) { listener.onState("failed", "SDP_FAILED") }
            }, SessionDescription(description.type, filtered))
        }

        override fun onSetSuccess() = Unit
        override fun onCreateFailure(error: String) = listener.onState("failed", "SDP_FAILED")
        override fun onSetFailure(error: String) = listener.onState("failed", "SDP_FAILED")
    }

    private fun channelObserver(onOpen: (() -> Unit)?, text: (String) -> Unit, binary: (ByteArray) -> Unit) = object : DataChannel.Observer {
        override fun onBufferedAmountChange(previousAmount: Long) = Unit
        override fun onStateChange() {
            val state = chat?.state() ?: bench?.state()
            val name = when (state) {
                DataChannel.State.OPEN -> "open"
                DataChannel.State.CONNECTING -> "connecting"
                DataChannel.State.CLOSING, DataChannel.State.CLOSED -> "closed"
                else -> "closed"
            }
            diagnostics.emit("datachannel.open", JSONObject().put("state", name).put("profile", profile),
                connectionId, attemptId)
            if (state == DataChannel.State.OPEN) onOpen?.invoke()
        }

        override fun onMessage(buffer: DataChannel.Buffer) {
            val bytes = ByteArray(buffer.data.remaining())
            buffer.data.get(bytes)
            if (buffer.binary) binary(bytes) else text(String(bytes, Charsets.UTF_8))
        }
    }

    // ---- 数据通道握手（与 core.js Handshake 一致，用房间密钥而不是 joinKey）----

    private fun sendHello() {
        val echo = remoteNonce
        val fields = Protocol.handshakeFields(false, room, connectionId, attemptId, localPeerId, peerId, localNonce)
        val message = JSONObject()
            .put("kind", Protocol.KIND_HELLO).put("peer", localPeerId).put("connectionId", connectionId)
            .put("attemptId", attemptId).put("nonce", localNonce)
            .put("proof", Protocol.hex(JoinProof.hmacSha256(secret.toByteArray(Charsets.UTF_8), fields.toByteArray(Charsets.UTF_8))))
        if (echo == null) Unit
        sendControl(message)
    }

    private fun verifyHandshake(message: JSONObject, ack: Boolean): Boolean {
        if (message.optString("peer") != peerId) return false
        if (message.optString("connectionId") != connectionId) return false
        if (message.optString("attemptId") != attemptId) return false
        val nonce = message.optString("nonce")
        if (!Regex("^[0-9a-f]{64}$").matches(nonce)) return false
        val echo = if (ack) message.optString("echoNonce") else null
        val fields = Protocol.handshakeFields(ack, room, connectionId, attemptId, peerId, localPeerId, nonce, echo)
        val expected = Protocol.hex(JoinProof.hmacSha256(secret.toByteArray(Charsets.UTF_8), fields.toByteArray(Charsets.UTF_8)))
        if (!Protocol.constantTimeEquals(expected, message.optString("proof"))) {
            diagnostics.emit("receive.error", JSONObject().put("code", "AUTH_FAILED").put("reason", "AUTH_FAILED"),
                connectionId, attemptId)
            return false
        }
        return true
    }

    // ---- 聊天：文本 / 图片 / 文件 / 录音（录音就是一个音频文件）----

    fun sendText(text: String): String {
        val id = Protocol.uuid()
        sendControl(JSONObject().put("kind", Protocol.KIND_TEXT).put("id", id).put("text", text))
        return id
    }

    fun sendFile(file: File, mime: String, echoOf: String? = null) {
        val bytes = file.readBytes()
        require(bytes.size.toLong() <= Protocol.FILE_LIMIT) { "LIMIT_EXCEEDED" }
        val id = Protocol.uuid()
        val digest = Protocol.sha256Hex(bytes)
        val transfer = Transfer(id, file.name, mime, bytes.size.toLong(), digest)
        outgoing[id] = transfer
        sendControl(JSONObject()
            .put("kind", Protocol.KIND_FILE_START).put("id", id).put("name", file.name).put("mime", mime)
            .put("size", bytes.size).put("sha256", digest).put("echoOf", echoOf ?: JSONObject.NULL)
            .put("benchmark", false))
        sendExecutor.execute {
            var offset = 0
            var sequence = 0L
            while (offset < bytes.size) {
                val length = minOf(Protocol.CHUNK, bytes.size - offset)
                val chunk = bytes.copyOfRange(offset, offset + length)
                while (true) {
                    val amount = chat?.bufferedAmount() ?: 0L
                    if (amount <= Protocol.HIGH_WATER) break
                    Thread.sleep(10)
                }
                chat?.send(DataChannel.Buffer(ByteBuffer.wrap(Protocol.encodeFrame(id, sequence, chunk)), true))
                offset += length
                sequence += 1
            }
            sendControl(JSONObject().put("kind", Protocol.KIND_FILE_END).put("id", id))
        }
    }

    private fun onChatText(text: String) {
        val message = runCatching { JSONObject(text) }.getOrNull() ?: return
        when (message.optString("kind")) {
            Protocol.KIND_HELLO, Protocol.KIND_HELLO_ACK -> {
                val ack = message.optString("kind") == Protocol.KIND_HELLO_ACK
                if (!verifyHandshake(message, ack)) return
                if (!ack && !gotAck) {
                    remoteNonce = message.optString("nonce")
                    val fields = Protocol.handshakeFields(true, room, connectionId, attemptId, localPeerId, peerId, remoteNonce!!, localNonce)
                    sendControl(JSONObject().put("kind", Protocol.KIND_HELLO_ACK).put("peer", localPeerId)
                        .put("connectionId", connectionId).put("attemptId", attemptId).put("nonce", localNonce)
                        .put("echoNonce", remoteNonce)
                        .put("proof", Protocol.hex(JoinProof.hmacSha256(secret.toByteArray(Charsets.UTF_8), fields.toByteArray(Charsets.UTF_8)))))
                }
                if (!authenticated.get()) {
                    authenticated.set(true)
                    diagnostics.emit("peer.authenticated_channel", JSONObject().put("ok", true).put("profile", profile),
                        connectionId, attemptId)
                    listener.onAuthenticated()
                    startPingLoop()
                }
            }
            Protocol.KIND_PING -> sendControl(JSONObject().put("kind", Protocol.KIND_PONG).put("id", message.optString("id")))
            Protocol.KIND_PONG -> {
                val sentAt = message.optLong("ts", 0L)
                if (sentAt > 0) listener.onLatency("chat", (System.currentTimeMillis() - sentAt).toDouble())
            }
            Protocol.KIND_TEXT -> if (authenticated.get()) {
                listener.onChatMessage(message.optString("text"), message.optString("id"))
                sendControl(JSONObject().put("kind", Protocol.KIND_DELIVERED).put("id", message.optString("id")))
            }
            Protocol.KIND_DELIVERED -> listener.onTextDelivered(message.optString("id"))
            Protocol.KIND_FILE_START -> if (authenticated.get()) {
                val id = message.optString("id")
                val size = message.optLong("size")
                if (size > Protocol.FILE_LIMIT) {
                    sendControl(JSONObject().put("kind", Protocol.KIND_FILE_READY).put("id", id).put("ok", false).put("reason", "LIMIT_EXCEEDED"))
                } else {
                    incoming[id] = Transfer(id, message.optString("name"), message.optString("mime"), size,
                        message.optString("sha256"))
                    sendControl(JSONObject().put("kind", Protocol.KIND_FILE_READY).put("id", id).put("ok", true))
                }
            }
            Protocol.KIND_FILE_END -> if (authenticated.get()) {
                val id = message.optString("id")
                val transfer = incoming.remove(id)
                if (transfer != null) {
                    val bytes = transfer.sink.toByteArray()
                    val ok = Protocol.constantTimeEquals(Protocol.sha256Hex(bytes), transfer.sha256)
                    if (ok) ioExecutor.execute { listener.onFileReceived(id, transfer.name, transfer.mime, bytes) }
                    diagnostics.emit("transfer.received", JSONObject().put("bytes", bytes.size).put("integrityOk", ok),
                        connectionId, attemptId)
                }
            }
        }
    }

    private fun onChatBinary(bytes: ByteArray) {
        if (!authenticated.get()) return
        val frame = runCatching { Protocol.decodeFrame(bytes) }.getOrNull() ?: run {
            diagnostics.emit("receive.error", JSONObject().put("code", "SCHEMA_INVALID").put("reason", "SCHEMA_INVALID"),
                connectionId, attemptId)
            return
        }
        val transfer = incoming[frame.id] ?: return
        if (frame.sequence != transfer.nextSequence) {
            diagnostics.emit("receive.error", JSONObject().put("code", "INTEGRITY_FAILED").put("reason", "INTEGRITY_FAILED"),
                connectionId, attemptId)
            incoming.remove(frame.id)
            return
        }
        transfer.sink.write(frame.payload)
        transfer.nextSequence += 1
        transfer.received += frame.payload.size
    }

    // ---- 独立通道测速（应用层速度，不是线路带宽）----

    fun runBenchmark(totalBytes: Long = 8L * 1024 * 1024) {
        val id = Protocol.uuid()
        benchRuns[id] = BenchRun(id, totalBytes, System.nanoTime())
        sendBench(JSONObject().put("v", 1).put("kind", Protocol.KIND_BENCH_START).put("id", id).put("bytes", totalBytes))
    }

    private fun onBenchText(text: String) {
        val message = runCatching { JSONObject(text) }.getOrNull() ?: return
        onBenchControl(message)
    }

    private fun onBenchBinary(bytes: ByteArray) {
        val frame = runCatching { Protocol.decodeFrame(bytes) }.getOrNull() ?: return
        val run = benchRuns[frame.id] ?: return
        run.sent += frame.payload.size.toLong()
    }

    private fun sendBench(message: JSONObject) {
        bench?.send(DataChannel.Buffer(ByteBuffer.wrap(message.toString().toByteArray(Charsets.UTF_8)), false))
    }

    fun onBenchControl(message: JSONObject) {
        when (message.optString("kind")) {
            Protocol.KIND_BENCH_START -> {
                val id = message.optString("id")
                val bytes = message.optLong("bytes")
                val payload = ByteArray(Protocol.CHUNK)
                var sent = 0L
                var sequence = 0L
                sendExecutor.execute {
                    val startNs = System.nanoTime()
                    while (sent < bytes) {
                        bench?.send(DataChannel.Buffer(ByteBuffer.wrap(Protocol.encodeFrame(id, sequence, payload)), true))
                        sent += payload.size
                        sequence += 1
                    }
                    val elapsedMs = (System.nanoTime() - startNs) / 1_000_000.0
                    sendBench(JSONObject().put("v", 1).put("kind", Protocol.KIND_BENCH_ACK).put("id", id)
                        .put("bytes", sent).put("elapsedMs", elapsedMs))
                }
            }
            Protocol.KIND_BENCH_ACK -> {
                val id = message.optString("id")
                val run = benchRuns.remove(id) ?: return
                val elapsedMs = (System.nanoTime() - run.startNs) / 1_000_000.0
                val goodput = if (elapsedMs > 0) message.optLong("bytes") / (elapsedMs / 1000.0) else 0.0
                listener.onBenchmark(goodput, message.optLong("bytes"), elapsedMs)
            }
            Protocol.KIND_BENCH_ERROR -> diagnostics.emit("task.error",
                JSONObject().put("code", message.optString("code", "INTERNAL_ERROR")), connectionId, attemptId)
        }
    }

    private fun startPingLoop() {
        sendExecutor.execute {
            while (!Thread.currentThread().isInterrupted) {
                runCatching {
                    sendControl(JSONObject().put("kind", Protocol.KIND_PING).put("id", Protocol.uuid())
                        .put("ts", System.currentTimeMillis()))
                }
                Thread.sleep(5000)
            }
        }
    }

    private fun sendControl(message: JSONObject) {
        val payload = message.toString().toByteArray(Charsets.UTF_8)
        chat?.send(DataChannel.Buffer(ByteBuffer.wrap(payload), false))
    }

    fun close() {
        runCatching { chat?.close() }
        runCatching { bench?.close() }
        runCatching { connection?.close() }
        sendExecutor.shutdownNow()
        ioExecutor.shutdownNow()
        diagnostics.emit("datachannel.closed", JSONObject().put("profile", profile), connectionId, attemptId)
    }

    /** 由信令层注入的两个回调（避免 RtcSession 直接依赖网络层）。 */
    var onLocalDescription: (String, String) -> Unit = { _, _ -> }
    var onLocalCandidate: (IceCandidate) -> Unit = { _ -> }

    companion object {
        private const val TAG = "P2PRtcSession"
    }
}
