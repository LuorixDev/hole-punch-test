package dev.p2pobservatory.nativeprobe

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * WebSocket 信令客户端（与桌面/网页同一条协议）。
 *
 * 加入流程（v2，密钥不上链路）：
 *   1) 发送 `{type:'join_challenge',room,clientSessionId}`
 *   2) 收到 `join_challenge{nonce,expiresInMs}`
 *   3) 发送 `join`（joinVersion=2 + nonce + HKDF/HMAC 证明；房间未建立时才带 verifier）
 *   4) 收到 `welcome`（必须 strictP2P=true；iceServers 只接受 stun:/stuns:）
 *   5) `roster` 给出同房间成员；`signal` 转发 offer/answer/candidate
 */
class SignalingClient(
    private val url: String,
    private val room: String,
    private val secret: String,
    private val name: String,
    private val diagnostics: Diagnostics,
    private val listener: Listener,
) {
    interface Listener {
        fun onJoined(localPeerId: String, stunUrls: List<String>)
        fun onRoster(peers: List<String>)
        fun onSignal(message: JSONObject)
        fun onServerError(code: String, detail: String?)
        fun onSocketClosed(reason: String)
        fun onTelemetryAck(ids: List<String>)
    }

    private val client = OkHttpClient.Builder()
        .pingInterval(20, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private var socket: WebSocket? = null
    private var joined = false
    private var reconnectCount = 0
    private var roomEverJoined = false

    val clientSessionId: String = Protocol.uuid()
    /** 只能声明服务器 `backend/protocol.py` 里 MECHANISMS 认识的机制（`stun` 不是机制，声明它会被判 SCHEMA_INVALID）。 */
    val capabilities: List<String> = listOf("webrtc")

    fun isJoined(): Boolean = joined

    fun connect() {
        val request = Request.Builder().url(url).build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                diagnostics.emit("client.boot", JSONObject().put("mode", "signaling"))
                webSocket.send(JoinProof.challengeMessage(room, clientSessionId).toString())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val message = runCatching { JSONObject(text) }.getOrNull() ?: return
                when (message.optString("type")) {
                    "join_challenge" -> onChallenge(message)
                    "welcome" -> onWelcome(message)
                    "roster" -> listener.onRoster(roster(message))
                    "signal" -> listener.onSignal(message)
                    "telemetry_ack" -> listener.onTelemetryAck(ackIds(message))
                    "pong" -> Unit
                    "error" -> listener.onServerError(message.optString("code"), message.optString("detail").ifEmpty { null })
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                joined = false
                diagnostics.emit("server.error", JSONObject().put("code", "SIGNAL_SOCKET_ERROR").put("detail", t.message ?: ""))
                listener.onSocketClosed("SIGNAL_SOCKET_ERROR")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                joined = false
                listener.onSocketClosed(reason.ifEmpty { "CLOSED" })
            }
        })
    }

    private fun onChallenge(message: JSONObject) {
        val nonce = message.optString("nonce")
        if (!Regex("^[0-9a-f]{48}$").matches(nonce)) {
            // 服务器要求 v2：拿不到可用 nonce 就明确失败，绝不发明文密钥。
            diagnostics.emit("session.error", JSONObject().put("code", "UNSUPPORTED_VERSION").put("reason", "UNSUPPORTED_VERSION"))
            listener.onServerError("UNSUPPORTED_VERSION", "服务器未下发一次性 nonce（需要 v2 加入证明）")
            return
        }
        // 服务器会在挑战里告诉我们房间里是否已建立密钥（更准确 than 本地猜测）。
        val roomEstablished = message.optBoolean("roomEstablished", roomEverJoined)
        val join = JoinProof.joinMessage(room, secret, name, clientSessionId, capabilities, nonce, roomEstablished)
        if (JoinProof.containsSecret(join, secret)) {
            // 静态检查之外的运行时兜底：报文里出现房间密钥就当场停手，不发出去。
            diagnostics.emit("session.error", JSONObject().put("code", "RELAY_FORBIDDEN").put("reason", "INTEGRITY_FAILED"))
            listener.onServerError("SECRET_ON_WIRE", "加入报文里出现了房间密钥，已中止（v2 不允许密钥上链路）")
            close()
            return
        }
        socket?.send(join.toString())
    }

    private fun onWelcome(message: JSONObject) {
        if (message.optBoolean("strictP2P", false).not()) {
            diagnostics.emit("session.error", JSONObject().put("code", "RELAY_FORBIDDEN").put("reason", "RELAY_FORBIDDEN"))
            listener.onServerError("RELAY_FORBIDDEN", "服务器没有声明 strictP2P，拒绝在可能中继的配置上继续")
            close()
            return
        }
        val urls = try {
            Protocol.stunUrls(message.optJSONArray("iceServers"))
        } catch (error: IllegalArgumentException) {
            diagnostics.emit("session.error", JSONObject().put("code", "RELAY_FORBIDDEN").put("reason", "RELAY_FORBIDDEN"))
            listener.onServerError("RELAY_FORBIDDEN", "服务器下发了 TURN/中继地址，已拒绝")
            close()
            return
        }
        roomsSeenMarker()
        joined = true
        reconnectCount = 0
        diagnostics.emit("session.joined", JSONObject().put("mode", if (urls.isEmpty()) "no-stun" else "stun"))
        listener.onJoined(message.optString("id"), urls)
    }

    fun sendControl(message: JSONObject) {
        if (!joined) { listener.onServerError("SIGNAL_OFFLINE", "信令离线：直连仍可用，日志保留待补传"); return }
        message.put("v", 1)
        socket?.send(message.toString())
    }

    fun signal(peerId: String, connectionId: String, attemptId: String, mechanism: String, profile: String, payload: JSONObject) {
        val message = JSONObject()
            .put("type", "signal").put("to", peerId).put("connectionId", connectionId)
            .put("attemptId", attemptId).put("mechanism", mechanism).put("profile", profile)
        for (key in payload.keys()) message.put(key, payload.get(key))
        sendControl(message)
    }

    fun uploadTelemetry(events: List<JSONObject>): Boolean {
        if (!joined || events.isEmpty()) return false
        val array = JSONArray()
        for (event in events) array.put(event)
        val message = JSONObject()
            .put("type", "telemetry").put("clientSessionId", clientSessionId).put("events", array)
        return socket?.send(message.toString()) ?: false
    }

    fun close() {
        joined = false
        socket?.close(1000, "client-close")
        socket = null
    }

    private fun roster(message: JSONObject): List<String> {
        val array = message.optJSONArray("peers") ?: return emptyList()
        return (0 until array.length()).mapNotNull { array.optString(it, null) }
    }

    private fun ackIds(message: JSONObject): List<String> {
        val array = message.optJSONArray("ids") ?: return emptyList()
        return (0 until array.length()).mapNotNull { array.optString(it, null) }
    }

    private fun roomsSeenMarker() {
        roomEverJoined = true
    }

    companion object {
        private const val TAG = "P2PSignaling"
    }
}
