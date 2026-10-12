package dev.p2pobservatory.nativeprobe

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * 中心日志（与桌面/网页同一套事件结构，服务端 `p2pchat/backend/telemetry.py` 校验）。
 *
 * 结构：`{v,id,clientSessionId,seq,tsWallMs,monoMs,connectionId,attemptId,event,data}`；
 * 字段白名单/枚举/数值键都在这里收口，任何不认识的键直接丢掉（脱敏 + 限额）。
 * 本地也留一份 `diagnostics.jsonl`（有上限、可轮转），中心不可达时先落本地、稍后补传。
 */
object TelemetrySchema {
    val EVENTS = setOf(
        "probe.ack", "transfer.complete", "client.error", "client.boot", "path.state", "path.stats",
        "session.joined", "session.error", "session.left", "signal.sdp", "signal.candidate", "stun.binding",
        "transfer.sent", "transfer.received", "chat.received", "chat.echo", "peer.ack", "task.error",
        "receive.error", "receive.queue_overflow", "datachannel.open", "datachannel.closed", "rtc.connection",
        "peer.authenticated_channel", "server.error", "diagnostic.dropped", "export.session",
    )
    val ENUMS = mapOf(
        "state" to setOf("unsupported", "gathering", "probing", "authenticating", "direct", "failed", "timeout",
            "closed", "new", "connecting", "connected", "disconnected", "completed", "checking"),
        "mechanism" to setOf("webrtc", "udp-probe", "quic", "tcp", "tcp-simopen", "upnp", "pcp", "natpmp", "stun"),
        "profile" to setOf("ice-v6", "ice-v4", "ice-dual", "default"),
        "protocol" to setOf("udp", "tcp", "quic", "sctp", "dtls"),
        "candidateType" to setOf("host", "srflx", "prflx", "mapped", "relay", "unknown"),
        "reason" to setOf("AUTH_FAILED", "SCHEMA_INVALID", "LIMIT_EXCEEDED", "RELAY_FORBIDDEN", "PEER_UNAVAILABLE",
            "EVENT_CONFLICT", "UNSUPPORTED_VERSION", "TIMEOUT", "CLOSED", "INTEGRITY_FAILED", "UNSUPPORTED",
            "INTERNAL_ERROR", "ROOM_EXPIRED", "ATTEMPT_CONFLICT", "ENDPOINT_UNOBSERVABLE"),
        "error" to setOf("AUTH_FAILED", "SCHEMA_INVALID", "LIMIT_EXCEEDED", "RELAY_FORBIDDEN", "TIMEOUT", "CLOSED",
            "INTEGRITY_FAILED", "INTERNAL_ERROR"),
    )
    val NUMBERS = setOf("bytes", "txBytes", "rxBytes", "rttMs", "goodput", "loss", "lostPackets", "packets",
        "elapsedMs", "requestBytes", "responseBytes", "droppedCount", "queuedBytes", "receivedBytes",
        "nextSequence", "rateBps")
    val BOOLS = setOf("ok", "echo", "integrityOk", "canMessage")
    val STRINGS = setOf("mechanism", "profile", "protocol", "candidateType", "reason", "error", "state", "address",
        "family", "mode", "detail", "code")
    val ALLOWED = STRINGS + NUMBERS + BOOLS + setOf("family")

    const val MAX_STRING = 200

    /** 服务端字段白名单之外/类型不符的一律丢弃；字符串截断。 */
    fun sanitize(data: JSONObject?): JSONObject {
        val out = JSONObject()
        if (data == null) return out
        for (key in data.keys()) {
            if (key !in ALLOWED) continue
            val value = data.opt(key) ?: continue
            when (key) {
                in NUMBERS -> if (value is Number) out.put(key, value.toDouble())
                in BOOLS -> if (value is Boolean) out.put(key, value)
                "family" -> if (value is Number) out.put(key, value.toInt())
                in ENUMS -> {
                    val allowed = ENUMS.getValue(key)
                    val text = value.toString()
                    if (text in allowed) out.put(key, text)
                }
                else -> {
                    val text = value.toString()
                    if (text.length <= MAX_STRING) out.put(key, text)
                }
            }
        }
        return out
    }

    fun normalizeEvent(kind: String): String = if (kind in EVENTS) kind else "session.error"
}

/**
 * 本地 + 中心两路诊断日志。配额：内存队列 400 条、本地文件 2 MiB（超出轮转），
 * 丢弃时补一条 `diagnostic.dropped`（数量），不静默丢。
 */
class Diagnostics(private val sessionId: String, private val directory: File) {
    private val queue = ConcurrentLinkedQueue<JSONObject>()
    private val seq = AtomicInteger(0)
    private val dropped = AtomicLong(0)
    private val file = File(directory, "diagnostics.jsonl")
    private val maxFileBytes = 2L * 1024 * 1024

    init {
        if (!directory.exists()) directory.mkdirs()
    }

    fun emit(kind: String, data: JSONObject? = null, connectionId: String? = null, attemptId: String? = null) {
        val event = JSONObject()
            .put("v", 1)
            .put("id", Protocol.uuid())
            .put("clientSessionId", sessionId)
            .put("seq", seq.getAndIncrement())
            .put("tsWallMs", System.currentTimeMillis())
            .put("monoMs", System.nanoTime() / 1_000_000.0)
            .put("event", TelemetrySchema.normalizeEvent(kind))
            .put("data", TelemetrySchema.sanitize(data))
        if (connectionId != null) event.put("connectionId", connectionId)
        if (attemptId != null) event.put("attemptId", attemptId)
        append(event)
    }

    private fun append(event: JSONObject) {
        while (queue.size >= 400) {
            queue.poll()
            val total = dropped.incrementAndGet()
            if (total % 50 == 1L) {
                val marker = JSONObject()
                    .put("v", 1).put("id", Protocol.uuid()).put("clientSessionId", sessionId)
                    .put("seq", seq.getAndIncrement()).put("tsWallMs", System.currentTimeMillis())
                    .put("monoMs", System.nanoTime() / 1_000_000.0).put("event", "diagnostic.dropped")
                    .put("data", JSONObject().put("droppedCount", total))
                queue.add(marker)
            }
        }
        queue.add(event)
        runCatching {
            if (file.exists() && file.length() > maxFileBytes) file.writeText("")
            file.appendText(event.toString() + "\n")
        }.onFailure { Log.w(TAG, "local diagnostics write failed: ${it.message}") }
    }

    fun batch(maxItems: Int = 100): List<JSONObject> {
        val out = ArrayList<JSONObject>()
        while (out.size < maxItems) {
            val event = queue.poll() ?: break
            out.add(event)
        }
        return out
    }

    fun requeue(events: List<JSONObject>) {
        for (event in events.reversed()) queue.add(event)
    }

    fun droppedCount(): Long = dropped.get()

    fun localFile(): File = file

    companion object {
        private const val TAG = "P2PDiagnostics"
    }
}
