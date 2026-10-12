package dev.p2pobservatory.nativeprobe

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/**
 * 与 `p2pchat/web/core.js` / `p2pchat/peer.py` 逐字对齐的协议层。
 *
 * 这里只放纯函数：帧编解码、候选地址族过滤、数据通道握手、JSON 分隔符。
 * 任何数值/字段名/分隔符改动都必须同时改桌面与网页端，否则加不进房间。
 */
object Protocol {
    // 与 core.js 的 LIMIT 一致
    const val FILE_LIMIT = 32L * 1024 * 1024
    const val RESERVED_LIMIT = 64L * 1024 * 1024
    const val CHUNK = 16384
    const val HIGH_WATER = 524288
    const val LOW_WATER = 131072
    const val TEXT_LIMIT = 16384
    const val ID_LIMIT = 100
    const val RECV_ITEMS = 8
    const val RECV_IDLE_MS = 30_000L

    // 三个 WebRTC 档位（内部代号只出现在「技术详情」里，不作为界面标题）
    const val PROFILE_DUAL = "ice-dual"
    const val PROFILE_V6 = "ice-v6"
    const val PROFILE_V4 = "ice-v4"
    val PROFILES = listOf(PROFILE_DUAL, PROFILE_V6, PROFILE_V4)

    // 数据通道上的控制消息 kind（与 peer.py 一致）
    const val KIND_HELLO = "hello"
    const val KIND_HELLO_ACK = "hello-ack"
    const val KIND_PING = "ping"
    const val KIND_PONG = "pong"
    const val KIND_TEXT = "text"
    const val KIND_DELIVERED = "delivered"
    const val KIND_FILE_START = "file-start"
    const val KIND_FILE_READY = "file-ready"
    const val KIND_FILE_PROGRESS = "file-progress"
    const val KIND_FILE_END = "file-end"
    const val KIND_BENCH_START = "bench-start"
    const val KIND_BENCH_END = "bench-end"
    const val KIND_BENCH_ACK = "bench-ack"
    const val KIND_BENCH_ERROR = "bench-error"

    const val LANE_CHAT = "chat"
    const val LANE_BENCH = "benchmark"

    private val HEX = "0123456789abcdef".toCharArray()

    fun uuid(): String = UUID.randomUUID().toString()

    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0f]
        }
        return String(out)
    }

    fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0) { "INVALID_HEX" }
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(text[i * 2], 16) shl 4) or Character.digit(text[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    fun sha256Hex(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    /** 与 core.js 的 `encodeFrame(id, sequence, payload)` 完全一致的二进制帧。 */
    fun encodeFrame(id: String, sequence: Long, payload: ByteArray): ByteArray {
        val idBytes = id.toByteArray(Charsets.UTF_8)
        require(idBytes.isNotEmpty() && idBytes.size <= ID_LIMIT) { "INVALID_CHUNK" }
        require(sequence in 0..0xffffffffL) { "INVALID_CHUNK" }
        require(payload.size <= CHUNK) { "INVALID_CHUNK" }
        val out = ByteArray(6 + idBytes.size + payload.size)
        putU16(out, 0, idBytes.size)
        System.arraycopy(idBytes, 0, out, 2, idBytes.size)
        putU32(out, 2 + idBytes.size, sequence)
        System.arraycopy(payload, 0, out, 6 + idBytes.size, payload.size)
        return out
    }

    class Frame(val id: String, val sequence: Long, val payload: ByteArray)

    fun decodeFrame(data: ByteArray): Frame {
        require(data.size >= 7) { "INVALID_CHUNK" }
        val idLength = getU16(data, 0)
        require(idLength in 1..ID_LIMIT) { "INVALID_CHUNK" }
        require(data.size >= 6 + idLength) { "INVALID_CHUNK" }
        require(data.size - 6 - idLength <= CHUNK) { "INVALID_CHUNK" }
        val id = String(data, 2, idLength, Charsets.UTF_8)
        val sequence = getU32(data, 2 + idLength)
        return Frame(id, sequence, data.copyOfRange(6 + idLength, data.size))
    }

    private fun putU16(out: ByteArray, at: Int, value: Int) {
        out[at] = ((value ushr 8) and 0xff).toByte()
        out[at + 1] = (value and 0xff).toByte()
    }

    private fun putU32(out: ByteArray, at: Int, value: Long) {
        out[at] = ((value ushr 24) and 0xff).toByte()
        out[at + 1] = ((value ushr 16) and 0xff).toByte()
        out[at + 2] = ((value ushr 8) and 0xff).toByte()
        out[at + 3] = (value and 0xff).toByte()
    }

    private fun getU16(data: ByteArray, at: Int): Int =
        ((data[at].toInt() and 0xff) shl 8) or (data[at + 1].toInt() and 0xff)

    private fun getU32(data: ByteArray, at: Int): Long {
        var value = 0L
        for (i in 0 until 4) value = (value shl 8) or (data[at + i].toLong() and 0xff)
        return value
    }

    /** 地址族：只有 IPv6 / IPv4 两种，认不出就 null（与 core.js 的 family 一致）。 */
    fun family(address: String?): Int? {
        if (address == null) return null
        if (address.contains(':')) return 6
        return if (Regex("^(\\d{1,3}\\.){3}\\d{1,3}$").matches(address)) 4 else null
    }

    class CandidateInfo(val family: Int?, val protocol: String, val type: String)

    /** 解析 SDP 的 `a=candidate:` 行（core.js 的 candidateInfo）。 */
    fun candidateInfo(candidateLine: String): CandidateInfo {
        val parts = candidateLine.trim().split(Regex("\\s+"))
        val address = parts.getOrNull(4)
        val protocol = parts.getOrNull(2)?.lowercase() ?: ""
        val typeIndex = parts.indexOf("typ")
        val type = if (typeIndex >= 0) parts.getOrNull(typeIndex + 1) ?: "" else ""
        return CandidateInfo(family(address), protocol, type)
    }

    /**
     * 无中继硬约束的第一道闸：`typ relay` 一律不允许，任何档位都不例外。
     * 然后在 v6 / v4 档位里按地址族过滤候选（dual 档不过滤）。
     */
    fun permitted(candidateLine: String, profile: String): Boolean {
        val info = candidateInfo(candidateLine)
        if (info.type == "relay") return false
        if (profile == PROFILE_DUAL) return true
        if (info.family == null) return true
        return info.family == if (profile == PROFILE_V6) 6 else 4
    }

    fun filterSdp(sdp: String, profile: String): String =
        sdp.split(Regex("\\r?\\n"))
            .filter { line -> !line.startsWith("a=candidate:") || permitted(line.removePrefix("a="), profile) }
            .joinToString("\r\n")

    /** 服务器下发的 STUN 白名单：只接受 stun:/stuns:，任何 turn:/relay 一律拒绝（回归即失败）。 */
    fun stunUrls(rawServers: JSONArray?): List<String> {
        if (rawServers == null) return emptyList()
        val urls = ArrayList<String>()
        for (i in 0 until rawServers.length()) {
            val entry = rawServers.optJSONObject(i) ?: continue
            val value = entry.opt("urls")
            val candidates = when (value) {
                is JSONArray -> (0 until value.length()).mapNotNull { value.optString(it, null) }
                is String -> listOf(value)
                else -> emptyList()
            }
            for (url in candidates) {
                val trimmed = url.trim()
                if (trimmed.isEmpty()) continue
                require(!trimmed.startsWith("turn:") && !trimmed.startsWith("turns:")) { "RELAY_FORBIDDEN" }
                require(trimmed.startsWith("stun:") || trimmed.startsWith("stuns:")) { "RELAY_FORBIDDEN" }
                urls.add(trimmed)
            }
        }
        return urls
    }

    /**
     * 与 JS `JSON.stringify(fields)` 等价的数组序列化：只转义 `"`、`\` 与控制字符，
     * 非 ASCII（中文/emoji）原样输出为 UTF-8。
     */
    fun jsonFields(fields: List<String>): String {
        val sb = StringBuilder("[")
        for ((index, field) in fields.withIndex()) {
            if (index > 0) sb.append(',')
            sb.append('"')
            for (ch in field) {
                when {
                    ch == '"' -> sb.append("\\\"")
                    ch == '\\' -> sb.append("\\\\")
                    ch.code < 0x20 -> sb.append(String.format("\\u%04x", ch.code))
                    else -> sb.append(ch)
                }
            }
            sb.append('"')
        }
        return sb.append(']').toString()
    }

    /**
     * 与 core.js `Handshake.fields()` 一致：数据通道握手的 HMAC 输入。
     * 注意用的是**房间密钥**（派生证明只用于加房间），不是 joinKey。
     */
    fun handshakeFields(
        ack: Boolean, room: String, connectionId: String, attemptId: String,
        sender: String, receiver: String, nonce: String, echoNonce: String? = null,
    ): String {
        val fields = ArrayList<String>(8)
        fields.add(if (ack) "p2pobs-v1-ack" else "p2pobs-v1")
        fields.add(room)
        fields.add(connectionId)
        fields.add(attemptId)
        fields.add(sender)
        fields.add(receiver)
        fields.add(nonce)
        if (ack) fields.add(echoNonce ?: "")
        return jsonFields(fields)
    }

    /** 帧 ID 只允许短 ASCII；防止把大对象塞进头里。 */
    fun validFrameId(id: String): Boolean = id.isNotEmpty() && id.toByteArray(Charsets.UTF_8).size <= ID_LIMIT

    fun newJson(): JSONObject = JSONObject()
}
