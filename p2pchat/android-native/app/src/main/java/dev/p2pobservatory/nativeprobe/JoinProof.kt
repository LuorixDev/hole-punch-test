package dev.p2pobservatory.nativeprobe

import org.json.JSONObject
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 加入证明 v2（与 `p2pchat/peer.py` / `p2pchat/web/core.js` 同算法）：
 *
 *   joinKey = HKDF-SHA256(secret, salt=room, info="p2pchat/join-key/v2")
 *   proof   = HMAC-SHA256(joinKey, room \0 nonce \0 clientSessionId)
 *
 * 房间密钥本身**不上链路**；服务器只保存/比较派生值。这里没有回退到明文密钥的分支：
 * 服务器说 nonce 不可用就明确失败（UNSUPPORTED_VERSION / AUTH_FAILED），绝不偷偷发明文。
 */
object JoinProof {
    const val JOIN_VERSION = 2
    const val ALGO = "hkdf-sha256-hmac-v2"
    private val INFO = "p2pchat/join-key/v2".toByteArray(Charsets.UTF_8)

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** HKDF-SHA256（RFC 5869）：extract + 单块 expand，输出 32 字节。 */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        require(length in 1..32) { "HKDF_LENGTH_UNSUPPORTED" }
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val block = hmacSha256(prk, info + byteArrayOf(1))
        return block.copyOf(length)
    }

    fun joinKeyBytes(secret: String, room: String): ByteArray =
        hkdfSha256(secret.toByteArray(Charsets.UTF_8), room.toByteArray(Charsets.UTF_8), INFO, 32)

    fun joinKeyHex(secret: String, room: String): String = Protocol.hex(joinKeyBytes(secret, room))

    fun proof(joinKeyHex: String, room: String, nonce: String, clientSessionId: String): String {
        val message = (room + "\u0000" + nonce + "\u0000" + clientSessionId).toByteArray(Charsets.UTF_8)
        return Protocol.hex(hmacSha256(Protocol.unhex(joinKeyHex), message))
    }

    /** 问服务器要一次性 nonce（服务器回 join_challenge）。 */
    fun challengeMessage(room: String, clientSessionId: String): JSONObject = JSONObject()
        .put("v", 1)
        .put("type", "join_challenge")
        .put("room", room)
        .put("clientSessionId", clientSessionId)

    /**
     * 加入报文的**纯字段**（不含 JSON）：字段名/顺序与 `core.js joinMessage()` 一致。
     * 只有房间里还没有密钥时才带 `verifier`（派生值本身，仍然不是房间密钥）。
     *
     * 单测直接断言这个 Map，不经过 `org.json`（Android 本地单测里它是 stub，会让断言失真）。
     */
    fun joinFields(
        room: String, secret: String, name: String, clientSessionId: String,
        capabilities: List<String>, nonce: String, roomEstablished: Boolean,
    ): Map<String, Any?> {
        val key = joinKeyHex(secret, room)
        val fields = linkedMapOf<String, Any?>(
            "v" to 1,
            "type" to "join",
            "joinVersion" to JOIN_VERSION,
            "room" to room,
            "name" to name,
            "clientSessionId" to clientSessionId,
            "capabilities" to capabilities,
            "nonce" to nonce,
            "proof" to proof(key, room, nonce, clientSessionId),
        )
        if (!roomEstablished) fields["verifier"] = key
        return fields
    }

    /** 端上实际发送的报文：把纯字段序列化成 JSON（行为与改动前一致，键顺序保持）。 */
    fun joinMessage(
        room: String, secret: String, name: String, clientSessionId: String,
        capabilities: List<String>, nonce: String, roomEstablished: Boolean,
    ): JSONObject {
        val message = JSONObject()
        for ((key, value) in joinFields(room, secret, name, clientSessionId, capabilities, nonce, roomEstablished)) {
            when (value) {
                is List<*> -> message.put(key, org.json.JSONArray(value))
                null -> Unit
                else -> message.put(key, value)
            }
        }
        return message
    }

    /** 纯判定：字段里出现了 `secret` 键、或任何值里带着房间密钥，都算泄漏。 */
    fun joinFieldsContainSecret(fields: Map<String, Any?>, secret: String): Boolean {
        if (secret.isEmpty()) return false
        if (fields.keys.any { it == "secret" }) return true
        return fields.values.any { value ->
            when (value) {
                is String -> value.contains(secret)
                is Collection<*> -> value.any { it?.toString()?.contains(secret) == true }
                else -> false
            }
        }
    }

    /** 加入报文字符串里绝不能出现房间密钥（运行时兜底用）。 */
    fun containsSecretIn(text: String, secret: String): Boolean {
        if (secret.isEmpty()) return false
        return text.contains("\"secret\"") || text.contains(secret)
    }

    /** 加入报文里绝不能出现房间密钥（静态与运行时都检查）。 */
    fun containsSecret(message: JSONObject, secret: String): Boolean =
        containsSecretIn(message.toString(), secret)

    /**
     * 自检向量：由 `p2pchat/android-native/tools/probe_join_vectors.py` 用 peer.py 同一套
     * HKDF/HMAC 生成。启动时校验，算法一改就当场失败（不会静默发一个假证明）。
     */
    class Vector(val secret: String, val room: String, val nonce: String, val session: String,
                 val joinKeyHex: String, val proofHex: String)

    val SELF_CHECK_VECTORS = listOf(
        Vector(
            secret = "correct horse battery staple",
            room = "测试房间",
            nonce = "0123456789abcdef0123456789abcdef0123456789abcdef",
            session = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab",
            joinKeyHex = "f0112deb8b30c04e03be2b99858754a60201a7e6189312e63123727cd3818c78",
            proofHex = "0b68f44e4e0121818472c75a6f5a198e2234ea0592ef906cef14a00d0f76f8b5",
        ),
    )

    fun selfCheck(): List<String> {
        val failures = ArrayList<String>()
        for (vector in SELF_CHECK_VECTORS) {
            val key = joinKeyHex(vector.secret, vector.room)
            if (!Protocol.constantTimeEquals(key, vector.joinKeyHex)) {
                failures.add("joinKey mismatch for room=${vector.room}")
                continue
            }
            val proof = proof(key, vector.room, vector.nonce, vector.session)
            if (!Protocol.constantTimeEquals(proof, vector.proofHex)) {
                failures.add("proof mismatch for room=${vector.room}")
            }
        }
        return failures
    }
}
