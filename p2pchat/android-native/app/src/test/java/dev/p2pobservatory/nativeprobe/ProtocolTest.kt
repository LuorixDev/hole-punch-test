package dev.p2pobservatory.nativeprobe

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 纯算法单元测试（JVM，不需要设备/模拟器）：
 *  - 加入证明 v2 的向量自检（与 `tools/probe_join_vectors.py` 同一组常量）
 *  - 帧编解码与限额
 *  - 地址族过滤（三档 profile）与 relay 丢弃
 *  - 握手 HMAC 输入的分隔符（与 core.js `JSON.stringify` 等价）
 *  - 「未测得显示 —」这类诚实语义
 *
 * 历史背景（t56）：这些用例第一次在 CI 真跑就两连败，根因是 Android 本地单测里 `org.json` 是
 * android.jar 的 **stub**（`JSONObject().put(...)` 返回 null → 链式调用 NPE；`JSONArray().length()`
 * 返回 0 → 断言失真）。修法见 `app/build.gradle.kts`：测试类路径加真实现 `org.json:json`，
 * 并把安全判定改成**不碰 JSON 的纯函数**（[Protocol.stunUrlsFrom]、[JoinProof.joinFields]）。
 *
 * 本机用 `./gradlew :app:testRtcDebugUnitTest` 跑；CI 的 android-native job 是同一条命令。
 */
class ProtocolTest {

    // ---------------------------------------------------------------- 加入证明 v2

    @Test
    fun joinProofMatchesIndependentVectors() {
        assertEquals(emptyList<String>(), JoinProof.selfCheck())
    }

    @Test
    fun joinKeyMatchesServerHkdfVector() {
        assertEquals(
            "f0112deb8b30c04e03be2b99858754a60201a7e6189312e63123727cd3818c78",
            JoinProof.joinKeyHex("correct horse battery staple", "测试房间"))
    }

    @Test
    fun joinMessageNeverCarriesSecret() {
        val secret = "correct horse battery staple"
        val message = JoinProof.joinMessage(
            room = "测试房间", secret = secret, name = "android",
            clientSessionId = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab",
            capabilities = listOf("webrtc"),
            nonce = "0123456789abcdef0123456789abcdef0123456789abcdef",
            roomEstablished = false)
        assertEquals(2, message.getInt("joinVersion"))
        assertFalse(message.toString().contains(secret))
        assertTrue(JoinProof.containsSecret(message, secret).not())
        assertEquals("join", message.getString("type"))
        assertEquals(64, message.getString("proof").length)
        assertEquals(64, message.getString("verifier").length)
    }

    /** 纯字段版本（不经过 org.json）：同样必须没有 secret 键、没有密钥值。 */
    @Test
    fun joinFieldsNeverCarrySecretAndSkipVerifierWhenEstablished() {
        val secret = "correct horse battery staple"
        val fields = JoinProof.joinFields(
            room = "测试房间", secret = secret, name = "android",
            clientSessionId = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab",
            capabilities = listOf("webrtc"),
            nonce = "0123456789abcdef0123456789abcdef0123456789abcdef",
            roomEstablished = false)
        assertEquals(2, fields["joinVersion"])
        assertEquals("join", fields["type"])
        assertEquals(listOf("webrtc"), fields["capabilities"])
        assertFalse(JoinProof.joinFieldsContainSecret(fields, secret))
        assertTrue(fields.containsKey("verifier"))
        assertFalse(JoinProof.joinFieldsContainSecret(fields, ""))

        val established = JoinProof.joinFields(
            room = "测试房间", secret = secret, name = "android",
            clientSessionId = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab",
            capabilities = listOf("webrtc"),
            nonce = "0123456789abcdef0123456789abcdef0123456789abcdef",
            roomEstablished = true)
        // 房间密钥已建立时不再交 verifier（少传一个派生值）
        assertFalse(established.containsKey("verifier"))
        // 同一 key/nonce/session ⇒ 同一 proof
        assertEquals(fields["proof"], established["proof"])
    }

    /** 泄漏检测本身要有效：把密钥塞进任何字段都必须被发现（否则"没有泄漏"的断言等于没说）。 */
    @Test
    fun secretLeakDetectorCatchesSecretAnywhere() {
        val secret = "correct horse battery staple"
        assertTrue(JoinProof.joinFieldsContainSecret(linkedMapOf("secret" to secret), secret))
        assertTrue(JoinProof.joinFieldsContainSecret(linkedMapOf("name" to "me-$secret"), secret))
        assertTrue(JoinProof.joinFieldsContainSecret(linkedMapOf("capabilities" to listOf("webrtc", secret)), secret))
        assertFalse(JoinProof.joinFieldsContainSecret(linkedMapOf("name" to "me"), secret))
        assertTrue(JoinProof.containsSecretIn("{\"secret\":\"x\"}", secret))
        assertFalse(JoinProof.containsSecretIn("{\"name\":\"me\"}", secret))
    }

    // ---------------------------------------------------------------- 帧编解码

    @Test
    fun frameRoundTripAndLimits() {
        val payload = ByteArray(Protocol.CHUNK) { it.toByte() }
        val frame = Protocol.encodeFrame("file-1", 7L, payload)
        val decoded = Protocol.decodeFrame(frame)
        assertEquals("file-1", decoded.id)
        assertEquals(7L, decoded.sequence)
        assertArrayEquals(payload, decoded.payload)
        val tooBig = ByteArray(Protocol.CHUNK + 1)
        assertTrue(runCatching { Protocol.encodeFrame("x", 0L, tooBig) }.isFailure)
    }

    /** 畸形输入必须**明确失败**，不能被当成"空帧"悄悄放过。 */
    @Test
    fun decodeFrameRejectsMalformedInput() {
        assertTrue(runCatching { Protocol.decodeFrame(ByteArray(0)) }.isFailure)
        assertTrue(runCatching { Protocol.decodeFrame(ByteArray(6)) }.isFailure)
        assertTrue(runCatching { Protocol.decodeFrame(Protocol.encodeFrame("x", 0L, ByteArray(1)).copyOf(4)) }.isFailure)
        val idTooLong = ByteArray(6 + 101 + 1)
        idTooLong[0] = 0; idTooLong[1] = 101
        assertTrue(runCatching { Protocol.decodeFrame(idTooLong) }.isFailure)
        val oversized = ByteArray(6 + 1 + Protocol.CHUNK + 1)
        oversized[0] = 0; oversized[1] = 1
        assertTrue(runCatching { Protocol.decodeFrame(oversized) }.isFailure)
    }

    // ---------------------------------------------------------------- 候选/地址族

    @Test
    fun familyProfilesFilterCandidatesAndDropRelay() {
        val v6 = "candidate:1 1 udp 2122260223 2001:db8::1 50000 typ host"
        val v4 = "candidate:2 1 udp 2122260223 192.0.2.5 50001 typ srflx"
        val relay = "candidate:3 1 udp 41885439 203.0.113.9 50002 typ relay"
        assertTrue(Protocol.permitted(v6, Protocol.PROFILE_DUAL))
        assertTrue(Protocol.permitted(v4, Protocol.PROFILE_DUAL))
        assertFalse(Protocol.permitted(relay, Protocol.PROFILE_DUAL))
        assertTrue(Protocol.permitted(v6, Protocol.PROFILE_V6))
        assertFalse(Protocol.permitted(v4, Protocol.PROFILE_V6))
        assertTrue(Protocol.permitted(v4, Protocol.PROFILE_V4))
        assertFalse(Protocol.permitted(v6, Protocol.PROFILE_V4))
        val sdp = "v=0\r\na=candidate:$v6\r\na=candidate:$relay\r\n"
        val filtered = Protocol.filterSdp(sdp, Protocol.PROFILE_V6)
        assertTrue(filtered.contains("2001:db8::1"))
        assertFalse(filtered.contains("typ relay"))
    }

    /** 畸形候选行不能让过滤逻辑崩，也不能把 relay 放过去。 */
    @Test
    fun malformedCandidateLinesAreHandled() {
        assertFalse(Protocol.permitted("candidate:1 1 udp 1 203.0.113.9 5 typ relay", Protocol.PROFILE_DUAL))
        val weird = Protocol.candidateInfo("candidate:")
        assertEquals(null, weird.family)
        assertTrue(Protocol.permitted("candidate:", Protocol.PROFILE_DUAL))
    }

    // ---------------------------------------------------------------- STUN 白名单（纯逻辑 + JSON 适配层）

    @Test
    fun stunUrlsRejectTurn() {
        val good = Protocol.stunUrls(org.json.JSONArray().put(org.json.JSONObject().put("urls", "stun:stun.l.google.com:19302")))
        assertEquals(listOf("stun:stun.l.google.com:19302"), good)
        val bad = org.json.JSONArray().put(org.json.JSONObject().put("urls", "turn:evil.example:3478"))
        assertTrue(runCatching { Protocol.stunUrls(bad) }.isFailure)
    }

    /** 纯逻辑（不碰 JSON）：空白丢弃、只留 stun/stuns、turn 与其它 scheme 一律拒绝。 */
    @Test
    fun stunUrlsFromIsStrictAndJsonFree() {
        assertEquals(
            listOf("stun:a.example:3478", "stuns:b.example:5349"),
            Protocol.stunUrlsFrom(listOf("  stun:a.example:3478  ", "", "   ", "stuns:b.example:5349")))
        assertEquals(emptyList<String>(), Protocol.stunUrlsFrom(emptyList()))
        for (bad in listOf("turn:evil.example:3478", "turns:evil.example:5349", "http://evil.example", "relay:evil")) {
            assertTrue("必须拒绝 $bad", runCatching { Protocol.stunUrlsFrom(listOf(bad)) }.isFailure)
        }
        // 一条非法就整批失败：不允许"跳过坏的那条、悄悄只用好的"
        assertTrue(runCatching {
            Protocol.stunUrlsFrom(listOf("stun:good.example:3478", "turn:evil.example:3478"))
        }.isFailure)
    }

    /** JSON 适配层：字段缺失/类型不对时不能 NPE、不能静默变"没有 TURN"。 */
    @Test
    fun stunUrlsAdapterHandlesMissingAndWeirdFields() {
        assertEquals(emptyList<String>(), Protocol.stunUrls(null))
        assertEquals(emptyList<String>(), Protocol.stunUrls(org.json.JSONArray()))
        // 缺 "urls" 键：跳过而不是崩
        assertEquals(emptyList<String>(),
            Protocol.stunUrls(org.json.JSONArray().put(org.json.JSONObject().put("note", "x"))))
        // 数组形式（服务器可能下发多个 URL）
        val multi = org.json.JSONArray().put(org.json.JSONObject().put("urls",
            org.json.JSONArray().put("stun:a.example:3478").put("stuns:b.example:5349")))
        assertEquals(listOf("stun:a.example:3478", "stuns:b.example:5349"), Protocol.stunUrls(multi))
        // 数组里混进 turn：整批失败
        val mixed = org.json.JSONArray().put(org.json.JSONObject().put("urls",
            org.json.JSONArray().put("stun:a.example:3478").put("turn:evil.example:3478")))
        assertTrue(runCatching { Protocol.stunUrls(mixed) }.isFailure)
        // 数字等垃圾值：交给纯逻辑，明确失败而不是被当成合法 URL
        val numeric = org.json.JSONArray().put(org.json.JSONObject().put("urls", org.json.JSONArray().put(1234)))
        assertTrue(runCatching { Protocol.stunUrls(numeric) }.isFailure)
        // 元素不是对象：跳过（不崩）
        assertEquals(emptyList<String>(), Protocol.stunUrls(org.json.JSONArray().put("stun:a.example:3478")))
    }

    // ---------------------------------------------------------------- JSON 与握手输入

    /**
     * org.json 必须是**真实现**：如果测试类路径上还是 android.jar 的 stub，
     * `put/get` 会返回 null/0 或抛 "not mocked" —— 这条会立刻红，防止"断言在桩上假通过"回归。
     */
    @Test
    fun orgJsonImplementationIsRealNotAStub() {
        val obj = org.json.JSONObject().put("a", 1).put("b", "x")
        assertEquals(1, obj.getInt("a"))
        assertEquals("x", obj.getString("b"))
        assertEquals(2, obj.length())
        assertEquals(2, org.json.JSONArray().put("x").put("y").length())
        assertEquals("stun:x", org.json.JSONObject().put("urls", "stun:x").getString("urls"))
    }

    @Test
    fun handshakeFieldsMatchJsonStringify() {
        val fields = Protocol.handshakeFields(true, "测试房间", "conn-1", "att-1", "me", "peer", "a".repeat(64), "b".repeat(64))
        assertEquals(
            "[\"p2pobs-v1-ack\",\"测试房间\",\"conn-1\",\"att-1\",\"me\",\"peer\",\"" + "a".repeat(64) + "\",\"" + "b".repeat(64) + "\"]",
            fields)
    }

    /** 转义必须与 JS `JSON.stringify` 一致，否则握手 HMAC 在两端算不到一起。 */
    @Test
    fun jsonFieldsEscapesLikeJsonStringify() {
        assertEquals("[\"a\\\"b\"]", Protocol.jsonFields(listOf("a\"b")))
        assertEquals("[\"a\\\\b\"]", Protocol.jsonFields(listOf("a\\b")))
        assertEquals("[\"a\\u0001b\"]", Protocol.jsonFields(listOf("a\u0001b")))
        assertEquals("[\"中文🙂\"]", Protocol.jsonFields(listOf("中文🙂")))
        assertEquals("[]", Protocol.jsonFields(emptyList()))
    }

    // ---------------------------------------------------------------- 诚实语义

    @Test
    fun unmeasuredLatencyIsEmDashNotZero() {
        assertEquals("—", MethodCatalog.formatLatency(null))
        assertEquals("12.0 ms", MethodCatalog.formatLatency(12.0))
        // 未测到的路径不允许被说成成功
        val method = MethodCatalog.methodFor("ice-v6")!!
        assertFalse(MethodCatalog.isHonestSuccess(method, "direct", authenticated = false))
        assertTrue(MethodCatalog.isHonestSuccess(method, "direct", authenticated = true))
        assertFalse(MethodCatalog.isHonestSuccess(method, "observed", authenticated = true))
    }

    @Test
    fun nineMethodsKeepDocumentedOrder() {
        assertEquals(
            listOf("双栈直连", "IPv6 直连", "IPv4 直连", "UDP 探测", "QUIC 加密直连", "TCP 加密直连", "TCP 同时打开", "STUN 映射观测", "路由器放行（自动开一个端口）"),
            MethodCatalog.METHODS.map { it.title })
    }
}
