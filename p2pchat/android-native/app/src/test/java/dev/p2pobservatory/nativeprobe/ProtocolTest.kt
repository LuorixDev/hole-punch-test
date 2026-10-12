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
 *
 * 本机的 JDK 是 25、且没有 Android SDK，跑不了 Gradle；这些用例在 CI/补好环境后用
 * `./gradlew :app:testRtcDebugUnitTest` 执行。
 */
class ProtocolTest {

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
        val message = JoinProof.joinMessage(
            room = "测试房间", secret = "correct horse battery staple", name = "android",
            clientSessionId = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab",
            capabilities = listOf("webrtc", "stun"),
            nonce = "0123456789abcdef0123456789abcdef0123456789abcdef",
            roomEstablished = false)
        assertEquals(2, message.getInt("joinVersion"))
        assertFalse(message.toString().contains("correct horse battery staple"))
        assertTrue(JoinProof.containsSecret(message, "correct horse battery staple").not())
    }

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

    @Test
    fun stunUrlsRejectTurn() {
        val good = Protocol.stunUrls(org.json.JSONArray().put(org.json.JSONObject().put("urls", "stun:stun.l.google.com:19302")))
        assertEquals(listOf("stun:stun.l.google.com:19302"), good)
        val bad = org.json.JSONArray().put(org.json.JSONObject().put("urls", "turn:evil.example:3478"))
        assertTrue(runCatching { Protocol.stunUrls(bad) }.isFailure)
    }

    @Test
    fun handshakeFieldsMatchJsonStringify() {
        val fields = Protocol.handshakeFields(true, "测试房间", "conn-1", "att-1", "me", "peer", "a".repeat(64), "b".repeat(64))
        assertEquals(
            "[\"p2pobs-v1-ack\",\"测试房间\",\"conn-1\",\"att-1\",\"me\",\"peer\",\"" + "a".repeat(64) + "\",\"" + "b".repeat(64) + "\"]",
            fields)
    }

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
