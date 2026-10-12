package dev.p2pobservatory.nativeprobe

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import org.webrtc.PeerConnectionFactory
import java.io.File

/**
 * 三屏原生界面（**没有 WebView 承载任何业务逻辑**）：
 *   1) 连接服务器：地址/房间/密钥/昵称 → v2 加入
 *   2) 逐条尝试打洞：九条方式的人话名称 + 什么网络下可行 + 状态词 + 分开标注的延迟 + 技术详情
 *   3) 聊天：文本/图片/文件/录音语音（录完走文件传输）+ 右上角「设置」（剩余方式/可用性/延迟/测速）
 */
class MainActivity : Activity(), SignalingClient.Listener, PathRunner.Listener, RtcSession.Listener {

    private lateinit var screenConnect: LinearLayout
    private lateinit var screenAttempt: LinearLayout
    private lateinit var screenChat: LinearLayout
    private lateinit var attemptRows: LinearLayout
    private lateinit var chatLog: TextView
    private lateinit var chatInput: EditText
    private lateinit var statusText: TextView
    private lateinit var joinButton: Button
    private lateinit var chatButton: Button

    private lateinit var diagnostics: Diagnostics
    private lateinit var peerFactory: PeerConnectionFactory
    private lateinit var runner: PathRunner
    private lateinit var recorder: VoiceRecorder
    private lateinit var discovery: LanDiscovery

    private var signaling: SignalingClient? = null
    private var session: RtcSession? = null
    private var room = ""
    private var secret = ""
    private var localPeerId = ""
    private var remotePeerId: String? = null
    private var attemptId = Protocol.uuid()
    private var connectionId = Protocol.uuid()
    private var stunUrls: List<String> = emptyList()
    private val handler = Handler(Looper.getMainLooper())
    private var uploadDelayMs = 1000L
    private val pickRequest = 4711

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        diagnostics = Diagnostics(Protocol.uuid(), File(filesDir, "diagnostics"))
        for (failure in JoinProof.selfCheck()) {
            // 算法自检失败就当场说出来，不要静默发一个假证明。
            diagnostics.emit("client.error", JSONObject().put("code", "INTEGRITY_FAILED").put("detail", failure))
        }
        peerFactory = PeerConnectionFactory.builder().createPeerConnectionFactory()
        runner = PathRunner(diagnostics, this)
        recorder = VoiceRecorder(this)
        discovery = LanDiscovery(this)
        buildUi()
        showScreen(1)
    }

    // ---------------- 界面（全部原生 View，程序化构建） ----------------

    private fun buildUi() {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.WHITE) }
        statusText = TextView(this).apply { setPadding(24, 16, 24, 16); textSize = 14f }
        root.addView(statusText)
        screenConnect = buildConnectScreen()
        screenAttempt = buildAttemptScreen()
        screenChat = buildChatScreen()
        root.addView(screenConnect)
        root.addView(screenAttempt)
        root.addView(screenChat)
        setContentView(root)
    }

    private fun label(text: String, size: Float = 16f): TextView = TextView(this).apply {
        this.text = text; textSize = size; setPadding(24, 12, 24, 4)
    }

    private fun field(hint: String, initial: String = "", password: Boolean = false): EditText = EditText(this).apply {
        this.hint = hint; setText(initial); setPadding(24, 8, 24, 8)
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun buildConnectScreen(): LinearLayout {
        val screen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        screen.addView(label("连接服务器", 22f))
        val urlField = field("信令地址，例如 ws://192.168.1.5:8080/ws", "ws://127.0.0.1:8080/ws")
        val roomField = field("房间名")
        val secretField = field("房间密钥（只在本机用来派生证明，不上链路）", password = true)
        val nameField = field("昵称", android.os.Build.MODEL ?: "android")
        val uploadBox = android.widget.CheckBox(this).apply { text = "把诊断日志上报到中心（脱敏、限额）"; isChecked = true }
        joinButton = Button(this).apply {
            text = "连接服务器"
            setOnClickListener {
                room = roomField.text.toString().trim()
                secret = secretField.text.toString()
                val url = urlField.text.toString().trim()
                if (room.isEmpty() || secret.isEmpty()) { toast("房间名和密钥都要填"); return@setOnClickListener }
                val scheme = Uri.parse(url).scheme ?: ""
                if (scheme != "wss" && !isLoopback(url)) {
                    // 明文信令只在本地回环上允许，其它情况要用户明确同意（与桌面/网页语义一致）。
                    toast("非本地地址的明文信令已被拒绝：请改用 wss:// 或在本地回环上使用")
                    diagnostics.emit("client.error", JSONObject().put("code", "SIGNAL_PLAINTEXT_REFUSED"))
                    return@setOnClickListener
                }
                diagnostics.emit("client.boot", JSONObject().put("mode", "native"))
                val client = SignalingClient(url, room, secret, nameField.text.toString(), diagnostics, this@MainActivity)
                signaling = client
                client.connect()
                toast("正在加入房间（v2 证明）…")
            }
        }
        screen.addView(urlField); screen.addView(roomField); screen.addView(secretField)
        screen.addView(nameField); screen.addView(uploadBox); screen.addView(joinButton)
        screen.addView(label(MethodCatalog.NO_RELAY_NOTE, 13f))
        screen.addView(label("当前安卓版：" + runner.snapshot().joinToString("　") { "${it.method.title}=${it.availability}" }, 12f))
        return screen
    }

    private fun buildAttemptScreen(): LinearLayout {
        val screen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        screen.addView(label("逐条尝试打洞", 22f))
        screen.addView(label(MethodCatalog.WEBRTC_PROFILE_NOTE, 13f))
        val scroll = ScrollView(this)
        attemptRows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(attemptRows)
        screen.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        chatButton = Button(this).apply {
            text = "进入聊天（需要先有一条「已打通」的路径）"
            isEnabled = false
            setOnClickListener { showScreen(3) }
        }
        screen.addView(chatButton)
        renderPaths()
        return screen
    }

    private fun renderPaths() {
        attemptRows.removeAllViews()
        for (path in runner.snapshot()) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 8) }
            row.addView(TextView(this).apply {
                text = "${path.method.index}. ${path.method.title}　【${path.statusWord()}】　可用性：${path.availability}"
                textSize = 16f
            })
            row.addView(TextView(this).apply {
                text = "它是什么：${path.method.explain}　｜　什么网络下可行：${path.method.works}"
                textSize = 13f
            })
            if (path.state == "observed") {
                row.addView(TextView(this).apply { text = "仅探测，不传内容"; textSize = 12f })
            }
            if (path.state == "unavailable") {
                row.addView(TextView(this).apply { text = "失败原因：${path.reason ?: path.method.failure}"; textSize = 12f })
            }
            row.addView(TextView(this).apply {
                text = "延迟：" + MethodCatalog.latencyLabel("probe") + "=" +
                    MethodCatalog.formatLatency(path.probeRttMs) + "　" +
                    MethodCatalog.latencyLabel("chat") + "=" + MethodCatalog.formatLatency(path.chatRttMs)
                textSize = 12f
            })
            row.addView(TextView(this).apply {
                // 内部代号只出现在技术详情里。
                text = "技术详情：" + path.method.technical
                textSize = 11f
            })
            attemptRows.addView(row)
        }
    }

    private fun buildChatScreen(): LinearLayout {
        val screen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        header.addView(label("聊天", 22f), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        header.addView(Button(this).apply { text = "设置"; setOnClickListener { showSettings() } })
        screen.addView(header)
        chatLog = TextView(this).apply { textSize = 14f; setPadding(24, 8, 24, 8) }
        screen.addView(ScrollView(this).apply { addView(chatLog) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        chatInput = field("输入消息")
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        actions.addView(Button(this).apply { text = "发送"; setOnClickListener { sendText() } })
        actions.addView(Button(this).apply { text = "图片"; setOnClickListener { pickFile("image/*") } })
        actions.addView(Button(this).apply { text = "文件"; setOnClickListener { pickFile("*/*") } })
        actions.addView(Button(this).apply { text = "录音"; setOnClickListener { toggleRecording() } })
        screen.addView(chatInput); screen.addView(actions)
        return screen
    }

    private fun showScreen(index: Int) {
        screenConnect.visibility = if (index == 1) View.VISIBLE else View.GONE
        screenAttempt.visibility = if (index == 2) View.VISIBLE else View.GONE
        screenChat.visibility = if (index == 3) View.VISIBLE else View.GONE
    }

    /** 右上角设置：剩余方式 / 可用性 / 延迟 / 测速（测速在独立通道上，标注为应用层速度）。 */
    private fun showSettings() {
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24) }
        body.addView(TextView(this).apply {
            text = "剩余方式：" + runner.remaining().joinToString("、") { it.title }.ifEmpty { "（都已打通）" }
            textSize = 14f
        })
        for (path in runner.snapshot()) {
            body.addView(TextView(this).apply {
                text = "${path.method.title}　可用性：${path.availability}　状态：${path.statusWord()}　" +
                    "延迟：" + MethodCatalog.formatLatency(path.chatRttMs)
                textSize = 13f
            })
        }
        val speedText = TextView(this).apply { text = "测速：尚未测（—）"; textSize = 13f }
        body.addView(speedText)
        body.addView(Button(this).apply {
            text = "测速（独立通道）"
            setOnClickListener {
                speedText.text = "测速中…（这是应用层速度，不是线路带宽）"
                runCatching { session?.runBenchmark() }.onFailure { speedText.text = "测速失败：${it.message}" }
            }
        })
        body.addView(TextView(this).apply { text = "测速结果只是应用层速度，不是线路带宽。安全提示：不做中继、不改走服务器。"; textSize = 12f })
        android.app.AlertDialog.Builder(this).setTitle("设置").setView(ScrollView(this).apply { addView(body) })
            .setPositiveButton("关闭", null).show()
    }

    // ---------------- 动作 ----------------

    private fun sendText() {
        val text = chatInput.text.toString()
        if (text.isEmpty()) return
        val session = session ?: return toast("还没有可用的直连路径")
        if (!session.isAuthenticated) return toast("通道还在互相验证，先别发")
        session.sendText(text)
        chatInput.setText("")
        appendLog("我：" + text)
    }

    private fun pickFile(mime: String) {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = mime; addCategory(Intent.CATEGORY_OPENABLE)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, pickRequest)
    }

    @Deprecated("framework-only file picker")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickRequest || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        val mime = contentResolver.getType(uri) ?: "application/octet-stream"
        val local = File(cacheDir, "outgoing-" + Protocol.uuid().take(8))
        runCatching {
            contentResolver.openInputStream(uri)!!.use { input -> local.outputStream().use { input.copyTo(it) } }
            session?.sendFile(local, mime)
            appendLog("已发送文件：" + local.name + "（" + local.length() + " 字节）")
        }.onFailure { toast("发送失败：${it.message}") }
    }

    private fun toggleRecording() {
        if (recorder.isRecording()) {
            val file = recorder.stop()
            if (file == null) {
                toast("录音失败或超限（60 秒 / 4 MiB）")
                diagnostics.emit("client.error", JSONObject().put("code", "LIMIT_EXCEEDED"))
            } else {
                // 录完的音频按文件传输，不做实时通话、不做语音识别。
                session?.sendFile(file, "audio/mp4")
                appendLog("已发送语音：" + file.name + "（" + file.length() + " 字节）")
            }
            return
        }
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), 91)
            return
        }
        runCatching { recorder.start() }.onFailure { toast("无法开始录音：${it.message}") }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 91) {
            toast("已拒绝录音权限：语音消息不可用（其它功能不受影响）")
        }
    }

    private fun appendLog(line: String) {
        runOnUiThread { chatLog.text = chatLog.text.toString() + line + "\n" }
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()

    private fun isLoopback(url: String): Boolean {
        val host = Uri.parse(url).host ?: return false
        return host == "127.0.0.1" || host == "::1" || host == "localhost"
    }

    // ---------------- 信令回调 ----------------

    override fun onJoined(localPeerId: String, stunUrls: List<String>) {
        this.localPeerId = localPeerId
        this.stunUrls = stunUrls
        statusText.text = "已加入 · " + localPeerId.take(8) + "　STUN：" + stunUrls.size + " 个（无 TURN）"
        KeepAliveService.start(this)
        discovery.start(room, secret)
        showScreen(2)
        renderPaths()
        startUploadLoop()
    }

    override fun onRoster(peers: List<String>) {
        val others = peers.filter { it != localPeerId }
        remotePeerId = others.firstOrNull()
        if (others.isEmpty()) {
            statusText.text = "房间已加入，但还没有别的设备。同一房间需要两台设备（或桌面端）才能打洞。"
            return
        }
        if (session == null) {
            connectAttempt(others.first())
        }
    }

    override fun onSignal(message: JSONObject) {
        val session = session ?: return
        val description = message.optJSONObject("description")
        if (description != null) {
            session.onRemoteDescription(description.optString("type"), description.optString("sdp"))
        }
        val candidate = message.optJSONObject("candidate")
        if (candidate != null) {
            // `optString(name, null)` 是拿 null 去顶一个平台类型 String 参数（Kotlin 报
            // "inferred type is 'Nothing?', but 'String' was expected"）。缺字段本来就表示"没有 mid"，
            // 所以显式判空，而不是把 null 塞进 String 位置。
            val sdpMid = if (candidate.has("sdpMid") && !candidate.isNull("sdpMid")) candidate.optString("sdpMid") else null
            val sdp = candidate.optString("candidate")
            if (sdp.isNotEmpty()) {
                session.onRemoteCandidate(sdpMid, candidate.optInt("sdpMLineIndex", 0), sdp)
            } else {
                // 空候选不往 WebRTC 里塞（否则要么抛异常要么静默丢弃）：如实记一条，不假装收到。
                diagnostics.emit("signal.candidate", JSONObject().put("candidateType", "unknown")
                    .put("reason", "SCHEMA_INVALID").put("profile", "ice-dual"))
            }
        }
    }

    override fun onServerError(code: String, detail: String?) {
        diagnostics.emit("server.error", JSONObject().put("code", code).put("detail", detail ?: ""))
        statusText.text = "服务器拒绝：$code ${detail ?: ""}"
        if (code == "AUTH_FAILED" || code == "UNSUPPORTED_VERSION") toast("加入失败：$code")
    }

    override fun onSocketClosed(reason: String) {
        statusText.text = "信令离线（$reason）· 已有直连仍可用 · 日志保留待补传"
    }

    override fun onTelemetryAck(ids: List<String>) {
        uploadDelayMs = 1000L
    }

    private fun connectAttempt(peerId: String) {
        remotePeerId = peerId
        runner.begin(localPeerId, peerId, stunUrls) { profile -> createSession(profile, peerId) }
        renderPaths()
    }

    private fun createSession(profile: String, peerId: String): RtcSession {
        val created = RtcSession(peerFactory, profile, room, secret, localPeerId, peerId, connectionId, attemptId,
            stunUrls, diagnostics, this)
        created.onLocalDescription = { type, sdp ->
            signaling?.signal(peerId, connectionId, attemptId, "webrtc", profile,
                JSONObject().put("description", JSONObject().put("type", type).put("sdp", sdp)))
        }
        created.onLocalCandidate = { candidate ->
            signaling?.signal(peerId, connectionId, attemptId, "webrtc", profile,
                JSONObject().put("candidate", JSONObject().put("sdpMid", candidate.sdpMid)
                    .put("sdpMLineIndex", candidate.sdpMLineIndex).put("candidate", candidate.sdp)))
        }
        session = created
        created.start()
        return created
    }

    private fun startUploadLoop() {
        handler.postDelayed(object : Runnable {
            override fun run() {
                val client = signaling
                if (client != null && client.isJoined()) {
                    val events = diagnostics.batch(50)
                    if (events.isNotEmpty() && !client.uploadTelemetry(events)) {
                        diagnostics.requeue(events)
                        uploadDelayMs = minOf(30_000L, uploadDelayMs * 2)
                    } else if (events.isNotEmpty()) {
                        uploadDelayMs = 1000L
                    }
                }
                handler.postDelayed(this, uploadDelayMs)
            }
        }, 1000L)
    }

    // ---------------- 路径 / 会话回调 ----------------

    override fun onPathChanged(state: PathRunner.PathState) {
        renderPaths()
    }

    override fun onChatReady(state: PathRunner.PathState) {
        chatButton.isEnabled = true
        chatButton.text = "进入聊天（已打通：" + state.method.title + "）"
        statusText.text = "已打通：" + state.method.title + "　延迟：" + MethodCatalog.formatLatency(state.chatRttMs)
    }

    override fun onState(state: String, detail: String?) {
        if (state == "connected") runner.markConnected(profileOfSession(), session?.isAuthenticated == true)
        if (state == "failed") runner.markFailed(profileOfSession(), detail ?: "ICE_FAILED")
    }

    private fun profileOfSession(): String = session?.let { "ice-dual" } ?: "ice-dual"

    override fun onAuthenticated() {
        runner.markConnected(profileOfSession(), true)
        appendLog("路径已互相验证（数据通道握手通过）")
    }

    override fun onChatMessage(text: String, id: String) {
        appendLog("对方：" + text)
    }

    override fun onFileReceived(id: String, name: String, mime: String, bytes: ByteArray) {
        val dir = File(filesDir, "incoming").apply { mkdirs() }
        val file = File(dir, name.ifEmpty { id })
        file.writeBytes(bytes)
        appendLog("收到" + (if (mime.startsWith("audio")) "语音" else if (mime.startsWith("image")) "图片" else "文件") +
            "：" + file.name + "（" + bytes.size + " 字节）已存到应用私有目录")
    }

    override fun onTextDelivered(id: String) = Unit

    override fun onLatency(kind: String, rttMs: Double) {
        runner.noteChatLatency(rttMs)
    }

    override fun onBenchmark(goodputBytesPerSecond: Double, bytes: Long, elapsedMs: Double) {
        toast(String.format("应用层速度：%.1f KB/s（%d 字节 / %.0f ms，不是线路带宽）",
            goodputBytesPerSecond / 1024.0, bytes, elapsedMs))
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { signaling?.close() }
        runCatching { session?.close() }
        runCatching { discovery.stop() }
        KeepAliveService.stop(this)
    }
}
