package dev.p2pobservatory.nativeprobe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.NetworkInterface

/**
 * 前台服务 + 通知：把连接真正保活需要用户看得见的前台服务，**不做保活欺骗、不要无关权限**。
 */
class KeepAliveService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "P2P 连接", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "保持直连与信令连接（锁屏/后台）" })
        }
        val notification: Notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
            .setContentTitle("P2P 直连进行中")
            .setContentText("保持与前台的直连通道；没有中继，不经过服务器转发聊天")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
        return START_STICKY
    }

    companion object {
        const val CHANNEL_ID = "p2p-keepalive"
        const val NOTIFICATION_ID = 8317

        fun start(context: Context) {
            val intent = Intent(context, KeepAliveService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
            else context.startService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, KeepAliveService::class.java))
        }
    }
}

/**
 * 局域网发现：组播 + 多播锁。参数与 `p2pchat/native/lan_discovery.py` 对齐：
 *   组 239.255.42.99（管理域，绝不跨链路路由）、端口 41420、
 *   lan_key = HMAC-SHA256(joinKey, "p2pobs-lan-key-v1")、
 *   scope   = HMAC-SHA256(lan_key, "p2pobs-lan-scope-v1:" + room).hex[:32]、
 *   mac     = HMAC-SHA256(lan_key, JSON([PROTOCOL, scope, nonce, ts, port, identity]))，
 *   frame   = {"v":1,"scope","nonce","ts","port","identity","mac"}（JSON、无空格、非 ASCII 不转义）。
 *
 * 诚实标注：本阶段**没有与桌面端做过字节级互通实测**（真机 + 桌面同网段才能确认），
 * 所以界面不会声称「局域网发现已工作」；这里只保证参数与算法域分隔一致，方便真机复核。
 */
class LanDiscovery(private val context: Context) {
    private var lock: WifiManager.MulticastLock? = null
    private var socket: MulticastSocket? = null
    private var thread: Thread? = null

    @Volatile private var running = false

    fun start(room: String, secret: String) {
        if (running) return
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        lock = wifi?.createMulticastLock("p2p-lan-discovery")?.apply { setReferenceCounted(false); acquire() }
        running = true
        thread = Thread {
            try {
                val group = InetAddress.getByName(GROUP4)
                val sock = MulticastSocket(DEFAULT_PORT)
                sock.timeToLive = 1
                sock.networkInterface = NetworkInterface.getByInetAddress(InetAddress.getByName("127.0.0.1"))
                    ?: NetworkInterface.getNetworkInterfaces().toList().firstOrNull()
                sock.joinGroup(group)
                socket = sock
                val lanKey = JoinProof.hmacSha256(JoinProof.joinKeyBytes(secret, room), LAN_KEY_LABEL)
                val scope = scope(room, lanKey)
                var sequence = 0L
                while (running) {
                    val nonce = Protocol.hex(ByteArray(8).also { java.security.SecureRandom().nextBytes(it) })
                    val frame = JSONObject()
                        .put("v", 1).put("scope", scope).put("nonce", nonce)
                        .put("ts", System.currentTimeMillis() / 1000)
                        .put("port", DEFAULT_PORT)
                        .put("identity", "android-" + (Build.MODEL ?: "device") + "-" + sequence)
                    val body = Protocol.jsonFields(
                        listOf(PROTOCOL_ID, scope, nonce, frame.get("ts").toString(),
                            DEFAULT_PORT.toString(), frame.getString("identity")))
                    frame.put("mac", Protocol.hex(JoinProof.hmacSha256(lanKey, body.toByteArray(Charsets.UTF_8))))
                    val payload = frame.toString().toByteArray(Charsets.UTF_8)
                    val packet = DatagramPacket(payload, payload.size, group, DEFAULT_PORT)
                    // 频率上限：每秒最多 4 个宣告（与 Python 端一致），不做泛洪。
                    repeat(4) {
                        if (!running) return@repeat
                        sock.send(packet)
                        Thread.sleep(250)
                    }
                    sequence += 1
                }
            } catch (error: Exception) {
                Log.w(TAG, "lan discovery stopped: ${error.message}")
            }
        }.apply { isDaemon = true; name = "p2p-lan-discovery" }
        thread?.start()
    }

    private fun scope(room: String, lanKey: ByteArray): String =
        Protocol.hex(JoinProof.hmacSha256(lanKey, (SCOPE_LABEL + ":" + room).toByteArray(Charsets.UTF_8))).take(32)

    fun stop() {
        running = false
        runCatching { socket?.close() }
        socket = null
        runCatching { lock?.release() }
        lock = null
        thread = null
    }

    companion object {
        private const val TAG = "P2PLanDiscovery"
        const val PROTOCOL_ID = "p2pobs-lan-announce-v1"
        const val SCOPE_LABEL = "p2pobs-lan-scope-v1"
        const val GROUP4 = "239.255.42.99"
        const val DEFAULT_PORT = 41420
        val LAN_KEY_LABEL = "p2pobs-lan-key-v1".toByteArray(Charsets.UTF_8)
    }
}
