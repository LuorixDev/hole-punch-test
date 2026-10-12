package dev.p2pobservatory.nativeprobe

import android.content.Context
import org.webrtc.PeerConnectionFactory

/**
 * WebRTC 原生库在任何 `PeerConnectionFactory` 被创建之前必须初始化一次。
 *
 * 真机证据（模拟器 API 37 上安装 CI 构建的 APK，launch 即闪退）：
 * ```
 * java.lang.IllegalStateException: PeerConnectionFactory.initialize was not called
 *   before creating a PeerConnectionFactory.
 *   at dev.p2pobservatory.nativeprobe.MainActivity.onCreate(MainActivity.kt:70)
 * ```
 * JVM 单测碰不到这条路径（不需要设备，也就不会初始化原生库），而 CI 此前只跑单测，
 * 所以这个缺陷一直没暴露。现在初始化只在这里发生一次，工厂也只能从这里拿
 * （[newFactory]），并由单测里的静态护栏钉住「别的文件不许自己调 builder()」。
 */
object RtcBootstrap {

    @Volatile
    private var initialized = false

    /** 幂等：`Application.onCreate` 与任何使用者都可以放心调用。 */
    fun ensureInitialized(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context.applicationContext)
                    .setEnableInternalTracer(false)
                    .createInitializationOptions()
            )
            initialized = true
        }
    }

    /** 唯一的工厂创建入口：先保证初始化，再建工厂。 */
    fun newFactory(context: Context): PeerConnectionFactory {
        ensureInitialized(context)
        return PeerConnectionFactory.builder().createPeerConnectionFactory()
    }
}
