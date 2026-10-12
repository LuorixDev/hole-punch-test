package dev.p2pobservatory.nativeprobe

import android.app.Application

/**
 * 在任何 Activity 之前完成 WebRTC 原生库初始化（原因见 [RtcBootstrap]）。
 *
 * 放在 Application 而不是 Activity：进程被系统重建、或从通知/前台服务回来时，
 * 初始化同样必须已经完成，不能依赖某个 Activity 的生命周期。
 */
class ProbeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        RtcBootstrap.ensureInitialized(this)
    }
}
