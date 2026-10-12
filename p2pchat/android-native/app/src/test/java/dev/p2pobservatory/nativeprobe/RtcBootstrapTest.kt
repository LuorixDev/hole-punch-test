package dev.p2pobservatory.nativeprobe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 静态护栏：WebRTC 原生库必须在建工厂之前初始化，而且工厂只能有一个创建入口。
 *
 * 为什么这条要用「扫源码」而不是跑代码：JVM 单测不需要设备，也就不会初始化原生库，
 * 所以真机那条闪退路径**跑不到**。实测证据（模拟器 API 37 上安装 CI 产出的 APK，
 * 一点开就闪退）：
 * ```
 * java.lang.IllegalStateException: PeerConnectionFactory.initialize was not called
 *   before creating a PeerConnectionFactory.
 *   at dev.p2pobservatory.nativeprobe.MainActivity.onCreate(MainActivity.kt:70)
 * ```
 * 这条用例就是把当时的写法钉死：谁再绕过 [RtcBootstrap] 直接 `builder()`，CI 立刻红。
 */
class RtcBootstrapTest {

    private val appDir: File = generateSequence(File(".").absoluteFile) { it.parentFile }
        .firstOrNull { File(it, "src/main/AndroidManifest.xml").isFile }
        ?: error("找不到 app 模块目录（请在 android-native/app 下运行单测）")

    private fun sources(): List<File> =
        File(appDir, "src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    @Test
    fun manifestDeclaresAnApplicationThatInitializesTheNativeLibrary() {
        val manifest = File(appDir, "src/main/AndroidManifest.xml").readText()
        assertTrue(
            "Manifest 必须声明 Application 子类（否则进程重建时初始化不会发生）：\n$manifest",
            manifest.contains("android:name=\".ProbeApplication\"")
        )
        val application = File(appDir, "src/main/java/dev/p2pobservatory/nativeprobe/ProbeApplication.kt")
        assertTrue("ProbeApplication.kt 必须存在", application.isFile)
        assertTrue(
            "ProbeApplication.onCreate 必须调用 RtcBootstrap.ensureInitialized",
            application.readText().contains("RtcBootstrap.ensureInitialized(")
        )
    }

    @Test
    fun theBootstrapActuallyCallsWebRtcInitialize() {
        val bootstrap = File(appDir, "src/main/java/dev/p2pobservatory/nativeprobe/RtcBootstrap.kt")
        assertTrue("RtcBootstrap.kt 必须存在", bootstrap.isFile)
        val text = bootstrap.readText()
        assertTrue(
            "RtcBootstrap 必须调用 PeerConnectionFactory.initialize(...)",
            text.contains("PeerConnectionFactory.initialize(")
        )
        assertTrue("初始化应当是幂等的（先看标志再进同步块）", text.contains("@Volatile") && text.contains("synchronized"))
    }

    @Test
    fun factoriesAreOnlyCreatedThroughTheBootstrap() {
        val callers = sources().filter { it.readText().contains("PeerConnectionFactory.builder()") }
        assertEquals(
            "PeerConnectionFactory.builder() 只允许出现在 RtcBootstrap.kt 里；" +
                "别的文件要工厂就调 RtcBootstrap.newFactory(context)，否则真机启动即闪退",
            listOf("RtcBootstrap.kt"),
            callers.map { it.name }.sorted()
        )
    }

    @Test
    fun everyFileThatBuildsAFactoryAlsoEnsuresInitialization() {
        val mainActivity = File(appDir, "src/main/java/dev/p2pobservatory/nativeprobe/MainActivity.kt").readText()
        assertTrue(
            "MainActivity 建工厂前必须经过 RtcBootstrap",
            mainActivity.contains("RtcBootstrap.newFactory(")
        )
    }
}
