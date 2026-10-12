package dev.p2pobservatory.nativeprobe

import android.content.Context
import android.media.MediaRecorder
import android.os.Build
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 录音语音消息：录完就是一个音频文件，走**文件传输**（不是实时通话、不做语音识别）。
 * 上限：60 秒 / 4 MiB，超了直接失败而不是偷偷截断。
 */
class VoiceRecorder(private val context: Context) {
    private var recorder: MediaRecorder? = null
    private var target: File? = null
    private var startedAt = 0L

    val maxDurationMs = 60_000L
    val maxBytes = 4L * 1024 * 1024

    fun isRecording(): Boolean = recorder != null

    fun start(): File {
        check(recorder == null) { "ALREADY_RECORDING" }
        val dir = File(context.filesDir, "outgoing")
        if (!dir.exists()) dir.mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(dir, "voice-$stamp.m4a")
        val media = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) MediaRecorder(context) else MediaRecorder()
        media.setAudioSource(MediaRecorder.AudioSource.MIC)
        media.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        media.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        media.setAudioEncodingBitRate(96_000)
        media.setAudioSamplingRate(44_100)
        media.setMaxDuration(maxDurationMs.toInt())
        media.setOutputFile(file.absolutePath)
        media.prepare()
        media.start()
        recorder = media
        target = file
        startedAt = System.currentTimeMillis()
        return file
    }

    /** 停止并返回文件；超过大小上限则返回 null（调用方要如实报失败）。 */
    fun stop(): File? {
        val media = recorder ?: return null
        val file = target
        recorder = null
        target = null
        runCatching { media.stop() }.onFailure { runCatching { media.reset() } }
        runCatching { media.release() }
        if (file == null || !file.exists()) return null
        if (file.length() > maxBytes || System.currentTimeMillis() - startedAt > maxDurationMs + 1000) {
            file.delete()
            return null
        }
        return file
    }

    fun cancel() {
        val media = recorder ?: return
        recorder = null
        runCatching { media.stop() }
        runCatching { media.release() }
        target?.delete()
        target = null
    }

    fun elapsedMs(): Long = if (recorder == null) 0L else System.currentTimeMillis() - startedAt
}
