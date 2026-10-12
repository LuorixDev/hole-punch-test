plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
// Resolves actual artifacts, not only lenient dependency-tree reporting.
val officialWebRtc by configurations.creating
val alternativeWebRtc by configurations.creating
dependencies {
    officialWebRtc("org.webrtc:google-webrtc:1.0.32006")
    alternativeWebRtc(libs.webrtc.android)
}
tasks.register("probeWebRtcCoordinates") {
    doLast {
        listOf("official" to officialWebRtc, "alternative" to alternativeWebRtc).forEach { (label, config) ->
            try {
                val files = config.resolve()
                check(files.isNotEmpty())
                files.forEach { println("WEBRTC_RESOLVED $label ${it.name} bytes=${it.length()}") }
            } catch (error: Exception) {
                println("WEBRTC_UNRESOLVED $label ${error.message}")
                if (label == "alternative") throw error
                // Expected negative probe, not bypassing app compilation gate.
            }
        }
    }
}
