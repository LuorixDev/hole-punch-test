plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "dev.p2pobservatory.nativeprobe"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "dev.p2pobservatory.nativeprobe"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1-spike"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    flavorDimensions += "engine"
    productFlavors {
        create("baseline") { dimension = "engine"; applicationIdSuffix = ".baseline" }
        create("rtc") { dimension = "engine" }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = false } }
}
dependencies {
    "rtcImplementation"("io.github.webrtc-sdk:android:150.7871.01")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
