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
        versionName = "0.2-native-phase1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // 16 KB 页合规：只保留这两条 ABI（armeabi-v7a / x86 的 PT_LOAD 对齐不达标，见 FEASIBILITY.md）。
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    flavorDimensions += "engine"
    productFlavors {
        create("baseline") { dimension = "engine"; applicationIdSuffix = ".baseline" }
        create("rtc") { dimension = "engine" }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug { isMinifyEnabled = false }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = false } }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    // WebRTC：社区镜像坐标（官方 org.webrtc:google-webrtc 已 404，见 FEASIBILITY.md）
    "rtcImplementation"(libs.webrtc.android)
    implementation(libs.okhttp)
    // 纯算法单元测试（JVM 上跑，不需要设备）：加入证明向量、帧编解码、地址族过滤
    testImplementation(libs.junit)
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
