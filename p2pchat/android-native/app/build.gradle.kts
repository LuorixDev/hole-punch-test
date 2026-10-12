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
    // 故意**不设** `unitTests.isReturnDefaultValues = true`：那个开关会让没被 mock 的
    // android.* / org.json 桩方法静默返回 null/0/false，于是"解析拿到 null"会变成"断言悄悄通过"
    // —— 这正是 t56 里 CI 首次真跑单测两连败的根因。现在任何意外的桩调用都会抛 "not mocked"。
    testOptions { unitTests.isIncludeAndroidResources = false }
}

dependencies {
    // WebRTC：社区镜像坐标（官方 org.webrtc:google-webrtc 已 404，见 FEASIBILITY.md）
    "rtcImplementation"(libs.webrtc.android)
    implementation(libs.okhttp)
    // 纯算法单元测试（JVM 上跑，不需要设备）：加入证明向量、帧编解码、地址族过滤
    testImplementation(libs.junit)
    // Android 本地单测里 `org.json` 是 android.jar 的 **stub**（方法体 no-op/返回默认值）：
    // JSONObject().put(...) 返回 null → 链式调用 NPE；JSONArray().length() 返回 0 → 断言失真。
    // 这里用参考实现覆盖测试类路径，让 JSON 相关断言在 JVM 上真的被执行。
    // 与 Android 端实现的差异：Android 用的是 AOSP 的 org.json fork（同源、API 一致），
    // 边角差异集中在数字/布尔强制转换与 JSONObject.NULL；
    // 本项目的关键安全判定（STUN/TURN 白名单、加入证明、密钥是否上链路、帧编解码）已经做成
    // **纯 Kotlin、完全不碰 JSON**（`Protocol.stunUrlsFrom` / `JoinProof.joinFields`），
    // 所以两种实现的差异不可能让关键断言假通过。
    testImplementation(libs.json)
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
