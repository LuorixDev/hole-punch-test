# 无中继与反射：WebRTC / OkHttp 都要保留必要的类名，R8 才能正确反射构造它们。
-keep class org.webrtc.** { *; }
-keep class okhttp3.** { *; }
-keep class okio.** { *; }
-dontwarn org.webrtc.**
-dontwarn okhttp3.**
-dontwarn okio.**
# 应用自身的协议常量/数据结构在 R8 下保持可反射（JSON 字段名与事件结构要稳定）。
-keep class dev.p2pobservatory.nativeprobe.Protocol { *; }
-keep class dev.p2pobservatory.nativeprobe.MethodCatalog { *; }
-keep class dev.p2pobservatory.nativeprobe.JoinProof { *; }
# 不要为了体积把 DNS/TLS 支持表删掉（wss 需要）。
-keep class org.conscrypt.** { *; }
-keep class org.bouncycastle.** { *; }
