# 安卓 APK 的明文信令（为什么要改、改了什么、边界在哪）

面向对象：装 APK 的手机用户 + 自己部署信令服务器的操作者。
结论先说：**APK 现在具备连明文 `ws://` 的能力**，页面仍在安全上下文里（录音不受影响）；
**但网页客户端目前仍拒绝连非 loopback 的 `ws://`**（见第 8 节），所以端到端能不能用明文，
取决于那个策略是否放宽。

---

## 1. 以前为什么连不上明文信令

两层拦截，缺一不可：

1. **混合内容（mixed content）**：Capacitor 页面原来跑在 `https://localhost`（安全上下文），
   从安全页面连 `ws://…` 属于混合内容，WebView 直接拦掉。真正的问题在这一层，
   而不是"页面必须 https"。
2. **Android 明文策略（cleartext）**：从 API 28 起，明文 HTTP/WS 默认被禁止，由
   Network Security Config（NSC）或 `android:usesCleartextTraffic` 决定。WebView 的网络栈同样受它约束。

所以"服务端加 SSE/同源代理"只是在绕第 1 层，本任务改的是这两层的配置。

## 2. 本次改动

| 文件 | 改动 | 作用 |
| --- | --- | --- |
| `p2pchat/capacitor.config.json` | `server.androidScheme`: `https` → `http` | 页面来源变成 `http://localhost`，从"安全页连明文"变成"本地页连明文"，不再触发混合内容拦截 |
| `p2pchat/android/app/src/main/AndroidManifest.xml` | 新增 `android:networkSecurityConfig="@xml/network_security_config"` | 明文策略改由 NSC 定义（保留 `usesCleartextTraffic="false"` 作为声明） |
| `p2pchat/android/app/src/main/res/xml/network_security_config.xml` | 新增 | 明文放行的唯一定义处，含理由与"只走 WSS"的一键收紧写法 |
| `MainActivity.java` / `SaveFilePlugin.java` / 新增 `LocalOrigin.java` | 页面来源判定从写死 `https://localhost` 改为接受 `http://localhost` 与 `https://localhost` | 录音权限与"保存文件"在两种 scheme 下都正常，且仍然只认这两个 loopback 来源 |

`android.allowMixedContent` **保持 `false`**：我们不是靠"允许混合内容"解决问题的，
没有放宽 WebView 的安全策略。

## 3. 录音为什么不受影响（重点）

- "安全上下文"不等于"必须 https"。按规范，主机为 `localhost`、`127.0.0.0/8`、`::1` 的来源
  本身就是 potentially trustworthy origin，因此 `http://localhost` **是**安全上下文，
  `getUserMedia` / `MediaRecorder` 照常可用（MDN：Secure contexts 一节的表格里
  `http://localhost` 标注为 ✅ Secure）。
- 录音链路其余部分全部保留：`RECORD_AUDIO` 权限、`onPermissionRequest` 仍然**只**对本地页面、
  **只**对 `RESOURCE_AUDIO_CAPTURE` 放行（不会顺带放开摄像头等其它资源）。
- **未实测**：本机没有安卓设备和已授权 SDK，真机录音、暂停/恢复、锁屏行为一律
  **NOT_RUN**，必须由用户实机验证。本文只陈述配置与规范层面的事实。
- 一个反面做法被明确拒绝：把页面留在 `https://localhost` 并打开 `allowMixedContent`，
  那是真的放宽 WebView 安全策略（任意 https 页面都能加载 http 内容）；本方案换的是
  "一个仍然是安全上下文的本地来源"，代价小得多。

## 4. 明文范围：为什么是 NSC，以及为什么不能再窄

**为什么用 NSC 而不是 `android:usesCleartextTraffic="true"`：**

1. manifest 属性是"一个开关管所有目标"，无法表达任何范围；NSC 是独立、可审计的文件，
   将来要给某些域名单独收紧，直接加 `<domain-config>` 即可。
2. Android 已宣布**将来废弃** `usesCleartextTraffic`，明确建议需要明文的 App 迁移到
   network security config（Android 17 behavior changes: usesCleartextTraffic deprecation plan）。
3. API 24+ 只要存在 NSC，平台就以 NSC 为准（AOSP 在 N 起记录了"使用 NSC 时该 manifest 属性被忽略"）。
   也就是说：**真正生效的策略就在 `network_security_config.xml` 这一个文件里**。

**为什么默认是 `base-config cleartextTrafficPermitted="true"`：**

信令服务器地址是用户在运行时自己输入的（家里服务器的裸 IPv4/IPv6 地址，或 DDNS 名）。
NSC 的 `<domain>` 只能写精确主机名或后缀，**不支持网段/CIDR**，无法枚举"我的服务器"。
只放 `localhost`/`127.0.0.1` 等于"只能连手机自己"，对用户没有意义。
因此这里统一放行明文，把严格性放在其它维度上：

- 只信任**系统 CA**（没有 `<certificates src="user">`，没有 `<debug-overrides>`，不可被中间人 CA 顶替）；
- 没有开 `allowMixedContent`、没有开 WebView 的 file 访问、没有新增 JS 桥、没有开调试开关；
- 页面不能导航离开（`shouldOverrideUrlLoading` 返回 `true`）；
- 明文只影响**信令控制面**；聊天/图片/文件/录音始终走 WebRTC DataChannel 直连，不经服务器转发。

**只走 WSS 的部署可以一键收紧**（应用其余部分不受影响，TLS 与录音路径都不依赖明文）：

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system" /></trust-anchors>
</base-config>
```

## 5. Origin allowlist 必须同步

WebView 的页面来源变了，服务端 `--origin` 就要跟着变（精确匹配，不带结尾斜杠）：

| 构建方式 | WebView 页面来源 | 服务端参数 |
| --- | --- | --- |
| 默认（本次改动，`androidScheme: http`） | `http://localhost` | `--origin http://localhost` |
| 若改回 TLS（`androidScheme: https`） | `https://localhost` | `--origin https://localhost` |

- 浏览器网页版仍是"你地址栏的来源"，两者同时使用时 `--origin` 可重复写多条。
- Origin 不是身份认证；房间密钥与数据面 HMAC 仍然独立生效，不要用通配 `*`。

## 6. 明文的风险（必须知道）

`ws://` 信令在同一条路径上可被**读取和篡改**：房间名、房间密钥、昵称、SDP/ICE 候选、
控制消息都在里面。数据面虽是 DTLS 加密的 DataChannel，但"能否直连、连到谁"是控制面决定的——
中间人可以打乱打洞过程、伪造候选、把连接引到错误的位置。
治本方案是给服务器配一张受信任证书并用 `wss://`（服务端对公网绑定强制 TLS + origin，路径一直保留）。

## 7. 构建与证据

```bash
cd p2pchat
node tools/sync-web.cjs                 # 同步 web → dist-web
./node_modules/.bin/cap sync android    # 生成 assets/capacitor.config.json + 拷贝 dist-web 到 assets/public
# APK 到 CI 上构建（本机无 Android SDK），产物记 sha256
```

- 本仓库 Linux 开发机上 **没有** Android SDK / 模拟器 / 系统镜像，也没有真机：
  `assembleDebug` 与任何"APK 能连上"的运行结论一律 **NOT_RUN**。
- 已在仓库内验证的只是：配置文件、Manifest/NSC、Java 来源判定、`cap sync` 的产物一致性
  （`android/app/src/main/assets/capacitor.config.json` 的 `androidScheme` 与根配置一致）。
- 真机安装、录音、锁屏/后台行为：**NOT_RUN（需用户实机）**。不得用模拟器或同机结果冒充。

## 8. 已知阻断：网页客户端仍只允许 loopback 的 `ws://`

`p2pchat/web/app.js:62` 有一条前端策略：

```js
if(!['ws:','wss:'].includes(url.protocol) || url.protocol==='ws:' && !['localhost','127.0.0.1','[::1]'].includes(url.hostname))
  throw Error('公网信令必须 WSS；WS 只允许 loopback');
```

`p2pchat/web/index.html:12` 也有同样的说明文字。该文件不在本任务范围内（本次只动
Capacitor/Android 配置与文档），所以：

- **好消息**：混合内容与 Android 明文策略这两层已经不再是障碍；
- **坏消息**：用户把家里的服务器地址写成 `ws://192.168.x.x:8088/ws` 或 `ws://公网IP:8088/ws`
  时，仍会被这条前端策略拦下（报"公网信令必须 WSS；WS 只允许 loopback"）。

要让明文真正端到端可用，需要 web 客户端负责人决定：要么在**用户显式确认服务器**的前提下
允许 `ws://`（并在界面上直接写明明文可被窃听/篡改），要么保留该策略（那么本任务只解决了
传输层的拦截，Android 上仍只能连 loopback 明文）。这个决定不在本任务权限内。
