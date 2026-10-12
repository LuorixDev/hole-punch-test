# P2P Observatory：严格无中继聊天与测速实验台

**当前交付：Linux 本机已实测的源码与本地构建；不是全平台/任意网络可用产品。** 小房间最多12人、逐对端mesh，支持文本、图片、文件和录制完成后的语音文件；不做实时通话或语音识别。TURN永久禁用，信令/日志不代转聊天；无可用直连就明确失败。

**本轮状态（p2p-delivery-v2）：桌面端已改为纯 Python + Qt(PySide6) + PyInstaller，Electron 桌面壳已删除。** 新增并接入：NAT 行为分类（多 STUN 观测）、局域网直连发现（同网段不用打洞）、对称 NAT 端口预测、以及「路由器放行」的真实接线——后三者**默认关闭、必须显式同意**。**每条打洞方式到底实现了什么、能传消息还是只能探测、证据到哪一级（L0–L4）与还剩哪些缺口，以 [打洞方式全量对照矩阵](docs/PUNCHING-MATRIX.md) 为准**；不要再凭印象判断「集成了没有」。

- **仍待确认（PENDING）**：新版 Python/Qt 桌面的 Windows CI 结果，以及最终冻结清单。`docs/SOURCE-MANIFEST.json` / `docs/FREEZE.json` 在 Qt 迁移落地、整套回归恢复全绿之后重新生成，**在那之前它们仍是上一轮的快照**。
- **真实家宽 / 双 NAT / CGNAT、真实路由器放行、Windows/macOS 与安卓实机、真实麦克风录音全部 NOT_RUN**，详见矩阵第 6 节与 [脱敏证据索引](docs/EVIDENCE-INDEX.md)。

**历史（不要当作当前状态）**：旧 Electron 桌面版与更早跨平台轮次的 CI 记录（`78a2050` 全套 70 passed/6 failed/1 skipped、`61b400e` 计时断言失败但关闭正常、`a1c6e7e` 诊断 90 秒 exit124、`855c19c` watchdog 600 秒 exit124 等）只属于**已删除的桌面壳与旧树**，不能继承到本轮 Python/Qt 桌面。历史版本表、失败留痕与上传边界见 [交付清单](docs/DELIVERY.md)。

历史基线`8687adf15b114380747308b43d78df29dd0634bc006a3e4d16215abeb4062388`（129文件）的 VERIFICATION-R2（本地私有证据，不随GitHub交付）（t15）/ROUND3（本地私有证据，不随GitHub交付）（t19）仅对应旧版；[旧a1c6e7e run38124339483](https://github.com/LuorixDev/hole-punch-test/actions/runs/38124339483)已终态：Linux/Android成功，Windows90秒诊断exit124未打包。挂起链已定位至Peer.close→RTCPeerConnection.close→ICE.stop→aioice StunProtocol.close；新版本必须重跑原双echo诊断、完整测试与打包门，不能继承旧成功包。差异与边界见 [Windows修复集成](docs/WINDOWS-INTEGRATION.md)。

快速导航：[打洞方式全量对照矩阵](docs/PUNCHING-MATRIX.md) · [平台/机制矩阵](docs/CAPABILITIES.md) · [交付状态与产物哈希](docs/DELIVERY.md) · [协议](docs/PROTOCOL.md) · [验收定义](docs/ACCEPTANCE.md) · [家宽服务器部署手册](docs/DEPLOY-HOME-SERVER.md) · [桌面端](docs/DESKTOP-PYTHON.md)。

## 1. 安装依赖（仓库根目录）

Linux优先路径，需要Python3.12及支持WebRTC的现代Chromium：

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r p2pchat/requirements-lock.txt
```

[精确依赖记录](requirements-lock.txt)对应已测Linux环境；跨平台wheel可用性不保证。桌面端另需 PyInstaller 6.20.0 与 PySide6（见 [platform/build-requirements.txt](platform/build-requirements.txt)）；网页版与安卓工程另需Node24与 [npm锁文件](package-lock.json)，不要盲目`audit fix --force`：

```sh
npm --prefix p2pchat ci --ignore-scripts
.venv/bin/python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec   # 桌面打包
```

**Electron 与 electron-builder 已从依赖中移除，不再有 `node node_modules/electron/install.js` 这一步**；`tools/build-native.cjs` 已标注废弃（只保留「单独构建原生 CLI」的用途，不接回桌面）。历史上那条「8 moderate、单一 sprintf-js 链」来自已删除的 Electron 构建工具链，**不能当作当前依赖审计结论**：仓库里 `platform/npm-audit.json` 是移除前的快照，需由 owner 重新生成或退役；每次 CI 会在私有产物里重跑两级 `npm audit`。依赖/构建细节见 [PLATFORMS](PLATFORMS.md)。

## 2. 启动IPv4信令、双栈STUN与日志中心

默认只监听loopback；以下命令只用于本机，不改路由器、不开放公网：

```sh
.venv/bin/python -m p2pchat.server \
  --host 127.0.0.1 --port 8088 \
  --stun-host 127.0.0.1 --stun-host ::1 --stun-port 3478 \
  --origin http://127.0.0.1:8088 \
  --data p2pchat/data/central
```

浏览器打开 `http://127.0.0.1:8088/`。控制面是TCP HTTP/WS；STUN是UDP3478，只观察映射地址，不分配relay。只需IPv4时省略第二个`--stun-host ::1`。默认不广告远程STUN，loopback/STUN测试不代表家宽NAT成功。

### 可选公网部署：操作者另行确认与配置

本交付**未实际部署公网**。确认授权后，自备域名、有效TLS证书/私钥、持久数据目录和防火墙策略；密钥不要进仓库。参考参数（示例域名/路径需替换）：

```sh
.venv/bin/python -m p2pchat.server \
  --host 0.0.0.0 --host :: --port 8443 \
  --cert /secure/server-fullchain.pem --key /secure/server-key.pem \
  --origin https://signal.example.test:8443 \
  --stun-host 0.0.0.0 --stun-host :: --stun-port 3478 \
  --stun-url stun:signal.example.test:3478 \
  --data /private/p2p-central
```

- `--host`与`--stun-host`一样可重复：每个值一个独立监听站点（各自`V6ONLY`），所以`--host 0.0.0.0 --host ::`是**单进程真双栈**、同端口、共享同一Store/数据目录（无跨进程SQLite写锁）。只写一个`--host`时另一族会被拒绝（不做隐式双栈）。默认仍是`127.0.0.1`。双栈行为目前**只在Linux实测**，Windows/macOS未实测。
- 远程使用 `wss://signal.example.test:8443/ws`，证书必须受信任，不跳过验证；端口443代理亦仅控制面，绝不是数据回退路径。
- Origin必须精确allowlist。**桌面端是纯 Python 进程（不再有 Electron 页面），不会带浏览器那种 `null` Origin**：按实际客户端分别配——浏览器用它的页面来源；Android 的 WebView 页面来源是`http://localhost`（APK默认构建，`androidScheme: http`），因此加`--origin http://localhost`；若你把`androidScheme`改回`https`，则对应`--origin https://localhost`。Origin不是身份认证，仍需房间secret和数据面HMAC。
- 仅按需开放控制端口及UDP3478；P2P数据连接仍需端点网络允许。IPv6可路由地址不表示stateful firewall允许入站。STUN不能保证对称NAT/CGNAT/UDP阻断网络成功。
- 网关UPnP/PCP/NAT-PMP操作需要单独opt-in，不能因启动中心或导入STUN配置而默认开端口。

## 3. 启动独立Python Echo终端

Echo是房间成员，只沿来源的认证WebRTC通道回声，不替两个客户端转发；**当前不接受原生QUIC/TCP Echo**。在另一个进程或设备启动，使用同一房间与私下共享的随机密钥：

```sh
# 首次本地生成；已存在则拒绝覆盖。不要把生成内容提交或发到日志。
.venv/bin/python -c "from pathlib import Path; import secrets; p=Path('p2pchat/data/room.key'); p.parent.mkdir(parents=True,exist_ok=True); f=p.open('x'); f.write(secrets.token_hex(32)); f.close(); p.chmod(0o600)"
.venv/bin/python -m p2pchat.peer \
  --server ws://127.0.0.1:8088/ws --room lab \
  --secret-file p2pchat/data/room.key \
  --origin http://127.0.0.1:8088 --logs p2pchat/data/echo
```

把本地密钥文件的内容通过自己的安全方式填入客户端，不使用文档示例固定密码。远程echo改为有效WSS与中心允许的`--origin`。共享房间key不是独立公钥身份：无法防持有同一key的恶意成员冒充。

## 4. 三个平台入口与安装边界

| 平台 | 如何运行/构建 | 当前可信状态 |
|---|---|---|
| Linux浏览器 | 打开上述本地网页，或已授权部署的HTTPS页面 | 真实本机浏览器↔独立echo验证通过 |
| Linux桌面（Python + Qt/PySide6） | `.venv/bin/python -m p2pchat.python_desktop.app`；或 `npm --prefix p2pchat run desktop:linux` 后运行 `dist/p2p-desktop/p2p-desktop` | 本机自检真实握手通过、PyInstaller 产物可启动（L1/L3）；**Qt 迁移已完成并经独立复审 pass（t43 needs_revision → t44 修复+重建产物 → t45 pass，基准 HEAD `e60ba0d`）**。其后的提交（网络环境体检、可达性结论分发、Windows 控制台 UTF-8 等）**不在该次审查范围内**；最终冻结前以真实状态为准。本机glibc2.44构建不保证旧发行版 |
| Windows桌面（Python + Qt/PySide6） | 同一份源码与同一个 `tools/desktop.spec`，在 Windows 上用 `.venv\Scripts\python.exe -m PyInstaller` | **未验证**：Windows CI 结果待 captain 推送后确认；旧 Electron 版的成功记录不可继承 |
| macOS桌面 | 同一个 spec（未验证） | **NOT_RUN**：`.app` 布局、签名与公证均未做 |
| Android Capacitor | 自备已授权SDK36/build-tools36、JDK21；`npm --prefix p2pchat run android:sync`，再在`p2pchat/android`运行`./gradlew --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug` | 页面来源`http://localhost`（仍是安全上下文，录音可用）+ network security config 放行明文，详见`docs/ANDROID-CLEARTEXT.md`；本机无SDK，APK构建与实机一律NOT_RUN |

桌面端是**纯 Python 进程**，自己建套接字：非回环 `ws://` 默认拒绝，只有操作者显式确认本次会话才放行，并在会话期间持续提示未加密（没有 trust-all）。Android debug APK仅调试签名、不是正式发行签名；不上传任何签名私钥，不代用户接受SDK许可。Android的WebView页面来源是`http://localhost`（安全上下文，录音不受影响），配合`res/xml/network_security_config.xml`后APK**具备**连明文`ws://`信令的能力：明文会被同一路径上的人窃听和篡改（房间密钥、SDP/ICE候选都在里面），你的服务器有受信任证书时就用`wss://`，服务端TLS路径完整保留。另需注意：网页客户端目前仍只允许`ws://`的目标是loopback（`web/app.js`），所以拿手机连`ws://`到你自己的服务器地址会被前端拦下；细节与取舍见`docs/ANDROID-CLEARTEXT.md`。

## 5. 加入、消息、路径、测速

1. 输入信令地址、房间、昵称和共享密钥，点击**连接实验室**；此操作同时确认当前诊断中心，默认自动汇集白名单脱敏元数据。
2. 选择在线节点。三个ICE profile是同一WebRTC的IPv4/IPv6/双栈地址策略，不是三种算法；全部可用路径并行，首路成功不取消其余。
3. 等待**双端确认直连**。查看实际候选对/地址族/协议、RTT与失败原因；隐藏地址显示unknown。UDP probe仅探测，不可聊天。点击某条可用路径的**选择**切换后续发送，不把在途文件迁到新attempt。
4. 输入文本发送；文件/图片选择文件（≤32MiB），只有对端大小/SHA-256 ACK匹配才成功。接收总预算≤64MiB且含对象开销，因此两个整32MiB文件可能并发拒绝。收到附件用**保存**，不执行任意内容。
5. **录音**首次请求音频权限，再点**结束并发送录音**；最长60秒，停止track后作为文件发送。没有实时通话。Android暂停会停止录音并回收路径；后台/Doze/系统回收不保证送达，恢复/切网有界重建，过频需手动重连。
6. **测速5秒/32MiB**独立按钮；WebRTC独立DataChannel、QUIC独立stream，仍共享链路/拥塞，可能影响聊天。TCP无隔离lane禁测速。显示接收ACK应用goodput，不是线路带宽；停止测速不表示关闭聊天。
7. 小房间需要群发时勾选mesh，逐对端直发，不经中心广播正文。无直连的目标会明确失败。
8. **新attempt/ICE restart**有界重试；高ID端最多等待对端12秒，未响应给终态与指引。主动**断开**回收通道；临时控制面离线可保留旧认证数据路径，重新join后新身份重建。

### 桌面原生配置

桌面版**在同一个 Python 进程内**直接调用 `p2pchat/native/*`（没有 stdio 桥、没有 sidecar、没有菜单里的「原生网络绑定」）。原生套接字默认只绑 loopback，不做隐式网络切换；需要别的本机接口时用显式参数重启，不接受渲染层/远端传入的任意绑定地址。原生 STUN 观测点必须显式配置（会话级、默认关闭），核对实际端点后才使用，不接受 DNS/URL 或任意命令。

**三件「默认关闭、必须你单独同意」的事**（都在设置面板里，各自有人话解释）：路由器放行（申请一个端口映射）、同网段直连发现（组播，生产模式拒绝回环）、对称 NAT 端口预测。它们**都不是聊天路径**：路由器放行只开端口（`canMessage=false`），另外两项成功后也仍走既有认证通道。**真实路由器映射 = NOT_RUN**——本仓库从未改动宿主路由/防火墙，只在受控回环 mock 上测过协议。原生 QUIC/TCP 须配另一支持 native 的客户端，不能用 WebRTC-only 的 echo 判这些机制失败。

## 6. 诊断、隐私与排障

本地IndexedDB20MiB/7天、待传最多2000条；中心SQLite/轮转日志默认100MiB/7天。事件有session/connection/attempt ID；断线缓存并补传，持久ACK后移出待传。暂停自动汇集、队列淘汰或存储失败会提示**中心记录不完整**。中心不收正文、文件、原始IP、密钥、完整SDP；显示页面上的实际tuple不等于上传它。

点击**导出脱敏日志**只保存本地NDJSON，不自动上传到GitHub/第三方；分享前仍要复核。不要上传整个data目录、原媒体、截图中的密钥/私人地址或抓包。清站点数据/卸载会丢日志；磁盘满/断电/七天长跑尚未验证。

| 症状 | 检查/处理 |
|---|---|
| 403/无法加入 | 核对WSS证书、精确Origin、房间key；不要关TLS校验或使用通配Origin |
| ICE timeout/unknown | 查看真实候选和网络限制；IPv6/UDP被阻断可正常失败，绝无TURN回退 |
| NATIVE_BRIDGE_UNAVAILABLE / 原生「不支持」 | 浏览器与安卓本来就没有原生网络适配器（UDP/QUIC/TCP/网关只在桌面 Python 版进程内）；桌面版若报此错，检查本机是否装全 aiortc/aioquic/cryptography/PySide6 |
| BACKPRESSURE_TIMEOUT | 本地发送队列/拥塞超预算（benchmark2秒、chat10秒），不是NAT分类结果 |
| 中心记录不完整 | 恢复自动汇集/控制连接，检查本地存储；淘汰事件不能凭空补回 |
| 麦克风失败 | 检查是否在localhost安全上下文（`http://localhost`与`https://localhost`都算）、音频权限与平台支持；不静默绕过权限 |
| Windows桌面结果 | 新版 Python/Qt 桌面的 Windows CI 结果 **PENDING**（待 captain 推送）；旧 Electron 版的 90/600 秒记录不适用于新版。不能跳过诊断/测试/打包门后称成功 |

## 7. 开发验证

```sh
.venv/bin/python -m pytest p2pchat/tests -q          # 必须能收集且全绿；收集报错时不能声称可冻结
.venv/bin/python -m p2pchat.python_desktop.app --self-test   # 同进程真实握手（服务端+回声+客户端）
node --test p2pchat/tests/client/*.test.cjs p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/integration/*.test.cjs
npm --prefix p2pchat run sync:web
```

本轮本地实跑（**Tk 基线**，Qt 迁移落地后必须整套重跑）：**450 Python passed**、`tests/desktop` 67 passed / 0 skipped（含真实 Tk 面板）、**55 Node client**、**6 platform** passed / 0 skipped；`--self-test`（源码与打包产物）真实握手通过，独立通道测速两次都拿到对端确认（65.52 / 53.58 Mbps，标注为**应用层 goodput、不是线路带宽**）。**取证时（2026-10-12）整套回归因 Qt 迁移中间态在收集阶段中止（`ImportError: cannot import name 'ui'`），所以本轮不生成冻结清单**——原因与处置见 [PUNCHING-MATRIX](docs/PUNCHING-MATRIX.md) 第 8 节 G9 与第 11 节。

**真实IPv4双家宽/NAT成功、真实路由器放行、Windows/macOS/Android实机、真实麦克风采集、磁盘满/断电/七天长跑均未验证（NOT_RUN）**；IPv6隔离netns stateful与延迟丢包成功也不是运营商现场证据。完整版本、历史失败及上传边界见 [DELIVERY](docs/DELIVERY.md)。
