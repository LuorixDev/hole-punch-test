# P2P Observatory：严格无中继聊天与测速实验台

**当前交付：已独立验证的 Linux 本地实验源码与本地构建；不是全平台/任意网络可用产品。** 小房间最多12人、逐对端mesh，支持文本、图片、文件和录制完成后的语音文件；不做实时通话或语音识别。TURN永久禁用，信令/日志不代转聊天；无可用直连就明确失败。

**当前状态：STUN窗口与native IPv6/网关平台修复已审，Windows待新commit CI确认。** 最新78a2050原双echo/计时2 passed，但完整suite70 passed/6 failed/1 skipped；六失败对应t30双栈STUN窗口假设及t31三项native IPv6/一项网关差异，不再是旧挂起或零计时。公开结论见 [脱敏证据索引](docs/EVIDENCE-INDEX.md)。以下61b400e仅历史。

**此前计时修复历史：** 最新源码/包哈希以 [SOURCE-MANIFEST](docs/SOURCE-MANIFEST.json) 和 [FREEZE](docs/FREEZE.json) 为准；本轮整合t27+t28性能计时/未知提示修复并重新sync和Linux构建，不改已审产品。最近61b400e的Linux/Android成功，Windows4000B已收到但elapsedMs=0断言失败；关闭正常完成，约4.937秒exit1，**不是旧关闭挂起/超时124**。新commit/run待captain推送，详见 [计时修复集成](docs/TIMING-INTEGRATION.md)。

历史基线`8687adf15b114380747308b43d78df29dd0634bc006a3e4d16215abeb4062388`（129文件）的 VERIFICATION-R2（本地私有证据，不随GitHub交付）（t15）/ROUND3（本地私有证据，不随GitHub交付）（t19）仅对应旧版；[旧a1c6e7e run38124339483](https://github.com/LuorixDev/hole-punch-test/actions/runs/38124339483)已终态：Linux/Android成功，Windows90秒诊断exit124未打包。挂起链已定位至Peer.close→RTCPeerConnection.close→ICE.stop→aioice StunProtocol.close；新版本必须重跑原双echo诊断、完整测试与打包门，不能继承旧成功包。差异与边界见 [Windows修复集成](docs/WINDOWS-INTEGRATION.md)。

快速导航：[平台/机制矩阵](docs/CAPABILITIES.md) · [交付状态与产物哈希](docs/DELIVERY.md) · [协议](docs/PROTOCOL.md) · [验收定义](docs/ACCEPTANCE.md) · [家宽服务器部署手册](docs/DEPLOY-HOME-SERVER.md)。

## 1. 安装依赖（仓库根目录）

Linux优先路径，需要Python3.12及支持WebRTC的现代Chromium：

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r p2pchat/requirements-lock.txt
```

[精确依赖记录](requirements-lock.txt)对应已测Linux环境；跨平台wheel可用性不保证。需要桌面构建时另装Node24，使用 [npm锁文件](package-lock.json)，不要盲目`audit fix --force`：

```sh
npm --prefix p2pchat ci --ignore-scripts
node p2pchat/node_modules/electron/install.js
```

当前已知构建链残留8个moderate节点（单一sprintf-js问题），0 high/critical为此前审计快照，不等于永远无漏洞。依赖/构建细节见 [PLATFORMS](PLATFORMS.md)；最终状态以本次交付文档为准。

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
- Origin必须精确allowlist。Electron本地页面Origin是`null`，仅在**明确允许桌面客户端**时另加`--origin null`；Android是`--origin https://localhost`。Origin不是身份认证，仍需房间secret和数据面HMAC。
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
| Linux Electron | `npm --prefix p2pchat run dist:linux`；运行`p2pchat/releases/linux-unpacked/p2p-observatory-chat` | 本基线本地构建+sandbox启动通过；需保留完整目录而非单独launcher；本机glibc2.44构建不保证旧发行版 |
| Windows Electron | 在Windows配置Python3.12、Node24后，执行`npm --prefix p2pchat run dist:windows`；将来仅安装对应最终commit的portable包 | 源码存在；当前最终同版成功包未取得。旧CI测试超时，未打包；不能声称可安装已测 |
| Android Capacitor | 自备已授权SDK36/build-tools36、JDK21；`npm --prefix p2pchat run android:sync`，再在`p2pchat/android`运行`./gradlew --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug` | 关闭修复同版待CI；旧commit debug APK构建成功但不是新版，实机NOT_RUN |

Windows构建可用构建环境变量`PYTHON`指定本机虚拟环境解释器；不是renderer可传命令。Android debug APK仅调试签名、不是正式发行签名；不上传任何签名私钥，不代用户接受SDK许可。Android连接远程中心要求有效WSS，不能用`ws://`绕过混合内容限制。

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

原生默认loopback。菜单**原生网络绑定**确认后选本机接口，改变配置会关闭旧路径。STUN菜单可导入一个≤1024B JSON `{"address":"已授权STUN的数字IPv4","port":3478}`，核对实际端点再确认；会话级、默认关闭，不接受DNS/URL或任意命令。网关映射不同于STUN：目前只有Python显式opt-in API，客户端桥显示`OPT_IN_GATEWAY_API_ONLY`，没有自动授权入口。原生QUIC/TCP须配另一支持native的客户端，不能用WebRTC-only echo判这些机制失败。

## 6. 诊断、隐私与排障

本地IndexedDB20MiB/7天、待传最多2000条；中心SQLite/轮转日志默认100MiB/7天。事件有session/connection/attempt ID；断线缓存并补传，持久ACK后移出待传。暂停自动汇集、队列淘汰或存储失败会提示**中心记录不完整**。中心不收正文、文件、原始IP、密钥、完整SDP；显示页面上的实际tuple不等于上传它。

点击**导出脱敏日志**只保存本地NDJSON，不自动上传到GitHub/第三方；分享前仍要复核。不要上传整个data目录、原媒体、截图中的密钥/私人地址或抓包。清站点数据/卸载会丢日志；磁盘满/断电/七天长跑尚未验证。

| 症状 | 检查/处理 |
|---|---|
| 403/无法加入 | 核对WSS证书、精确Origin、房间key；不要关TLS校验或使用通配Origin |
| ICE timeout/unknown | 查看真实候选和网络限制；IPv6/UDP被阻断可正常失败，绝无TURN回退 |
| NATIVE_BRIDGE_UNAVAILABLE | 使用包含sidecar的完整桌面包；浏览器/Android原生能力本就受限 |
| BACKPRESSURE_TIMEOUT | 本地发送队列/拥塞超预算（benchmark2秒、chat10秒），不是NAT分类结果 |
| 中心记录不完整 | 恢复自动汇集/控制连接，检查本地存储；淘汰事件不能凭空补回 |
| 麦克风失败 | 检查HTTPS/localhost、音频权限与平台支持；不静默绕过权限 |
| Windows CI超时 | 旧IOCP关闭挂起链已定位，窄运行时补丁待同版Windows确认；不能跳过诊断/测试/打包门后称成功 |

## 7. 开发验证

```sh
.venv/bin/python -m pytest p2pchat/tests -q
node --test p2pchat/tests/client/*.test.cjs p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/integration/*.test.cjs
npm --prefix p2pchat run sync:web
```

旧8687adf独立复验：58 Python、34客户端/平台Node、4真实native应用集成通过；关闭修复后实现者Linux全套72通过、独立T26 backend/core/负例33通过，Windows原生CI仍待确认；含真实独立进程断信令超过60秒、同socket候选切换、跨tuple完整proof重放拒绝、移动生命周期模拟。**真实IPv4双家宽/NAT成功、真实网关、Windows/Android实机均未验证**；IPv6隔离netns stateful/延迟丢包成功也不是运营商现场证据。完整版本、历史失败及上传边界见 [DELIVERY](docs/DELIVERY.md)。
