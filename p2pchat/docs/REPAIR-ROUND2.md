# Round 2 修复记录（t12 / R1–R4）

本轮处理独立审查缺陷，不覆盖或重写第一轮证据；新源码将重新冻结，旧fd54a6…版本不冒称已修复。

## R1 接收对象预算与有效进度

- 每个文件只接受16KiB非尾块，最后一块必须等于剩余字节；0B文件只允许start/end，拒绝任何空块。
- 最大块数为ceil(size/16KiB)；预留计入文件字节+每块256B对象预算+每transfer1024B元数据预算。每个32MiB文件最多2048个块对象；64MiB总预算因此不能再同时接收两个整32MiB文件。
- 非法序号/空块/极小非尾块在保存对象、更新时间前拒绝；Transfers捕获后释放该接收；真实native应用数据管线负例关闭对应attempt。
- benchmark也拒绝非16KiB块且最多2048块，收到畸形块立即释放benchmark状态。

## R2 多候选与受控STUN

t14实现并交接：UDP/QUIC同remote socketId+证书的最多64个候选，每精确source独立HMAC状态，≤20probe/sec轮询；host sink不可达250ms后再trickle映射候选，经可控UDP转换双端认证和QUIC双向64KiB通过，原fd/port未变。错key、错证书、跨tuple组合hello/ACK负例拒绝。桌面主进程菜单导入≤1024B `{address,port}` JSON后明确授权，session-only固定CLI argv传IPv4 STUN；无renderer新RPC。真实NAT/公网仍不从可控转换结果推断。TCP改tuple仍需新attempt，UDP/QUIC认证选定后固定tuple、不自动migration。

## R3 真正的应用层QUIC测速

原生capability统一为 `limits.independentBenchmark`；新测试从真实sidecar capabilities取limits构造与UI相同path，调用实际 `Transfers.bench`，经QUIC传输bench-start/chunks/end，再由对端Transfers回bench-ack校验实际字节。不能只用native任意byte双lane成功代替应用协议通过。TCP无独立lane仍拒绝。实际高吞吐回归暴露native `BACKPRESSURE`拒收会冒泡，JS adapter仅对该明确未入队错误每20ms重试，benchmark总截止2秒/chat10秒（不会每次重置）；其它超时/不确定结果不重发，关闭attempt即拒绝，超时明确BACKPRESSURE_TIMEOUT不归因NAT。真实benchmark最终ACK字节/sequence验证无重复。UI明确独立lane仍共享底层拥塞/链路，测速可能影响聊天。

## R4 移动生命周期

- Android MainActivity向本地WebView发pause/resume及ConnectivityManager网络变化信号；Java只发固定枚举，无任意命令/秘密。
- mobile bridge在pause立即停止所有已登记录音track；visibilitychange为辅助；getUserMedia权限异步返回时若已pause立即停止该新stream。
- app暂停/切网关闭旧WS、注销其handler、清空paths/ACK/transfers与录音；resume/切网500ms合并，最多3次/分钟自动重建，否则明确让用户点击连接。重新join获得新peerId和新attempt，旧ACK无匹配waiter。
- UI提示后台/系统回收不保证存活。此处实现和模拟测试存在不等于Android实机验证，实机录音/锁屏/切网仍NOT_RUN。

## 验证入口

```sh
node --test p2pchat/tests/client/*.test.cjs p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/integration/native_benchmark.test.cjs
.venv/bin/python -m pytest p2pchat/tests -q
npm --prefix p2pchat run sync:web
```

最终回归：Python全套52 passed、8项AppKey建议警告（77.74秒）；client/platform Node34 passed；真实native应用集成4 passed（benchmark ACK、恶意空/极小块拒绝清理、原桥双lane）。`sync:web`退出0。所有媒体/地址/密钥仍不进入证据摘要；Android生命周期仅模拟及源码测试，实机NOT_RUN。

冻结清单同时补入Android构建已引用的proguard-rules.pro（原仅为模板注释，无秘密）。测试/包哈希以更新后的FREEZE与SOURCE-MANIFEST为准；不git/push，captain管理CI/源码发布。
