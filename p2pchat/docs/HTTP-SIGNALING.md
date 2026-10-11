# HTTP 信令（POST + SSE）：与 WebSocket 等价的无中继信令通道

> **先读这一段**
> 这份文档描述的是**信令传输**，不是聊天数据通道。聊天内容、图片、文件和录音语音**永远**只在两台设备之间直连传输；服务端在 HTTP 通道上同样**不代转、不存储、不转发**这些内容。
> 本产品**没有 TURN、没有中继**。HTTP 信令不会改变这一点，也不允许把 HTTP 当成"连不上时的退路"。

## 1. 为什么会有这条通道

有人问："能不能不用 WebSocket，HTTP 就够了？"

**能用 HTTP 做信令**，而且语义可以和 WS 完全等价：信令本来就是"上行一条消息、下行一条消息"。本仓库因此新增了一条传输：

* **上行**：客户端用 `POST` 把信令消息交给服务器；
* **下行**：服务器用 `SSE`（Server-Sent Events，`GET` 长连接）把房间事件与对端信令推给客户端。

两条通道（WS 与 HTTP）**共用同一个 `App`、同一个 `Store`、同一套房间/鉴权/限流/无中继语义**：同一个进程里，WS 客户端和 HTTP 客户端可以进同一个房间、互相看到、互相转发信令（有测试覆盖）。

## 2. 端点与流程

所有端点都在**同一个进程、同一个端口**上（就是原来的 `--port`，默认 8088）。

| 方法 | 路径 | 作用 |
|---|---|---|
| `POST` | `/signal/join` | 加入房间：请求体是标准 `join` 消息；响应是 `welcome` + `eventToken` |
| `GET` | `/signal/events?token=<eventToken>` | SSE 下行流：房间事件、对端信令、pong、telemetry_ack、error |
| `POST` | `/signal` | 上传一条信令消息（`signal`/`telemetry`/`ping`）；响应 `202 {"type":"accepted"}` |

`eventToken` 也可以放在 `POST /signal` 的 `X-P2P-Token` 头里。SSE 的 `token` 必须放在查询串，因为浏览器的 `EventSource` **不能设置自定义请求头**。

### 2.1 典型时序

```
客户端                                            服务器
  |-- POST /signal/join {join 消息} -------------->|  鉴权 + 房间人数上限
  |<- 200 {welcome, id, eventToken, ...} ----------|  广播花名册（自己那份留在队列）
  |-- GET /signal/events?token=... -------------->|  开始 SSE 下行
  |<- data: {"type":"roster","peers":[...]} ------|
  |-- POST /signal {signal, to, ...} ------------->|  校验 + 转发给对端
  |<- 202 {"type":"accepted"} --------------------|
  |                        （对端）<-- data: {"type":"signal", ...}
  |-- GET ...（连接断开）------------------------->|  会话结束、退出房间、广播新花名册
```

* 加入成功后**必须尽快打开 SSE 流**：所有下行内容（包括你发 `ping` 得到的 `pong`）都从这条流回来。
* 一个会话只允许**一条** SSE 流；重复打开返回 `409`。断线后请重新 `join`（本版本不做断点续传，见第 9 节）。

### 2.2 SSE 帧格式

```
retry: 3000                    ← 建议客户端 3 秒后重连（重连前需要重新 join）
data: {"v":1,"type":"roster","peers":[...]}
                                ← 空行结束一帧
: keepalive                     ← 注释行，约每 20 秒一次，用于穿过代理/保持连接
data: {"v":1,"type":"error","code":"LIMIT_EXCEEDED"}   ← 超限断开前的最后一帧
```

`data:` 之后是 UTF-8 JSON，字段与 WS 通道**逐字相同**。

## 3. 与 WebSocket 的差异（只有两处，其余完全等价）

| 方面 | WebSocket (`/ws`) | HTTP (`/signal/*`) | 是否影响语义 |
|---|---|---|---|
| 上行 | `ws.send_json` | `POST /signal` | 否，同一份 schema |
| 下行 | `ws.receive_json` | `GET /signal/events` (SSE) | 否，同一份 payload |
| `welcome` 额外字段 | 无 | `transport`/`eventToken`/`eventsPath` | 否，附加信息；其余字段（`id`/`strictP2P`/`iceServers`/`profiles`/`limits`）用同一个构造函数 |
| 传输层结果 | 只有帧，没有状态码 | HTTP 状态码 + `{"type":"error","code":...}` | 否，**错误码集合完全相同**（见下） |
| 出错后的行为 | 关连接 | 断开该会话（SSE 流结束） | 否，行为对齐 |
| 心跳 | WS ping/heartbeat=20s | SSE `: keepalive` 注释（约 20s） | 否 |
| Origin 校验 | 精确 allowlist | 精确 allowlist（同一函数） | 否 |
| 限流 | 80 msg/s、2 telemetry/s | 同一窗口，另有每来源上限 | 否，同一 `rate_tick()` |
| 无中继不变量 | 拒绝 chat/file/voice/TURN | 同一 dispatcher，同样拒绝 | 否，同一个 `Hub.dispatch` |

错误码与 HTTP 状态码的对应（**码本身与 WS 完全一致**）：

| code | HTTP | 含义 |
|---|---|---|
| `AUTH_FAILED` | 401 / 403 | 令牌无效（401）、房间密码不匹配或 Origin 不匹配（403） |
| `SCHEMA_INVALID` | 400 | schema 不合法，或试图发聊天/文件/语音 |
| `RELAY_FORBIDDEN` | 403 | 出现 relay 候选（TURN 被禁止） |
| `LIMIT_EXCEEDED` | 429（消息过大时 413） | 速率/连接数/未读缓冲/消息体超限 |
| `UNSUPPORTED_VERSION` | 400 | `v != 1` |
| `PEER_UNAVAILABLE` | 404 | 目标不在同一房间 |
| `ATTEMPT_CONFLICT` | 409 | 同一次连接/尝试的绑定冲突 |
| `TIMEOUT` | 408 | webrtc 尝试超时 |
| `ROOM_EXPIRED` | 410 | 房间到期 |
| `EVENT_CONFLICT` | 409 | 同一事件 id 内容不一致 |

## 4. 严格无中继不变量（两条通道完全一致）

* `type` 只允许 `signal` / `telemetry` / `ping`；`chat`、`file-start`、`voice` 等一律 `SCHEMA_INVALID`。**服务端不代转任何聊天内容**。
* 候选与 SDP 里的 `typ relay` 一律 `RELAY_FORBIDDEN`：没有 TURN，没有服务器中继。
* 服务端不存储、不重放任何聊天数据；中心日志只有白名单字段（事件名、字节数、成败），**不含消息正文**。
* 直连不成就是失败——HTTP 通道也**不会**偷偷改走服务器转发。

## 5. 有界性：所有上限与超限行为

| 资源 | 默认上限 | 配置键 | 超限行为 |
|---|---|---|---|
| HTTP 会话总数（并发） | 128 | `max_http_sse` | `POST /signal/join` → `429 LIMIT_EXCEEDED` |
| 每来源连接数 | 4 | `max_http_sse_per_source` | `POST /signal/join` → `429 LIMIT_EXCEEDED` |
| 每会话消息速率 | 80 条/秒（与 WS 相同） | 固定 `RATE_MESSAGES` | `POST /signal` → `429 LIMIT_EXCEEDED`，会话断开 |
| 每来源消息速率 | 240 条/秒 | `max_http_messages_per_source` | 同上 |
| 消息体大小 | 128 KiB（与 WS `max_msg_size` 相同） | 固定 `MESSAGE_BYTES` | `413 LIMIT_EXCEEDED` |
| 每会话未读下行缓冲 | 64 帧 | `max_http_queue` | **明确断开**：记录 `session.error{LIMIT_EXCEEDED}`，SSE 最后补一帧 `error LIMIT_EXCEEDED`，会话退出房间 |
| 会话 TTL（从未打开 SSE 的会话） | 120 秒 | `http_session_ttl` | 下一次任意 HTTP 请求时被清理回收 |
| 房间人数 | 12 | `max_room` | `LIMIT_EXCEEDED` |
| 房间 TTL | 3600 秒 | `room_ttl` | `ROOM_EXPIRED` |

* 未读缓冲用的是**定长队列**，不是无限队列：**不会**用"无限增长 + 静默丢弃"来掩盖慢消费者。
* 慢消费者（完全不读下行流，或读得极慢）在缓冲填满后会被**断开并记下原因**；该会话的令牌立即失效，后续 `POST` 得到 `401 AUTH_FAILED`（而不是被悄悄忽略）。
* 每来源的计数基于**直连对端地址**（`request.remote`）。本服务端**不信任** `X-Forwarded-For`；如果你在反向代理后面，代理 IP 会成为所有客户端的来源，请把连接数上限调大或按代理情况自行评估。

## 6. 会话生命周期

一个 HTTP 会话只在下面任一条发生时才结束（其他时候它一直占着房间名额）：

1. 客户端**SSE 流断开**（关页面、断网、主动断开）——服务端约 1 秒内识别；
2. 未读缓冲**溢出**（慢消费者）；
3. 任一**超限**（速率/大小/连接数）；
4. **心跳/协议错误**：schema 不合法、relay、版本不对、发给不在房间的人……（与 WS 一样，出错即断开）；
5. **会话 TTL** 到期且从未打开过 SSE；
6. **房间 TTL** 到期（`ROOM_EXPIRED`）；
7. 服务端**关停**（SSE 流会被主动结束，客户端应重连并重新 `join`）。

## 7. Origin 与鉴权边界

* **浏览器来源仍按精确 allowlist**：配置了 `--origin https://p2p.example` 时，`Origin` 头必须逐字符命中（协议+主机+端口，不带结尾斜杠），否则 `403 AUTH_FAILED`。这条规则对 WS 与 HTTP **用的是同一个函数**，不会分叉。
* **非浏览器客户端（Python / 原生）默认不能"沉默加入"**：没有 `Origin` 头时，只要配了 allowlist 就会 `403`。要放行必须由操作者**显式打开**开关：

  ```bash
  python -m p2pchat.server --host 127.0.0.1 --port 8088 \
    --origin https://p2p.example --allow-no-origin
  ```

  * `--allow-no-origin` 默认**关闭**；
  * 打开后：无 `Origin` 的请求放行，但**带了** `Origin` 且不匹配的请求**仍然**被拒；
  * 这个开关对 WS 与 HTTP 同时生效（不会出现"HTTP 松、WS 紧"的分叉）；非回环绑定时启动日志会打一条 warning。
* **房间密钥校验与 WS 完全一致**：同一个 HMAC 摘要算法、同一个"先到者定密钥"语义、同一套 `AUTH_FAILED` 判定；服务端只保存摘要，不保存密码明文。

## 8. 部署方式（端口 / 路径 / 代理）

* **不需要新端口**：HTTP 信令复用 `--port`（默认 8088）；同一个进程还提供 `/ws`、`/health`、`/`（网页）与 `/assets/`。
* 需要放行的端口与 WS 部署完全相同：`TCP <--port>`（信令）+ `UDP <--stun-port>`（STUN，默认 3478）。**不要**为 HTTP 信令额外开放别的端口。
* `--host 0.0.0.0 --host ::` 的双栈行为对 HTTP 通道同样生效（每个 `--host` 一个站点，见 [家宽服务器部署手册](DEPLOY-HOME-SERVER.md)）。
* 浏览器页面与服务端**同源**时最省事：直接用 `https://<你的域名>:8088/` 打开网页，前端就能用相对路径 `/signal/*`。
* 用反向代理时注意三点：
  1. **关闭响应缓冲**（nginx: `proxy_buffering off;`；本服务端已在 SSE 响应里发 `X-Accel-Buffering: no`）；
  2. **放长读超时**（SSE 是长连接；本服务端每约 20 秒发一次 `: keepalive`）；
  3. 不要改写或丢弃 `Origin` 头，否则精确 allowlist 会拒绝；也不要依赖 `X-Forwarded-For` 做限流来源（见第 5 节）。

## 9. 明文与 TLS 的选择边界（**必读**）

**服务端自身已经强制**：只要有一个 `--host` 不是回环地址，就必须同时提供 `--cert/--key` 与至少一个 `--origin`，否则拒绝启动。也就是说：

| 部署形态 | 允许吗 | 说明 |
|---|---|---|
| 回环地址 + 明文 `http://127.0.0.1:8088` | 允许 | 只给本机用；本仓库测试与自检就是这么跑的 |
| 非回环地址 + 明文 HTTP | **服务端拒绝启动** | 必须给 `--cert/--key`（TLS） |
| 非回环地址 + TLS（`https://`/`wss://`） | 推荐 | 公网/家宽部署用这个 |

> ⚠️ **在加入"不再明文发送房间密钥"的改动落地前，非回环明文部署仍会暴露凭据。**
>
> 这句话是给未来的自己看的：当前实现里，客户端 `join` 时会把**房间密钥（room secret）**放进请求体发给服务端（WS 与 HTTP 都一样，`server.py` 的 join 处理）。如果这条通道是明文 HTTP，链路上任何能看到流量的人都能拿到这个**可复用**的凭据。因此：
> * **不要**用明文 HTTP 把服务端暴露到非回环地址（服务端也会拒绝启动）；
> * 回环之外的部署**必须**用 TLS；
> * 后续任务会改掉"明文发送房间密钥"这件事（例如改成挑战-应答），在那之前，本文档的这一句必须保留。
>
> 另外注意：**`eventToken` 会出现在访问日志的查询串里**（`GET /signal/events?token=...`）。它是一个**短时效、单流、非房间凭据**的通道句柄（每次 join 重新生成，会话结束即失效），拿到它**不能**加入房间。若不希望它进日志，请在反向代理/服务器侧对 `token` 参数做脱敏，或关闭该端点的访问日志。

## 10. 客户端接入示例

浏览器（`EventSource` 不能设 header，所以 token 走查询串）：

```js
const base = location.origin;
const join = async (room, secret, name) => {
  const r = await fetch(`${base}/signal/join`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ v: 1, type: 'join', room, secret, name,
                           clientSessionId: crypto.randomUUID(), capabilities: ['webrtc'] }),
  });
  if (!r.ok) throw new Error((await r.json()).code);
  const welcome = await r.json();
  const events = new EventSource(`${base}/signal/events?token=${encodeURIComponent(welcome.eventToken)}`);
  events.onmessage = (e) => handle(JSON.parse(e.data));      // roster / signal / pong / error
  return { welcome, events };
};
const send = (eventToken, payload) => fetch(`${base}/signal`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-P2P-Token': eventToken },
  body: JSON.stringify(payload),
});
```

Python（`aiohttp`）：

```python
import aiohttp
async with aiohttp.ClientSession() as session:
    async with session.post(f'{base}/signal/join', json=join_body) as response:
        welcome = await response.json()
    token = welcome['eventToken']
    events = await session.get(f'{base}/signal/events', params={'token': token},
                               timeout=aiohttp.ClientTimeout(total=None))
    async for line in events.content:      # data: {...} 帧 + 空行
        ...
    await session.post(f'{base}/signal', json=message, headers={'X-P2P-Token': token})
```

> 非浏览器客户端如果不发 `Origin`，必须在服务端加 `--allow-no-origin`（第 7 节），否则 `403`。

## 11. 本版本**没做**的事（边界）

* 不做长轮询/短轮询回退；只有 SSE 一条下行通道。
* 不做断点续传/消息重放：`token` 不承载历史，SSE 断开后必须重新 `join`（重连时的 `retry: 3000` 只是浏览器默认行为提示）。
* 不做多路复用/压缩；不做 HTTP/2 专项优化。
* 不改变"客户端把房间密钥发给服务端"这件事（第 9 节，后续任务处理）。
* 证据范围：本通道在 **Linux（本仓库开发机）** 上实测；**Windows / macOS 未实测**。测试文件在非 Linux 上会整体跳过并注明原因，不要把 Linux 结论当成跨平台结论。这里的验证都是 loopback/本机实验，**不是家宽/NAT 可打通的证据**。

## 12. 本次改动与 sha256

| 文件 | 说明 | sha256 |
|---|---|---|
| `p2pchat/server.py` | 新增 HTTP/SSE 传输；抽出共享的 `open_session`/`dispatch`/`close_session`/`origin_allowed`；WS 行为不变 | `cce0cb0abf1adae62488a9fd68cb66988f3e69808d863f348a246c6945276541` |
| `p2pchat/tests/backend/test_http_signal.py` | 新增 25 项测试：HTTP-only 双端流程、WS/HTTP 互操作、无中继负例、错误码对齐、限流/大小/连接数/慢消费者/关停 | `f6847b743faea30b5110ac1fb50ffabbec5bc1fba776b72d33c3885e5ba8efec` |
| `p2pchat/docs/HTTP-SIGNALING.md` | 本文档 | 见交付报告（文档自引用哈希会让哈希失效） |

复现命令：

```bash
.venv/bin/python -m pytest p2pchat/tests/backend/test_http_signal.py -q   # 25 passed
.venv/bin/python -m pytest p2pchat/tests/backend -q                      # 164 passed
```
