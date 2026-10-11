# 隔离通道测速（benchmark）协议与失败语义

状态：**本地实现与受控替身通道测试已完成**；真实 WebRTC/QUIC 长轮次实测在本机 Linux 通过，Windows/macOS 未验证。测速只报告**应用层吞吐**，不是线路带宽。

涉及代码：`p2pchat/peer.py`（WebRTC 数据通道）、`p2pchat/python_desktop/engine.py`（发送端）、`p2pchat/python_desktop/native_session.py`（原生通道）。

## 1. 通道与帧

- **独立通道**：WebRTC 用单独的 `benchmark` DataChannel；原生走各自的 benchmark lane/stream。测速流量永不与聊天/文件共用队列，也永不回声。
- **帧**：`bench-start {v,kind,id,drainMs?}` → 若干二进制数据帧（`frame(id,payload,seq)`）→ `bench-end {v,kind,id,bytes}`；接收端回 `bench-ack {v,kind,id,bytes,elapsedMs,timingError?}`，失败时回 `bench-error {v,kind,id,code}`。
- 每轮上限：32 MiB 或进度窗口（见下）。一轮未结束时收到新的 `bench-start` 回 `BENCH_BUSY`。

## 2. 轮次窗口：进度型空闲窗口 + 硬上限（t21 修复）

旧实现用**固定 10 秒总时长**（`time.monotonic()-start>10`）判定轮次有效，看门狗也用同一个 10 秒常量。但发送端的预算是：发送最长 5 秒 + drain 最长 10 秒，`bench-end` 可能在第 ~15 秒才发出 → 接收端必然先到期，`raise` 被 `except (ValueError,KeyError,TypeError): path['bench']=None; dc.close()` **完全吞掉**（无事件、无日志），发送端只能看到 `ACK_TIMEOUT`。

现在的窗口语义（`p2pchat/peer.py`）：

| 常量 | 值 | 含义 |
|---|---|---|
| `BENCH_IDLE_TIMEOUT` | 20 s | 距**最后一帧**超过这么久没有任何进展 → 轮次过期 |
| `BENCH_DRAIN_MARGIN` | 5 s | 发送端在 `bench-start` 里宣告 `drainMs` 时，空闲窗口取 `max(BENCH_IDLE_TIMEOUT, drainMs/1000 + 5)` |
| `BENCH_HARD_CEILING` | 300 s | 绝对上限，只用来兜住资源，不参与正常判定 |

- 每收到一帧（数据或控制）都会推进 `progress`，所以**只要还在传就允许继续**；只有真正的停顿才过期。
- `drainMs` 是有界协商：合法范围 `0 < drainMs ≤ 60000`，超出就忽略。桌面端发送端宣告 `drainMs=10000`，因此 15 秒的 `bench-end` 现在会正常拿到 `bench-ack`。
- 这不是"放宽超时换取通过"：窗口仍是有界的、按进展推进，且**没有任何伪造 ACK**；对端真的不回确认时依旧报超时。

## 3. 失败必须可见（t21 修复）

旧实现里任何异常路径都只做 `path['bench']=None; dc.close()`，没有任何事件或失败帧。现在：

- **给发送端明确失败帧**：`bench-error` + 受限 code（`BENCH_TIMEOUT` / `BENCH_NOT_STARTED` / `BENCH_ID_MISMATCH` / `BENCH_BUSY` / `SCHEMA_INVALID` / `AUTH_REQUIRED` / `LIMIT_EXCEEDED`）；发送端把它映射成 `{ok:false, reason:<code>}`，**不会**退化成假成功。
- **诊断事件**：同时发 `task.error`（遥测白名单内），`data.reason` 取枚举值（`TIMEOUT`/`SCHEMA_INVALID`/`LIMIT_EXCEEDED`/`AUTH_FAILED`）、`data.state="failed"`；精确 code 通过失败帧传递，遥测里不落任何测速载荷。
- **看门狗不再静默清状态**：过期时记录 `bench_failure`（id+code+时间），并立刻发失败帧+事件；迟到的 `bench-end` 会保留 `BENCH_TIMEOUT` 这个明确原因，而不是被当作"从没开始"。

## 4. `bench-ack` 是合法帧（t21 修复）

旧代码把入站 `bench-ack` 归入 `else: raise ValueError()`，于是**发送方收到自己的确认后反而关掉了自己的测速通道**（并触发下面的 `dc.close()`）。现在 `bench-ack` 与 `bench-error` 都通过 `deliver()` 交给应用层（`peer.received` → 桌面端 `_consumer` 用它解析 `bench:{id}` future）。通道保持可用，下一轮不必重开。

## 5. 失败与"测不到"的如实呈现

- 对端不回确认 → `ACK_TIMEOUT`（`ok:false`，没有 `mbps`）。
- 对端回 `bench-error` → 把 code 作为原因显示，`ok:false`。
- 背压超时 → `BACKPRESSURE`；通道关闭 → `CHANNEL_CLOSED`。
- 计时器分辨率不足 → `elapsedMs:null` + `timingError:TIMING_UNAVAILABLE`，不给 epsilon 时长或"无限好"的速率。
- 界面显示"未完成 + 已发送字节数"，**不显示速度**；应用层速度始终标注"不是线路带宽"。

## 6. 本地验证

```text
.venv/bin/python -m pytest p2pchat/tests/backend/test_benchmark_ack.py -q
10 passed
```

覆盖：正常轮次拿到 ack；12 秒（含 drain）轮次拿到 ack；超过空闲窗口 → `BENCH_TIMEOUT` 失败帧 + 诊断事件、绝无 ack；数据帧落到窗口外 → 同样响亮失败；硬上限仍生效；入站 `bench-ack`/`bench-error` 被投递且不关通道；无对应轮次的 `bench-end` → `BENCH_NOT_STARTED`；看门狗过期 + 迟到 `bench-end` 保留明确原因；对端沉默 → `ACK_TIMEOUT` 且不伪造速率。

受控替身数据通道与单进程替身对端，**不是真实跨设备/跨 NAT 证据**。真实双设备长轮次仍为 NOT_RUN。
