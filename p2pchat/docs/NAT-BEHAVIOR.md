# NAT 行为探测与分类（多 STUN 观测）

状态：**本地实现与受控端点测试已完成；真实家宽 NAT 行为 = NOT_RUN**（必须由用户在真实网络运行，见文末）。本模块只使用用户显式配置的观测点，不引入任何中继。

实现：`p2pchat/native/nat_behavior.py`　测试：`p2pchat/tests/native/test_nat_behavior.py`

## 1. 为什么需要它

只做一次 STUN 观测，只能拿到「我在你眼里是哪个公网地址和端口」。这**不是** NAT 类型，也无法解释打洞为什么失败。本模块用多个观测点，看**同一个本地端口对不同目的地得到的对外端口是否变化**，以及**哪些来源的回包能被放进来**，据此判定 NAPT 的映射行为与过滤行为（RFC 4787 术语），并给出能不能打洞、该优先走哪条路的人话结论。

## 2. 两种行为（界面统一用这套说法）

映射行为（对外端口是否随目标变化）：

| 取值 | 人话 |
|---|---|
| 端点无关 | 对外端口不随目标变化 |
| 地址相关 | 对外端口随目标**地址**变化，同地址不同端口不变 |
| 地址+端口相关（对称型） | 每换一个目标地址或端口，对外端口就换 |
| 无法判定（观测不足） | 数据不够，不下结论 |

过滤行为（谁能把包送进来）：

| 取值 | 人话 |
|---|---|
| 端点无关 | 不限制外部来源 |
| 地址相关 | 只允许你联系过的地址回包 |
| 地址+端口相关 | 只允许你联系过的地址和端口回包 |
| 无法判定（观测不足或缺可选观测点） | 数据或服务器能力不足，不下结论 |

可打洞性预期：映射为「地址+端口相关」→ **低**；映射可判定且过滤为端点无关 → **高**；映射可判定、过滤为地址相关/地址+端口相关 → **中**（需要双方同时向对方候选发包）；映射无法判定 → **未知**。

## 3. 怎么测（全部基于实际观测，不做启发式猜测）

1. **配置观测点**：至少两个不同的 `IP:端口` 目的地（可以是两台 STUN 服务器，也可以同一台服务器的不同 IP，或同一 IP 的不同端口）。必须是 IP 字面量，不接受域名——**不做 DNS、不做发现、不做扫描**。
2. **每个观测点、每个本地端口、多次重复**：探测按 `local_ports`（默认 2）个本地端口分别建 socket，每个 socket 对每个观测点做 `repeats`（默认 2）次 RFC 5389 Binding 请求。同一 `(本地端口, 观测点)` 的多次结果必须一致，否则报「映射不稳定 → 无法判定」，绝不硬猜。
3. **映射判定**（只看观测到的对外端点如何随目的地变化）：
   - 同一个本地端口，对所有观测点得到同一个对外端点，且观测点覆盖 ≥2 个不同地址 → 端点无关；
   - 对外端点按目的地**地址**分组、组内恒定、组间不同 → 地址相关；
   - 同一个地址的不同端口得到不同对外端点 → 地址+端口相关（对称型）。
   - 只有同一个地址的观测点（无法区分端点无关与地址相关）→ **无法判定**，并给出 `mappingPartial = endpoint-independent-or-address-dependent` 的粗结论提示。
4. **过滤判定**：在一个新建的 socket 上先建立映射，再用 RFC 5780 `CHANGE-REQUEST` 请求服务器**从别的来源**回包：
   - 收到来自**不同地址**的回包 → 端点无关；
   - 只收到同地址不同端口的回包 → 地址相关；
   - 两类都被丢、但主地址仍然能应答 → 地址+端口相关；
   - 服务器从主地址回答了 `CHANGE-REQUEST`（说明它不支持 RFC 5780 测试）→ **无法判定**；
   - 测试中途路径整体失联 → **无法判定**（不能把超时说成过滤严格）。
   可选来源优先取服务器 `OTHER-ADDRESS` 宣告的地址，其次取用户为该观测点显式配置的 `alternate_address`（不同 IP）/ `alternate_port`（同 IP 不同端口）。
5. **只接受合法回包**：事务 ID、cookie、长度、来源地址逐项核对；伪造、过期、畸形（缺 `XOR-MAPPED-ADDRESS`、长度不符）或来源不符的回包一律丢弃并计入 `RESPONSE_REJECTED`，绝不当作观测。

## 4. 结论怎么读

`NatProfile.report()` 把**推断**和**原始观测**分开：

- 推断：`mapping` / `mappingLabel` / `mappingEvidence`、`filtering` / `filteringLabel` / `filteringEvidence`、`reachability`、`guidance`、`summary`（一行中文结论，例如「你的网络：映射行为=地址+端口相关（对称型）；过滤行为=无法判定（观测不足或缺可选观测点）；直连打洞预期成功率=低……」，**不含具体公网地址**）。
- 原始观测：`observations` / `mappedEndpoints` **仅**在 `report(include_mappings=True)` 时给出，并带 `inferenceNote` 说明「推断来自对外端点的变化规律，不等于这些地址本身」。

因此界面可以显示「观测到的映射地址=…」和「NAT 类型推断=…」两行，不能把前者说成后者。

## 5. 隐私与安全边界

- **只联系用户显式配置的观测点**（以及该观测点自己宣告的 `OTHER-ADDRESS`，仅用于这一次过滤测试）。没有内置任何第三方 STUN，没有服务器列表，没有发现/扫描。
- 观测到的公网映射地址属于**本地私有诊断数据**：`report()` 默认不包含，只有本地 `--include-mappings` 才打印；**默认不进中心上报**。
- 观测点是 IP 字面量，因此不产生 DNS 查询；本地地址必须显式 `--bind`，不枚举网卡。
- 不修改既有协议 HMAC、候选 nonce、证书 pinning 或限额语义（本模块只读 STUN，不参与信令）；不引入中继、TURN 或任何转发。
- 错误列表有上限（64 条），不会因异常网络无限增长。

## 6. 在真实网络运行

```bash
# 至少两个观测点；--bind 填本机对应网段的地址（不自动探测）
.venv/bin/python -m p2pchat.native.nat_behavior \
  --bind 192.168.1.20 \
  --server <你的STUN-A-IP>:3478 \
  --server <你的STUN-B-IP>:3478

# 需要本地查看观测到的公网映射地址时才加（不要上传）
.venv/bin/python -m p2pchat.native.nat_behavior --bind 192.168.1.20 \
  --server <A-IP>:3478 --server <B-IP>:3478 --include-mappings
```

退出码：`0` 表示映射行为已判定；`3` 表示无法判定（观测不足）。要区分「地址相关」与「端点无关」，两个观测点必须是**不同地址**；只有同地址不同端口时只能得到粗结论。服务器不支持 RFC 5780 时，映射行为仍可判定，过滤行为会明确报「无法判定」。

## 7. 证据边界

- 本地验证使用**受控脚本化 STUN 应答端点**（真实 loopback socket + 真实 RFC 5389/5780 报文，NAT 的映射与过滤模型是脚本化的），只证明分类逻辑与协议实现正确。
- 这些结果**不是真实家宽 NAT 证据**；`NatProfile.evidenceScope` 固定标注 `local-controlled-observation-points-only-not-real-home-network-evidence`。**真实家宽 NAT 行为 = NOT_RUN**，必须由用户按第 6 节在自己网络上运行后才有结论。
- 本模块是后续对称 NAT 端口预测的基础，本身不做端口预测、不建立连接。

### 本地可复现命令与哈希

```text
.venv/bin/python -m pytest p2pchat/tests/native/test_nat_behavior.py -q
23 passed in 3.91s    exit 0

.venv/bin/python -m pytest p2pchat/tests/native -q
115 passed in 23.21s  exit 0
```

变更文件 sha256：

```text
3c735bdf791a428a5135cfa721894eaedd64b72956190adbb64efeb11f67efdf  p2pchat/native/nat_behavior.py
1566386de51fe1e6868d3e0bd4a6162b343d2768765b178adf95cebf2c78bf23  p2pchat/tests/native/test_nat_behavior.py
```

同一轮全量 `pytest p2pchat/tests` 的 11 个失败全部位于 `p2pchat/tests/desktop/`（并行在途的桌面端工作，与本模块无关，不 import `nat_behavior`）；本任务的验收命令是上面的两条 native 门禁，均为绿。

Windows 说明：探测发送/接收复用 `native/stun.py` 的 `socket_address` / `receive_udp_retry`，与 native 传输一样走 IOCP 需要的四元组地址与有界无应答语义（见 [WINDOWS-ADDRESS-FORM-FIX](../ci/WINDOWS-ADDRESS-FORM-FIX.md)）；真实 Windows 运行仍以 captain 推送 runner 的结果为准。
