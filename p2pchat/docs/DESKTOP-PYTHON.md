# 桌面客户端（纯 Python + Tkinter + PyInstaller）

本文档说明 p2pchat 桌面端的实现、运行方式与打包方式。
**网页版保留，Electron 桌面壳已删除。**

## 一、验证状态（先看这里）

| 平台 | 实现 | 本机验证 | 说明 |
|---|---|---|---|
| Linux x86_64 | 纯 Python + Tkinter | **已实测** | 无界面自检真实握手通过；PyInstaller 产物已构建并启动；本机 `DISPLAY=:0` 下 GUI 可启动 |
| Windows x64 | 同一份 Python 源码 | **未验证** | 打包命令与 Linux 相同（见第五节），从未在 Windows 主机或 Windows CI 上运行过 |
| macOS | 同一份 Python 源码 | **未验证** | 打包命令与 Linux 相同（见第五节），`.app` 布局、签名与公证均未验证 |

本机 Linux 证据能证明的是：这套客户端**能在这台机器上完成真实的、经过身份校验的 P2P 握手**，并且打包产物能启动。
它**不能**证明任何家庭宽带、跨 NAT、跨运营商或跨设备场景可用，也**不能**代表 Windows / 安卓。
自检里的所有套接字都在同一台主机上。

## 二、三屏流程

| 屏 | 内容 |
|---|---|
| 1 / 3 连接服务器 | 服务器地址、房间、你的名字、房间密码；填完点「连接并寻找对方」才开始连接 |
| 2 / 3 逐条尝试打洞 | 每种方式的**人话名称**、一句话说明、当前状态、实测延迟 |
| 3 / 3 聊天 | 左侧选人，右侧聊天；文字、图片、文件、录音语音 |

右上角「设置」随时可打开（连接不会中断），里面有：

- **剩余方式**：还没成功、仍在后台继续尝试的方式
- **可用性**：每种方式是「可用 / 不可用 / 不支持」
- **延迟**：已打通方式的实测往返时间；没测到就显示「—」，不会用 0 代替
- **测速**：手动按钮，在独立通道上测，并注明「这是应用层速度，不是线路带宽」
- **查看我这台机器的出口地址**：STUN 映射观测，只观测地址，不转发任何数据
- **本机支持哪些功能**：版本与能力清单

### 文案来源

界面文案**只有唯一来源**：`docs/METHODS-PLAIN.md`。
`p2pchat/python_desktop/methods.py` 里的九种方式名称、一句话说明、状态用词、可用性用词都取自该文档，
`p2pchat/tests/desktop/test_methods_copy.py` 会直接解析该 Markdown 表格来核对，
所以文档改了而代码没跟上时会测试失败。

内部代号（`ice-v6`、`ice-v4`、`ice-dual`、`tcp-simopen`、`udp-probe`…）只作为引擎里的标识符存在，
**不会**出现在任何标题或说明里。

### 明文连接策略（与网页版同一规则）

- **默认拒绝**：非回环地址上的 `ws://` 会被拒绝，公网服务器必须用加密的 `wss://`；只有 `127.0.0.1` /
  `localhost` / `::1` 这类本机地址可以直接用明文。
- **显式确认**：连接页有一个默认不勾选的确认框；勾选后允许本次会话使用 `ws://` 到非回环地址。
- **持续提示**：一旦这样连上，界面在会话期间一直显示「⚠ 未加密连接：…」，不会滚走。
- **没有 trust-all**：没有跳过证书校验的开关，也不会静默降级成明文。
- `--self-test` 里保留一条默认拒绝的断言（非回环 `ws://` 必须 `PLAINTEXT_REFUSED`），显式确认后必须给出提示。

### 界面必须保留的三条限制

1. UDP 探测（第 4 项）标注「仅探测，不传内容」——它通了也**不能**聊天。
2. STUN 映射观测（第 8 项）不是中继，只观察地址；整个产品**没有中继、没有 TURN，也不通过服务器转发聊天**。
3. 路由器放行（第 9 项）默认关闭，需要操作者单独显式授权；本客户端**不会**自动修改路由器，界面上显示为「不支持」。

## 三、复用而不是重写

| 能力 | 复用的模块 | 调用方式 |
|---|---|---|
| WebRTC / ICE 三种地址组合 | `p2pchat/peer.py`（`Peer`） | 进程内直接实例化 |
| 回声节点、数据通道消息协议、文件分片与校验 | `p2pchat/peer.py` | 复用 `send()` / `send_file()` / `receive()` |
| UDP 探测、QUIC、TCP、TCP 同时打开 | `p2pchat/native/adapter.py`（`NativeAdapter`） | 进程内直接实例化，**没有** stdio 桥接 |
| 房间密钥与信令校验 | `p2pchat/server.py` + `backend/protocol.py` | 未改动，桌面端只是又一个客户端 |
| 诊断日志 | `backend/telemetry.py`（`LocalQueue` / `Store`） | 复用既有限额与脱敏 |

### 为什么需要一个额外的信令会话

`peer.py` 只处理 `mechanism == 'webrtc'` 的信令，非 WebRTC 的方式会被它有意丢弃。
桌面端因此额外开一个房间成员身份（`python_desktop/signal_session.py`）来承载这些信令，
WebRTC 依旧完全走 `peer.py`。两个成员身份在界面上会合并成**一个人**。
桌面端自己**不改** `peer.py` / `server.py` / `native/`；它只是这些模块的又一个进程内使用者。
加入流程的 v2 改动（`join_v2`）来自 t16，桌面端按下面的说明依赖并跟随其冻结。

桌面端唯一依赖的、`peer.py` 之外的接缝是它自己的 `ClientSession` 构造（`peer.py` 的 `run()` 内部
`from aiohttp import ClientSession`）。引擎在运行期间把该模块命名空间里的这个名字换成透明代理，
用来把非 WebRTC 的信令转发给适配器；除此之外不改动 `peer.py` 的任何行为。

### 依赖 `peer.py` 的 `join_v2`（随 t16 一并冻结）

服务端现在的加入流程是 v2 挑战-证明：先要一次性 nonce，再用
`joinKey = HKDF-SHA256(secret, salt=room, info='p2pchat/join-key/v2')` 派生出的值做 HMAC 证明。
**原始房间密钥不会发给服务器。**

桌面端**不复制**这套握手：`python_desktop/signal_session.py` 直接调用 `p2pchat.peer.join_v2`，
所以第二个房间成员身份的加入方式与 WebRTC 成员完全一致。

> **桌面依赖 `peer.py` 的 `join_v2`，随 t16 一并冻结。**
> 复制一份实现会让两份握手漂移，因此这里刻意选择 import。

`join_v2` 缺失时的行为是**可读失败**而不是裸 `ImportError`：`signal_session.py` 捕获导入错误，
抛出带说明的 `ImportError`（指明依赖 `p2pchat.peer.join_v2`、随 t16 冻结、原始错误原因）。
`p2pchat/tests/desktop/test_round2_contracts.py` 用一个不含 `join_v2` 的假 `peer` 模块验证这一点。

### 没有的依赖

`asar`、`preload`、`contextBridge`、stdio sidecar、Node/Electron 主进程——删除 Electron 之后**一个都不剩**。
`p2pchat/tests/desktop/test_electron_removed.py` 会检查这一点。

## 四、运行

```sh
# 图形界面（需要有图形显示）
.venv/bin/python -m p2pchat.python_desktop.app

# 无界面自检（CI 用；启动服务端 + 回声 + 客户端，完成一次真实握手）
.venv/bin/python -m p2pchat.python_desktop.app --self-test

# 版本与本机能力清单
.venv/bin/python -m p2pchat.python_desktop.app --capabilities

# 显式允许未加密 ws:// 到非回环地址（默认拒绝；会话期间持续显示未加密提示）
.venv/bin/python -m p2pchat.python_desktop.app --allow-plaintext
```

### 自检做了什么

`--self-test` 会在**同一个进程**里：

1. 起一个本项目自己的信令 + STUN 服务端（随机端口，不碰宿主防火墙）；
2. 用 `peer.py` 起一个回声节点，加入同一个房间；
3. 起一个桌面引擎客户端，走完整三屏背后的握手流程；
4. 等第一条**经过身份校验**的直连打通，打印：实际用到的方式、实测往返延迟、仍在尝试的方式、失败方式的真实原因；
5. 发一条文本并确认收到对方回显；
6. 发一个 64 KiB 文件并确认对方收到；
7. 在独立通道上尝试测速（拿不到对方确认就**如实报告失败**，不编造速度）。

退出码 0 = 通过，1 = 未通过。失败时它会明确说「失败就是失败，不会改走服务器转发」。

实测输出样例（本机 Linux，2026-10-11）：

```
桌面客户端自检（无界面模式）
范围：同一台 Linux 主机上的真实套接字与真实握手；不是家宽或跨 NAT 证据。
原生方式：参与尝试
  已打通的方式：双栈直连、IPv4 直连
  实测往返延迟：尚未测到（不会用 0 代替）
  仅探测、不传内容的方式：STUN 映射观测
  仍在尝试的其它方式：UDP 探测、QUIC 加密直连、TCP 加密直连、TCP 同时打开
  不可用：IPv6 直连（这条连接已经关闭。）
  文本消息：已通过已认证直连送达，并收到对方回显。
  文件传输：65536 字节经 webrtc 通道发送，发送端校验值 74cb163d776622b4… 已记录 1 条本地记录。
  数据通道往返复测：0.5 毫秒。
  测速未完成：ACK_TIMEOUT
  STUN 映射观测：出口 94.18.164.67:8596（只观测，不转发）
结论：通过（用时 33.2 秒）
```

### 已知局限

- **应用层测速在 WebRTC 数据通道上还没有成功取到对方的确认**（报告为 `ACK_TIMEOUT`），
  原因是被复用的 `peer.py` 隔离测速通道在高吞吐突发下会先于确认超时关闭。
  界面因此只显示「未完成 + 已发送字节数」，**不显示速度**。原生 QUIC 通道上的测速是另一条实现，不受此影响。
  这是如实报告失败，不是静默降级。
- 延迟只在有直连、并且打开设置或握手成功时测量；没测到就显示「—」。
- 录音依赖本机已有的 ALSA/PortAudio 前端（如 `arecord`）；没有的话界面直接说「录音不可用」，不会假装录到。

## 五、打包（PyInstaller）

```sh
# Linux（已验证）
.venv/bin/python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec

# 产物
dist/p2p-desktop/p2p-desktop                  # 启动客户端
dist/p2p-desktop/p2p-desktop --capabilities   # 版本 + 能力清单
dist/p2p-desktop/p2p-desktop --self-test      # 打包产物里的自检

# Windows：命令相同，用 .venv\Scripts\python.exe —— 未验证
# macOS：命令相同，用 .venv/bin/python          —— 未验证
# （npm --prefix p2pchat run desktop:linux 等价于上面第一条命令）
```

冻结入口由 spec 自己生成（`desktop-entry.py`，跑完即删），它只调用 `p2pchat.python_desktop.app.main`，
所以打包程序和 `python -m p2pchat.python_desktop` 的行为不会分叉。

### spec 里显式处理了什么

- `collect_submodules` 收集 `aiortc`、`aioice`、`aioquic`、`aiohttp`、`cryptography` 与 `p2pchat` 自身的子模块
  （这些包的隐式导入静态分析跟不到）；
- `collect_dynamic_libs` 收集 `av`、`cryptography`、`aioquic`、`aiortc`、`pylibsrtp` 的动态库；
- 显式收集 `_tkinter` 与 `libtcl*.so*` / `libtk*.so*`：`_tkinter` 是动态加载的扩展，
  它对 Tcl/Tk 是**按名字**链接的（`ldd` 在 Tcl 初始化前显示 `not found`），不显式带上就会 `ImportError`；
- 只打包 `p2pchat` 的源码模块，**排除** `node_modules/`、`releases/`、`verification/`、`review/`、
  `dist-web/`、`android*/`、`tests/` 等构建产物与研究证据；
- 数据只带 `p2pchat/web/`（保留的网页版）与 `docs/METHODS-PLAIN.md`（界面文案来源）。

Linux 实测：产物目录约 181 MiB，`--capabilities` 与 `--self-test` 都能在打包后运行。

## 六、不做什么

- 不部署公网服务、不改宿主防火墙、不申请路由器端口映射；
- 不把 ICE 的三种地址组合说成三种独立协议（它们是同一个 WebRTC 协议的地址族策略）；
- 不把同机或模拟结果当成真实家宽证据；
- 不静默改走其它通道：直连不成功就是失败，界面按用户能懂的话说明原因。
