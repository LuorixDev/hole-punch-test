# 桌面客户端（纯 Python + Qt(PySide6) + PyInstaller）

本文档说明 p2pchat 桌面端的实现、运行方式与打包方式。
**网页版保留，Electron 桌面壳已删除。** 界面工具包是 **Qt(PySide6)**（`qt_ui.py`）；早期那版 Tkinter 壳（`ui.py`）已按用户要求移除，原因见下文「为什么从 Tk 换成 Qt」。

## 一、验证状态（先看这里）

| 平台 | 实现 | 本机验证 | 说明 |
|---|---|---|---|
| Linux x86_64 | 纯 Python + Qt(PySide6) | **Qt 版已在本机实跑**：三条 verify 命令通过、`DISPLAY=:0` 下六张中文截图（见「Qt 中文渲染证据」）、打包产物在无 DISPLAY 环境 `--capabilities` / `--self-test` 通过；**独立复审待 t27** | 无界面自检走引擎层（与界面库无关），两种壳都成立；图形界面的 Qt 版已有截图与实跑证据，但**尚未经过独立复审**，请不要把「已实跑」当成「已复审」 |
| Windows x64 | 同一份 Python 源码 | **未验证** | 打包命令与 Linux 相同（见第五节），从未在 Windows 主机或 Windows CI 上运行过 |
| macOS | 同一份 Python 源码 | **未验证** | 打包命令与 Linux 相同（见第五节），`.app` 布局、签名与公证均未验证 |

本机 Linux 证据能证明的是：这套客户端**能在这台机器上完成真实的、经过身份校验的 P2P 握手**，并且打包产物能启动。
它**不能**证明任何家庭宽带、跨 NAT、跨运营商或跨设备场景可用，也**不能**代表 Windows / 安卓。
自检里的所有套接字都在同一台主机上。

### 为什么从 Tk 换成 Qt（用户要求，2026-10-11）

早期那版是 Tkinter。本机这个 Tk 运行时**没有链接 Xft**，`tkinter.font.families()` 只返回 `('fixed',)`，
中文文本测量宽度是 0 —— 三屏界面里的中文会渲染成空白。Qt(PySide6) 有正常的字体处理，因此界面壳改为 Qt：
`python_desktop/ui.py`（Tk）已删除，`app.py` 调用 `qt_ui.run`，`tools/desktop.spec` 收集 Qt 平台插件并**显式排除** `tkinter`。
旧实现作为**不可导入的参考**留在 `python_desktop/evidence/tk_ui_reference.py.txt`（产品路径下没有 `ui.py`），
`python_desktop/*.py` 中不再出现任何 `import tkinter`；`tests/desktop/test_ui.py` 的
`test_product_code_no_longer_imports_tkinter` 会静态断言这一点，`tests/native/test_gateway_optin.py`
另有「界面库只允许出现在薄界面层」的守门用例。

### Qt 中文渲染证据（DISPLAY=:0 实拍）

四张截图在 `p2pchat/python_desktop/evidence/`，由真实图形会话（`DISPLAY=:0`，Qt 6.12.0）截取：

| 文件 | 尺寸 | 内容 |
|---|---|---|
| `qt-1-connect.png` | 1000×697 | 第 1 屏：连接服务器（表单、明文确认框、无中继说明） |
| `qt-2-attempt.png` | 1000×697 | 第 2 屏：九种方式逐条列出（人话名称 / 一句话说明 / 可行网络 / 状态 / 可用性 / 实测延迟） |
| `qt-3-chat.png` | 1000×697 | 第 3 屏：聊天（房间成员、消息区、发送/图片/文件/录音） |
| `qt-4-settings.png` | 1000×720 | 右上角设置：剩余方式、可用性、延迟、测速、诊断暂停开关、「需要你单独同意的三件事」 |
| `qt-5-frozen-packaged.png` | 1000×722 | **打包产物** `dist/p2p-desktop/p2p-desktop` 的真实窗口（Wayland 平台插件） |
| `qt-6-frozen-xcb.png` | 1000×721 | **打包产物**用 `QT_QPA_PLATFORM=xcb` 启动的真实窗口，证明包里的 X11 平台插件（`libqxcb.so`）可用 |

六张合计约 **900 KB**（已压到 1000 px 宽），全部来自**最终**一次 PyInstaller 构建（2026-10-12）对应的代码，其中 1–4 为源码运行、5–6 为 `dist/p2p-desktop/` 里的冻结产物。`qt-1…4` 由源码运行并在 `DISPLAY=:0` 下用 Qt 自绘抓取；
`qt-5`/`qt-6` 是对**冻结产物**窗口的真实截屏（窗口类 `p2p-desktop`，标题「直连聊天 · 桌面版 0.2.0」，
后者在窗口管理器里以 `client_type=x11` 出现）。

复核方式（可复现）：在图形会话里跑下面这段，然后**用眼睛看**截图里的中文是否成字（不是方块/空白）：

```sh
PYTHONPATH=. DISPLAY=:0 .venv/bin/python - <<'PY'
from PySide6 import QtWidgets
from p2pchat.python_desktop import qt_ui
app = QtWidgets.QApplication([])
w = qt_ui.DesktopApp(app=app); w.resize(1120, 780); w.show()
w._refresh_paths()                      # 连接前的第 2 屏也会列出九种方式
app.processEvents(); w.grab().save("/tmp/qt-check.png")
print("font:", w.font_family)
PY
```

字体是按**字形覆盖率**挑的（`pick_cjk_font()` 用 `QFontMetrics.inFontUcs4('中文渲染')` 逐个测量候选家族），
不是按名字猜。本机选中 `Noto Sans CJK SC`。如果系统一个能画中文的字体都没有，界面会在底部**持续显示**
「⚠ 本机没有找到能渲染中文的字体…请安装中文字体（例如 fonts-noto-cjk / fonts-wqy-zenhei）」，
而不是给出一片空白。

## 二、三屏流程

| 屏 | 内容 |
|---|---|
| 1 / 3 连接服务器 | 服务器地址、房间、你的名字、房间密码；填完点「连接并寻找对方」才开始连接 |
| 2 / 3 逐条尝试打洞 | 按 `METHODS-PLAIN.md` 的固定顺序逐条列出**九种方式**：人话名称、一句话说明、**什么网络下可行**、失败最常见原因、状态、可用性、实测延迟。还没连上/还没对端时也会列出来（状态=等待中、可用性与延迟显示「—」，绝不猜） |
| 3 / 3 聊天 | 左侧选人，右侧聊天；文字、图片、文件、录音语音 |

右上角「设置」随时可打开（连接不会中断），里面有：

- **剩余方式**：还没成功、仍在后台继续尝试的方式
- **可用性**：每种方式是「可用 / 不可用 / 不支持」
- **延迟**：已打通方式的实测往返时间；没测到就显示「—」，不会用 0 代替
- **测速**：手动按钮，在独立通道上测，并注明「这是应用层速度，不是线路带宽」
- **查看我这台机器的出口地址**：STUN 映射观测，只观测地址，不转发任何数据
- **本机支持哪些功能**：版本与能力清单
- **三件默认关闭、必须你单独同意的事**：「让路由器开一个端口」（只申请映射，不传数据）、「同网段直连发现」（组播，生产模式拒绝回环）、「对称 NAT 端口预测」。每件都先给人话解释再问你要不要同意；不同意就什么都不做

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
3. 路由器放行（第 9 项）默认关闭，需要操作者单独显式授权；本客户端**不会**自动修改路由器。它的可用性按平台如实显示：能在本机只读核对路由表的平台（当前实测是 Linux）显示「**可用，但需要你点同意**」，其它平台显示「不支持」并给出平台原因（Windows/macOS fail-closed）。它**只申请端口映射，不能传消息**。

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

`asar`、`preload`、`contextBridge`、stdio sidecar、Node/Electron 主进程——删除 Electron 之后**一个都不剩**；Tk 界面壳（`ui.py`）也已在 Qt 迁移中删除。
`p2pchat/tests/desktop/test_electron_removed.py` 会检查 Electron 相关文件确实不存在。

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

历史输出样例（本机 Linux，2026-10-11，**Tk 基线、测速修复之前**；保留作对照，其中的 `测速未完成：ACK_TIMEOUT` 已不代表当前行为）：

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

- **测速现在能拿到对端确认**：隔离通道改为**进度型空闲窗口**（空闲 20 秒才算超时，发起方可协商 `drainMs`，桌面端宣告 10000，另设 300 秒硬顶兜底）之后，独立复审在**源码**与**打包产物**上各跑一次 `--self-test`，两次都拿到对端 bench-ack：**65.52 Mbps / 53.58 Mbps**。这是**应用层 goodput（对端实际确认收到的字节 ÷ 单调时间）**，**不是线路带宽**，也不保证跨网络可重复。
  对端始终沉默时仍然如实报 `ACK_TIMEOUT`，**不会**编造速度；TCP 通道没有独立 lane，明确不允许测速。
- 延迟只在有直连、并且打开设置或握手成功时测量；没测到就显示「—」。
- 录音依赖本机已有的 ALSA/PortAudio 前端（如 `arecord`）；没有的话界面直接说「录音不可用」，不会假装录到。

## 五、打包（PyInstaller）

```sh
# Linux（Qt 版已在本机实跑；独立复审待 t27 —— 见第一节的验证状态与截图）
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
- 收集 Qt/PySide6 的平台插件（`PySide6/Qt/plugins/platforms/libqxcb.so` 等），并在 COLLECT 之后**断言平台插件真的进了包**，不盲信 hook；同时**显式排除** `tkinter` / `_tkinter`（Tk 壳已被 Qt 替换）；
- 只打包 `p2pchat` 的源码模块，**排除** `node_modules/`、`releases/`、`verification/`、`review/`、
  `dist-web/`、`android*/`、`tests/` 等构建产物与研究证据；
- 数据只带 `p2pchat/web/`（保留的网页版）、`docs/METHODS-PLAIN.md`（界面文案来源）与 `python_desktop/licenses/`（LGPL/GPL 文本）。

本机 Linux 实测（Qt 版，2026-10-12）：产物目录 `dist/p2p-desktop` 约 **350 MiB**（Tk 基线是 181 MiB，
**增量约 +169 MiB / +93%**），其中 Qt 部分约 84 MiB（`libQt6Core/Gui/Widgets`、`libQt6XcbQpa`、平台插件与
`PySide6/*.abi3.so`），加上 ICU 数据约 32 MiB —— 这是「中文能渲染」和「不依赖宿主 Tk」的直接代价。
打包产物在**没有 DISPLAY**的环境里 `--capabilities` 与 `--self-test` 都通过（GUI 起不来时 `--self-test` 本来就走引擎层）。

### 依赖声明：requirements.txt / constraints.txt / requirements-lock.txt

三个文件分工不同，**不要混用**：

| 文件 | 是什么 | 谁在用 |
|---|---|---|
| `p2pchat/requirements.txt` | 运行时 + 测试依赖的**声明**（区间为主；桌面 GUI 固定到已测版本）。**产品代码 import 到的每个第三方模块都必须在这里** | **CI 唯一安装的运行时清单**：`pip install -r p2pchat/requirements.txt -r p2pchat/platform/build-requirements.txt -c p2pchat/platform/constraints.txt`；本地开发同样从它开始 |
| `p2pchat/platform/constraints.txt` | 传输/加密栈的**精确已测版本**（aiohttp / aiortc / aioquic / cryptography / pylibsrtp …），Linux 与 Windows 通用 | CI 的 `-c` 约束；不含 Qt（GUI 的固定版本在 requirements.txt 里） |
| `p2pchat/platform/build-requirements.txt` | 打包工具链精确版本（PyInstaller / hooks-contrib / setuptools） | CI 与本地打包 |
| `p2pchat/requirements-lock.txt` | 本机**实测环境**的精确记录（含 PySide6-Essentials 6.12.0 / shiboken6 6.12.0 及 wheel 大小与 sha256） | `README.md` 的本地环境安装命令、`DELIVERY.md` / `VERIFICATION-*.md` 的冻结哈希记录、`licenses/PYSIDE6-NOTICE.txt` 的合规记录 |

**保持一致**：同一个包同时出现在两处时版本必须相容；桌面 GUI 在 `requirements.txt` 里
固定为 `PySide6-Essentials==6.12.0`，与锁文件记录的已测版本、`licenses/PYSIDE6-NOTICE.txt`
里的 wheel sha256 完全一致（它的元数据自带 `shiboken6==6.12.0`，所以绑定运行时版本也被固定）。
CI 不安装锁文件（它装 requirements.txt + constraints.txt），这一点在本轮已如实报告给 captain；
本轮**没有**改 `.github/`，也没有删除锁文件。

**防漂移**：`p2pchat/tests/desktop/test_declared_dependencies.py` 会扫描产品代码
（`p2pchat/*.py`、`python_desktop/`、`native/`、`backend/`，外加 `tools/*.py`）里 import 的
第三方顶层模块，断言它们都在 `requirements.txt`（`tools/` 可为 `build-requirements.txt`）里声明；
标准库自动放过，确需豁免的（可选依赖、平台专有）只能进显式白名单并**逐条写明理由**，
已声明的包反过来写豁免会被判为多余。它还会断言扫描真的看到了已知第三方模块、requirements
真的解析出了核心包，避免检查退化成“零 imports → 全绿”。

这道门就是 CI run 38191690337 事故的产物：当时 Qt 依赖只写在锁文件里，CI 装的
`requirements.txt` 没有它，`test_ui.py` 在**收集阶段**就因 `ModuleNotFoundError: No module named 'PySide6'`
让三个平台一起红。现在把 PySide6 声明进 requirements.txt 之后，CI 的既有安装命令即可满足导入。

### LGPL 合规（Qt / PySide6）

`PySide6-Essentials==6.12.0` + `shiboken6==6.12.0`（LGPL-3.0-only；wheel 元数据写作
`LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`，本项目选 LGPL），版本与 wheel 校验值记在
`p2pchat/requirements-lock.txt`，合规说明在 `p2pchat/python_desktop/licenses/PYSIDE6-NOTICE.txt`：

- **动态链接**：Qt 库与 PySide6/shiboken6 扩展模块以独立 `.so` 放在包里（`_internal/PySide6/…`），没有静态链接、没有包装改许可；
- **不改二进制**：包里的 Qt/PySide6 与上面两个 wheel 一致，构建过程不 patch 它们；
- **许可证文本随包**：`licenses/LGPL-3.0.txt`、`licenses/GPL-3.0.txt`（LGPL-3.0 引用 GPL-3.0 条款）由 spec 复制进包，源码树里也有一份；
- **不引入 WebEngine**：只 import `QtCore/QtGui/QtWidgets`，没有 Qt WebEngine/Quick/商业组件或静态插件。

## 六、不做什么

- 不部署公网服务、不改宿主防火墙；
- 路由器放行**默认关闭**：不会在启动/连接/后台时申请任何端口映射，也**不会自动修改路由器**；只有你点「让路由器开一个端口」并在弹出的同意说明里确认后，才会尝试**一次**映射（`docs/GATEWAY-OPTIN.md` 是这条的完整规则：只申请映射、用完可撤销、失败如实说明、不能传消息）。同网段直连发现同样默认关闭、需要单独同意，且生产模式拒绝回环地址（回环只用于测试并会标注「不算局域网证据」）；
- 不把 ICE 的三种地址组合说成三种独立协议（它们是同一个 WebRTC 协议的地址族策略）；
- 不把同机或模拟结果当成真实家宽证据；
- 不静默改走其它通道：直连不成功就是失败，界面按用户能懂的话说明原因。
