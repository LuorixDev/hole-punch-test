# 网页版三屏流程与状态机

界面文案的唯一来源是 [METHODS-PLAIN.md](METHODS-PLAIN.md)；本文只写**流程、状态和数据来源**，不另起一套说法。
实现位置：`p2pchat/web/index.html`、`style.css`、`ux.js`（展示与状态判定）、`app.js`（把真实连接状态喂给 `ux.js`）。
测试：`p2pchat/tests/client/ux-flow.test.cjs`（三屏、文案、状态、并行语义），`app.test.cjs`（启动与信令回归）。

## 用户要求 → 三屏

用户原话：第一个界面连接服务器、第二个界面逐个尝试、发现有可用的进入聊天界面、右上角设置可查看剩余方式和延迟可用性测速；打洞界面要用人话说明每条是什么方式。

| 屏 | DOM | 只做这件事 | 不在这里做 |
|---|---|---|---|
| 第 1 屏 | `#screen-connect` | 服务器地址 / 房间 / 昵称 / 房间密码（8–256 字符），连接按钮与错误提示（`#connection-error`） | 不列任何打洞方式，不显示设置入口 |
| 第 2 屏 | `#screen-attempt` | 按固定顺序逐条列出九种方式：人话名称、一句话说明、什么网络可行、失败最常见的原因、状态、实测延迟；任一方式可聊天就自动进入第 3 屏 | 不能发消息（消息只在已确认的直连上发） |
| 第 3 屏 | `#screen-chat` | 聊天：文本 / 图片 / 文件 / 录音语音；右上角 `#open-settings` 打开设置面板 | 不把失败或未测显示成成功 |

设置面板（`#settings-panel`）在页面里只有一份：**剩余方式**（`#remaining`）、**可用性**（`#availability`）、**每条方式的延迟与实测值**（`#paths` 中每一行）、**测速**（`#speed` / `#stop-speed` / `#benchmark-result`）。第 2 屏也有一个 `#attempt-settings` 按钮可以打开同一份面板。

## 三屏状态机

屏幕切换由 `app.js` 的 `showScreen()` 执行；唯一的判定函数是 `ux.js` 的 `screen(current,{joined,connecting,paths})`：

```
能聊天的直连存在            → chat        （任一成功立即进入第 3 屏）
没有直连 且 未加入服务器     → connect     （含：离开、被登出、信令断开且没有可用直连）
没有直连 且 已加入服务器     → attempt
已加入 且 当前在 chat       → chat        （粘住：后台某条方式失败不把用户踢出聊天）
```

要点：

- **进入聊天的条件**是存在 `state==='direct' && canMessage===true` 的路径。仅 `state==='direct'` 但没有完成「可以传消息」校验的路径**不算**成功，第 2 屏显示「不可用」，第 3 屏的 `#active-path` 也只会显示「连接尚未打通，消息不会发送」。
- **离开 / 断开**：`#leave` 清空路径、`joined=false`，状态机回到 `connect`。
- **信令掉线但直连还在**：路径仍在，状态机保持 `chat`，底部状态栏显示「信令离线 · 已有直连仍可用」。
- 第 1 屏停留期间 `connecting` 只用于文案提示，不额外增加屏幕。

## 第 2 屏每一行显示什么

固定顺序就是 METHODS-PLAIN.md 的顺序 1→9（双栈直连、IPv6 直连、IPv4 直连、UDP 探测、QUIC 加密直连、TCP 加密直连、TCP 同时打开、STUN 映射观测、路由器放行）。
顺序**不代表启动先后**：所有可用方式并行尝试，界面必须如实说明这一点（`copy.parallelNotice`）。

每一行渲染：人话名称（`title`）、状态徽标（`state`）、必要的限制徽标（`badges`）、一句话说明（`explain`）、「什么网络可行：…」（`worksWhen`）、「失败最常见的原因：…」（`commonFailure`）、本行当前进展（`detail`）、实测往返延迟与收发速率（没有测到就写「尚未测得」）。
内部代号（`ice-v6`、`ice-v4`、`ice-dual`、`udp-probe`、`quic`、`tcp`、`tcp-simopen`、`upnp` …）只允许出现在每一行折叠的「查看技术详情」里，**不能当标题**。

三种浏览器直连（双栈 / IPv6 / IPv4）是同一套 WebRTC 协议的三种地址选择，界面上必须这样讲，不能写成三个独立协议。

## 状态语义

| 状态 | 使用条件 |
|---|---|
| 等待中 | 还没开始尝试（等待加入服务器、等待对方加入、或排队中） |
| 尝试中 | 有该方式的路径且处于 `gathering/probing/authenticating/connecting` |
| 已打通 | 路径 `direct` 且 `canMessage`（只有能聊天的路径） |
| 已观测 | 只能探测/观测的方式（UDP 探测、STUN 映射观测）得到结果；同行标注「仅探测，不传内容」 |
| 不可用 | 试过但失败（`failed/timeout/closed`），或连接建立但未确认可传消息；`detail` 用人话给出原因 |
| 不支持 | 平台/配置用不了：网页与安卓没有桌面网络组件、安卓不支持路由器放行、服务器没给 STUN 观测地址、浏览器没有 WebRTC |

「已观测」存在的唯一理由：METHODS-PLAIN.md 把「已打通」定义为**可以用来聊天**，而 UDP 探测和 STUN 观测不具备这个能力，把它们写成「已打通」就是把没打通说成打通。除这两条外，界面不新增任何状态词。

## 并行尝试语义

- 九条方式并行尝试；第一条 `direct && canMessage` 的路径成功 → 立即进入第 3 屏，`#active-path` 显示该方式名称与实测延迟。
- 其余方式**继续在后台尝试**，界面不因进入聊天而停止它们；状态变化继续刷新第 3 屏右上角设置里的列表。
- 后续更优的方式成功后，用户可以在设置面板里用「用于聊天」把当前聊天切到那条路径。
- 失败的方式留在「剩余方式」之外、进「不可用」，附带人话原因；**不会**被重写成成功，也**不会**改走服务器。

## 数据来源

| 界面元素 | 来源 |
|---|---|
| 方式名称与说明 | `ux.js` 的 `methods`（逐字对应 METHODS-PLAIN.md） |
| 状态 / 延迟 | `app.js` 维护的 `paths`（每条 `attemptId` 的 `state/canMessage/rttMs/rxRate/txRate/failureCode`） |
| 桌面/原生方式可用性 | `NativeAdapter.capabilities()` 的结果（`nativeMethods`）；浏览器与安卓拿不到就显示「不支持」 |
| STUN 观测 | `welcome` 里的 `iceServers`（只保留 `stun:`/`stuns:`）＋ WebRTC 路径的 `gathering`/`tuple` |
| 安卓差异 | `window.p2pPlatform.platform==='android'` → 路由器放行显示「不支持」 |
| 测速 | `transfers.bench()` 独立通道，结果标注「这是应用层速度，不是线路带宽」 |

## 严格无中继

界面上任何位置都不得出现「TURN / 中继 / 服务器转发 / 服务器代传」作为**可用选项**；这些词只允许出现在「没有…」「不会…」的否定句里。
`ux.js` 的 `copy.relayNotice`、`copy.stunNotice`、`copy.probeNotice` 与 `index.html` 第 2 屏、设置面板的「安全与测量边界」共同保证这一点，测试会逐句检查否定语义。
找不到直连就是明确失败：产品没有中继、没有 TURN、没有服务器代传，也不会因为直连失败就改走服务器转发聊天。

## 怎么跑

```
node --test p2pchat/tests/client
```

`node --test <目录>` 在 Node 26 会展开目录内 `*.test.cjs`；Node 24 不再展开目录参数，会把目录当模块加载。
因此 `p2pchat/tests/client/index.js` 只做一件事：按文件名顺序加载同目录的测试文件，不含断言、不改变任何测试行为。
两个版本上这条命令都必须通过；也可以显式跑 `node --test p2pchat/tests/client/*.test.cjs`。

三屏的**观感**可以在不连服务器的情况下人工检查：用任意静态服务器打开 `p2pchat/tests/client/render-harness.html?phase=1|2|3|4`
（同一份 index.html 结构 + 同一份 style.css/ux.js/app.js，状态由页面脚本注入）。那只是看排版用的模拟页：
页面顶部有红条声明「模拟数据」，它**不是**连通性证据，也不能拿来证明任何真实网络或真实家宽可用。
