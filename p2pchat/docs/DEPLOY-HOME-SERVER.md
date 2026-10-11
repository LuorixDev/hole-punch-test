# 家宽服务器部署手册（Python 信令 + STUN + 集中日志）

这份文档教你**在自己家的服务器上**启动 P2P 服务端，让公网上的客户端（网页版 / 桌面版 / 安卓）能连上来。

> **诚实标注（请先读这三条）**
> 1. **本仓库没有在任何用户的家宽服务器上部署过。** 下面的步骤是按代码的实际行为写的，但"照抄就一定成功"需要你在自己机器上验证。
> 2. **家宽双 NAT / CGNAT 能不能打通，必须实测。** 服务端能启动 ≠ 两台设备能直连。很多家宽在运营商侧还有一层 NAT，或者 IPv4 只给了 CGNAT 地址，这种情况下 IPv4 直连会失败。
> 3. **STUN 只观测地址映射，不保证成功，也不中继数据。** 本产品没有 TURN、没有中继、服务端不转发聊天内容；直连失败就是失败。
>
> 文档里所有域名、邮箱、路径都是**明显的占位符**（`p2p.example`、`<YOUR_...>`），必须换成你自己的值。`p2p.example` 是保留示例域名，永远不会解析到你的机器。

---

## 0. 这套服务端到底做什么

| 它做 | 它不做 |
|---|---|
| 让同一个房间的人互相"看见"（信令） | 不转发聊天消息、不存聊天内容 |
| 回答 STUN 绑定请求，告诉客户端"你在我眼里是什么地址" | 不做 TURN、不做端口分配、不当中继 |
| 收集**不含聊天内容**的诊断事件（限额、脱敏、保留 7 天） | 不提供任何读取聊天/文件的路由 |
| 提供一个静态网页（客户端界面）和 `/health` 健康检查 | 不代替客户端做打洞决策 |

服务端启动时会强制：

* 公网绑定（非回环地址）**必须**同时给 `--cert/--key` 和至少一个 `--origin`，否则直接拒绝启动；
* `--origin` 是**精确匹配**浏览器 `Origin` 头，不匹配就 403；
* 每个房间的加入靠"房间名 + 房间密码"派生的 HMAC 摘要，服务端只存摘要（在数据目录的 SQLite 里），不存密码明文；
* 单房间最多 12 人、信令消息 ≤ 128 KiB、单文件 ≤ 32 MiB、房间默认 3600 秒后过期。

---

## 1. 需要准备什么

| 项目 | 说明 |
|---|---|
| 一台常开的机器 | 家里的旧电脑 / 小主机 / NAS 都行；**不用**给它开 root 登录 |
| Python | 3.10 或更高（仓库开发环境是 3.12） |
| 一个域名 | 例如 `p2p.example`，把这个域名的 A（IPv4）和/或 AAAA（IPv6）记录指向你家宽的公网地址 |
| TLS 证书 | 用 Let's Encrypt 免费证书即可（下面第 3 节） |
| 两个端口 | TCP 控制端口（本文用 `8088`）+ UDP `3478`（STUN） |
| 能登录路由器 | 用于端口映射 / 放行（本文不代替你做这一步） |

**不要用 1024 以下的端口**（80/443 需要额外权限或 root）。用 `8088` / `3478` 就行。

---

## 2. 部署前先体检（强烈建议，一条命令）

仓库自带只读体检工具，**不需要 root，不改任何系统配置，不替你开端口**：

```bash
# 先按第 4 节把证书和域名准备好，再执行：
python -m p2pchat.tools.server_preflight \
  --host 0.0.0.0 --host :: \
  --port 8088 \
  --stun-host 0.0.0.0 --stun-host :: \
  --stun-port 3478 \
  --stun-url stun:p2p.example:3478 \
  --domain p2p.example \
  --cert /etc/letsencrypt/live/p2p.example/fullchain.pem \
  --key  /etc/letsencrypt/live/p2p.example/privkey.pem \
  --origin https://p2p.example \
  --data ~/p2p-data \
  --self-check
```

它会逐项给出「通过 / 提醒 / 阻断」和人话解释，最后给一句结论。退出码：`0` = 没有阻断项，`1` = 有阻断项，`2` = 参数写错。

体检覆盖：

1. Python 版本与依赖是否齐全；
2. 有没有可用的**全局 IPv6** 地址（回环 / 链路本地 / ULA 不算）；
3. 有没有 IPv4 出口；
4. 证书与私钥能不能读、域名是否匹配、私钥和证书是否配对、还剩多少天；
5. `--origin` 写法，以及（可选）和客户端实际来源是否一致；
6. `--data` 数据目录能不能写、权限是否过宽；
7. 信令 TCP 端口和 UDP `3478` 现在能不能绑定；还会按你给的 `--host` 列出它在监听哪个地址族、
   并提示"下发了 --stun-url 但只绑回环"这类矛盾配置；
8. `--self-check`：临时起一组 server + echo + client，做一次**真实的 HMAC 身份握手 + ICE 协商**，并报告实际用上的方式（例如 `ice-v4`、地址族、候选类型）。这是"代码在本机能跑通"的证据，**不是**家宽可打通的证据。自检会依次用回环地址 `127.0.0.1` 和 `::1` 各试一次（先成功即停），不会因为 `--host ::` 就误报"代码跑不通"。

边界说明：

* 体检工具只读：唯一的写操作是在 `--data` 目录里建一个临时文件立刻删掉（写权限探测），以及 `--self-check` 时在该目录下建 `_selfcheck/` 放临时日志、跑完删除；
* 除你显式传入的 `--stun-url` / `--probe-url` 外不访问外部服务；`--probe-url` 只允许本机地址；
* 输出默认不含私钥内容、房间密码；JSON 输出默认把完整路径收敛成文件名（要完整路径加 `--json-paths`）。

---

## 3. 域名与 TLS 证书

### 3.1 域名

在你域名的 DNS 服务商处添加：

| 类型 | 名称 | 值 |
|---|---|---|
| A | `p2p.example` | 你家宽的公网 IPv4 |
| AAAA | `p2p.example` | 你家宽下发给这台机器的全局 IPv6 地址 |

> 家宽的公网 IP 可能会变（PPPoE 重播、运营商回收）。要么用 DNS 服务商的动态 DNS（DDNS）功能，要么接受"IP 变了就得手改记录"。
> 如果你家的 IPv4 是 CGNAT 地址（`100.64.0.0/10` 那一类），A 记录对外没有意义——IPv4 只能靠客户端侧打洞，别指望它。

验证解析（在你家服务器上执行）：

```bash
dig +short A    p2p.example
dig +short AAAA p2p.example
```

### 3.2 证书

**最省事的办法**：certbot 申请证书，并把自动续期交给 systemd timer。

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d p2p.example       # 80 端口空闲时可用
```

> `--standalone` 需要 80 端口空闲；如果 80 被占用，改用 `--webroot` 或 DNS 插件。这一步需要 sudo，**它属于你的系统运维，不属于本项目**。
> 证书路径（占位符，按你实际域名替换）：
> * 证书链 `/etc/letsencrypt/live/p2p.example/fullchain.pem`
> * 私钥 `/etc/letsencrypt/live/p2p.example/privkey.pem`

自动续期检查：

```bash
systemctl list-timers | grep certbot
sudo certbot renew --dry-run
```

**续期后要重启服务**才生效，加一个 hook：

```bash
# /etc/letsencrypt/renewal-hooks/deploy/restart-p2pchat.sh
#!/bin/sh
systemctl restart p2pchat-signaling
```

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-p2pchat.sh
```

想让 systemd 的运行用户读到私钥，见第 5 节（推荐做法是加一个 `letsencrypt` 组，而不是把私钥权限开成 644）。

---

## 4. 服务账号与数据目录

**不要用 root 跑服务端。**

```bash
# 1) 建一个没有登录 shell 的服务账号（把 <YOUR_SERVER_USER> 换成你想起的名字）
sudo useradd --system --create-home --shell /usr/sbin/nologin <YOUR_SERVER_USER>

# 2) 数据目录：中心日志与去重用的盐会写在这里
sudo mkdir -p /srv/p2p-data
sudo chown <YOUR_SERVER_USER>:<YOUR_SERVER_USER> /srv/p2p-data
sudo chmod 700 /srv/p2p-data

# 3) 让服务账号能读私钥（比把私钥改成 644 安全）
sudo groupadd -f letsencrypt
sudo usermod -aG letsencrypt <YOUR_SERVER_USER>
sudo chgrp -R letsencrypt /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
sudo find /etc/letsencrypt/archive -name 'privkey*.pem' -exec chmod 640 {} \;
```

数据目录里会出现：

| 文件 | 内容 |
|---|---|
| `server.jsonl` | 服务端事件日志（房间名以摘要形式出现，**不含聊天内容**） |
| `events.sqlite3` | 客户端上报的诊断事件（白名单字段、限额、保留 7 天） |
| `server.jsonl.1` | 滚动出来的上一份日志 |

---

## 5. 启动命令

```bash
cd <FULL_PATH_TO_REPO>          # 例如 /srv/p2pchat
python -m p2pchat.server \
  --host 0.0.0.0 --host :: \
  --port 8088 \
  --stun-host 0.0.0.0 --stun-host :: \
  --stun-port 3478 \
  --data /srv/p2p-data \
  --cert /etc/letsencrypt/live/p2p.example/fullchain.pem \
  --key  /etc/letsencrypt/live/p2p.example/privkey.pem \
  --origin https://p2p.example \
  --stun-url stun:p2p.example:3478
```

参数逐条说明：

| 参数 | 含义 | 注意 |
|---|---|---|
| `--host 0.0.0.0 --host ::` | **可重复**：每个值建一个独立监听站点。两个都写，就是单进程真双栈 | 每个站点的监听套接字都是 `IPV6_V6ONLY`，所以同一端口上两族并存、互不遮挡（不是靠关掉 V6ONLY 或"未指定地址"的隐式回退）。只写一个就只收那一族。默认（不写）仍是 `127.0.0.1`，只给本机用 |
| `--port 8088` | 信令 / 控制 TCP 端口，也是网页和 `/health` 的端口 | 所有 `--host` 站点共用这一个端口；不要用 1024 以下 |
| `--stun-host 0.0.0.0 --stun-host ::` | STUN 的 **UDP** 绑定地址，可重复 | **两个都要写**：只写 `::` 就只收 IPv6（STUN 侧代码自己设了 `IPV6_V6ONLY`，同样是单族）；不写就只绑 `127.0.0.1` 和 `::1`，外网客户端根本够不着 STUN |
| `--stun-port 3478` | STUN 的 UDP 端口 | 要在路由器上放行 |
| `--data` | 数据目录 | 必须让运行用户可写。**所有监听站点共用同一个 Store**，所以不存在跨进程 SQLite 写锁竞争 |
| `--cert` / `--key` | TLS 证书链和私钥 | **只要有一个 `--host` 不是回环就必须给**，且必须成对 |
| `--origin` | 允许的浏览器来源，**精确匹配**，可重复 | 必须和客户端实际来源一致：协议 + 主机 + 端口，**不带结尾斜杠**。浏览器网页版是你地址栏的来源（例如 `https://p2p.example`；走非标端口就写 `https://p2p.example:8443`）；**安卓 APK 的页面来源固定在 `http://localhost`**，所以要让它连你的服务器必须再写一条 `--origin http://localhost`（若你把 `androidScheme` 改回 `https`，则对应 `https://localhost`）。多个客户端就写多条 |
| `--stun-url` | 可选：下发给客户端的 STUN 地址，例如 `stun:p2p.example:3478` | **只接受 `stun:` 前缀**。写 `turn:` 会被拒绝（本产品禁止中继）。不写这一项，客户端就把"STUN 映射观测"显示为不可用 |

> **实测记录（本仓库 Linux 开发机上验证，供你参照）**：`--host 0.0.0.0 --host ::` 时
> `ss -lntp` 同时显示 `0.0.0.0:8088` 与 `[::]:8088`（同一个进程、同一端口），
> 从 `127.0.0.1` 和 `::1` 分别发起真实 WS 升级 + 加入同一房间都成功，且 IPv4 侧的成员能看到
> IPv6 侧成员出现在花名册里（证明是同一个进程、同一份状态）。
> 只写一个 `--host` 时，另一族连接被拒绝（没有隐式双栈）。
> `--stun-host 0.0.0.0 --stun-host ::` 时两个地址族都能收到 STUN 回复。
> **Windows / macOS 未实测**：上面这些结论只在 Linux 上成立，那两个平台请自己重跑
> 体检与测试，不要用 Linux 结论代替。
> 你自己的系统上再用体检工具确认一遍。

先手工前台跑一遍，确认没有报错：

```bash
# 前台试跑（Ctrl+C 结束）
python -m p2pchat.server --host 0.0.0.0 --host :: --port 8088 \
  --stun-host 0.0.0.0 --stun-host :: \
  --stun-port 3478 --data /srv/p2p-data --cert ... --key ... \
  --origin https://p2p.example --stun-url stun:p2p.example:3478

# 另一个终端确认两个地址族都活着
curl -sS https://p2p.example:8088/health
curl -sS "https://[<你的IPv6地址>]:8088/health"
# 期望：{"ok":true,"mode":"strict-p2p","peers":0,"role":"signaling-stun"}
```

启动日志会逐个打印实际绑定的地址，例如：

```
INFO:p2pchat:signaling listening on 0.0.0.0:8088 (IPv4, requested --host 0.0.0.0); every site shares one Store/data dir
INFO:p2pchat:signaling listening on [::]:8088 (IPv6, requested --host ::); every site shares one Store/data dir
```

看到这两行，就说明双栈真的起来了；只看到一行就说明你只传了一个 `--host`。

本仓库**不会**替你启动服务、写 systemd 单元、开端口或改防火墙。下面几节是给你照抄的模板，执行与否由你决定。

### 5.1 关于双栈的常见误配

* **`--host` 只能写一次？** 不是。它和 `--stun-host` 一样可以重复，写几次就建几个站点。
* **只想收 IPv6？** 只写 `--host ::`（服务器没有公网 IPv4 时就这样），此时 IPv4 客户端会被拒绝。
* **同一端口两族能并存吗？** 能。每个站点的套接字都是 `V6ONLY`，IPv6 站点不会把 IPv4 也收走，
  所以 `--host 0.0.0.0 --host ::` 可以共用一个 `--port`。
* **要不要再起第二个进程或 socat？** 不需要。单进程多站点共享同一个 Store/数据目录，
  比两个实例少一份日志、也没有跨进程写锁；文档早先版本里的"两个实例 / socat"说法已作废。


---

## 6. systemd 单元模板

`/etc/systemd/system/p2pchat-signaling.service`：

```ini
[Unit]
Description=Strict P2P signaling + STUN + central diagnostics
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<YOUR_SERVER_USER>
Group=<YOUR_SERVER_USER>
WorkingDirectory=<FULL_PATH_TO_REPO>
ExecStart=/usr/bin/python3 -m p2pchat.server \
  --host 0.0.0.0 \
  --host :: \
  --port 8088 \
  --stun-host 0.0.0.0 \
  --stun-host :: \
  --stun-port 3478 \
  --data /srv/p2p-data \
  --cert /etc/letsencrypt/live/p2p.example/fullchain.pem \
  --key  /etc/letsencrypt/live/p2p.example/privkey.pem \
  --origin https://p2p.example \
  --stun-url stun:p2p.example:3478
Restart=on-failure
RestartSec=5
# 私钥只能读、不能改
ReadOnlyPaths=/etc/letsencrypt
# 只允许写数据目录
ReadWritePaths=/srv/p2p-data
# 基础加固（如果启动失败，先注释掉这几行定位问题）
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

常用操作（**需要 sudo，属于你的运维动作**）：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now p2pchat-signaling
systemctl status p2pchat-signaling
journalctl -u p2pchat-signaling -f          # 看实时输出
journalctl -u p2pchat-signaling -n 200      # 看最近 200 行
```

> `ProtectSystem=strict` 会把整个文件系统挂成只读，只放开 `ReadWritePaths`。如果 `privateTmp` 或路径写错导致启动失败，先注释掉加固行确认服务本身没问题，再逐条加回来。
> 如果 `ExecStart` 里的 `/usr/bin/python3` 不是你装依赖的那个解释器，改成 `which python3` 的实际路径（用 venv 的话写 venv 里的绝对路径）。

### 6.1 双栈是一个单元，不是两个

`--host` 可重复，所以 **IPv4 和 IPv6 用同一个 systemd 单元、同一个进程**：

* 一个 `ExecStart` 里写 `--host 0.0.0.0 --host ::`；
* 两个站点共享同一个 `--data`，不会出现两份日志，也没有跨进程 SQLite 写锁；
* 日志里会出现两行 `signaling listening on ...`，分别对应 IPv4 和 IPv6；
* 只需要 `TCP 8088` + `UDP 3478` 各放行一次（不是两个端口）。

> 只有一种情况才需要第二个单元：你想让两族监听在**不同端口**（例如 443 给 IPv6、8443 给 IPv4）。
> 那样才需要两套 `--data`（避免两个进程同时写同一个 SQLite 库）。


---

## 7. 需要放行哪些端口

| 协议 | 端口 | 用途 | 必须？ |
|---|---|---|---|
| TCP | `8088`（你选的 --port） | 网页、WebSocket 信令、`/health`；`--host 0.0.0.0 --host ::` 时同一个端口同时服务 IPv4 与 IPv6 | **必须** |
| UDP | `3478`（你选的 --stun-port） | STUN 映射观测 | 想让客户端观测地址就要开 |
| TCP | `80` | 仅证书申请/续期时临时用 | 只在签/续证书时需要 |
| UDP | 客户端自己协商出来的高位端口 | 两台设备之间真正的直连数据 | **不要在服务器上放行**，这是两台客户端之间的事 |

### 7.1 路由器 / 光猫上的端口映射

到你家路由器的"端口转发 / NAT 映射"页面添加：

* `TCP 8088` → 这台服务器的内网地址 `:8088`（IPv4 与 IPv6 共用这一个端口）
* `UDP 3478` → 这台服务器的内网地址 `:3478`（STUN；同时给 IPv4 和 IPv6 映射到同一台机器）

> 这一步**只能你自己做**：本仓库不代替用户开端口、不修改宿主防火墙。
> 如果同一个端口在两台设备上都要用，注意路由器是否支持；有的光猫还会自己做一层 NAT（"桥接模式"能减少一层）。

### 7.2 主机防火墙（如果你开了的话）

按你的发行版选一条（仅供参考，执行前确认端口和网卡名）：

```bash
# ufw
sudo ufw allow 8088/tcp
sudo ufw allow 3478/udp
# firewalld
sudo firewall-cmd --permanent --add-port=8088/tcp
sudo firewall-cmd --permanent --add-port=3478/udp
sudo firewall-cmd --reload
# nftables/iptables 请按你自己的规则集谨慎添加
```

---

## 8. IPv6 入站的注意点

IPv6 和 IPv4 的"放行"是两套东西，很多人卡在这里：

1. **必须要有全局 IPv6 地址**。在这台服务器上执行 `ip -6 addr show scope global`，看不到 `2xxx:`/`3xxx:` 开头的地址就说明运营商没给。先在路由器上开启 IPv6（多为 `DHCPv6-PD` / `SLAAC`），再确认服务器拿到了地址。
2. **每个设备都有全局地址 ≠ 能入站**。运营商和路由器默认常常**只放行出站**：
   * 路由器上要允许"IPv6 入站 / 防火墙放行"到这台服务器的 `8088/tcp`（和 `3478/udp`）；
   * 有些运营商在 IPv6 上还拦入站，这种情况 IPv6 直连会失败，只能退回 IPv4 打洞。
3. **不要用 ULA 或链路本地地址当公网地址**（`fd00::/8`、`fe80::/10`）。体检工具的 IPv6 项会把这些算作"没有全局 IPv6"，这是故意的。
4. **IPv6 地址会随前缀变化**（运营商换前缀、路由器重启）。AAAA 记录最好交给 DDNS 维护。
5. **对称 NAT 与 IPv6 无关**：IPv6 没有 NAT，只要双向放行，直连通常比 IPv4 简单——所以家宽能拿到可用 IPv6 时，优先修 IPv6 这条路的性价比最高。
6. **单个监听套接字永远只服务一族的地址**：TCP 侧的 asyncio 强制 `IPV6_V6ONLY=1`，
   STUN 侧的代码自己也设了 `IPV6_V6ONLY=1`。**能同时收 IPv4 和 IPv6 不是因为某个套接字"顺手全收"，
   而是因为服务端给每个 `--host` 建了一个独立站点**（`--host 0.0.0.0 --host ::`）。
   只写一个 `--host` 时，另一族就是不接——这是刻意的，避免不同系统上出现"有时能连有时不能连"的隐式行为。

一个能说明问题的自检顺序（都在服务器本机执行，不需要外部服务）：

```bash
ip -6 addr show scope global          # 有没有全局 IPv6
ss -lntp | grep 8088                  # 双栈应当同时看到 0.0.0.0:8088 与 [::]:8088（同一个 pid）
ss -lnup | grep 3478                  # STUN 在哪些地址上监听
```

---

## 9. 怎么从外网验证可达

**不要在同机、同局域网里测完就说"成功"**——那是本机闭环，不是外网证据。

### 9.1 用手机蜂窝网络（关掉 Wi-Fi）验证

```bash
# 在手机热点上的笔记本执行（<...> 换成你的值）
curl -v https://p2p.example:8088/health
```

期望：证书校验通过、返回 JSON `{"ok":true,...}`。证书报错说明证书/域名/时间有问题；连不上说明端口映射、防火墙或 CGNAT 有问题。

### 9.2 看 WebSocket 能不能建起来

```bash
# 在手机热点上的笔记本执行
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Origin: https://p2p.example" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://p2p.example:8088/ws
```

* `101 Switching Protocols`：信令通；
* `403`：`--origin` 和你的 `Origin` 头不一致（这正是它该有的表现）；
* 连接超时：端口没通。

### 9.3 验证 STUN

```bash
# 需要 stun 客户端；没有就跳过，客户端里也能看到"STUN 映射观测"这一项的结果
stun p2p.example:3478            # 或
python -c "import socket,struct;print('发送 20 字节绑定请求并读回复')"
```

> STUN 的回复只告诉你"出口地址和端口是什么"。**它不代表能直连**：对称 NAT 下，观测到的端口和对方要用的端口不是同一个，打洞照样失败。

### 9.4 双向都测

* 一端在**家宽**、另一端在**手机热点**（不同运营商）各测一次；
* 两端都在家宽同运营商、或都在同一台机器上测 → **只能算本机事件，不能当外网证据**；
* 结果要记录：域名、时间、客户端类型、用的哪种方式、是否成功、失败原因。

### 9.5 安卓 APK 连你的服务器（来源与明文）

安卓 APK 不是浏览器：Capacitor 把网页装进 App 内部，页面来源固定为 `http://localhost`
（`p2pchat/capacitor.config.json` 里 `server.androidScheme: http`），所以：

* **必须在服务端加 `--origin http://localhost`**，否则 APK 的 WebSocket 升级会被 403 拒绝；
  这个来源与你的域名无关，手机连的是"你自己的服务器地址"，但 Origin 头永远是 `http://localhost`。
* 明文 `ws://`：APK 已经放行明文（`android/app/src/main/res/xml/network_security_config.xml`），
  你可以让手机用 `ws://<你的IP或域名>:8088/ws` 连；但**明文信令会被同一路径上的人读取和篡改**
  （房间密钥、SDP/ICE 候选都在里面），能配证书就配证书用 `wss://`。
* **限制**：网页客户端目前仍只允许 `ws://` 指向 loopback（`web/app.js`），
  所以在它放宽之前，手机在 APK 里填 `ws://` 到你的服务器地址会被前端拦下；
  用 `wss://` 则不受影响。详见 `p2pchat/docs/ANDROID-CLEARTEXT.md`。
* 录音依赖安全上下文：`http://localhost` 本身就是安全上下文（和 `https://localhost` 一样），
  所以改 scheme 不影响麦克风；但**真机录音、锁屏/后台行为在仓库里是 NOT_RUN，需要你自己实测**。

---

## 10. 查看中心日志与诊断

数据都在 `--data` 目录（本文是 `/srv/p2p-data`）：

```bash
# 最近的服务端事件（人话：谁进了哪个房间摘要、STUN 观测、错误原因）
tail -n 50 /srv/p2p-data/server.jsonl | python3 -m json.tool --json-lines

# 有没有报错（AUTH_FAILED / SCHEMA_INVALID / LIMIT_EXCEEDED / ROOM_EXPIRED ...）
grep -o '"event":"[^"]*"' /srv/p2p-data/server.jsonl | sort | uniq -c | sort -rn | head

# 客户端上报的诊断事件（白名单字段）
sqlite3 /srv/p2p-data/events.sqlite3 \
  "SELECT datetime(received,'unixepoch','localtime') AS t, peer, body
   FROM diagnostics ORDER BY received DESC LIMIT 20;"
```

要点：

* **日志里不会有聊天内容**。文本、文件、图片、录音都只在两台客户端之间走直连；服务端只记录"发生过一次传输、多少字节、成功与否"这类白名单字段。
* 客户端上报的每个事件都带 `clientSessionId`，用它可以把本地日志和中心日志对上；
* 体积限额：`server.jsonl` 单份超过 25 MiB 会滚动成 `.jsonl.1`；SQLite 侧按 100 MiB 预算裁剪；都保留 7 天；
* 房间名在日志里只以 HMAC 摘要（`scope`）出现，**不要**试图从日志里还原房间名或密码。

---

## 11. 停机、更新与清理

```bash
# 停机
sudo systemctl stop p2pchat-signaling

# 更新代码后重启（先新开一个终端跑前台验证，再切回 systemd）
cd <FULL_PATH_TO_REPO> && git pull    # 由你自己决定是否/如何更新
sudo systemctl restart p2pchat-signaling

# 彻底停用（不想再开机自启）
sudo systemctl disable --now p2pchat-signaling
```

清理数据（**先确认你不需要这些诊断记录**）：

```bash
# 只清诊断数据，保留目录
rm -f /srv/p2p-data/server.jsonl /srv/p2p-data/server.jsonl.1 /srv/p2p-data/events.sqlite3

# 连目录一起删
sudo rm -rf /srv/p2p-data
```

收尾清单（按需）：

* 路由器上删除 `TCP 8088` / `UDP 3478` 的端口映射；
* 主机防火墙里删除对应放行规则；
* 停用 certbot 的部署 hook（如果你加了）；
* `sudo systemctl disable certbot.timer`（仅当你不再续期其它证书）；
* 删除服务账号：`sudo userdel -r <YOUR_SERVER_USER>`。

---

## 12. 常见问题（人话版）

| 现象 | 最可能的原因 | 怎么确认 |
|---|---|---|
| 服务起不来，日志说 `public signaling requires TLS and --origin allowlist` | 绑了公网地址但少了 `--cert/--key` 或 `--origin` | 这是**故意的**安全限制，补齐参数即可 |
| 服务起不来，说读不到证书/私钥 | 运行用户没权限读 `/etc/letsencrypt` | 按第 4 节把用户加进 `letsencrypt` 组；体检工具会直接报 `KEY_UNREADABLE` |
| 浏览器打开就 `403` | `--origin` 和地址栏来源不一致（端口/协议/斜杠） | 用体检工具的 `--origin` 项核对；`curl` 的 `Origin` 头要一模一样 |
| 安卓 APK 连不上或 `403` | 少了 `--origin http://localhost`（APK 的页面来源永远是 `http://localhost`，和你的域名无关） | 启动参数里补上这一条；用 `-H "Origin: http://localhost"` 复现；见第 9.5 节 |
| 手机填 `ws://` 到你的服务器被前端拒绝 | 网页客户端目前只允许 `ws://` 指向 loopback（`web/app.js`） | 先改用 `wss://`；或按 `docs/ANDROID-CLEARTEXT.md` 第 8 节处理该策略 |
| 网页能开，但手机流量下连不上 | 端口映射没做 / 光猫还有一层 NAT / CGNAT | 手机热点上 `curl https://p2p.example:8088/health` |
| IPv6 能连、IPv4 客户端连不上 | 只传了一个 `--host`（例如只写了 `--host ::`） | 加上 `--host 0.0.0.0 --host ::`（同一端口，单进程双栈）；`ss -lntp` 要同时看到 `0.0.0.0:8088` 与 `[::]:8088` |
| 客户端说 STUN 不可用 | `--stun-url` 没配，或 STUN 只绑了回环 | `ss -lnup \| grep 3478`；体检工具的 STUN 项会直接报出来 |
| IPv6 地址有，但对方连不上 | 路由器/运营商只放行出站 | 第 8 节；这条不通就先走 IPv4 打洞 |
| 两端都连上服务器，但一直"不可用"，打不通 | 双方都在 CGNAT 后面 / UDP 被拦 / 都没有可用 IPv6 | 这是真实的网络限制，**没有中继可退**；换网络实测，或优先修 IPv6 |
| 房间进第二个密码不同的人被拒 | 这是对的：房间密码派生的摘要不一致 | `AUTH_FAILED`，不是 bug |
| 客户端显示"STUN 映射观测 已观测"但仍然不能聊天 | STUN 只是观测，不传内容 | 这是设计如此，见 `docs/METHODS-PLAIN.md` |

---

## 13. 最后再说一遍边界

* 本仓库**没有**在用户家宽上部署过；请以你机器上的体检结果和实测为准。
* **双栈监听只在 Linux 上实测过**：本手册里 `--host 0.0.0.0 --host ::` 的实测记录来自 Linux。
  Windows / macOS 未实测，那两个平台的行为必须自己重跑（见 `p2pchat/tests/backend/test_dual_stack.py`，
  该文件在这两个平台会被整体跳过，不会用 Linux 结论冒充）。
* **家宽双 NAT / CGNAT 能否打通必须实测**，服务端体检通过不能代替这个结论。
* **STUN 只观测映射，不保证成功**；本产品没有 TURN / 中继 / 服务端转发，直连失败就是失败。
* 本手册给你可照抄的步骤，但**开端口、改防火墙、装证书、起服务都是你的动作**，工具不会替你做，也不改宿主网络配置。
* Android / 桌面（Python + Tkinter）客户端目前仍在推进中；能确认的只有仓库里已有的实现与测试，本文不替它们背书。
