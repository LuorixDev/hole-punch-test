def explanation(spec):
    method = spec.get("method", "")
    descriptions = {
        "quic-sync": "控制信道测 RTT/2 后协调双方发 UDP；不依赖两端墙钟同步；认证后保持同 socket 建立 QUIC",
        "quic-ttl": "低 TTL / IPv6 Hop Limit 预热本端 NAT 或防火墙状态，恢复正常跳数后再认证并建立 QUIC",
        "prediction-wide": "验证固定端口步长后扩大预测窗口，容忍有限并发偏移，分别覆盖观察到的多个公网 IP；认证后用原 socket 建立 QUIC",
        "udp-birthday": "单侧生日碰撞：一端使用多 socket，另一端在已观察到的对端 IP 上有限随机探测端口；双方认证并协商获胜 socket，再建立 QUIC",
        "udp-birthday-dual": "双侧生日碰撞：两端均使用 socket 阵列与有限端口探测；不套用单侧碰撞概率，不承诺必通",
        "udp-port-search": "分轮端口搜索：把对端端口范围分段，多轮有限探测；只访问配对对端已交换的 IP，保留认证获胜 socket",
        "tcp-race": "TCP 监听与连接竞争：同本地端口同时 listen 和多候选 connect，两端协调选择同一条经 TLS 与应用认证的连接",
        "tcp-sync": "TCP RTT 同步打洞：双方准备后以控制通道 RTT/2 协调 SYN，用 TLS 与应用握手验证；无普通监听兜底",
        "tcp-ttl": "TCP 低 TTL SYN 预热：先以有限跳数建立本端状态，再恢复默认 TTL 继续 connect；需要真实内核与网关支持",
        "tcp-stunt": "STUNT #2 连接反转：双方低 TTL connect 建立网关状态，撤销原 socket 后以同端口重新监听或主动连接；再用 TLS 认证，不保证网关保留原状态",
        "lan": "主动局域网发现：签名广播/组播发现已配对端点，不依赖公网 NAT 候选；验证同端点 UDP/QUIC",
        "hairpin": "NAT hairpin 回环诊断：从原 UDP socket 向自己观察到的外部映射发送签名挑战；仅回环证据，不算对端聊天通道",
        "nat64": "NAT64 跨族打洞：IPv6 端发现转换前缀并合成 IPv4 对端地址，通过 STUN 观察转换后的 IPv4 映射，再验证原 socket 的 QUIC",
        "ice-tcp": "原生 libnice ICE-TCP：仅采集/检查库实际支持的 TCP 候选，通常为 active/passive；可靠流之上用 TLS 与应用握手认证，禁用 TURN，不保证生成 so 候选",
        "ice-native": "原生 libnice ICE-UDP：无中继的 UDP ICE 与 PseudoTCP 可靠流；再以 TLS 与应用握手认证，不把它算成新的 NAT 类型",
        "utp": "uTP 对照传输：使用原生 libutp 的拥塞控制可靠 UDP 流与端点协调，TLS 应用数据仅点对点发送",
        "pwnat": "pwnat ICMP 关联实验：向观察服务器发送 Echo，对端注入引用该报文的 Time Exceeded，检查 NAT 是否交付关联错误，再认证 UDP/QUIC；需原始 socket 权限，回包与聊天成功分开记录",
        "natblaster": "NATBlaster 原始 TCP 实验：抓取低 TTL SYN 的内核序列号，经信令交换后注入 SYNACK，让内核完成连接，再验证 TLS；需 Linux 原始 socket 权限，不保证 NAT 支持",
    }
    if method in descriptions:
        return descriptions[method]
    if method.endswith("-tcp"):
        return "TCP 网关放行：" + gateway_description(method[:-4]) + "；用原监听端口的 TLS 验证，租约响应不等于连通"
    if method in ("upnp-any", "pcp-peer", "pcp-filter", "pcp-prefer"):
        return gateway_description(method) + "；在原 UDP socket 上认证并验证 QUIC，租约响应不等于连通"
    return None


def gateway_description(method):
    return {
        "upnp": "请求 UPnP IGD AddPortMapping 转发",
        "upnp-any": "请求 UPnP IGDv2 AddAnyPortMapping，由网关选择可用外部端口",
        "natpmp": "请求 NAT-PMP 转发",
        "pcp": "请求 PCP MAP 映射或防火墙放行",
        "pcp-peer": "请求 PCP PEER，为指定对端创建/维护目的相关状态",
        "pcp-filter": "请求 PCP MAP + FILTER，仅允许指定对端地址和端口",
        "pcp-prefer": "请求 PCP MAP + PREFER_FAILURE，要求保留请求的端口，否则明确失败",
        "pinhole": "请求 UPnP IPv6 AddPinhole 为指定对端开孔",
    }.get(method, method)
