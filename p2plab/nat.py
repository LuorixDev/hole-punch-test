from __future__ import annotations

import ipaddress

LABELS = {
    1: "NAT1 公网直连",
    2: "NAT2 完全锥形",
    3: "NAT3 受限锥形",
    4: "NAT4 目的相关映射",
}


def assess_nat(probes):
    """Classify IPv4 UDP behavior only when mapping and filtering evidence support it."""
    if not probes:
        return {"state": "not-tested", "level": None, "label": "未测", "evidence": []}

    probe = probes[-1]
    mapping = probe.get("mapping")
    filtering = probe.get("filtering")
    samples = probe.get("samples", [])
    local = probe.get("local")
    evidence = []

    if isinstance(local, list) and len(local) == 2:
        try:
            address = ipaddress.ip_address(local[0])
            if address.version == 4 and address.is_global and any(
                sample.get("mapped") == local for sample in samples
            ):
                evidence.append("本地 UDP 地址与 STUN 映射地址/端口一致且为公网地址")
                return {"state": "classified", "level": 1, "label": LABELS[1], "evidence": evidence}
        except ValueError:
            pass

    if mapping == "destination-dependent-observed":
        evidence.append("同一 UDP socket 对不同 STUN 目标观察到不同映射；目的相关行为会降低直连成功率")
        return {"state": "classified", "level": 4, "label": LABELS[4], "evidence": evidence}

    if mapping == "endpoint-independent-observed":
        evidence.append("同一 UDP socket 对不同 STUN 目标保持相同映射")
        if filtering == "endpoint-independent-observed":
            evidence.append("RFC 5780 变更源地址与端口回包成功")
            return {"state": "classified", "level": 2, "label": LABELS[2], "evidence": evidence}
        if filtering in (
            "address-dependent-or-change-ip-loss",
            "address-and-port-dependent-or-network-loss",
        ):
            evidence.append("RFC 5780 变更源回包未到达；受丢包影响，过滤类型为推断")
            return {
                "state": "classified",
                "level": 3,
                "label": "NAT3? 受限过滤（推测）",
                "evidence": evidence,
            }

    reason = "STUN/过滤行为证据不足，或探测点不支持 RFC 5780"
    if mapping:
        reason += f"（映射：{mapping}）"
    if filtering:
        reason += f"（过滤：{filtering}）"
    evidence.append(reason)
    return {"state": "inconclusive", "level": None, "label": "证据不足", "evidence": evidence}
