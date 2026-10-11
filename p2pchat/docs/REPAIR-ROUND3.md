# Round 3：R5 精确候选挑战重放修复

仅修复多候选认证的新缺口，不改v1消息格式、不把缺陷扩大描述成QUIC TLS身份绕过。旧round2源码bfac700a…与独立review证据保留原结论；此轮重新冻结与重建。

## 修改

`Attempt.signal`为每个新可信远端tuple构造独立Auth，保留其自动生成的32字节随机nonce，不再复制attempt共用nonce。hello-ack必须echo当前候选自己的nonce且MAC正确，因此另一个候选完整捕获proof对不能满足该tuple挑战。密钥、connectionId、attemptId、peer身份、socketId、证书及精确接收source约束不变。

不对本地/远端地址字符串增加跨端相等要求：NAT两端观察到的tuple可能不同；两端各自在接收source对应的Auth状态维护随机challenge及对方nonce，以nonce回显建立双向证明。同socket调度、首host黑洞后trickle srflx、QUIC后续TLS仍保持。

## 新增有界真实socket负例

[test_candidate_nonce.py](../tests/native/test_candidate_nonce.py)：

- 一个可信候选实际收到探测包后生成并捕获完整hello+ACK wire bytes，不先回给源；从另一个已信令tuple原样重放，两种报文次序都拒绝升direct。测试明确不重签proof、不改nonce。随后将同样报文从原正确候选返回能成功，避免“全部拒绝”假通过。
- 两个真实原生端点经受控UDP地址转换，分别阻断两个方向；UDP probe和QUIC共四个组合都timeout，不出现direct或data。
- 旧split-proof测试现在使用具体candidate的实际challenge，保留原分拆负例语义；新增完整proof复制负例独立覆盖旧漏洞。
- 原host sink→srflx转换正例、同fd/port QUIC双向64KiB、错key/cert/socket/source及资源限额继续运行。

这些为本机可控socket/转换实验，不是家宽、真实网关、跨平台实机证明；不发公网流量、不添加relay产品功能。冻结和产物SHA256见 [FREEZE](FREEZE.json)、[SOURCE-MANIFEST](SOURCE-MANIFEST.json)。

## 复测

最终Python全套58 passed（8项AppKey建议警告，80.37秒）；client/platform Node34 passed；真实native应用管线4 passed；sync:web退出0。新增6项真实socket负例与原候选回归合计13 passed。Linux包以本轮源码重建，冻结和随包manifest另校验，不复用旧包。

```sh
.venv/bin/python -m pytest p2pchat/tests -q
node --test p2pchat/tests/client/*.test.cjs p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/integration/*.test.cjs
npm --prefix p2pchat run sync:web
npm --prefix p2pchat run dist:linux
```
