# t24：Windows关闭修复集成与重新冻结

**Windows修复待当前commit CI确认。** 本任务仅整合已审t22+t25变更、交付文档与构建产物，不扩大产品功能，不修改Peer/backend/native/web/tests/独立审查证据，不执行Git/push。当前源码与产物精确值在 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)、[FREEZE](FREEZE.json)；不用旧8687adf或旧Linux包冒充新版。

## 旧版本与本轮差异

旧`8687adf15b114380747308b43d78df29dd0634bc006a3e4d16215abeb4062388`、129文件的t15本地复验与t19审查仍只适用于旧版。其远端commit `a1c6e7e724390440d6422e4bb0b06804c9ba16a7` / run38124339483已终态：Linux/Android成功，Windows90秒诊断exit124、未打包。

诊断捕捉到的链：Peer.close→RTCPeerConnection.close→ICE.stop→aioice StunProtocol.close。这证明阻塞位置；Linux受控Proactor pending-write机制复现不等同完整Windows根因证明。

本轮合并已审修改：

- 新增 [rtc_shutdown.py](../backend/rtc_shutdown.py)：仅精确win32、Python3.12.10、aiortc1.15.0、aioice0.10.2及本PC精确ProactorDatagramTransport启用；正常close短grace后，只对is_closing的owned transport调用公开abort，再等原pc.close真正完成并检查socket fileno=-1。不伪造connection_lost、库Future或成功状态，不全局换event loop。
- Peer关闭共有幂等task、绝对deadline、shield；超时/required RTC或WS/path closer取消必须失败，稳定码P2P_CLOSE_CANCELLED，不输出closed成功。普通worker取消允许。无法合作的残余任务不承诺已释放，外层watchdog处理。
- 双echo测试等待真实benchmark通道open；测试cleanup保留body原错误和关闭异常，不吞原失败；新增正常/超时/取消/真实socket未释放负例。
- t9 README/CAPABILITIES/DELIVERY overlay现纳入新manifest；PLATFORMS同步版本分层。没有依赖/锁文件变化，77个既有native/web/desktop/platform/Android安全域文件在T26核对不变。

## 审查与回归来源

[独立T26](../review/windows/T26.md) pass：33项backend/core/独立关闭测试通过；原未经修改的真实UDP取消probe现在明确失败，W1解决。实现者t25：backend27通过、全套72通过、90秒诊断双echo2项通过exit0；这些全部是Linux证据。T24只核对审查目标字节与构建，不无故重跑旧浏览器/公网实验。

T26目标SHA256：

| 文件 | SHA256 |
|---|---|
| peer.py | `fb9fe26f55bf0394415481fbbaa9299755fe74cfbead6ed27e43f9e53b2edf1d` |
| backend/rtc_shutdown.py | `3eacae1b61521e3353dddeeebed3d0c3adcae4af4ec2c0987b242f80dcc2f1d0` |
| tests/backend/cleanup.py | `2b433f8cc85bce20e5b86db19ff7b682391bebf9e9eb29416f3201f8164e201b` |
| tests/backend/test_close_cancellation.py | `716d03d961799a2c904e98c6beebf252915bbcd494c83e9c55008b9e67f5d750` |

## 当前版本必须过的Windows门

1. captain推送新完整源码commit，并记录精确Python/aiortc/aioice/OS版本；补丁版本不匹配时不静默套用，只保留明确关闭失败/超时。
2. 原双echo90秒诊断原样执行：要求真实benchmark open、bytes/ACK、正常退出；诊断runner保留pytest退出状态。仍exit124或其他失败就保留失败，不跳测试、不把watchdog终止当完成。
3. 完整Python/Node及安全负例通过，再执行Windows native构建与portable打包；确认随包native源码manifest和commit一致。
4. 当前run链接、各job终态、artifact SHA由captain追加。构建成功仍不等于Windows交互实机、麦克风/防火墙或家庭网络已测。

## 上传边界与构建

`uploadAllowlist`包含当前产品/测试/锁/文档；`ciUploadAllowlist`独立仅列已审 [diagnostic_runner.py](../ci/windows-analysis/diagnostic_runner.py)。既有workflow/watchdog由captain独立审核，本任务不修改。**ci/windows-analysis其它源码快照、proposal patch、运行日志、临时证据一律排除**；review/verification的run树、data/媒体/key/地址、outputs/依赖与构建缓存不上传。

执行 `sync:web`、`dist:linux`、带sandbox `--platform-smoke`，核对build目录及最终Linux包内两份native source-manifest与当前源码；FREEZE记本轮实际结果。重建只证明Linux当前构建/启动，不继承或创造Windows IOCP通过。真实手机、Windows交互实机、真实家宽NAT/网关继续NOT_RUN。完成后停止产品与交付文档编辑，由captain统一上传。
