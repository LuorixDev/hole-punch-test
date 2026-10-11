# t29：高分辨率计时修复整合

**当前状态：计时修复已审，待captain推送当前冻结版本CI；Windows尚未完成。** 最新完整源码与产物SHA仅以 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)、[FREEZE](FREEZE.json) 为准。t29仅文档/清单/生成物更新，产品代码不再变。

## 两种Windows失败必须分开

- a1c6e7e/run38124339483：Linux/Android成功，Windows90秒exit124，阻塞链到aioice StunProtocol.close；属于旧关闭挂起。
- **61b400e98ff955120e42caafe05284fcb940b11f / [run38129731771](https://github.com/LuorixDev/hole-punch-test/actions/runs/38129731771)：Linux job114441379539及Android job114441379707成功；Windows收到4000B ACK，但elapsedMs=0.0导致原bytes==4000且elapsedMs>0断言失败。关闭RTC/Peer/AppRunner均正常完成，watchdog约4.937秒exit1，不是超时124。** 这一轮关闭挂起未复现，不扩大为所有Windows关闭场景通过。
- 当前t27+t28计时修复版：新commit/run待captain推送；不得把61b400e成功Linux/Android产物或正常关闭当Windows全测试/打包成功。

## 已审最小改动

Python性能测量用perf_counter_ns同源整数先相减再换算ms；timeouts/progress仍为monotonic，不混用。非正采样返回null+TIMING_UNAVAILABLE，不补sleep、epsilon或伪正值。原真实双echo4000B、ACK、正耗时测试文件不变。

JS消费者区分完整性和计时可用性：远端未知时间提示不可计算，本地有效采样才计算速率；删除Math.max(1,elapsed)人为下限，零/负/非有限不产生NaN/Infinity。因为前端字节改变，本轮重新sync和Linux完整构建，不复用旧app.asar；native源码未变仍核对随包来源hash。

独立 T28（本地私有证据，不随GitHub交付） pass：25 Python+17 Node（含真实QUIC）通过、7目标hash匹配；实现者t27全套77 Python通过、Node transfer14通过。这些均是Linux/Node证据，不是Windows计数器频率或IOCP实测。t29核对审查字节并重建，不重复无关全套或旧浏览器实验。

## 交付与验证门

manifest必须含新增 [test_timing.py](../tests/backend/test_timing.py)、实际peer/transfer源与测试及本轮文档。源allowlist排除ci/windows-analysis的patch/log/快照和review/verification原始数据；独立CI项仍仅已审diagnostic_runner.py，不新增脚本执行权限。Git/push由captain。

新Windows runner需原双echo诊断、完整Python/Node、native构建+portable打包全部真通过；不弱化原断言、不跳失败节点。Linux/Android也按同commit记录产物SHA。构建即便通过仍不等于Android/Windows交互实机、麦克风或真实家宽/NAT/网关通过，以上继续NOT_RUN。任务完成即停止文档与产品修改。
