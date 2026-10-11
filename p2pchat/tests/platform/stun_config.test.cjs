'use strict';
/**
 * STUN 端点策略（Electron 壳删除之后仍然成立的那部分）。
 *
 * 随 Electron 退役的用例（被测对象已删除，因此移除而不是 mock 顶替）：
 *   - validateStunConfig / sidecarArgs：主进程把 STUN 配置变成 sidecar 固定 argv，
 *     "桌面已改为纯 Python + 进程内调用"，不再有 stdio sidecar，也没有 argv 组装；
 *   - validateRequest('configureStun') 的 renderer-ban：Python 桌面没有 renderer RPC 层；
 *   - main.cjs 的选择器用例（showOpenDialog / ≤1024B / "授权此 STUN 地址" 确认）：
 *     该 Electron 菜单不存在了。
 *
 * 现在唯一活着、且值得守住的策略在原生 CLI 与 Python 桌面里：
 *   - 只有"显式给出的一对数值 IPv4 地址 + 端口"才被接受（默认关闭）；
 *   - 拒绝 DNS 名/URL、多播、未指定、链路本地、广播、IPv6、越界端口、半配置；
 *   - 任何中继（turn:/relay）选项都不存在：本产品严格无中继。
 *
 * 这些用例**真的执行** python -m p2pchat.native.bridge（不是复制一份逻辑、也不是 mock）；
 * 找不到带原生依赖的解释器时**判失败**并写出原因：CI 必须显式传 PYTHON，
 * 环境问题不允许被静默跳过。
 */
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const pkg = path.resolve(__dirname, '../..');
const root = path.resolve(pkg, '..');
const candidates = [process.env.PYTHON, path.join(root, '.venv/bin/python'), 'python3', 'python'].filter(Boolean);

function resolvePython() {
  for (const exe of candidates) {
    const probe = spawnSync(exe, ['-c', 'import p2pchat.native.bridge'], {cwd: root, encoding: 'utf8', timeout: 120000});
    if (probe.status === 0) return exe;
  }
  return null;
}

const python = resolvePython();
// 解释器解析失败是**环境错误**，不是"本轮跳过"：CI 必须显式提供 PYTHON，
// 解析不到就让用例失败，避免整套原生断言在无人察觉的情况下消失。
const pythonError = python ? null : `找不到可导入原生依赖的 Python 解释器（试过：${candidates.join(', ')}）。请在 CI 中显式传入 PYTHON。`;

function requirePython() {
  if (pythonError) assert.fail(pythonError);
}

function runBridge(args) {
  return spawnSync(python, ['-m', 'p2pchat.native.bridge', ...args], {
    cwd: root,
    encoding: 'utf8',
    input: '',
    timeout: 120000,
  });
}

test('STUN 默认关闭；只有显式给出的一对数值 IPv4 端点被接受', () => {
  requirePython();
  for (const args of [[], ['--bind', '127.0.0.1'], ['--stun-address', '127.0.0.1', '--stun-port', '3478']]) {
    const result = runBridge(args);
    assert.equal(result.status, 0, `应接受 ${args.join(' ') || '(无参数)'}：${result.stderr}`);
    assert.ok(!result.stderr.includes('INVALID_STUN_CONFIG'), `不应报 INVALID_STUN_CONFIG：${result.stderr}`);
  }
});

test('拒绝 DNS/URL、多播、未指定、链路本地、广播、IPv6、越界端口与半配置', () => {
  requirePython();
  const rejected = [
    ['--stun-address', 'stun.example', '--stun-port', '3478'],
    ['--stun-address', 'stun:127.0.0.1', '--stun-port', '3478'],
    ['--stun-address', 'http://127.0.0.1', '--stun-port', '3478'],
    ['--stun-address', '127.0.0.1;touch x', '--stun-port', '3478'],
    ['--stun-address', '224.0.0.1', '--stun-port', '3478'],
    ['--stun-address', '0.0.0.0', '--stun-port', '3478'],
    ['--stun-address', '169.254.1.1', '--stun-port', '3478'],
    ['--stun-address', '255.255.255.255', '--stun-port', '3478'],
    ['--stun-address', '::1', '--stun-port', '3478'],
    ['--stun-address', '127.0.0.1', '--stun-port', '0'],
    ['--stun-address', '127.0.0.1', '--stun-port', '65536'],
    ['--stun-address', '127.0.0.1', '--stun-port', '3478.5'],
    ['--stun-address', '127.0.0.1'],
    ['--stun-port', '3478'],
    ['--stun-address', '127.0.0.1', '--stun-port', '3478', '--turn-url', 'turn:example.test:3478'],
  ];
  for (const args of rejected) {
    const result = runBridge(args);
    assert.notEqual(result.status, 0, `必须拒绝 ${args.join(' ')}`);
  }
});

test('原生 CLI 与 Python 桌面都不存在中继入口，桌面只接受服务器下发的 stun: 地址', () => {
  const bridge = fs.readFileSync(path.join(pkg, 'native/bridge.py'), 'utf8');
  assert.ok(!/turn:/i.test(bridge), 'CLI 不得接受 turn: 中继地址');
  assert.ok(!/--(turn|relay)\b/i.test(bridge), 'CLI 不得提供 turn/relay 选项');
  assert.ok(/--stun-address/.test(bridge) && /--stun-port/.test(bridge), 'CLI 必须同时提供 STUN 地址与端口参数');

  const engine = fs.readFileSync(path.join(pkg, 'python_desktop/engine.py'), 'utf8');
  assert.ok(engine.includes('url.startswith("stun:")'), '桌面端只接受服务器下发的 stun: 地址');
  assert.ok(!/turn:/i.test(engine), '桌面端不得出现 turn: 中继地址');
});
