'use strict';
/**
 * 平台边界测试：保留的客户端（网页 + Capacitor 安卓）与"桌面已改为纯 Python"的事实。
 *
 * 随 Electron 一起退役（p2pchat/desktop/*.cjs 已被桌面 Python 化删除）的用例：
 *   - IPC 发送者信任（isTrustedSender / main frame URL）
 *   - stdio sidecar 的请求关联、超时、崩溃语义
 *   - stdout 畸形/超长导致 sidecar 关闭
 * 这些用例的被测对象已经不存在，因此**删除而不是用 mock 顶替**；它们保护的不变量
 * 现在由 p2pchat/tests/desktop/test_electron_removed.py（Python）与本文件第一条
 * "Electron 保持消失" 用例承担。本文件不伪造任何已删除组件的行为。
 *
 * 明文相关的断言对应用户批准的行为：页面来源 http://localhost（仍是安全上下文），
 * 明文放行由 network security config 定义，而不是放宽全局开关或混合内容策略。
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');

test('Electron 桌面壳保持删除，保留的客户端仍在', () => {
  for (const gone of [
    'desktop',
    'desktop/main.cjs',
    'desktop/preload.cjs',
    'desktop/bridge.cjs',
    'electron-builder.yml',
  ]) {
    assert.equal(fs.existsSync(path.join(root, gone)), false, `${gone} 又出现了：Electron 已按用户要求删除`);
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const blob = JSON.stringify(manifest).toLowerCase();
  for (const needle of ['electron-builder', 'electron', 'asar']) {
    assert.equal(blob.includes(needle), false, `package.json 仍提到 ${needle}`);
  }
  // 删除 Electron 不等于可以顺手删掉可交付的网页/安卓入口。
  for (const kept of [
    'web/index.html',
    'web/app.js',
    'platform/mobile.js',
    'capacitor.config.json',
    'tools/sync-web.cjs',
    'python_desktop/app.py',
  ]) {
    assert.equal(fs.existsSync(path.join(root, kept)), true, `${kept} 不应消失`);
  }
});

test('Android facade reports explicit unsupported and calls SAF save plugin', async () => {
  const vm = require('node:vm');
  const calls = [];
  const window = {Capacitor: {isNativePlatform: () => true, Plugins: {P2PSaveFile: {saveFile: async request => { calls.push(request); return {saved: true}; }}}}};
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, '../../platform/mobile.js'), 'utf8'), {window});
  const capabilities = await window.p2pNative.invoke('capabilities');
  assert.equal(capabilities.methods.length, 7);
  assert.ok(capabilities.methods.every(item => !item.canMessage && item.status === 'unsupported'));
  await assert.rejects(window.p2pNative.invoke('start', {}), /ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED/);
  assert.equal((await window.p2pPlatform.saveFile({name: 'test', dataB64: ''})).saved, true);
  assert.equal(calls.length, 1);
});

test('安卓明文支持只动用 network security config，不放宽全局开关或混合内容', () => {
  const manifest = fs.readFileSync(path.join(root, 'android/app/src/main/AndroidManifest.xml'), 'utf8');
  assert.ok(manifest.includes('android:networkSecurityConfig="@xml/network_security_config"'), '明文策略必须由 network security config 定义');
  assert.ok(manifest.includes('android:usesCleartextTraffic="false"'), '不得改成全局 usesCleartextTraffic=true 来放行明文');
  assert.ok(manifest.includes('android.permission.RECORD_AUDIO'), '录音权限必须保留');
  assert.ok(!manifest.includes('MANAGE_EXTERNAL_STORAGE'));
  assert.ok(!manifest.includes('android:debuggable'), '不得为调试打开 debuggable');

  const config = JSON.parse(fs.readFileSync(path.join(root, 'capacitor.config.json'), 'utf8'));
  assert.equal(config.server.androidScheme, 'http', '页面来源是 http://localhost（仍是安全上下文），这样从本地页连 ws:// 才不触发混合内容拦截');
  assert.equal(config.android.allowMixedContent, false, '不得靠放宽混合内容策略换取明文');

  // 只看生效的 XML：注释里解释"没有 debug-overrides"不算开启。
  const nsc = fs.readFileSync(path.join(root, 'android/app/src/main/res/xml/network_security_config.xml'), 'utf8')
    .replace(/<!--[\s\S]*?-->/g, '');
  assert.match(nsc, /<base-config\s+cleartextTrafficPermitted="true">/, '明文必须由 base-config 明确放行');
  assert.match(nsc, /<certificates src="system"\s*\/>/, '只信任系统 CA');
  assert.ok(!/<certificates src="user"\s*\/>/.test(nsc), '不得信任用户 CA');
  assert.ok(!/<debug-overrides>/.test(nsc), '不得开启 debug-overrides');
  assert.ok(!/<domain-config\s+cleartextTrafficPermitted="true">/.test(nsc), '除 base-config 外不得再按域名放宽（保持单一明文策略）');

  // 页面来源判定必须精确等于两个 loopback 来源之一（不做后缀/包含放宽）。
  const localOrigin = fs.readFileSync(path.join(root, 'android/app/src/main/java/dev/p2pobservatory/chat/LocalOrigin.java'), 'utf8');
  assert.ok(localOrigin.includes('"http://localhost"') && localOrigin.includes('"https://localhost"'), '两种 scheme 的 loopback 页面来源都要被识别');
  assert.ok(localOrigin.includes('HTTP.equals(origin)') && localOrigin.includes('HTTPS.equals(origin)'), '页面来源必须精确匹配，不能做包含匹配');
  const activity = fs.readFileSync(path.join(root, 'android/app/src/main/java/dev/p2pobservatory/chat/MainActivity.java'), 'utf8');
  assert.ok(activity.includes('LocalOrigin.isPageOrigin'), '录音权限必须走统一的来源判定');
  const savePlugin = fs.readFileSync(path.join(root, 'android/app/src/main/java/dev/p2pobservatory/chat/SaveFilePlugin.java'), 'utf8');
  assert.ok(savePlugin.includes('LocalOrigin.isLocalPageUrl'), '保存文件必须走统一的来源判定');
});
