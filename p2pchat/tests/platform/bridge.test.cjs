'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough} = require('node:stream');
const fs = require('node:fs');
const path = require('node:path');
const {Sidecar, validateRequest, isTrustedSender, unavailable} = require('../../desktop/bridge.cjs');
function fake() { const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough(); child.kill = () => { child.killed = true; }; return child; }
test('reject unknown commands and oversized/bad payloads', () => {
  for (const method of ['exec', 'readFile', 'subscribe', 'constructor']) assert.throws(() => validateRequest(method, {}));
  assert.throws(() => validateRequest('send', {dataB64: '!'}));
  assert.throws(() => validateRequest('send', {dataB64: Buffer.alloc(65537).toString('base64')}));
  validateRequest('send', {dataB64: Buffer.from('test').toString('base64')});
});
test('IPC requires same contents AND exact main frame URL', () => {
  const contents = {isDestroyed: () => false, mainFrame: {url: 'file:///app/index.html'}};
  const event = {sender: contents, senderFrame: contents.mainFrame};
  assert.equal(isTrustedSender(event, contents, 'file:///app/index.html'), true);
  assert.equal(isTrustedSender({...event, senderFrame: {url: contents.mainFrame.url}}, contents, contents.mainFrame.url), false);
  assert.equal(isTrustedSender(event, contents, 'https://evil.test'), false);
  assert.equal(isTrustedSender({...event, sender: {}}, contents, contents.mainFrame.url), false);
});
test('sidecar request correlates result and relays protocol events only', async () => {
  const child = fake(); const bridge = new Sidecar(child);
  const events = []; bridge.on('event', value => events.push(value));
  const p = bridge.request('capabilities', {}); const request = JSON.parse(child.stdin.read().toString());
  child.stdout.write(JSON.stringify({v: 1, id: request.id, result: {methods: []}}) + '\n');
  assert.deepEqual(await p, {methods: []});
  child.stdout.write('{"v":1,"event":"data","params":{"dataB64":"YQ=="}}\n');
  assert.equal(events.length, 1); bridge.stop();
});
test('sidecar timeout and crash reject without success fabrication', async () => {
  const child = fake(); const bridge = new Sidecar(child, {timeoutMs: 10});
  await assert.rejects(bridge.request('stats', {}), /SIDECAR_TIMEOUT/);
  const p = bridge.request('stats', {}); child.emit('exit', 1);
  await assert.rejects(p, /SIDECAR_EXITED/); assert.equal(child.killed, true);
  await assert.rejects(bridge.request('capabilities', {}), /SIDECAR_UNAVAILABLE/);
  assert.ok(unavailable('missing').methods.every(x => x.status === 'unsupported' && x.canMessage === false));
});
test('malformed and overlong stdout kill sidecar', () => {
  for (const line of ['bad\n', 'x'.repeat(131073)]) { const child = fake(); const bridge = new Sidecar(child); child.stdout.write(line); assert.equal(bridge.closed, true); }
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
test('desktop and Android enforce platform security invariants', () => {
  const root = path.resolve(__dirname, '../..');
  const main = fs.readFileSync(path.join(root, 'desktop/main.cjs'), 'utf8');
  for (const invariant of ['contextIsolation: true', 'sandbox: true', 'nodeIntegration: false', 'shell: false', "event.preventDefault()", 'assertSender(event)']) assert.ok(main.includes(invariant), invariant);
  const manifest = fs.readFileSync(path.join(root, 'android/app/src/main/AndroidManifest.xml'), 'utf8');
  assert.ok(manifest.includes('android:usesCleartextTraffic="false"'));
  assert.ok(manifest.includes('android.permission.RECORD_AUDIO'));
  assert.ok(!manifest.includes('MANAGE_EXTERNAL_STORAGE'));
  const config = JSON.parse(fs.readFileSync(path.join(root, 'capacitor.config.json')));
  assert.equal(config.server.androidScheme, 'https'); assert.equal(config.android.allowMixedContent, false);
});
