'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {validateStunConfig, sidecarArgs, validateRequest} = require('../../desktop/bridge.cjs');

test('STUN is disabled by default and explicit config becomes fixed argv only', () => {
  assert.deepEqual(sidecarArgs('127.0.0.1'), ['--bind', '127.0.0.1']);
  assert.deepEqual(sidecarArgs('192.168.1.2', {address: '127.0.0.1', port: 3478}),
    ['--bind', '192.168.1.2', '--stun-address', '127.0.0.1', '--stun-port', '3478']);
  assert.ok(Object.isFrozen(validateStunConfig({address: '127.0.0.1', port: 3478})));
});

test('reject URL, DNS, ranges, multicast, executable injection and invalid ports', () => {
  for (const config of [null, [], {}, {address: 'stun.example', port: 3478}, {address: '127.0.0.1;touch x', port: 3478},
    {address: '224.0.0.1', port: 3478}, {address: '0.0.0.0', port: 3478}, {address: '169.254.1.1', port: 3478},
    {address: '127.0.0.1', port: 0}, {address: '127.0.0.1', port: 65536}, {address: '127.0.0.1', port: '3478'},
    {address: '127.0.0.1', port: 3478, executable: '/bin/sh'}, {address: ['127.0.0.1'], port: 3478}]) {
    assert.throws(() => validateStunConfig(config), /INVALID_STUN_CONFIG/);
  }
  assert.throws(() => validateRequest('configureStun', {}), /METHOD_NOT_ALLOWED/);
});

test('main-only chooser reads bounded file then confirms endpoint; renderer gains no config RPC', () => {
  const source = fs.readFileSync(require.resolve('../../desktop/main.cjs'), 'utf8');
  assert.match(source, /showOpenDialog/);
  assert.match(source, /stat\.isFile\(\).*stat\.size > 1024/);
  assert.match(source, /validateStunConfig\(JSON\.parse/);
  assert.match(source, /授权此 STUN 地址/);
  assert.match(source, /spawn\(executable, sidecarArgs\(bindAddress, stunConfig\)/);
  assert.match(source, /shell: false/);
  assert.match(source, /stunConfig = null/);
});
