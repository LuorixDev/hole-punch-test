'use strict';
const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const net = require('node:net');
function validateStunConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'address,port' || typeof value.address !== 'string' || net.isIP(value.address) !== 4 ||
      !Number.isInteger(value.port) || value.port < 1 || value.port > 65535) throw new Error('INVALID_STUN_CONFIG');
  const octets = value.address.split('.').map(Number);
  if (octets[0] >= 224 || value.address === '0.0.0.0' || (octets[0] === 169 && octets[1] === 254)) throw new Error('INVALID_STUN_CONFIG');
  return Object.freeze({address: value.address, port: value.port});
}
function sidecarArgs(bindAddress, stun = null) {
  if (!net.isIP(bindAddress)) throw new Error('INVALID_BIND_ADDRESS');
  const args = ['--bind', bindAddress];
  if (stun !== null) {
    const safe = validateStunConfig(stun);
    args.push('--stun-address', safe.address, '--stun-port', String(safe.port));
  }
  return args;
}
const METHODS = new Set(['capabilities', 'start', 'signal', 'send', 'stats', 'close']);
const EVENTS = new Set(['candidate', 'state', 'data', 'diagnostic']);
const MAX_LINE = 128 * 1024;
function validateRequest(method, params) {
  if (!METHODS.has(method)) throw new Error('METHOD_NOT_ALLOWED');
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('INVALID_PARAMS');
  const encoded = JSON.stringify(params);
  if (Buffer.byteLength(encoded) > MAX_LINE - 256) throw new Error('LIMIT_EXCEEDED');
  if (method === 'send' && (typeof params.dataB64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(params.dataB64) || Buffer.from(params.dataB64, 'base64').length > 65536)) throw new Error('INVALID_DATA');
}
function isTrustedSender(event, webContents, entryURL) {
  return !!webContents && !webContents.isDestroyed() && event.sender === webContents && event.senderFrame === webContents.mainFrame && event.senderFrame.url === entryURL;
}
class Sidecar extends EventEmitter {
  constructor(child, {timeoutMs = 15000} = {}) {
    super(); this.child = child; this.timeoutMs = timeoutMs; this.pending = new Map(); this.attempts = new Map(); this.buffer = ''; this.closed = false;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => this.consume(chunk));
    child.on('error', () => this.stop('SIDECAR_UNAVAILABLE'));
    child.on('exit', () => this.stop('SIDECAR_EXITED'));
    // Never forward raw stderr (may contain network endpoints or secrets).
    child.stderr.on('data', () => {});
    child.stdin.on('error', () => this.stop('SIDECAR_EXITED'));
  }
  consume(chunk) {
    this.buffer += chunk;
    while (this.buffer.includes('\n')) {
      const index = this.buffer.indexOf('\n');
      const line = this.buffer.slice(0, index); this.buffer = this.buffer.slice(index + 1);
      if (Buffer.byteLength(line) > MAX_LINE) return this.stop('SIDECAR_PROTOCOL');
      let frame; try { frame = JSON.parse(line); } catch { return this.stop('SIDECAR_PROTOCOL'); }
      if (frame.v !== 1) return this.stop('SIDECAR_PROTOCOL');
      if (EVENTS.has(frame.event) && frame.params && typeof frame.params === 'object') this.emit('event', frame);
      else if (typeof frame.id === 'string' && this.pending.has(frame.id)) {
        const item = this.pending.get(frame.id); this.pending.delete(frame.id); clearTimeout(item.timer);
        if (frame.error) item.reject(new Error(String(frame.error.code || 'SIDECAR_ERROR')));
        else item.resolve(frame.result);
      }
    }
    if (Buffer.byteLength(this.buffer) > MAX_LINE) this.stop('SIDECAR_PROTOCOL');
  }
  request(method, params = {}) {
    try { validateRequest(method, params); } catch (e) { return Promise.reject(e); }
    if (this.closed) return Promise.reject(new Error('SIDECAR_UNAVAILABLE'));
    if (this.pending.size >= 64 || this.child.stdin.writableLength > 512 * 1024) return Promise.reject(new Error('BACKPRESSURE'));
    if (method === 'start' && typeof params.attemptId === 'string' && typeof params.connectionId === 'string') {
      if (this.attempts.size >= 64) return Promise.reject(new Error('LIMIT_EXCEEDED'));
      this.attempts.set(params.attemptId, params.connectionId);
    }
    if (method === 'close') this.attempts.delete(params.attemptId);
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('SIDECAR_TIMEOUT')); }, this.timeoutMs);
      this.pending.set(id, {resolve, reject, timer});
      this.child.stdin.write(JSON.stringify({v: 1, id, method, params}) + '\n');
    });
  }
  stop(code = 'SIDECAR_CLOSED') {
    if (this.closed) return; this.closed = true;
    for (const item of this.pending.values()) { clearTimeout(item.timer); item.reject(new Error(code)); }
    this.pending.clear();
    for (const [attemptId, connectionId] of this.attempts) this.emit('event', {v: 1, event: 'state', params: {attemptId, connectionId, state: 'failed', failureCode: code}});
    this.attempts.clear(); this.child.kill(); this.emit('unavailable', code);
  }
}
const unavailable = reason => ({v: 1, methods: ['udp-probe','quic','tcp','tcp-simopen','upnp','pcp','natpmp'].map(mechanism => ({mechanism, status: 'unsupported', canMessage: false, reason, limits: {}}))});
module.exports = {Sidecar, validateRequest, isTrustedSender, unavailable, METHODS, validateStunConfig, sidecarArgs};
