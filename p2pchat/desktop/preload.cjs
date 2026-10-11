'use strict';
const {contextBridge, ipcRenderer} = require('electron');
const allowed = new Set(['capabilities', 'start', 'signal', 'send', 'stats', 'close']);
contextBridge.exposeInMainWorld('p2pNative', Object.freeze({
  invoke(method, params = {}) {
    if (!allowed.has(method)) return Promise.reject(new Error('METHOD_NOT_ALLOWED'));
    return ipcRenderer.invoke('p2p:native', method, params);
  },
  onEvent(callback) {
    if (typeof callback !== 'function') throw new TypeError('callback required');
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('p2p:event', listener);
    return () => ipcRenderer.removeListener('p2p:event', listener);
  }
}));
contextBridge.exposeInMainWorld('p2pPlatform', Object.freeze({
  platform: process.platform,
  saveFile: request => ipcRenderer.invoke('p2p:save', request)
}));
