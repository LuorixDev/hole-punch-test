'use strict';
const {app, BrowserWindow, session, dialog, ipcMain, Menu} = require('electron');
const os = require('node:os');
let bindAddress = '127.0.0.1';
let stunConfig = null; // session-only, explicitly confirmed; never read from renderer
const path = require('node:path');
const fs = require('node:fs/promises');
const {pathToFileURL} = require('node:url');
const {spawn} = require('node:child_process');
const {Sidecar, validateRequest, isTrustedSender, unavailable, validateStunConfig, sidecarArgs} = require('./bridge.cjs');
const entry = path.join(__dirname, '../dist-web/index.html');
const entryURL = pathToFileURL(entry).href;
let win, sidecar, saving = false;
function assertSender(event) { if (!isTrustedSender(event, win?.webContents, entryURL)) throw new Error('IPC_ORIGIN_DENIED'); }
function startSidecar() {
  // Fixed, packaged executable only: never accept executable/argv/cwd from renderer.
  const root = app.isPackaged ? path.join(process.resourcesPath, 'native') : path.join(__dirname, '../platform/build/p2p-native');
  const executable = path.join(root, process.platform === 'win32' ? 'p2p-native.exe' : 'p2p-native');
  const child = spawn(executable, sidecarArgs(bindAddress, stunConfig), {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false,
    cwd: app.getPath('userData'), env: {...process.env, PYTHONNOUSERSITE: '1'}});
  sidecar = new Sidecar(child);
  sidecar.on('event', event => { if (win && !win.isDestroyed() && win.webContents.getURL() === entryURL) win.webContents.send('p2p:event', event); });
}
async function configureStun() {
  // Native file picker is main-owned: the renderer cannot nominate/read paths.
  // A tiny explicit JSON document avoids DNS resolution, lists/ranges and scanning.
  const selected = await dialog.showOpenDialog(win, {title: '选择 STUN 设置 JSON（仅 address、port）',
    properties: ['openFile'], filters: [{name: 'STUN JSON', extensions: ['json']}]});
  if (selected.canceled || selected.filePaths.length !== 1) return;
  let handle;
  try {
    handle = await fs.open(selected.filePaths[0], 'r');
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 1024) throw new Error('INVALID_STUN_CONFIG');
    const buffer = Buffer.alloc(1025);
    const {bytesRead} = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 1024) throw new Error('INVALID_STUN_CONFIG');
    const config = validateStunConfig(JSON.parse(buffer.subarray(0, bytesRead).toString('utf8')));
    const result = await dialog.showMessageBox(win, {type: 'question', buttons: ['取消', '授权此 STUN 地址'], defaultId: 0, cancelId: 0,
      message: `允许向 ${config.address}:${config.port} 发送有限 STUN Binding 请求？`,
      detail: '仅本次应用会话有效。不会扫描网段、修改网关或中继聊天；STUN 服务可见公网端点。更改会断开旧原生路径，需重新发现。'});
    if (result.response === 1) { stunConfig = config; sidecar?.stop(); startSidecar(); }
  } catch {
    await dialog.showMessageBox(win, {type: 'error', message: '无效的 STUN 设置',
      detail: '需要不超过 1024 字节的 JSON，例如 {"address":"127.0.0.1","port":3478}。只接受一个明确 IPv4 单播地址和 UDP 端口；默认关闭。'});
  } finally { await handle?.close(); }
}
function createWindow() {
  win = new BrowserWindow({width: 1360, height: 960, minWidth: 840, minHeight: 650, backgroundColor: '#0c111b',
    webPreferences: {preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, allowRunningInsecureContent: false, webviewTag: false}});
  win.webContents.setWindowOpenHandler(() => ({action: 'deny'}));
  win.webContents.on('will-navigate', event => event.preventDefault());
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  win.webContents.on('render-process-gone', () => { sidecar?.stop(); });
  win.on('closed', () => { sidecar?.stop(); win = null; });
  if (process.argv.includes('--platform-smoke')) {
    win.webContents.once('did-finish-load', () => { console.log('P2P_PLATFORM_LOCAL_RENDERER_LOADED'); app.quit(); });
    win.webContents.once('did-fail-load', () => app.exit(2));
  }
  startSidecar(); win.loadFile(entry);
}
app.whenReady().then(() => {
  ipcMain.handle('p2p:native', async (event, method, params = {}) => {
    assertSender(event); validateRequest(method, params);
    if (!sidecar || sidecar.closed) {
      if (method === 'capabilities') return unavailable('SIDECAR_UNAVAILABLE');
      throw new Error('SIDECAR_UNAVAILABLE');
    }
    try { return await sidecar.request(method, params); }
    catch (error) { if (method === 'capabilities') return unavailable(error.message); throw error; }
  });
  ipcMain.handle('p2p:save', async (event, request) => {
    assertSender(event);
    if (saving) throw new Error('SAVE_BUSY');
    if (!request || typeof request.name !== 'string' || request.name.length > 255 || typeof request.dataB64 !== 'string' || request.dataB64.length > 44739244 || !/^[A-Za-z0-9+/]*={0,2}$/.test(request.dataB64)) throw new Error('INVALID_FILE');
    const bytes = Buffer.from(request.dataB64, 'base64');
    if (bytes.length > 32 * 1024 * 1024) throw new Error('FILE_TOO_LARGE');
    saving = true;
    try {
      const result = await dialog.showSaveDialog(win, {defaultPath: path.basename(request.name.replaceAll('\\', '/')) || 'download.bin'});
      if (result.canceled || !result.filePath) return {saved: false, cancelled: true};
      await fs.writeFile(result.filePath, bytes, {mode: 0o600});
      return {saved: true, cancelled: false};
    } finally { saving = false; }
  });
  session.defaultSession.setPermissionCheckHandler((contents, permission, _origin, details) =>
    contents === win?.webContents && contents.getURL() === entryURL && permission === 'media' && details.mediaType === 'audio');
  session.defaultSession.setPermissionRequestHandler(async (contents, permission, callback, details) => {
    if (contents !== win?.webContents || contents.getURL() !== entryURL || permission !== 'media' || !details.isMainFrame || !details.mediaTypes?.length || details.mediaTypes.some(type => type !== 'audio')) return callback(false);
    const result = await dialog.showMessageBox(win, {type: 'question', buttons: ['拒绝', '允许麦克风'], defaultId: 0, cancelId: 0,
      message: '允许录制本次 P2P 语音消息？', detail: '仅在点击录音后采集；不启用实时通话。'});
    callback(result.response === 1);
  });
  const interfaces = [...new Set(Object.values(os.networkInterfaces()).flat().filter(item => item && !item.internal && !item.address.includes('%') && !item.address.startsWith('fe80:')).map(item => item.address))];
  Menu.setApplicationMenu(Menu.buildFromTemplate([{label: '原生网络绑定（更改将断开原生路径）', submenu: ['127.0.0.1', ...interfaces].map(address => ({label: address, type: 'radio', checked: address === bindAddress, click: async () => {
    const result = await dialog.showMessageBox(win, {buttons: ['取消', '绑定本机接口'], defaultId: 0, cancelId: 0, message: `允许原生 P2P 传输使用本机接口 ${address}？`, detail: '不会开放本地 RPC 服务；停止旧原生路径。网络变化后需重新选择和发现。'});
    if (result.response === 1) { bindAddress = address; sidecar?.stop(); startSidecar(); }
  }}))}, {label: '原生 STUN（默认关闭）', submenu: [
    {label: '从 JSON 配置并确认授权…', click: configureStun},
    {label: '禁用 STUN 并断开旧原生路径', click: () => { stunConfig = null; sidecar?.stop(); startSidecar(); }}
  ]}, {label: '窗口', submenu: [{role: 'reload'}, {role: 'quit'}]}]));
  createWindow(); app.on('activate', () => { if (!win) createWindow(); });
});
app.on('before-quit', () => sidecar?.stop());
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
