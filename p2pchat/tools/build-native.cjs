'use strict';
/**
 * 废弃（DEPRECATED）：仅用于单独构建原生 CLI 二进制，与桌面端无关。
 *
 * 理由：Electron 桌面壳已删除，桌面端改为纯 Python + Tkinter（Qt 迁移见 t24），
 * 直接进程内调用 `p2pchat/native/*`。因此不再需要 stdio sidecar 二进制、也不需要
 * 把它塞进 asar 或随 Electron 分发——`npm run build:native` 不再是任何构建/CI 步骤
 * 的一部分（CI 已无 build-native/native_entry 调用点）。
 *
 * 保留它的唯一用途：给原生 CLI 单独打一个 onedir 包，用于 native↔native 的
 * QUIC/TCP 互通试验。**不要**把它重新接回桌面构建，也不要再引入 sidecar/asar。
 * 若要删除本文件，请同时删除 package.json 里的 build:native 脚本。
 */
console.error('[deprecated] tools/build-native.cjs 只用于单独构建原生 CLI；桌面端不使用 stdio sidecar。');
const path = require('node:path');
const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const repo = path.dirname(root);
const crypto = require('node:crypto');
const sourceHashes = {};
for (const name of fs.readdirSync(path.join(root, 'native')).filter(name => name.endsWith('.py'))) {
  sourceHashes[`native/${name}`] = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'native', name))).digest('hex');
}
// Build-time environment only; never reachable from renderer IPC.
const python = process.env.PYTHON || (fs.existsSync(path.join(repo, '.venv/bin/python')) ? path.join(repo, '.venv/bin/python') : 'python');
const result = spawnSync(python, ['-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'p2p-native', '--paths', repo,
  '--collect-submodules', 'p2pchat.native', '--distpath', path.join(root, 'platform/build'), '--workpath', path.join(root, 'platform/work'),
  '--specpath', path.join(root, 'platform/work'), path.join(root, 'platform/native_entry.py')], {cwd: repo, stdio: 'inherit', shell: false});
if (result.error) console.error(result.error.message);
if (result.status === 0) {
  fs.writeFileSync(path.join(root, 'platform/build/p2p-native/source-manifest.json'), JSON.stringify({sourceCommit: process.env.GITHUB_SHA || 'local-uncommitted', sourceHashes}, null, 2));
  for (const [name, hash] of Object.entries(sourceHashes)) {
    if (crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex') !== hash) {
      console.error('Native sources changed during build; rebuild after source freeze'); process.exit(1);
    }
  }
}
process.exit(result.status ?? 1);
