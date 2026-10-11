'use strict';
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
