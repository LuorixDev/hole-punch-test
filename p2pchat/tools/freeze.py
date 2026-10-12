"""Explicit-source allowlist and SHA-256 freeze. No runtime evidence is copied."""
import argparse
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CI_ALLOWLIST=('ci/windows-analysis/diagnostic_runner.py',)
# electron-builder.yml was deleted with the Electron shell: it must never be
# required again (see the guard below), and the desktop source now lives in
# python_desktop/ so the frozen manifest actually covers it.
ROOT_FILES={'README.md','PLATFORMS.md','__init__.py','server.py','peer.py','requirements.txt','requirements-lock.txt','package.json','package-lock.json','capacitor.config.json'}
SOURCE_DIRS={'web','backend','native','python_desktop','tools','tests','docs'}
# The removed shell must stay removed; assert absence instead of requiring it.
REMOVED_WITH_ELECTRON_SHELL=('desktop/main.cjs','desktop/preload.cjs','desktop/bridge.cjs','electron-builder.yml')
SKIP={'__pycache__','.pytest_cache','.gradle','build','node_modules'}
def allowed(p):
    r=p.relative_to(ROOT);parts=r.parts
    if not p.is_file() or any(v in SKIP for v in parts):return False
    if len(parts)==1:return r.name in ROOT_FILES
    if parts[0] in SOURCE_DIRS:
        return p.suffix in {'.py','.js','.cjs','.css','.html','.md','.spec'} and r.name!='freeze.pyc'
    if parts[0]=='platform':return len(parts)==2 and r.name in {'native_entry.py','mobile.js','build-requirements.txt','constraints.txt'}
    if parts[0]=='android':
        if 'assets' in parts or 'capacitor-cordova-android-plugins' in parts or '.idea' in parts:return False
        return p.suffix in {'.gradle','.properties','.java','.kt','.xml','.png','.jar','.bat','.pro'} or r.name in {'gradlew','.gitignore'}
    if parts[0]=='android-native':
        # 原生安卓客户端同样是交付源码：以前这里漏掉整个目录，清单里它 0 个文件，
        # 等于「冻结了但没覆盖」。构建产物由 SKIP('build'/'.gradle') 挡掉；机器相关的
        # local.properties（含本机 SDK 路径）与 NDK 中间产物 .cxx 不入清单。
        if r.name=='local.properties' or '.cxx' in parts:return False
        return (p.suffix in {'.gradle','.kts','.properties','.java','.kt','.xml','.png','.jar','.bat','.pro'}
                or r.name in {'gradlew','gradlew.bat','.gitignore','gradle-wrapper.properties'})
    return False
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def assert_shell_removed():
    """The Electron shell is gone; assert that instead of listing it as source."""
    present=[name for name in REMOVED_WITH_ELECTRON_SHELL if (ROOT/name).exists()]
    assert not present,'ELECTRON_SHELL_REAPPEARED: '+', '.join(present)
def snapshot():return {str(p.relative_to(ROOT)):sha(p) for p in sorted(ROOT.rglob('*')) if allowed(p)}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    assert_shell_removed()
    target=ROOT/'docs/SOURCE-MANIFEST.json'
    if args.verify:
        saved=json.loads(target.read_text());current=snapshot();assert current==saved['sourceHashes'],'SOURCE_FREEZE_CHANGED';print('SOURCE_FREEZE_VERIFIED',saved['treeSha256'],len(current));return
    hashes=snapshot();tree=hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    manifest={'scope':'p2pchat explicit source only; .github reviewed separately by captain','treeSha256':tree,'sourceHashes':hashes,'excluded':['data','media','logs','pcap','screenshots','releases','platform/build','platform/work','node_modules','dist-web','android/app/src/main/assets','ci/windows-analysis except explicit ciUploadAllowlist','review','verification','research outputs'],'uploadAllowlist':['p2pchat/'+p for p in hashes], 'ciUploadAllowlist':['p2pchat/'+p for p in CI_ALLOWLIST], 'ciSourceHashes':{p:sha(ROOT/p) for p in CI_ALLOWLIST}, 'ciScope':'Only the previously reviewed diagnostic runner; workflow/watchdog review remains captain-owned. Never upload windows-analysis snapshots, proposals, patches, logs or runtime evidence.'}
    target.write_text(json.dumps(manifest,indent=2)+'\n');print('SOURCE_FREEZE_CREATED',tree,len(hashes))
if __name__=='__main__':main()
