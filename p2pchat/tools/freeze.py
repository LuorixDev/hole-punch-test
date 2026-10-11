"""Explicit-source allowlist and SHA-256 freeze. No runtime evidence is copied."""
import argparse
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ROOT_FILES={'README.md','PLATFORMS.md','__init__.py','server.py','peer.py','requirements.txt','requirements-lock.txt','package.json','package-lock.json','capacitor.config.json','electron-builder.yml'}
SOURCE_DIRS={'web','backend','native','desktop','tools','tests','docs'}
SKIP={'__pycache__','.pytest_cache','.gradle','build','node_modules'}
def allowed(p):
    r=p.relative_to(ROOT);parts=r.parts
    if not p.is_file() or any(v in SKIP for v in parts):return False
    if len(parts)==1:return r.name in ROOT_FILES
    if parts[0] in SOURCE_DIRS:
        return p.suffix in {'.py','.js','.cjs','.css','.html','.md'} and r.name!='freeze.pyc'
    if parts[0]=='platform':return len(parts)==2 and r.name in {'native_entry.py','mobile.js','build-requirements.txt','constraints.txt'}
    if parts[0]=='android':
        if 'assets' in parts or 'capacitor-cordova-android-plugins' in parts or '.idea' in parts:return False
        return p.suffix in {'.gradle','.properties','.java','.kt','.xml','.png','.jar','.bat','.pro'} or r.name in {'gradlew','.gitignore'}
    return False
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(ROOT)):sha(p) for p in sorted(ROOT.rglob('*')) if allowed(p)}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    target=ROOT/'docs/SOURCE-MANIFEST.json'
    if args.verify:
        saved=json.loads(target.read_text());current=snapshot();assert current==saved['sourceHashes'],'SOURCE_FREEZE_CHANGED';print('SOURCE_FREEZE_VERIFIED',saved['treeSha256'],len(current));return
    hashes=snapshot();tree=hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    manifest={'scope':'p2pchat explicit source only; .github reviewed separately by captain','treeSha256':tree,'sourceHashes':hashes,'excluded':['data','media','logs','pcap','screenshots','releases','platform/build','platform/work','node_modules','dist-web','android/app/src/main/assets','research outputs'],'uploadAllowlist':['p2pchat/'+p for p in hashes]}
    target.write_text(json.dumps(manifest,indent=2)+'\n');print('SOURCE_FREEZE_CREATED',tree,len(hashes))
if __name__=='__main__':main()
