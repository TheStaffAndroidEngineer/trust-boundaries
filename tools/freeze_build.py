#!/usr/bin/env python3
"""Bind a C25 source checkpoint to actual APKs and shrinker output."""
from pathlib import Path
import argparse,datetime,hashlib,json,os,shutil,subprocess
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def clone(src,dst):
 dst.parent.mkdir(parents=True,exist_ok=True)
 if os.uname().sysname=='Darwin':subprocess.run(['cp','-c',str(src),str(dst)],check=True)
 else:shutil.copy2(src,dst)
 assert sha(src)==sha(dst)
sources={}
for directory,dirs,names in os.walk(ROOT):
 dirs[:]=[d for d in dirs if d not in ['build','.gradle','.kotlin','evidence','__pycache__','.git']]
 for name in names:
  f=Path(directory)/name
  if name in ['local.properties','README.md','verification.md'] or name.endswith('.log'):continue
  rel=str(f.relative_to(ROOT));clone(f,a.out/'source'/rel);sources[rel]=sha(f)
paths=['app/build/outputs/apk/debug/app-debug.apk','app/build/outputs/apk/release/app-release.apk',
 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk','probe/build/outputs/apk/debug/probe-debug.apk']
paths += [str(f.relative_to(ROOT)) for f in (ROOT/'app/build/outputs/mapping/release').glob('*') if f.is_file()]
artifacts={}
for rel in paths:
 f=ROOT/rel;assert f.exists(),rel;dest=a.out/'artifacts'/rel;clone(f,dest);artifacts[str(dest.relative_to(ROOT))]=sha(f)
(a.out/'manifest.json').write_text(json.dumps({'status':'SOURCE_AND_ARTIFACT_IDENTITY_ONLY','created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':sources,'artifacts':artifacts},indent=2)+'\n')
print(json.dumps({'sources':len(sources),'artifacts':len(artifacts),'out':str(a.out)}))
