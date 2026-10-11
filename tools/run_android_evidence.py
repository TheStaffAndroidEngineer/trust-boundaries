#!/usr/bin/env python3
"""Install exact retained APKs, execute instrumentation, retain typed private reports."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,tarfile,io
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--app',type=Path,required=True);p.add_argument('--test',type=Path,required=True);a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False)
adb=Path(os.environ.get('ANDROID_HOME',str(Path.home()/'Library/Android/sdk')))/'platform-tools/adb'
def call(*args):return subprocess.check_output([str(adb),'-s','emulator-5554',*map(str,args)],stderr=subprocess.STDOUT)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'STARTING','scope':'API36 emulator correctness and actual local HTTP; not browser UI, hardware security or performance measurement','apks':{}}
for key,path in [('app',a.app),('test',a.test)]:
 report['apks'][key]={'path':str(path.resolve()),'sha256':sha(path),'install':call('install','-r',path).decode()}
for key,pkg in [('app','staff.android.trust'),('test','staff.android.trust.test')]:
 remote=call('shell','pm','path',pkg).decode().strip().removeprefix('package:');local=a.out/(key+'-installed.apk');call('pull',remote,local);assert sha(local)==report['apks'][key]['sha256']
report['device']={k:call('shell','getprop',k).decode().strip() for k in ['ro.product.model','ro.product.cpu.abi','ro.build.version.sdk','ro.build.version.release','ro.build.fingerprint']}
report['reverse']=call('reverse','--list').decode();assert 'tcp:8875 tcp:8875' in report['reverse']
result=call('shell','am','instrument','-w','staff.android.trust.test/androidx.test.runner.AndroidJUnitRunner');(a.out/'instrumentation.txt').write_bytes(result)
report['passed']='OK (13 tests)' in result.decode() and 'FAILURES' not in result.decode()
archive=call('exec-out','run-as','staff.android.trust','tar','-cf','-','files/http-integration');(a.out/'http-integration.tar').write_bytes(archive)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
 for item in tar:
  if not item.isfile():continue
  path=Path(item.name);assert path.parts[:2]==('files','http-integration') and '..' not in path.parts
  raw=tar.extractfile(item).read();data=json.loads(raw);assert data['completed'] and data['typed_event_audit_passed'];target=a.out/'http-integration'/path.name;target.parent.mkdir(exist_ok=True);target.write_bytes(raw)
report['privateReports']=sorted(p.name for p in (a.out/'http-integration').glob('*.json'));assert len(report['privateReports'])==6
report['status']='PASS' if report['passed'] else 'FAILED';(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(report['status']);assert report['passed']
