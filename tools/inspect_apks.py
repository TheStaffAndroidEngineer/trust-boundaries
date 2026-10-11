#!/usr/bin/env python3
"""Check the actual merged APK boundary, separate from source declarations."""
from pathlib import Path
import argparse,hashlib,json,subprocess,xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
android='{http://schemas.android.com/apk/res/android}'
import os
analyzer=Path(os.environ.get('ANDROID_HOME',str(Path.home()/'Library/Android/sdk')))/'cmdline-tools/latest/bin/apkanalyzer'
if not analyzer.exists():raise SystemExit('Supply this machine SDK apkanalyzer path in script before running.')
raw=subprocess.check_output([str(analyzer),'manifest','print',str(a.apk)]).decode(); root=ET.fromstring(raw);app=root.find('application');assert app is not None
components=[{'kind':n.tag,'name':n.get(android+'name'),'exported':n.get(android+'exported'),'permission':n.get(android+'permission')} for n in app if n.tag in ['activity','service','receiver','provider']]
byname={n['name']:n for n in components};assert byname['staff.android.trust.MainActivity']['exported']=='true';assert byname['staff.android.trust.OrdersActivity']['exported']=='false'
assert app.get(android+'allowBackup')=='false'
assert app.get(android+'networkSecurityConfig') is not None
for c in components:
 if c['exported']=='true':
  assert c['name'] in ['staff.android.trust.MainActivity','androidx.profileinstaller.ProfileInstallReceiver']
  if c['name']=='androidx.profileinstaller.ProfileInstallReceiver':assert c['permission']=='android.permission.DUMP'
a.out.mkdir(parents=True,exist_ok=False);(a.out/'manifest.xml').write_text(raw)
(a.out/'report.json').write_text(json.dumps({'status':'PASS','apk':str(a.apk.resolve()),'apkSha256':hashlib.sha256(a.apk.read_bytes()).hexdigest(),'components':components,'allowBackup':False,'scope':'Actual merged APK component/backup declarations; no assertion about OEM transfer behavior, verified domain association or all runtime attacks.'},indent=2)+'\n')
print('Merged APK boundary PASS')
