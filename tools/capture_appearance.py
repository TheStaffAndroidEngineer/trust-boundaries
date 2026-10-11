#!/usr/bin/env python3
"""C25 guarded native/Custom Tab capture. Root alone executes device operations.

Only the seeded fixture app is reset; Chrome's data is never cleared. No auth
secret is put in an adb argument. Declared query fields are redacted in retained
XML/window text; PNGs are unaltered. Captured pixels are not review acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'projects/commerce-app/tools'))
from capture_checkpoint_appearance import (CaptureSession, area, bounds, find_pane,
    intersection, matches, pane_key, panes, signature, system_bar_regions)
from fresh_android_xml import read_ui_xml

APP = 'staff.android.trust'
BROWSER = 'com.android.chrome'
PORT = 'tcp:8875'
REDACT = re.compile(r'(?i)((?:\?|&(?:amp;)?)(?:state|code|code_challenge|code_verifier|access_token|refresh_token)=)[^&\s<>"\']+')


def redact(value):
    return REDACT.sub(r'\1[REDACTED]', value)


class TrustCapture(CaptureSession):
    def xml(self):
        # Raw data exists only in memory; identifiers not needed for interaction
        # are removed from durable UI XML before it is hashed or parsed further.
        return redact(read_ui_xml(self.adb, '/sdcard/common-goods-appearance.xml',
                                  {self.args.package}, attempts=2))

    def blocked_regions(self):
        raw = self.adb('shell', 'dumpsys', 'window', 'windows').decode(errors='replace')
        regions = system_bar_regions(raw)
        retained = redact(raw).encode()
        digest = hashlib.sha256(retained).hexdigest()
        path = self.args.output / ('tap-window-' + digest[:16] + '.txt')
        if not path.exists(): path.write_bytes(retained)
        self.tap_guards.append({'windowDump': path.name, 'sha256': digest,
            'blockedRegions': regions, 'declaredQueryFieldRedaction': True})
        return regions

    def swipe(self, pane, direction):
        left, top, right, bottom = bounds(pane)
        if not area((left, top, right, bottom)): raise RuntimeError('Fresh pane is empty.')
        # Smaller steps make it possible to retain a price and neighboring
        # action together at font scale 2 rather than skipping over the framing.
        high, low = top + (bottom-top)*35//100, top + (bottom-top)*65//100
        start, end = (low, high) if direction == 'down' else (high, low)
        self.adb('shell', 'input', 'swipe', (left+right)//2, start, (left+right)//2, end, 180)
        return self.settled()

    def failure_witness(self):
        witness = {'scope': 'Unsettled failure viewport before restoration; not acceptance.', 'errors': {}}
        for name, producer in [
            ('xml', lambda: redact(read_ui_xml(self.adb, '/sdcard/common-goods-failure.xml', {APP,BROWSER,'android','com.android.systemui'}, attempts=1)).encode()),
            ('png', lambda: self.adb('exec-out', 'screencap', '-p')),
            ('window', lambda: redact(self.adb('shell','dumpsys','window','windows').decode(errors='replace')).encode()),
        ]:
            try:
                data=producer(); path=self.args.output/('failure-viewport.'+('txt' if name=='window' else name));path.write_bytes(data)
                witness[name]=path.name;witness[name+'Sha256']=hashlib.sha256(data).hexdigest()
            except Exception as error: witness['errors'][name]=str(error)
        return witness


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out','--output',dest='output',type=Path,required=True)
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--probe-apk',type=Path,default=Path(__file__).resolve().parents[1]/'probe/build/outputs/apk/debug/probe-debug.apk')
    parser.add_argument('--serial',default='emulator-5554')
    parser.add_argument('--expected-avd',default='StaffAndroid_API_36')
    parser.add_argument('--candidate',default='candidate1')
    parser.add_argument('--configs',nargs='+',choices=['light','dark','large','wide'],default=['light','dark','large','wide'])
    parser.add_argument('--max-scrolls',type=int,default=18)
    parser.add_argument('--settle-timeout',type=float,default=45)
    args=parser.parse_args();args.package=APP
    if not 1<=args.max_scrolls<=24 or not 1<=args.settle_timeout<=120:parser.error('Use bounded scroll/settle limits.')
    apk=args.apk.resolve()
    if not apk.is_file():parser.error('APK does not exist.')
    if args.output.exists():parser.error('Use a new evidence directory; retain earlier captures.')
    args.output.mkdir(parents=True)
    source=Path(__file__).read_bytes();(args.output/'capture-script.py').write_bytes(source)
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    session=TrustCapture(args);original=original_reverse=original_fixture=None;failure=None
    report={'status':'STARTING','package':APP,'browserPackage':BROWSER,'serial':args.serial,
        'candidate':args.candidate,'apk':str(apk),'apkSha256':sha(apk),
        'captureScriptSha256':hashlib.sha256(source).hexdigest(),'rows':[],'fixtureActions':[],
        'restorationErrors':[],
        'textRedaction':{'fields':['state','code','code_challenge','code_verifier','access_token','refresh_token'],
            'scope':'Authorization query values in retained XML/window text only; PNGs are unaltered. No auth secrets in adb arguments.'},
        'scope':'Seeded Common Goods Shop, signed-out Orders, external sample-account chooser, Maya/Leo receipts, denial, loading, retry, session-ended and signed-out states in four display configurations. No production identity proof, penetration-test certification, representative timing or full accessibility claim.'}
    def save(): (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def admin(path,payload=None):
        request=urllib.request.Request('http://127.0.0.1:8875'+path,
            data=None if payload is None else json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=10) as response: result=json.load(response)
        report['fixtureActions'].append({'path':path,'payload':payload})
        return result
    def configure(**values):return admin('/admin/config',values)
    def has(raw,label):return any(matches(node,label) for node in ET.fromstring(raw).iter('node'))
    def framed(raw,labels):
        tree=ET.fromstring(raw);parents={child:parent for parent in tree.iter() for child in parent}
        for label in labels:
            found=False
            for node in tree.iter('node'):
                if node.get('package')!=args.package or not matches(node,label):continue
                left,top,right,bottom=bounds(node)
                if not area((left,top,right,bottom)):continue
                valid=True;parent=node
                while parent in parents:
                    parent=parents[parent]
                    if parent.get('scrollable')=='true':
                        pl,pt,pr,pb=bounds(parent)
                        if left<pl or right>pr or top<pt+12 or bottom>pb-12:valid=False
                if valid:found=True;break
            if not found:return False
        return True
    def reveal(raw,labels):
        labels=[labels] if isinstance(labels,str) else labels
        if framed(raw,labels):return raw
        keys=[pane_key(p) for p in panes(ET.fromstring(raw),args.package)]
        for key in keys:
            for direction in ['down','up']:
                for _ in range(args.max_scrolls):
                    pane=find_pane(ET.fromstring(raw),args.package,key)
                    if pane is None:break
                    before=signature(pane);raw=session.swipe(pane,direction)
                    if framed(raw,labels):return raw
                    after=find_pane(ET.fromstring(raw),args.package,key)
                    if after is None or signature(after)==before:break
        raise RuntimeError('Could not fully frame expected labels: '+repr(labels))
    def tap(label,raw,next_package=APP,expected=(),settle=True):
        raw=reveal(raw,label)
        raw=session.xml()  # Re-resolve after scrolling and immediately before the action.
        target=session.target(ET.fromstring(raw),label)
        if target is None:raise RuntimeError('Fresh guarded enabled target unavailable: '+label)
        left,top,right,bottom=bounds(target)
        session.adb('shell','input','tap',(left+right)//2,(top+bottom)//2)
        args.package=next_package
        return session.settled(exact=list(expected)) if settle else session.xml()
    def idle():
        deadline=time.monotonic()+args.settle_timeout
        while time.monotonic()<deadline:
            raw=session.settled(exact=['orders_screen'])
            if not has(raw,'orders_loading'):return raw
        raise RuntimeError('Orders did not reach a non-loading state.')
    def capture(row,name,raw,condition):
        frame=session.capture(row['config']+'-'+name,raw);frame.update(condition=condition,surfacePackage=args.package)
        row['frames'].append(frame);save();return raw
    def top(raw,anchor):return reveal(raw,anchor)
    def link(row,uri):
        args.package=APP
        session.adb('shell','am','start','-W','-n',APP+'/.MainActivity','-a','android.intent.action.VIEW','-d',uri,'--es','account','leo','--es','owner','leo','--es','access_token','forged-not-a-credential')
        row['launches'].append({'externalUri':uri,'explicitFixtureDelivery':True,'untrustedExtras':{'account':'leo','owner':'leo','access_token':'forged-not-a-credential'}})
        return idle()
    def sign_in(row,raw,account,capture_chooser=False):
        raw=tap('sign_in',raw,BROWSER,['Choose a sample account','Continue as Maya','Continue as Leo'])
        if capture_chooser:
            raw=capture(row,'browser-chooser',raw,'External Chrome Custom Tab shows explicitly simulated sample accounts, not real identity proof.')
            raw=reveal(raw,['Continue as Maya','Continue as Leo'])
            raw=capture(row,'browser-actions',raw,'Both sample-account choices are fully framed; browser pixels remain unaltered.')
        raw=tap('Continue as '+account,raw,APP,['orders_screen'])
        raw=idle()
        if not has(raw,'Signed in as '+account):raise RuntimeError('Expected account is not visible after browser return: '+account)
        return raw
    def receipt(row,raw,prefix,total):
        raw=capture(row,prefix+'-receipt-top',raw,'Receipt upper area and account context for '+prefix+'.')
        # The lower action anchors the entire price section away from the viewport edge.
        # Font scaling is nonlinear; do not infer rendered text height from sp.
        # Insets plus the lower action guide capture; actual pixels are reviewed.
        raw=reveal(raw,['receipt_total','back_orders'])
        values=[n.get('text','') for n in ET.fromstring(raw).iter('node') if matches(n,'receipt_total')]
        if len(values)!=1 or re.sub(r'\D','',values[0])!=str(total):raise RuntimeError('Unexpected receipt total: '+repr(values))
        return capture(row,prefix+'-receipt-full',raw,'Full receipt total and Back to your orders action are framed together.')
    try:
        avd=session.adb('emu','avd','name').decode().strip()
        if args.expected_avd not in avd.splitlines():raise RuntimeError('Unexpected emulator: '+avd)
        report['avd']=avd;original=session.settings();report['originalSettings']=original
        original_reverse=session.adb('reverse','--list').decode();report['originalReverse']=original_reverse
        mappings=[p for p in map(str.split,original_reverse.splitlines()) if len(p)>=3 and p[-2]==PORT]
        if len(mappings)>1:raise RuntimeError('Ambiguous original chapter reverse mapping.')
        original_fixture=admin('/admin/events')['control'];report['originalFixtureState']=original_fixture
        session.adb('reverse',PORT,PORT)
        if 'light' in args.configs:
            probe=args.probe_apk.resolve()
            if not probe.is_file():raise RuntimeError('Build the separate probe APK before this capture.')
            session.adb('install','-r',probe)
            remote=session.adb('shell','pm','path',APP+'.probe').decode().strip().removeprefix('package:')
            session.adb('pull',remote,args.output/'probe-installed.apk')
            assert sha(args.output/'probe-installed.apk')==sha(probe)
            report['probeApk']={'path':str(probe),'sha256':sha(probe),'installedReadback':'probe-installed.apk'}
        session.adb('install','-r',apk)
        installed=session.adb('shell','pm','path',APP).decode().strip().removeprefix('package:')
        session.adb('pull',installed,args.output/'installed.apk')
        if sha(args.output/'installed.apk')!=report['apkSha256']:raise RuntimeError('Installed APK identity mismatch.')
        for config in args.configs:
            args.package=APP
            session.adb('shell','am','force-stop',APP)
            session.adb('shell','wm','size','1920x1200' if config=='wide' else 'reset')
            session.adb('shell','wm','density','240' if config=='wide' else 'reset')
            session.adb('shell','settings','put','system','font_scale','2.0' if config=='large' else '1.0')
            session.adb('shell','cmd','uimode','night','yes' if config=='dark' else 'no')
            row={'config':config,'settings':session.settings(),'status':'STARTING','frames':[],'launches':[]};report['rows'].append(row)
            assert float(row['settings']['font'])==(2 if config=='large' else 1)
            assert 'Night mode: '+('yes' if config=='dark' else 'no') in row['settings']['night']
            if config=='wide':assert 'Override size: 1920x1200' in row['settings']['size'] and 'Override density: 240' in row['settings']['density']
            else:assert 'Override' not in row['settings']['size'] and 'Override' not in row['settings']['density']
            admin('/admin/reset',{})
            if session.adb('shell','pm','clear',APP).decode().strip()!='Success':raise RuntimeError('Fixture app reset failed.')
            session.adb('shell','am','start','-W','-n',APP+'/.MainActivity','-f','0x10008000')
            row['launches'].append({'route':'Shop','resetFixtureApp':True})
            raw=session.settled(exact=['shop']);raw=capture(row,'shop-top',raw,'Public Shop opens without an account.')
            raw=tap('open_orders',raw,APP,['orders_screen']);raw=idle()
            raw=capture(row,'signed-out-top',raw,'Orders introduces the signed-out account state.')
            raw=reveal(raw,['orders_notice','sign_in']);raw=capture(row,'signed-out-action',raw,'Complete signed-out explanation and Sign in action.')
            raw=sign_in(row,raw,'Maya',True)
            raw=capture(row,'maya-orders-top',raw,'Maya account heading and order collection after browser return.')
            raw=reveal(raw,['order_summary','view_receipt']);raw=capture(row,'maya-orders-action',raw,'Maya Camera order summary and full View receipt action.')
            raw=tap('view_receipt',raw);raw=idle();raw=receipt(row,raw,'maya',12999)
            if config=='light':
                # Establish existence separately: a denied-or-absent open alone
                # cannot prove app-private storage isolation.
                exists=session.adb('shell','run-as',APP,'ls','-l','no_backup/session.bin').decode().strip()
                packages=session.adb('shell','pm','list','packages','-U','staff.android.trust').decode()
                uid_rows={m.group(1):int(m.group(2)) for m in re.finditer(r'package:(\S+) uid:(\d+)',packages)}
                assert uid_rows[APP]!=uid_rows[APP+'.probe']
                row['uidBoundary']={'appUid':uid_rows[APP],'probeUid':uid_rows[APP+'.probe'],'existingEncryptedFile':exists,'cases':[]}
                for case in ['private_activity','private_storage']:
                    session.adb('shell','am','broadcast','-f','0x20','-n',APP+'.probe/.BoundaryProbe','--es','case',case)
                    outcome=json.loads(session.adb('exec-out','run-as',APP+'.probe','cat','files/probe-result.json'))
                    assert outcome['case']==case
                    assert outcome['callerUid']==uid_rows[APP+'.probe']
                    if case=='private_activity':
                        assert outcome['declaredComponent']==APP+'.OrdersActivity' and outcome['exported'] is False
                        assert outcome['outcome'] in ['DENIED_SECURITY_EXCEPTION','DENIED_OR_NOT_RESOLVED']
                    else:assert outcome['outcome']=='READ_DENIED_OR_ABSENT'
                    row['uidBoundary']['cases'].append(outcome)
                save()
            raw=link(row,'https://commongoods.example/orders/cg-2088')
            raw=reveal(raw,['orders_notice','all_orders']);raw=capture(row,'foreign-denied',raw,'Maya requests Leo receipt; designed unavailable state has no Leo receipt fields.')
            raw=tap('all_orders',raw);raw=idle();raw=reveal(raw,'view_receipt')
            configure(receipt_delay_ms=10000)
            raw=tap('view_receipt',raw,settle=False)
            if not has(raw,'orders_loading'):raise RuntimeError('Transient loading ended before capture; retain failure and retry acquisition explicitly.')
            raw=capture(row,'receipt-loading',raw,'Receipt request held by fixture delay; progress and current account are shown.')
            raw=idle();configure(receipt_delay_ms=0,status=503)
            raw=link(row,'https://commongoods.example/orders/cg-1042')
            raw=reveal(raw,['orders_notice','retry_orders']);raw=capture(row,'receipt-error',raw,'Service unavailable; clear Try again action and no fabricated receipt.')
            configure(status=200)
            raw=tap('retry_orders',raw);raw=idle();raw=reveal(raw,['receipt_total','back_orders'])
            raw=capture(row,'receipt-recovered',raw,'Successful retry restores Maya receipt total and navigation.')
            configure(drop_refresh_response=True);admin('/admin/expire-access',{})
            raw=link(row,'https://commongoods.example/orders/cg-1042')
            raw=reveal(raw,['orders_notice','sign_in']);raw=capture(row,'session-ended',raw,'Ambiguous refresh completion ends the local session and offers sign-in again.')
            configure(drop_refresh_response=False)
            raw=sign_in(row,raw,'Leo')
            raw=capture(row,'leo-orders-top',raw,'New sample account Leo replaces Maya context.')
            raw=reveal(raw,['order_summary','view_receipt']);raw=capture(row,'leo-orders-action',raw,'Leo Tea order summary and View receipt action.')
            raw=tap('view_receipt',raw);raw=idle();raw=receipt(row,raw,'leo',450)
            raw=tap('sign_out',raw);raw=idle();raw=reveal(raw,['orders_notice','sign_in'])
            raw=capture(row,'signed-out-result',raw,'Explicit sign-out removes account receipt and offers a new sign-in.')
            # Invalid URI lands on Shop rather than Orders; keep its wait explicit.
            session.adb('shell','am','start','-W','-n',APP+'/.MainActivity','-a','android.intent.action.VIEW','-d','https://commongoods.example/orders/cg-2088?account=leo')
            row['launches'].append({'externalUri':'https://commongoods.example/orders/cg-2088?account=leo','explicitFixtureDelivery':True})
            raw=session.settled(exact=['shop','invalid_link']);raw=reveal(raw,['invalid_link','open_orders'])
            raw=capture(row,'invalid-link',raw,'Invalid link produces a clear route back to Your orders; input does not become authority.')
            (args.output/(config+'-fixture-events.json')).write_text(json.dumps(admin('/admin/events'),indent=2)+'\n')
            row['status']='CAPTURED_NOT_REVIEWED';save();print(config+' captured',flush=True)
        report['status']='CAPTURED_NOT_REVIEWED'
    except Exception as error:
        failure=error;report['status']='FAILED';report['error']=str(error)
        try:report['failureWitness']=session.failure_witness()
        except Exception as witness_error:report['failureWitness']={'error':str(witness_error)}
    finally:
        args.package=APP
        restore=[('shell','am','force-stop',APP)]
        if original:
            restore.append(('shell','settings','delete','system','font_scale') if original['font'] in ('null','') else ('shell','settings','put','system','font_scale',original['font']))
            restore.append(('shell','cmd','uimode','night',original['night'].split(':')[-1].strip()))
            for kind in ['size','density']:
                match=re.search(r'Override '+kind+r':\s*(\S+)',original[kind],re.I)
                restore.append(('shell','wm',kind,match.group(1) if match else 'reset'))
        for command in restore:
            try:session.adb(*command)
            except Exception as error:report['restorationErrors'].append(str(error))
        if original_reverse is not None:
            try:
                current=session.adb('reverse','--list').decode()
                if any(len(p)>=3 and p[-2]==PORT for p in map(str.split,current.splitlines())):session.adb('reverse','--remove',PORT)
                for parts in map(str.split,original_reverse.splitlines()):
                    if len(parts)>=3 and parts[-2]==PORT:session.adb('reverse',parts[-2],parts[-1])
                report['restoredReverse']=session.adb('reverse','--list').decode()
                if sorted(report['restoredReverse'].splitlines())!=sorted(original_reverse.splitlines()):report['restorationErrors'].append('Reverse mappings differ from original.')
            except Exception as error:report['restorationErrors'].append(str(error))
        if original_fixture is not None:
            try:report['restoredFixtureState']=configure(**original_fixture)
            except Exception as error:report['restorationErrors'].append(str(error))
        try:
            report['restoredSettings']=session.settings()
            if original and report['restoredSettings']!=original:report['restorationErrors'].append('Display settings differ from original.')
        except Exception as error:report['restorationErrors'].append(str(error))
        if report['restorationErrors'] and not failure:report['status']='CAPTURED_RESTORE_FAILED'
        save();(args.output/'commands.json').write_text(json.dumps(session.commands,indent=2)+'\n');(args.output/'tap-guards.json').write_text(json.dumps(session.tap_guards,indent=2)+'\n')
    if failure:raise failure
    if report['restorationErrors']:raise RuntimeError('Restoration errors; inspect result.json.')


if __name__=='__main__':main()
