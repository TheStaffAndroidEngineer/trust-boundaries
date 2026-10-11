#!/usr/bin/env python3
"""Bounded optimized-release Shop -> browser -> Maya receipt capture; root runs it."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from capture_appearance import TrustCapture, APP, BROWSER, PORT, bounds, matches, panes, pane_key, find_pane, signature, area
ROOT=HERE.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--out','--output',dest='output',type=Path,required=True);p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--candidate',default='release-candidate2');p.add_argument('--serial',default='emulator-5554');p.add_argument('--expected-avd',default='StaffAndroid_API_36')
    p.add_argument('--max-scrolls',type=int,default=18);p.add_argument('--settle-timeout',type=float,default=45)
    args=p.parse_args();args.package=APP
    if not 1<=args.max_scrolls<=24 or not 1<=args.settle_timeout<=120:p.error('Use bounded scroll and settle limits.')
    apk=args.apk.resolve()
    if not apk.is_file():p.error('APK is missing.')
    if args.output.exists():p.error('Use a new capture directory.')
    args.output.mkdir(parents=True)
    script=Path(__file__).read_bytes();(args.output/'capture-script.py').write_bytes(script)
    dependencies=[HERE/'capture_appearance.py',ROOT/'projects/commerce-app/tools/capture_checkpoint_appearance.py',ROOT/'projects/catalog-network/tools/fresh_android_xml.py']
    session=TrustCapture(args);original=reverse=fixture=None;failure=None
    report={'status':'STARTING','package':APP,'browserPackage':BROWSER,'serial':args.serial,'candidate':args.candidate,
        'apk':str(apk),'apkSha256':sha(apk),'captureScriptSha256':hashlib.sha256(script).hexdigest(),
        'captureDependencies':{str(x.relative_to(ROOT)):sha(x) for x in dependencies},
        'scope':'Optimized release, bounded light configuration: public Shop, signed-out Orders, actual external sample account selection, Maya order and full receipt price/navigation. No secrets in adb arguments; no production identity or penetration-test claim.',
        'textRedaction':{'fields':['state','code','code_challenge','code_verifier','access_token','refresh_token'],'scope':'Retained XML/window query text only; unaltered PNGs.'},
        'rows':[],'fixtureActions':[],'restorationErrors':[]}
    def save():(args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def admin(path,payload=None):
        req=urllib.request.Request('http://127.0.0.1:8875'+path,data=None if payload is None else json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=10) as r:value=json.load(r)
        report['fixtureActions'].append({'path':path,'payload':payload});return value
    def has(raw,label):return any(matches(n,label) for n in ET.fromstring(raw).iter('node'))
    def framed(raw,labels):
        tree=ET.fromstring(raw);parents={c:p for p in tree.iter() for c in p}
        for label in labels:
            good=False
            for node in tree.iter('node'):
                if node.get('package')!=args.package or not matches(node,label):continue
                l,t,r,b=bounds(node)
                if not area((l,t,r,b)):continue
                valid=True;parent=node
                while parent in parents:
                    parent=parents[parent]
                    if parent.get('scrollable')=='true':
                        pl,pt,pr,pb=bounds(parent)
                        if l<pl or r>pr or t<pt+12 or b>pb-12:valid=False
                if valid:good=True;break
            if not good:return False
        return True
    def reveal(raw,labels):
        labels=[labels] if isinstance(labels,str) else labels
        if framed(raw,labels):return raw
        for key in [pane_key(x) for x in panes(ET.fromstring(raw),args.package)]:
            for direction in ['down','up']:
                for _ in range(args.max_scrolls):
                    pane=find_pane(ET.fromstring(raw),args.package,key)
                    if pane is None:break
                    before=signature(pane);raw=session.swipe(pane,direction)
                    if framed(raw,labels):return raw
                    after=find_pane(ET.fromstring(raw),args.package,key)
                    if after is None or signature(after)==before:break
        raise RuntimeError('Could not frame release controls: '+repr(labels))
    def tap(raw,label,next_package=APP,expected=()):
        raw=reveal(raw,label);raw=session.xml();target=session.target(ET.fromstring(raw),label)
        if target is None:raise RuntimeError('No fresh guarded release target: '+label)
        l,t,r,b=bounds(target);session.adb('shell','input','tap',(l+r)//2,(t+b)//2);args.package=next_package
        return session.settled(exact=list(expected))
    def idle():
        # The fixture's successful responses are immediate; settled UI waits
        # are bounded by the same session limit and require a ready action.
        return session.settled(exact=['orders_screen','view_receipt'])
    def capture(name,raw,condition):
        f=session.capture('light-release-'+name,raw);f.update(condition=condition,surfacePackage=args.package);row['frames'].append(f);save();return raw
    try:
        avd=session.adb('emu','avd','name').decode().strip()
        if args.expected_avd not in avd.splitlines():raise RuntimeError('Unexpected emulator.')
        report['avd']=avd;original=session.settings();report['originalSettings']=original
        reverse=session.adb('reverse','--list').decode();report['originalReverse']=reverse
        fixture=admin('/admin/events')['control'];report['originalFixtureState']=fixture
        session.adb('reverse',PORT,PORT);session.adb('shell','am','force-stop',APP)
        session.adb('shell','wm','size','reset');session.adb('shell','wm','density','reset');session.adb('shell','settings','put','system','font_scale','1.0');session.adb('shell','cmd','uimode','night','no')
        session.adb('install','-r',apk)
        installed=session.adb('shell','pm','path',APP).decode().strip().removeprefix('package:');session.adb('pull',installed,args.output/'installed.apk')
        assert sha(args.output/'installed.apk')==report['apkSha256']
        admin('/admin/reset',{})
        if session.adb('shell','pm','clear',APP).decode().strip()!='Success':raise RuntimeError('Could not reset seeded release app.')
        row={'config':'light','settings':session.settings(),'status':'STARTING','frames':[],'launches':[{'route':'Shop','resetFixtureApp':True}]};report['rows'].append(row)
        assert row['settings']['font']=='1.0' and 'Night mode: no' in row['settings']['night']
        assert 'Override' not in row['settings']['size'] and 'Override' not in row['settings']['density']
        session.adb('shell','am','start','-W','-n',APP+'/.MainActivity','-f','0x10008000')
        raw=session.settled(exact=['shop']);raw=capture('shop',raw,'Optimized release public catalog and Orders route.')
        raw=tap(raw,'open_orders',expected=['orders_screen']);raw=reveal(raw,['orders_notice','sign_in']);raw=capture('signed-out',raw,'Signed-out Orders and complete Sign in control.')
        raw=tap(raw,'sign_in',BROWSER,['Choose a sample account','Continue as Maya']);raw=reveal(raw,['Continue as Maya','Continue as Leo']);raw=capture('browser',raw,'Real external Custom Tab with both sample-account choices.')
        raw=tap(raw,'Continue as Maya',APP,['orders_screen']);raw=idle()
        assert has(raw,'Signed in as Maya');raw=capture('orders-top',raw,'Maya account context in the optimized release app.')
        raw=reveal(raw,['order_summary','view_receipt']);raw=capture('orders-action',raw,'Full Camera order summary and View receipt action.')
        raw=tap(raw,'view_receipt');raw=session.settled(exact=['orders_screen','receipt_total']);raw=capture('receipt-top',raw,'Maya receipt upper area.')
        # Require the exact price and neighboring action inside the scroll pane;
        # actual glyph completeness is inspected in the retained PNG.
        raw=reveal(raw,['receipt_total','back_orders'])
        value=[n.get('text','') for n in ET.fromstring(raw).iter('node') if matches(n,'receipt_total')]
        assert len(value)==1 and re.sub(r'\D','',value[0])=='12999'
        raw=capture('receipt-full',raw,'Complete ₹12,999 receipt total and Back to your orders action.')
        (args.output/'release-fixture-events.json').write_text(json.dumps(admin('/admin/events'),indent=2)+'\n')
        row['status']='CAPTURED_NOT_REVIEWED';report['status']='CAPTURED_NOT_REVIEWED';save();print('Release captured; actual pixel review remains separate.',flush=True)
    except Exception as error:
        failure=error;report['status']='FAILED';report['error']=str(error)
        try:report['failureWitness']=session.failure_witness()
        except Exception as extra:report['failureWitness']={'error':str(extra)}
    finally:
        args.package=APP;commands=[('shell','am','force-stop',APP)]
        if original:
            commands.append(('shell','settings','delete','system','font_scale') if original['font'] in ('null','') else ('shell','settings','put','system','font_scale',original['font']))
            commands.append(('shell','cmd','uimode','night',original['night'].split(':')[-1].strip()))
            for kind in ['size','density']:
                match=re.search(r'Override '+kind+r':\s*(\S+)',original[kind],re.I);commands.append(('shell','wm',kind,match.group(1) if match else 'reset'))
        for command in commands:
            try:session.adb(*command)
            except Exception as error:report['restorationErrors'].append(str(error))
        if reverse is not None:
            try:
                current=session.adb('reverse','--list').decode()
                if any(len(x)>=3 and x[-2]==PORT for x in map(str.split,current.splitlines())):session.adb('reverse','--remove',PORT)
                for x in map(str.split,reverse.splitlines()):
                    if len(x)>=3 and x[-2]==PORT:session.adb('reverse',x[-2],x[-1])
                report['restoredReverse']=session.adb('reverse','--list').decode();assert sorted(reverse.splitlines())==sorted(report['restoredReverse'].splitlines())
            except Exception as error:report['restorationErrors'].append(str(error))
        if fixture is not None:
            try:report['restoredFixtureState']=admin('/admin/config',fixture)
            except Exception as error:report['restorationErrors'].append(str(error))
        try:
            report['restoredSettings']=session.settings()
            if original and report['restoredSettings']!=original:report['restorationErrors'].append('Display settings differ from original.')
        except Exception as error:report['restorationErrors'].append(str(error))
        if report['restorationErrors'] and not failure:report['status']='CAPTURED_RESTORE_FAILED'
        save();(args.output/'commands.json').write_text(json.dumps(session.commands,indent=2)+'\n');(args.output/'tap-guards.json').write_text(json.dumps(session.tap_guards,indent=2)+'\n')
    if failure:raise failure
    if report['restorationErrors']:raise RuntimeError('Release restoration failed; inspect result.json.')


if __name__=='__main__':main()
