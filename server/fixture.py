#!/usr/bin/env python3
"""Local OAuth-mechanics teaching fixture. The chooser SIMULATES authentication.

No passwords, real accounts, OIDC identity tokens, production TLS or external IdP.
Durable events are typed/allowlisted; no request headers, bodies or query values.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
import argparse, base64, copy, hashlib, hmac, html, json, re, secrets, threading, time

LOCK = threading.RLock()
CLIENT = 'common-goods-book'
CALLBACK = 'staff.android.trust:/oauth2redirect'
ACCOUNTS = {'maya': {'id': 'maya', 'name': 'Maya'}, 'leo': {'id': 'leo', 'name': 'Leo'}}
RECEIPTS = {
    'cg-1042': {'id': 'cg-1042', 'ownerId': 'maya', 'productId': 'camera', 'title': 'Camera', 'totalMinor': 1299900, 'status': 'Delivered'},
    'cg-2088': {'id': 'cg-2088', 'ownerId': 'leo', 'productId': 'tea', 'title': 'Tea', 'totalMinor': 45000, 'status': 'Delivered'},
}
CODES, ACCESS, REFRESH, FAMILIES, EVENTS = {}, {}, {}, {}, []
CONTROL = {'receipt_delay_ms': 0, 'status': 200, 'drop_refresh_response': False}

def secret(): return secrets.token_urlsafe(32)
def fields(raw):
    value = parse_qs(raw, keep_blank_values=True, strict_parsing=True)
    if any(len(v) != 1 for v in value.values()): raise ValueError('duplicate')
    return {k: v[0] for k, v in value.items()}
def valid_authorize(value):
    return (set(value) == {'client_id','redirect_uri','response_type','code_challenge_method','code_challenge','state'}
        and value['client_id'] == CLIENT and value['redirect_uri'] == CALLBACK
        and value['response_type'] == 'code' and value['code_challenge_method'] == 'S256'
        and re.fullmatch(r'[A-Za-z0-9_-]{43}', value['code_challenge']) is not None
        and re.fullmatch(r'[A-Za-z0-9_-]{43}', value['state']) is not None)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def event(self, kind, outcome, principal=None, resource=None):
        assert kind in {'authorize','choose','exchange','refresh','revoke','orders','receipt'}
        assert principal is None or principal in ACCOUNTS
        assert resource is None or re.fullmatch(r'cg-[0-9]{4}', resource)
        with LOCK:
            row = {'sequence': len(EVENTS)+1, 'kind': kind, 'outcome': outcome}
            if principal: row['principal'] = principal
            if resource: row['resource'] = resource
            EVENTS.append(row)
            if self.server.log_path:
                with self.server.log_path.open('a') as stream: stream.write(json.dumps(row)+'\n')
    def send(self, status, value=None, content_type='application/json', location=None):
        data = value.encode() if isinstance(value, str) else json.dumps(value if value is not None else {}).encode()
        self.send_response(status); self.send_header('Content-Type',content_type); self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store'); self.send_header('Pragma','no-cache')
        self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Content-Type-Options','nosniff')
        if location: self.send_header('Location',location)
        self.end_headers()
        try: self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError): pass
    def authenticated(self):
        value = self.headers.get('Authorization','')
        token = value[7:] if value.startswith('Bearer ') else ''
        item = ACCESS.get(token)
        if not item or item['expires'] <= time.monotonic(): return None
        family = FAMILIES[item['family']]
        if family['revoked'] or family['expires'] <= time.monotonic(): return None
        return family['principal']
    def issue(self, principal, family_id=None):
        if family_id is None:
            family_id = secret(); FAMILIES[family_id] = {'principal':principal,'revoked':False,'expires':time.monotonic()+900}
        access, refresh = secret(), secret()
        ACCESS[access] = {'family':family_id,'expires':time.monotonic()+120}
        REFRESH[refresh] = {'family':family_id,'used':False}
        return {'account':ACCOUNTS[principal],'accessToken':access,'refreshToken':refresh,'expiresAtMillis':int(time.time()*1000)+120000}
    def do_GET(self):
        parsed = urlsplit(self.path); path = parsed.path
        if path == '/admin/events':
            with LOCK: self.send(200,{'events':copy.deepcopy(EVENTS),'control':dict(CONTROL)})
            return
        if path == '/authorize':
            try: value = fields(parsed.query)
            except ValueError: value = {}
            if not valid_authorize(value): self.event('authorize','rejected'); self.send(400,{'error':'invalid_request'}); return
            hidden = ''.join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k,v in value.items())
            self.event('authorize','chooser')
            page = '''<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Common Goods sample sign-in</title>
<style>body{font-family:system-ui;background:#f1f4f6;color:#192327;margin:0;padding:24px}main{max-width:540px;margin:32px auto;background:white;border-radius:24px;padding:28px}h1{font-size:32px;line-height:1.1}p{line-height:1.6}button{font:inherit;font-weight:650;display:block;width:100%;margin-top:16px;padding:18px;border:0;border-radius:18px;background:#3156d3;color:white}small{display:block;margin-top:24px;line-height:1.6}</style>
<main><b>Common Goods</b><h1>Choose a sample account</h1><p>This local teaching service simulates an identity provider. No password or real account is used.</p>
<form method="post" action="/choose">''' + hidden + '''<button name="account" value="maya">Continue as Maya</button><button name="account" value="leo">Continue as Leo</button></form><small>You will return to the app to view this sample account's orders.</small></main></html>'''
            self.send(200,page,'text/html; charset=utf-8'); return
        with LOCK:
            principal = self.authenticated()
            if path == '/orders':
                if not principal: self.event('orders','unauthorized'); self.send(401,{'error':'unauthorized'}); return
                if CONTROL['status'] != 200: self.event('orders','unavailable',principal); self.send(CONTROL['status'],{'error':'unavailable'}); return
                result = [{k:v for k,v in row.items() if k not in {'ownerId','status'}} for row in RECEIPTS.values() if row['ownerId']==principal]
                self.event('orders','allowed',principal); self.send(200,result); return
            match = re.fullmatch(r'/orders/(cg-[0-9]{4})',path)
            if match:
                resource = match.group(1)
                if not principal: self.event('receipt','unauthorized',resource=resource); self.send(401,{'error':'unauthorized'}); return
                row = RECEIPTS.get(resource)
                # Same response for nonexistent and non-owned objects: selector != authority.
                if row is None or row['ownerId'] != principal:
                    self.event('receipt','denied',principal,resource); self.send(404,{'error':'unavailable'}); return
                if CONTROL['status'] != 200: self.event('receipt','unavailable',principal,resource); self.send(CONTROL['status'],{'error':'unavailable'}); return
                reply = dict(row); delay = CONTROL['receipt_delay_ms']/1000
                self.event('receipt','admitted',principal,resource)
            else: self.send(404,{'error':'not_found'}); return
        # Models an already-authorized response completing after local account transition.
        time.sleep(delay)
        self.event('receipt','completed',principal,resource); self.send(200,reply)
    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            size = int(self.headers.get('Content-Length','0'))
            if not 0 <= size <= 8192: self.send(413); return
            raw = self.rfile.read(size).decode('utf-8',errors='strict')
            value = json.loads(raw or '{}') if path.startswith('/admin/') else fields(raw)
        except (ValueError,UnicodeError): self.send(400,{'error':'invalid_request'}); return
        with LOCK:
            if path == '/admin/reset':
                CODES.clear(); ACCESS.clear(); REFRESH.clear(); FAMILIES.clear(); EVENTS.clear()
                CONTROL.update(receipt_delay_ms=0,status=200,drop_refresh_response=False); self.send(200,dict(CONTROL)); return
            if path == '/admin/config':
                if not isinstance(value,dict) or not set(value)<=set(CONTROL): self.send(400); return
                proposed = dict(CONTROL,**value)
                if type(proposed['receipt_delay_ms']) is not int or not 0<=proposed['receipt_delay_ms']<=10000 or proposed['status'] not in [200,503] or type(proposed['drop_refresh_response']) is not bool: self.send(400); return
                CONTROL.update(proposed); self.send(200,dict(CONTROL)); return
            if path == '/admin/expire-access':
                for row in ACCESS.values(): row['expires']=0
                self.send(200,{'expired':len(ACCESS)}); return
            if path == '/choose':
                principal=value.pop('account',None)
                if principal not in ACCOUNTS or not valid_authorize(value): self.event('choose','rejected'); self.send(400,{'error':'invalid_request'}); return
                code=secret(); CODES[code]={'challenge':value['code_challenge'],'principal':principal,'expires':time.monotonic()+60,'used':False}
                self.event('choose','code_issued',principal)
                self.send(302,location=CALLBACK+'?'+urlencode({'code':code,'state':value['state']})); return
            if path == '/token':
                if value.get('client_id') != CLIENT: self.send(400,{'error':'invalid_client'}); return
                if value.get('grant_type') == 'authorization_code':
                    item=CODES.get(value.get('code')); verifier=value.get('code_verifier','')
                    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                    if (set(value)!={'grant_type','client_id','redirect_uri','code','code_verifier'} or value.get('redirect_uri')!=CALLBACK or not re.fullmatch(r'[A-Za-z0-9_-]{43}',verifier) or not item or item['used'] or item['expires']<=time.monotonic() or not hmac.compare_digest(challenge,item['challenge'])):
                        self.event('exchange','rejected'); self.send(400,{'error':'invalid_grant'}); return
                    item['used']=True; self.event('exchange','issued',item['principal']); self.send(200,self.issue(item['principal'])); return
                if value.get('grant_type') == 'refresh_token':
                    item=REFRESH.get(value.get('refresh_token'))
                    if set(value)!={'grant_type','client_id','refresh_token'} or not item: self.event('refresh','rejected'); self.send(400,{'error':'invalid_grant'}); return
                    family=FAMILIES[item['family']]
                    if item['used']:
                        family['revoked']=True; self.event('refresh','reuse_family_revoked',family['principal']); self.send(400,{'error':'invalid_grant'}); return
                    if family['revoked'] or family['expires']<=time.monotonic(): self.event('refresh','expired',family['principal']); self.send(400,{'error':'invalid_grant'}); return
                    item['used']=True; reply=self.issue(family['principal'],item['family'])
                    self.event('refresh','rotated',family['principal'])
                    if CONTROL['drop_refresh_response']:
                        self.event('refresh','response_dropped',family['principal']); self.close_connection=True; return
                    self.send(200,reply); return
                self.send(400,{'error':'unsupported_grant_type'}); return
            if path == '/revoke':
                item=REFRESH.get(value.get('token'))
                if item: FAMILIES[item['family']]['revoked']=True
                self.event('revoke','accepted'); self.send(200); return
        self.send(404,{'error':'not_found'})

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--port',type=int,default=8875); parser.add_argument('--log',type=Path); args=parser.parse_args()
    if args.log:
        args.log.parent.mkdir(parents=True,exist_ok=True)
        if args.log.exists(): raise SystemExit('Use a new event log; previous evidence is preserved.')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler); server.log_path=args.log
    print(f'Common Goods local identity fixture on127.0.0.1:{args.port}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
