#!/usr/bin/env python3
"""Independent real-HTTP contract campaign; fixture secrets stay in process memory.

Starts an owned fixture on 8876, never the device fixture on 8875. Retains only
allowlisted outcomes/events and source hashes, not requests, redirect headers,
token responses or raw exception messages. Not a production penetration test.
"""
from pathlib import Path
from hashlib import sha256
from urllib.parse import urlencode, urlsplit, parse_qs
import argparse
import base64
import http.client
import json
import secrets
import signal
import socket
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
SERVER = PROJECT / 'server/fixture.py'
CLIENT = 'common-goods-book'
CALLBACK = 'staff.android.trust:/oauth2redirect'
PORT = 8876
KNOWN = set()
CASES = []
EVENTS = []

class ContractFailure(Exception): pass
def require(condition, label):
    if not condition: raise ContractFailure(label)
def secret():
    value = secrets.token_urlsafe(32); KNOWN.add(value); return value
def exchange(method, path, values=None, bearer=None, raw=None, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)
    actual = dict(headers or {})
    if bearer: actual['Authorization'] = 'Bearer ' + bearer
    if raw is None and values is not None:
        raw = urlencode(values).encode(); actual['Content-Type'] = 'application/x-www-form-urlencoded'
    try:
        connection.request(method, path, body=raw, headers=actual)
        response = connection.getresponse()
        data = response.read(65_537)
        require(len(data) <= 65_536, 'response_bound')
        return response.status, dict(response.getheaders()), data
    finally: connection.close()
def form(path, values): return exchange('POST', path, values=values)
def admin(path, values=None):
    status, _, data = exchange('POST', path, raw=json.dumps(values or {}).encode(), headers={'Content-Type':'application/json'})
    require(status == 200, 'admin_status'); return json.loads(data)
def auth_request():
    verifier, state = secret(), secret()
    challenge = base64.urlsafe_b64encode(sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
    return verifier, {'client_id':CLIENT, 'redirect_uri':CALLBACK, 'response_type':'code',
                      'code_challenge_method':'S256', 'code_challenge':challenge, 'state':state}
def choose(account='maya'):
    verifier, values = auth_request()
    status, headers, _ = form('/choose', dict(values, account=account))
    require(status == 302, 'chooser_redirect')
    location = headers.get('Location',''); parsed = urlsplit(location)
    require(parsed.scheme == 'staff.android.trust' and parsed.path == '/oauth2redirect' and not parsed.netloc, 'fixed_callback')
    query = parse_qs(parsed.query, strict_parsing=True)
    require(set(query)=={'code','state'} and all(len(v)==1 for v in query.values()), 'callback_fields')
    require(query['state'][0] == values['state'], 'state_returned')
    code = query['code'][0]; KNOWN.add(code)
    return verifier, code
def token_form(verifier, code):
    return {'grant_type':'authorization_code','client_id':CLIENT,'redirect_uri':CALLBACK,'code':code,'code_verifier':verifier}
def tokens(data, expected):
    value=json.loads(data)
    require(set(value)=={'account','accessToken','refreshToken','expiresAtMillis'}, 'token_shape')
    require(value['account']['id']==expected, 'token_account')
    for key in ['accessToken','refreshToken']:
        require(isinstance(value[key],str) and len(value[key])==43, 'opaque_token_length')
        KNOWN.add(value[key])
    return value
def sign_in(account='maya'):
    verifier, code = choose(account)
    status, headers, body = form('/token',token_form(verifier,code))
    require(status==200,'valid_exchange')
    require(headers.get('Cache-Control')=='no-store' and headers.get('Pragma')=='no-cache','token_cache_headers')
    return tokens(body,account)
def refresh(value): return form('/token',{'grant_type':'refresh_token','client_id':CLIENT,'refresh_token':value})
def typed_events():
    status, _, body = exchange('GET','/admin/events'); require(status==200,'events_status')
    rows=json.loads(body)['events']
    kinds={'authorize','choose','exchange','refresh','revoke','orders','receipt'}
    outcomes={'rejected','chooser','code_issued','issued','unauthorized','unavailable','allowed','denied',
              'admitted','completed','reuse_family_revoked','expired','rotated','response_dropped','accepted'}
    for number,row in enumerate(rows,1):
        require(set(row)<= {'sequence','kind','outcome','principal','resource'}, 'event_field_allowlist')
        require(row['sequence']==number and row['kind'] in kinds and row['outcome'] in outcomes,'event_value_allowlist')
        require(row.get('principal') in {None,'maya','leo'},'event_principal_allowlist')
        require(row.get('resource') in {None,'cg-1042','cg-2088','cg-9999'},'event_resource_allowlist')
    serialized=json.dumps(rows)
    require(not any(value in serialized for value in KNOWN),'events_exclude_known_secrets')
    return rows
def case(name, action):
    start=time.monotonic()
    try:
        observations=action() or {}
        CASES.append({'name':name,'passed':True,'observations':observations,'duration_seconds':round(time.monotonic()-start,6)})
    except Exception as error:
        # An assertion/exception must never serialize request values or credentials.
        CASES.append({'name':name,'passed':False,'failure_type':type(error).__name__,
                      'failure_check':str(error) if isinstance(error,ContractFailure) else 'unexpected_exception'})
        raise

def campaign():
    admin('/admin/reset')
    def authorization_shapes():
        verifier, value=auth_request()
        status,headers,body=exchange('GET','/authorize?'+urlencode(value))
        require(status==200 and b'Choose a sample account' in body,'external_sample_chooser')
        require(verifier.encode() not in body,'verifier_not_in_authorization_page')
        observed=[]
        for changed in [dict(value,client_id='other-client'),dict(value,redirect_uri='https://evil.example/cb'),
                        dict(value,code_challenge_method='plain'),dict(value,code_challenge='short')]:
            status,_,_=exchange('GET','/authorize?'+urlencode(changed)); observed.append(status);require(status==400,'authorize_rejected')
        status,_,_=exchange('GET','/authorize?'+urlencode(value)+'&state='+value['state']);require(status==400,'duplicate_authorize_state')
        return {'valid_chooser_status':200,'rejected_variants':len(observed)+1,'rejection_status':400}
    case('authorization_exact_client_redirect_s256_and_single_parameters',authorization_shapes)

    def code_bindings():
        verifier,code=choose(); valid=token_form(verifier,code)
        attempts=[dict(valid,code_verifier=secret()),dict(valid,client_id='other-client'),
                  dict(valid,redirect_uri='staff.android.trust:/other'),dict(valid,unexpected='field')]
        for values in attempts:
            status,_,_=form('/token',values);require(status==400,'code_binding_rejected')
        status,headers,data=form('/token',valid);require(status==200,'correct_binding_after_rejected_attempts')
        current=tokens(data,'maya')
        require(headers.get('Cache-Control')=='no-store','token_not_cacheable')
        status,_,_=form('/token',valid);require(status==400,'code_replay_rejected')
        state['maya']=current
        return {'wrong_bindings_rejected':4,'valid_exchange_status':200,'replay_status':400}
    state={}
    case('code_pkce_client_redirect_extra_field_binding_and_one_use',code_bindings)

    def resource_ownership():
        access=state['maya']['accessToken']
        status,_,noauth=exchange('GET','/orders/cg-1042');require(status==401,'missing_bearer')
        status,_,own=exchange('GET','/orders/cg-1042',bearer=access);require(status==200,'owned_receipt')
        row=json.loads(own);require(row['ownerId']=='maya' and row['id']=='cg-1042' and row['totalMinor']==1299900,'owned_fields')
        status,_,denied=exchange('GET','/orders/cg-2088',bearer=access,headers={'X-Owner':'leo','X-Account':'leo'})
        require(status==404 and json.loads(denied)=={'error':'unavailable'},'foreign_receipt_no_fields')
        status,_,missing=exchange('GET','/orders/cg-9999',bearer=access);require(status==404 and denied==missing,'generic_nonowned_missing')
        status,_,data=exchange('GET','/orders',bearer=access)
        require(status==200 and [r['id'] for r in json.loads(data)]==['cg-1042'],'orders_owner_filter')
        return {'missing_session_status':401,'owned_status':200,'foreign_and_missing_status':404,
                'foreign_body_has_only_generic_error':True,'forged_owner_headers_ignored':True,'orders_ids':['cg-1042']}
    case('server_receipt_ownership_without_client_ui',resource_ownership)

    def rotate_reuse():
        previous=state['maya'];status,_,data=refresh(previous['refreshToken']);require(status==200,'first_rotation')
        replacement=tokens(data,'maya')
        require(replacement['refreshToken']!=previous['refreshToken'] and replacement['accessToken']!=previous['accessToken'],'fresh_rotated_credentials')
        status,_,_=exchange('GET','/orders/cg-1042',bearer=replacement['accessToken']);require(status==200,'replacement_access')
        status,_,_=refresh(previous['refreshToken']);require(status==400,'reuse_rejected')
        status,_,_=exchange('GET','/orders/cg-1042',bearer=replacement['accessToken']);require(status==401,'reuse_revokes_current_access')
        status,_,_=refresh(replacement['refreshToken']);require(status==400,'reuse_revokes_current_refresh')
        return {'rotation_status':200,'reused_refresh_status':400,'family_access_after_reuse':401,'family_refresh_after_reuse':400}
    case('refresh_rotation_and_reuse_family_invalidation',rotate_reuse)

    def refresh_client_binding():
        current=sign_in()
        status,_,_=form('/token',{'grant_type':'refresh_token','client_id':'other-client','refresh_token':current['refreshToken']})
        require(status==400,'wrong_refresh_client')
        status,_,data=refresh(current['refreshToken']);require(status==200,'correct_client_not_consumed_by_wrong_client');tokens(data,'maya')
        return {'wrong_client_status':400,'subsequent_correct_client_status':200}
    case('refresh_client_binding_does_not_consume_on_mismatch',refresh_client_binding)

    def leo_revoke():
        current=sign_in('leo')
        status,_,data=exchange('GET','/orders/cg-2088',bearer=current['accessToken']);require(status==200,'leo_owned')
        require(json.loads(data)['totalMinor']==45000,'leo_amount')
        status,_,body=exchange('GET','/orders/cg-1042',bearer=current['accessToken']);require(status==404 and json.loads(body)=={'error':'unavailable'},'leo_cannot_read_maya')
        status,_,_=form('/revoke',{'token':current['refreshToken']});require(status==200,'revoke_status')
        status,_,_=exchange('GET','/orders',bearer=current['accessToken']);require(status==401,'revoked_access')
        status,_,_=refresh(current['refreshToken']);require(status==400,'revoked_refresh')
        status,_,_=form('/revoke',{'token':secret()});require(status==200,'unknown_revoke_is_nondisclosing')
        return {'leo_owned_status':200,'leo_foreign_status':404,'revocation_status':200,'revoked_access_status':401,
                'revoked_refresh_status':400,'unknown_token_revocation_status':200}
    case('second_account_ownership_and_revocation',leo_revoke)

    def lost_response():
        current=sign_in();before=len(typed_events());admin('/admin/config',{'drop_refresh_response':True})
        disconnected=False
        try: refresh(current['refreshToken'])
        except http.client.RemoteDisconnected: disconnected=True
        require(disconnected,'dropped_refresh_connection')
        after=typed_events()[before:]
        require(sum(r['kind']=='refresh' and r['outcome']=='rotated' for r in after)==1,'one_observed_rotation')
        require(sum(r['kind']=='refresh' and r['outcome']=='response_dropped' for r in after)==1,'one_observed_drop')
        admin('/admin/config',{'drop_refresh_response':False})
        status,_,_=refresh(current['refreshToken']);require(status==400,'lost_response_old_token_consumed')
        status,_,_=exchange('GET','/orders',bearer=current['accessToken']);require(status==401,'lost_response_reuse_revokes_family')
        return {'client':'Python http.client; no automatic retries in this test','connection_closed_without_response':True,
                'observed_rotations_before_manual_replay':1,'observed_drops':1,'manual_old_token_replay_status':400,'family_access_status':401}
    case('lost_refresh_response_keeps_consumption_and_reuse_semantics',lost_response)

    def malformed():
        observations=[]
        for name,body,headers,expected in [
            ('invalid_length',b'',{'Content-Length':'bad'},400),('negative_length',b'',{'Content-Length':'-1'},413),
            ('over_bound',b'',{'Content-Length':'8193'},413),('invalid_utf8',bytes([255]),{},400),
            ('malformed_form',b'broken-field',{},400),('duplicate_form',b'client_id=a&client_id=b',{},400),
        ]:
            status,_,body=exchange('POST','/token',raw=body,headers=headers)
            require(status==expected,'malformed_'+name);observations.append({'variant':name,'status':status})
        return {'rejections':observations}
    case('malformed_framing_utf8_and_form_inputs_reject_without_traceback',malformed)
    global EVENTS
    EVENTS=typed_events()
    case('retained_typed_events_exclude_all_known_transaction_credentials',lambda:{'event_count':len(EVENTS),
        'known_secret_values_scanned_in_memory':len(KNOWN),'event_field_and_value_allowlists_verified':True,'known_secrets_found':0})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists(): raise SystemExit('Use a new output directory to preserve prior evidence.')
    # Refuse to take over a port owned by another process.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',PORT))
    before=sha256(SERVER.read_bytes()).hexdigest()
    process=subprocess.Popen([sys.executable,str(SERVER),'--port',str(PORT)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    top_failure=None
    try:
        ready=False
        for _ in range(60):
            if process.poll() is not None: break
            try:
                with socket.create_connection(('127.0.0.1',PORT),timeout=.2): ready=True;break
            except OSError: time.sleep(.05)
        require(ready,'owned_fixture_ready');campaign()
    except Exception as error:
        top_failure={'type':type(error).__name__,'check':str(error) if isinstance(error,ContractFailure) else 'unexpected_exception'}
    finally:
        if process.poll() is None: process.send_signal(signal.SIGINT)
        stdout,stderr=process.communicate(timeout=10)
    log_leak=any(v.encode() in stdout or v.encode() in stderr for v in KNOWN)
    stable=before==sha256(SERVER.read_bytes()).hexdigest()
    passed=not top_failure and all(c['passed'] for c in CASES) and not stderr and not log_leak and process.returncode==0 and stable
    result={'status':'PASS' if passed else 'FAIL','passed':passed,'port':PORT,'client':'Python stdlib http.client',
            'server_source_sha256_before':before,'server_source_sha256_after':sha256(SERVER.read_bytes()).hexdigest(),
            'checker_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),'source_unchanged':stable,
            'cases':CASES,'case_count':len(CASES),'failure':top_failure,
            'process':{'exit_code':process.returncode,'stdout_sha256':sha256(stdout).hexdigest(),'stderr_bytes':len(stderr),
                       'stderr_sha256':sha256(stderr).hexdigest(),'known_secret_in_stdout_or_stderr':log_leak},
            'limits':['Controlled local HTTP fixture with seeded identities; no real identity verification or production TLS.',
                      'No Android HttpURLConnection transport retry conclusion from Python client results.',
                      'Server code expiry and absolute family expiry are source-reviewed; no timed expiry claim in this campaign.',
                      'Typed fixture events and owned process output checked, not every OS/browser/crash channel.',
                      'Secrets and raw HTTP messages are intentionally not retained.']}
    args.output.mkdir(parents=True)
    (args.output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    if not any(v in json.dumps(EVENTS) for v in KNOWN):
        (args.output/'events.json').write_text(json.dumps(EVENTS,indent=2)+'\n')
    print(json.dumps({'passed':passed,'cases':len(CASES),'failure':top_failure,'events':len(EVENTS)}))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
