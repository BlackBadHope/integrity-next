"""Signed administrative accounting, never a forged original turn terminal.

An immutable root-issued grant binds an exact current curator registration,
context, complete request, namespace, targets and expiry. Mutation is available
only through the admitted model-owned facade. Existing registrations and normal
terminal receipts are never modified. Unknown action outcomes remain explicit.
"""
import datetime as dt,hashlib,json,os,re,stat,tempfile
try:
    import fcntl
except ImportError:
    fcntl = None
from pathlib import Path
from .canonical import canonical_bytes
from .signing import verify_trusted_signature

PROTOCOL='integrity-guardian/turn-curator-reconciliation/v1'
GRANT_DIR=Path('/etc/integrity-client-memory-lts/curator-grants')
class CuratorError(ValueError):pass
def need(ok,code):
    if not ok:raise CuratorError(code)
def digest(value):return hashlib.sha256(canonical_bytes(value)).hexdigest()
def now():return dt.datetime.now(dt.UTC)
def utc(value):
    x=dt.datetime.fromisoformat(value.replace('Z','+00:00'));need(x.tzinfo is not None,'curator_time_naive');return x
def normalize_request(args):
    need(isinstance(args,dict) and set(args)=={'grant_id','curator_registration_id','context_admission_id','decisions'},'curator_request_shape')
    for k in ['grant_id','curator_registration_id','context_admission_id']:
        need(isinstance(args[k],str) and re.fullmatch(r'sha256:[a-f0-9]{64}',args[k]),'curator_request_identity')
    decisions=args['decisions'];need(isinstance(decisions,list) and 1<=len(decisions)<=8,'curator_decisions_bound')
    seen=set()
    for d in decisions:
        need(isinstance(d,dict) and set(d)=={'registration_id','classification','evidence_sha256','events'},'curator_decision_shape')
        need(re.fullmatch(r'sha256:[a-f0-9]{64}',str(d['registration_id'])) is not None and d['registration_id'] not in seen,'curator_target_identity')
        seen.add(d['registration_id']);need(re.fullmatch(r'[a-f0-9]{64}',str(d['evidence_sha256'])) is not None,'curator_evidence_digest')
        need(d['classification'] in ['event-backed','interrupted-unknown','missing-terminal-unknown'],'curator_classification')
        need(isinstance(d['events'],list),'curator_events_shape')
        if d['classification']=='event-backed':need(1<=len(d['events'])<=8,'curator_events_required')
        else:need(d['events']==[],'curator_unknown_cannot_assert_events')
    return {k:args[k] for k in ['curator_registration_id','context_admission_id','decisions']}
def read_grant(grant_id):
    path=GRANT_DIR/(grant_id.split(':')[1]+'.json')
    for p in (GRANT_DIR,path):
        info=p.lstat();need(not p.is_symlink(),'curator_grant_symlink')
        if os.name!='nt':need(info.st_uid==0 and not stat.S_IMODE(info.st_mode)&0o022,'curator_grant_custody')
    need(path.is_file() and path.stat().st_size<=65536,'curator_grant_bound')
    raw=path.read_bytes();need('sha256:'+hashlib.sha256(raw).hexdigest()==grant_id,'curator_grant_digest')
    grant=json.loads(raw)
    need(set(grant)=={'protocol','namespace_fingerprint','owner_scope_sha256','curator_registration_id','context_admission_id','actor_identity','request_digest','target_preimages','issued_at','expires_at'},'curator_grant_shape')
    need(grant['protocol']=='integrity-guardian/turn-curator-grant/v1','curator_grant_protocol')
    need(utc(grant['issued_at'])<=now()<utc(grant['expires_at']) and (utc(grant['expires_at'])-utc(grant['issued_at'])).total_seconds()<=3600,'curator_grant_expired')
    need(re.fullmatch(r'[a-f0-9]{64}',str(grant['owner_scope_sha256'])) is not None,'curator_owner_scope')
    return grant
def store_for(server,registration):
    aggregate=server._require_turn_memory()
    if hasattr(aggregate,'_registration_owner'):
        _,store=aggregate._registration_owner(registration)
    else:
        store=aggregate
        need(store.find_registration(registration) is not None,'curator_registration_missing')
    return store
def has_terminal(store,registration):
    with store._read_connection() as connection:
        row=connection.execute('SELECT receipt_json FROM turn_terminal_receipts WHERE registration_id=?',(registration,)).fetchone()
    if row is None:return False
    receipt=store._verify_profile_receipt('terminal-receipt',json.loads(bytes(row['receipt_json'])))
    store._verify_join(receipt,store.find_registration(registration));return True
def ledger_root(store):
    root=store.path.parent/'curator-reconciliations-v1'
    if not root.exists():root.mkdir(mode=0o700)
    need(not root.is_symlink() and root.is_dir(),'curator_ledger_custody')
    if os.name!='nt':need(root.stat().st_uid==os.geteuid() and not stat.S_IMODE(root.stat().st_mode)&0o077,'curator_ledger_custody')
    return root
def verify_pack(pack,store):
    need(isinstance(pack,dict) and pack.get('protocol')==PROTOCOL,'curator_receipt_protocol')
    need(verify_trusted_signature(pack,store.trusted_key),'curator_receipt_signature')
    need(pack.get('namespace_fingerprint')==store.namespace,'curator_receipt_namespace')
    unsigned={k:v for k,v in pack.items() if k not in ['signature','receipt_id']}
    need(pack.get('receipt_id')=='sha256:'+digest(unsigned),'curator_receipt_digest')
    need(pack.get('original_terminal_asserted') is False and pack.get('retry_authority') is False,'curator_receipt_semantics')
    return pack
def read_packs(store):
    root=store.path.parent/'curator-reconciliations-v1'
    if not root.exists():return []
    need(not root.is_symlink(),'curator_ledger_symlink')
    files=list(root.glob('*.json'));need(len(files)<=512,'curator_ledger_read_bound')
    result=[]
    for path in files:
        need(not path.is_symlink() and path.is_file() and path.stat().st_size<=131072,'curator_receipt_custody')
        result.append(verify_pack(json.loads(path.read_bytes()),store))
    return result
def reconcile(server,args):
    need(os.name=='posix' and fcntl is not None,'curator_posix_custody_required')
    request=normalize_request(args)
    need(server._broker_tool_surface_authenticated,'curator_authenticated_broker_required')
    need(not getattr(server,'_context_reattach_read_only',False) and not getattr(server,'_context_reattach_control_only',False),'curator_reattach_cannot_mutate')
    need(server._write_plane_runtime_is_ready(),'curator_write_plane_unavailable')
    need(server._context_admission_id==request['context_admission_id'],'curator_current_context_required')
    actor_store=store_for(server,request['curator_registration_id'])
    actor=actor_store.find_registration(request['curator_registration_id']);need(actor is not None,'curator_actor_registration_missing')
    need((server._archive_prompt_binding or {}).get('prompt_sha256')==actor['prompt_sha256'],'curator_actor_context_join')
    grant=read_grant(args['grant_id'])
    need(grant['namespace_fingerprint']==actor_store.namespace and grant['curator_registration_id']==request['curator_registration_id'] and grant['context_admission_id']==request['context_admission_id'] and grant['actor_identity']==actor['identity'],'curator_grant_actor')
    need(grant['request_digest']==digest(request),'curator_grant_request')
    targets=[];target_store=None
    for decision in request['decisions']:
        rid=decision['registration_id'];need(rid!=request['curator_registration_id'],'curator_cannot_account_current_self')
        store=store_for(server,rid);registration=store.find_registration(rid)
        need(store.namespace==actor_store.namespace,'curator_cross_namespace')
        need(target_store is None or target_store.path==store.path,'curator_batch_profile_mismatch');target_store=store
        need(registration is not None and digest(registration)==grant['target_preimages'].get(rid),'curator_target_preimage')
        need(not has_terminal(store,rid),'curator_original_terminal_exists')
        if decision['classification']=='event-backed':
            need(server.action_witness is not None,'curator_event_witness_missing')
            for event in decision['events']:
                need(isinstance(event,dict) and set(event)=={'event_id','event_uid','request_sha256'},'curator_event_reference')
                witness=server.action_witness.observe(event_uid=event['event_uid'],request_sha256=event['request_sha256'])
                need(witness.get('status')=='exact' and witness.get('event_id')==event['event_id'],'curator_event_not_witnessed')
        targets.append({'registration_id':rid,'original_identity':registration['identity'],'original_prompt_sha256':registration['prompt_sha256'],
            'original_registration_digest':digest(registration),'classification':decision['classification'],
            'evidence_sha256':decision['evidence_sha256'],'events':decision['events'],
            'action_outcome':'event-backed' if decision['classification']=='event-backed' else 'unknown',
            'coverage_status':'administratively-accounted','original_terminal_asserted':False})
    root=ledger_root(target_store);path=root/(args['grant_id'].split(':')[1]+'.json')
    lock=os.open(root/'.lock',os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if path.exists():
            pack=verify_pack(json.loads(path.read_bytes()),target_store)
            need(pack['request_digest']==digest(request),'curator_conflicting_replay')
            return {'receipt':pack,'replayed':True,'canonical_writes':0}
        prior={d['registration_id'] for p in read_packs(target_store) for d in p['targets']}
        need(not prior.intersection(d['registration_id'] for d in targets),'curator_already_accounted')
        core={'protocol':PROTOCOL,'namespace_fingerprint':target_store.namespace,'grant_id':args['grant_id'],
            'owner_scope_sha256':grant['owner_scope_sha256'],'curator_registration_id':request['curator_registration_id'],
            'curator_identity':actor['identity'],'context_admission_id':request['context_admission_id'],
            'request_digest':digest(request),'targets':targets,'accounted_at':now().isoformat().replace('+00:00','Z'),
            'original_terminal_asserted':False,'production_authority':False,'retry_authority':False}
        pack=target_store.signer.sign({**core,'receipt_id':'sha256:'+digest(core)})
        verify_pack(pack,target_store);raw=canonical_bytes(pack)
        fd,temp=tempfile.mkstemp(prefix='.curator-',dir=root)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.link(temp,path);os.unlink(temp)
            dfd=os.open(root,os.O_DIRECTORY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:
            if os.path.exists(temp):os.unlink(temp)
        return {'receipt':pack,'replayed':False,'canonical_writes':1}
    finally:os.close(lock)
def decorate_coverage(server,result,args):
    aggregate=server._require_turn_memory();packs=[]
    for store in getattr(aggregate,'stores',{'legacy-v1':aggregate}).values():
        if store is not None:packs.extend(read_packs(store))
    decisions={d['registration_id']:{'decision':d,'curator_receipt_id':p['receipt_id'],'curator_identity':p['curator_identity']} for p in packs for d in p['targets']
      if (args.get('machine_id') is None or d['original_identity']['machine_id']==args['machine_id']) and (args.get('thread_id') is None or d['original_identity']['thread_id']==args['thread_id'])}
    result=json.loads(json.dumps(result));sample=result.get('receipt_sample',{}).get('receipts',[])
    known_closed={rid for rid in decisions if has_terminal(store_for(server,rid),rid)}
    accounted={k:v for k,v in decisions.items() if k not in known_closed}
    result['curator_accounting']={'protocol':PROTOCOL,'original_records_modified':False,'accounted_count':len(accounted),
       'unknown_action_outcomes':sum(v['decision']['action_outcome']=='unknown' for v in accounted.values()),'receipts':list(accounted.values())}
    # Original unresolved/terminal counts remain exact and unchanged. Consumers
    # can distinguish raw lifecycle debt from separately signed curator coverage.
    result['curator_accounting']['unaccounted_from_returned_unresolved']=[r['registration_id'] for r in result.get('unresolved',[]) if r['registration_id'] not in accounted]
    return result

TOOL={'name':'integrity_turn_memory_reconcile','description':'Create one separate signed curator accounting receipt under an exact root-issued, expiring grant. Never impersonates or creates an original turn terminal; unknown action outcomes remain unknown.',
 'inputSchema':{'type':'object','additionalProperties':False,'required':['grant_id','curator_registration_id','context_admission_id','decisions'],
 'properties':{k:{'type':'string','pattern':'^sha256:[a-f0-9]{64}$'} for k in ['grant_id','curator_registration_id','context_admission_id']}},
 'annotations':{'readOnlyHint':False,'destructiveHint':False,'idempotentHint':True,'openWorldHint':False}}
TOOL['inputSchema']['properties']['decisions']={'type':'array','minItems':1,'maxItems':8,'items':{'type':'object','additionalProperties':False,'required':['registration_id','classification','evidence_sha256','events'],'properties':{
 'registration_id':{'type':'string','pattern':'^sha256:[a-f0-9]{64}$'},'classification':{'type':'string','enum':['event-backed','interrupted-unknown','missing-terminal-unknown']},'evidence_sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'},
 'events':{'type':'array','maxItems':8,'items':{'type':'object','additionalProperties':False,'required':['event_id','event_uid','request_sha256'],'properties':{'event_id':{'type':'integer','minimum':1},'event_uid':{'type':'string','minLength':1},'request_sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'}}}}}}}
