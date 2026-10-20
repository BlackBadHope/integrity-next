# SPDX-License-Identifier: Apache-2.0
"""Automatic same-session Core delivery; no model-supplied runbook content."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import copy,hashlib,json,time
from pathlib import Path

def delivery(upstream,local,source,experiment,expected_catalog_digest):
    local=copy.deepcopy(local);local['task_source']=source
    # A narrowly scoped owner-configured context ablation, independent from all
    # authentication, admission, SCOPE and actuator permissions.
    in_experiment=(source.get('parent_thread_id')==experiment['parent_thread_id']
        and source.get('parent_turn_id')==experiment['parent_turn_id']
        and time.time()<experiment['expires_epoch'])
    if in_experiment and source.get('agent_path') in experiment['control_agent_paths']:
        return {'status':'task-route-withheld-for-control','scope_source':local.get('scope_source'),
                'task_source':source,'entities':local.get('entities'),
                'core_delivery':{'status':'withheld-by-frozen-experiment','calls':0},
                'external_action_authority':False,'automatic_execution':False}
    if local.get('status')!='navigation-ready':
        if source.get('navigation_text_available') is False:
            # An authenticated opaque carrier proves custody, not its topic.
            # A missing selector must not choose a route from retained state or
            # the catalogue's first/only topic. An explicit snapshot-bound
            # current-task query may still select a matching route in query().
            local['status']='task-context-unavailable'
            local['task_context']={'status':'current-task-selector-unavailable',
                'reason':source.get('navigation_text_reason','opaque-native-task'),
                'snapshot_id':local.get('snapshot_id'),
                'topic_inferred':False,'retained_context_used':False,
                'explicit_current_task_query_required':True}
            local.pop('task_query',None)
            local['core_delivery']={'status':'not-attempted','calls':0}
        return local
    started=time.monotonic()
    try:
        result=upstream.call_tool('integrity_memory_ttt_autofill',{'goal':'bdcom-onu-service-vlan',
            'last_hop':'example-operation-0001','snapshot_id':local['snapshot_id']})
    except Exception:
        return {'status':'core-not-delivered','task_source':source,'core_delivery':{'status':'not-delivered','reason':'canonical-Core-upstream-unavailable','calls':1},'external_action_authority':False}
    elapsed=time.monotonic()-started
    try:value=json.loads(result['content'][0]['text'])
    except (KeyError,IndexError,TypeError,ValueError):value={}
    binding=value.get('snapshot_binding') or {}
    valid=(not result.get('isError') and value.get('result')=='REMAINING'
        and value.get('path_catalog_digest')==expected_catalog_digest
        and binding.get('snapshot_id')==local['snapshot_id']
        and binding.get('ttt_receipt_id')==value.get('receipt_id')
        and len(value.get('remaining_path',[]))==6)
    # Never silently replace missing Core with a locally invented procedure.
    if not valid:return {'status':'core-not-delivered','task_source':source,
        'core_delivery':{'status':'not-delivered','reason':'canonical-core-response-or-binding-mismatch','calls':1,'elapsed_seconds':elapsed},
        'external_action_authority':False,'automatic_execution':False}
    local['hops']=value['remaining_path'];local.pop('evidence',None)
    local['source']='same-model-owned-upstream-Core-response'
    local['core_delivery']={'status':'delivered','calls':1,'elapsed_seconds':elapsed,
        'receipt_id':value['receipt_id'],'snapshot_binding_receipt_id':binding['receipt_id'],
        'path_catalog_digest':value['path_catalog_digest'],'snapshot_id':local['snapshot_id'],
        'snapshot_event_id':binding.get('snapshot_event_id'),'remaining_count':6,
        'first_identity_read_still_required':True,'completed_hop_assertion_verified':False,
        'response_sha256':hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}
    return local

def query(navigator,upstream,args,binding,scope,source,experiment,catalog):
    """The admitted model supplies task entities, never the Core procedure."""
    if not source or source.get('navigation_text_available') is not False:return None
    if args.get('snapshot_id')!=binding.get('snapshot_id'):raise ValueError('task query snapshot mismatch')
    local=navigator.admit(args.get('goal',''),scope,args['snapshot_id'])
    local['snapshot_id']=args['snapshot_id'];local['scope_source']=scope.get('project_scope_source')
    source=copy.deepcopy(source);source['task_selector_source']='current-admitted-model-tool-query'
    source['task_selector_sha256']=hashlib.sha256(args.get('goal','').encode()).hexdigest()
    value=delivery(upstream,local,source,experiment,catalog)
    journal(value,binding['context_admission_id'],phase='query')
    if value.get('status') not in ('navigation-ready','task-route-withheld-for-control'):
        return {'content':[{'type':'text','text':json.dumps({'operational_context':value})}],'isError':True}
    return {'content':[{'type':'text','text':json.dumps({'operational_context':value})}]}

def guard_curator(envelope,binding,args):
    """Administrative accounting still requires the current own actor slot."""
    identity=envelope._resume_identity();head=envelope._native_owning_head(identity)
    hashes=binding.get('hashes') or {}
    sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
    if not (binding.get('admitted') is True and hashes.get('thread_id')==sha(identity)
            and head.get('status')=='inProgress' and hashes.get('turn_id')==sha(head.get('id',''))):
        raise ValueError('curator current own Native binding missing')
    path=Path.home()/'.codex/integrity-memory/state'/(sha(identity)+'.json')
    if path.is_symlink() or not path.is_file():raise ValueError('curator own receipt state missing')
    state=json.loads(path.read_bytes())
    if not (args.get('curator_registration_id')==state.get('turn_memory_registration_id')
            and args.get('context_admission_id')==binding.get('context_admission_id')==state.get('model_mcp_context_admission_id')
            and binding.get('intent_id')==state.get('turn_memory_intent_id')
            and state.get('turn_memory_terminal_receipt_id') in (None,'')):
        raise ValueError('curator actor must be the current own open registration')

def journal(local,context_admission_id,phase='admission'):
    # Diagnostics only, never an alternate canonical memory source.
    value={'protocol':'integrity-client/automatic-Core-delivery/v1','context_admission_id':context_admission_id,
        'status':local.get('status'),'task_source':local.get('task_source'),'core_delivery':local.get('core_delivery'),
        'external_action_authority':False}
    path=Path.home()/'.codex/integrity-memory/state'/('core-delivery-'+('query-' if phase=='query' else '')+hashlib.sha256(context_admission_id.encode()).hexdigest()+'.json')
    if path.exists():
        previous=json.loads(path.read_bytes())
        if previous.get('context_admission_id')!=context_admission_id:raise ValueError('Core journal binding drift')
        return
    with path.open('x',encoding='utf-8') as out:json.dump(value,out,ensure_ascii=False)
