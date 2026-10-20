"""Disposable full domain/wire fixture; no working Memory endpoints or state.

NativeTrust, signatures, architecture, catalog, Action Log HTTP, witness and
lifecycle stores are real. The producer envelope is explicitly synthetic; this
does not claim a live Codex/Claude/Antigravity owning-producer acceptance.
"""
from __future__ import annotations
import hashlib
import ast
import importlib.util
import json
import os
import sqlite3
from pathlib import Path
import sys
import threading
import uuid

from integrity_guardian import memory_synapse_mcp as mcp
from integrity_guardian.memory_synapse_mcp_protocol import dispatch
from integrity_guardian.native_trust import ExternalSignerBackend, NativeTrustStore
from integrity_guardian.seed_catalog import SeedCatalog
from integrity_guardian.signing import Ed25519Signer, public_key_fingerprint
from integrity_guardian.turn_memory import TurnMemoryStore, namespace_fingerprint
from integrity_guardian.turn_memory_profiles import VersionedTurnMemoryService

REPO=Path(__file__).resolve().parents[1]

def digest(value):
    return 'sha256:'+hashlib.sha256(value.encode()).hexdigest()

class Stand:
    def __init__(self, root, monkeypatch):
        self.root=root.resolve();self.root.chmod(0o700)
        self.monkeypatch=monkeypatch;self.facades=[];self.wire=[];self.next_id=0
        self.admissions={}
        component=REPO/'components/integrity-action-log'
        source=component/'src/integrity_action_log/resources'
        monkeypatch.syspath_prepend(str(component/'src'))
        monkeypatch.syspath_prepend(str(source))
        template=json.loads((component/'configuration.example.json').read_text())
        template['configured']=True
        template['values']={key:str(self.root/key) for key in template['values']}
        config=self.root/'action-log-config.json';config.write_text(json.dumps(template))
        monkeypatch.setenv('INTEGRITY_ACTION_LOG_CONFIG',str(config))
        monkeypatch.setenv('CODEX_LOG_DB',str(self.root/'stand-events.sqlite3'))
        monkeypatch.setenv('CODEX_LOG_DATA_DIR',str(self.root/'data'))
        self.test_token='isolated-stand-synthetic-not-a-credential-'*2
        monkeypatch.setenv('CODEX_LOG_TOKEN',self.test_token)
        name='recovery_stand_action_log_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(name,source/'codex_action_log.py')
        self.al=importlib.util.module_from_spec(spec);sys.modules[name]=self.al
        spec.loader.exec_module(self.al);self.al.ensure_db()
        self.al.DB_PATH.chmod(0o600)
        self.al.insert_event({'actor':'stand','action':'agent_change_start',
            'summary':'Disposable recovery acceptance project',
            'details':{'task_id':'stand-recovery-acceptance'},'tags':['stand'],
            'event_uid':'client:stand:seed'})
        with self.al.open_db() as db:
            db.row_factory=sqlite3.Row
            events=self.al.rows_to_events(db.execute('SELECT * FROM events ORDER BY id').fetchall())
        self.catalog=SeedCatalog(self.root/'catalog.sqlite3')
        self.catalog.import_events(events)
        self.http=self.al.BoundedThreadingHTTPServer(('127.0.0.1',0),self.al.Handler)
        self.worker=threading.Thread(target=self.http.serve_forever,daemon=True);self.worker.start()
        self.signers={}
        def resolve(role,key_id):
            if key_id not in self.signers:self.signers[key_id]=Ed25519Signer.generate(key_id)
            return self.signers[key_id]
        self.backend=ExternalSignerBackend('stand-ram-native46',resolve)
        self.native=NativeTrustStore(self.root/'native',instance_id='instance:stand46',backend=self.backend)
        self.native.bootstrap();self.device='device:stand46'
        self.native.ensure_local_transport_device(device_id=self.device)
        self.database=self.native.ensure_database(tenant_id=mcp.TENANT_ID,ledger_id=mcp.CUSTODY_LEDGER_ID)
        self.snapshots=self.root/'snapshots';self.snapshots.mkdir(mode=0o700)
        self.archroot=self.root/'architecture';self.archroot.mkdir(mode=0o700)
        lts=mcp.MemorySynapseLtsService(self.catalog.path)
        self.namespace=namespace_fingerprint(source_namespace=lts.snapshot()['source_namespace'],
            trust_fingerprint=public_key_fingerprint(self.database.source_signer.public_key))
        self.legacy=self.archroot/'turn-memory/turn-memory.sqlite3'
        TurnMemoryStore(self.legacy,namespace=self.namespace,signer=self.database.checkpoint_signer,
            identity_profile='legacy-v1',create=True)
        self.subject_thread=str(uuid.uuid4())

    def facade(self):
        architecture=mcp.PersistentMedorArchitectureService(self.archroot,
            keys=mcp.MedorArchitectureKeys(source_signer=self.database.source_signer,
                checkpoint_signer=self.database.checkpoint_signer),
            event_authority_key=self.native.trusted_key('event-append-issuer'),
            native_database_enrollment=self.database.enrollment,
            native_ledger_issuer_key=self.native.trusted_key('ledger-issuer'))
        lts=mcp.MemorySynapseLtsService(self.catalog.path)
        turns=VersionedTurnMemoryService(self.legacy,namespace=self.namespace,
            signer=self.database.checkpoint_signer,initialize_native=True)
        assert turns.complete
        f=mcp.MemorySynapseMcp(lts,
            action_log=mcp.ActionLogClient('http://127.0.0.1:'+str(self.http.server_address[1]),
                auth_token=self.test_token,timeout=5),
            architecture=architecture,action_witness=mcp.SqliteActionLogWitness(self.al.DB_PATH),
            security_admission=self.native.security_admission(artifact_digest=lts.package_digest()),
            native_trust=self.native,native_device_id=self.device,turn_memory=turns,
            snapshot_source=self.catalog.path,snapshot_root=self.snapshots,audit=lambda receipt:None)
        self.facades.append(f)
        return f

    def rpc(self,f,method,params):
        self.next_id+=1
        request={'jsonrpc':'2.0','id':self.next_id,'method':method,'params':params}
        self.wire.append({'method':method,'tool':params.get('name')})
        result=dispatch(f,json.loads(json.dumps(request)))
        assert result is not None and 'error' not in result,result
        return result['result']

    def tool(self,f,name,arguments):
        trace=[]
        def observe(frame,event,arg):
            if event=='exception' and Path(frame.f_code.co_filename).name=='same_session_recovery.py':
                error=arg[1];message=str(error)
                literals={n.value for n in ast.walk(ast.parse(Path(frame.f_code.co_filename).read_text()))
                    if isinstance(n,ast.Constant) and isinstance(n.value,str) and len(n.value)<250}
                trace.append({'type':type(error).__name__,'function':frame.f_code.co_name,
                    'line':frame.f_lineno,'static_message':message if message in literals else 'dynamic-text-suppressed'})
            return observe
        if name=='integrity_turn_memory_open':sys.settrace(observe)
        try:result=self.rpc(f,'tools/call',{'name':name,'arguments':arguments})
        finally:sys.settrace(None)
        assert result.get('isError') is not True,result
        document=json.loads(result['content'][0]['text'])
        if name=='integrity_turn_memory_open' and not document.get('session_recovery',{}).get('available'):
            document['_stand_safe_diagnostic']=trace[-5:]
        return document

    def initialize(self,f,*,control_only=False):
        replay=digest('stand-reservation-'+uuid.uuid4().hex)
        declaration={'protocol':mcp.CONTEXT_ADMISSION_REPLAY_PROTOCOL,
            'request_identity_field':mcp.CONTEXT_ADMISSION_REPLAY_FIELD,
            'request_identity_format':'sha256/v1'}
        if not control_only:declaration['reservation_id']=replay
        caps={mcp.BROKER_TOOL_SURFACE_CAPABILITY:{'protocol':mcp.BROKER_TOOL_SURFACE_PROTOCOL,
            'tools_surface_sha256':mcp._tool_surface_sha256(mcp.tools(profile='turn-curator-v1'))},
            mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY:declaration,
            mcp.CONTEXT_REATTACH_CAPABILITY:{'protocol':mcp.CONTEXT_REATTACH_PROTOCOL,
                **({'control_only':True} if control_only else {})},
            'integrity/session-recovery':{'protocol':'integrity-client/session-recovery/v1'}}
        response=self.rpc(f,'initialize',{'protocolVersion':'2024-11-05',
            'clientInfo':{'name':'integrity-client-turn-broker','version':'1.6.0'},
            'capabilities':{'experimental':caps}})
        experimental=response['capabilities'].get('experimental',{})
        return replay,experimental

    def fill_reservations(self,f):
        count=0
        for i in range(128):
            response=self.rpc(f,mcp.CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD,
                {'reservation_id':digest('stand-capacity-'+uuid.uuid4().hex)})
            if not response['reserved']:return count
            count+=1
        raise AssertionError('finite normal replay reservation budget was not reached')

    def admit(self,f,number,replay=None):
        prompt='GO record isolated stand recovery acceptance result '+str(number)
        self.args={'machine_id':'machine:stand46','thread_id':self.subject_thread,
            'turn_id':str(uuid.uuid4()),'intent_id':'intent:'+hashlib.sha256(prompt.encode()).hexdigest(),
            'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest()}
        binding={'protocol':mcp.TURN_ENVELOPE_PROTOCOL,'turn_ref_digest':digest('stand-synthetic-producer-'+str(number)),
            'prompt_sha256':self.args['prompt_sha256'],'prompt_bytes':len(prompt.encode()),
            'segment_count':1,'prompt_coverage':'text-only','truncation':False,'generation':number}
        arguments={'intent':prompt,mcp.TURN_ENVELOPE_BINDING_FIELD:binding}
        request_digest=mcp._sha256(arguments)
        if replay is not None:arguments[mcp.CONTEXT_ADMISSION_REPLAY_FIELD]=replay
        result=self.tool(f,'integrity_context_admission',arguments)
        assert result['write_plane']['outcome']=='ready',result['write_plane']
        assert result['context_delivery']['read_plane']=='ready'
        self.admissions[number]={'result':result,'replay_id':replay,'request_digest':request_digest,
            'response_digest':mcp._sha256(mcp._tool_result(result))}
        if replay is not None:
            acknowledgement={k:self.admissions[number][k] for k in ['replay_id','request_digest','response_digest']}
            assert self.rpc(f,mcp.CONTEXT_ADMISSION_REPLAY_ACK_METHOD,acknowledgement)['retired']
        return result

    def controls(self,number,opened):
        record=self.admissions[number];admission=record['result']
        return {k:record[k] for k in ['replay_id','request_digest','response_digest']}|{
            'context_admission_id':admission['context_admission_id'],
            'snapshot_id':admission['snapshot']['snapshot_id'],'prompt_binding':admission['prompt_binding'],
            'logical_generation':admission['logical_generation'],'registration_id':opened['receipt']['receipt_id']}

    def append(self,f,admission,suffix='one'):
        return self.tool(f,'integrity_append_event',{
            'context_admission_id':admission['context_admission_id'],
            'event_uid':'client:stand46:'+self.subject_thread+':'+suffix,
            'kind':'thought','summary':'Disposable full-path stand result '+suffix})

    def close_turn(self,f,opened,event=None):
        arguments={'registration_id':opened['receipt']['receipt_id'],
            'outcome':'events' if event else 'no-event'}
        if event:
            arguments['events']=[{k:event['receipt'][k] for k in ['event_id','event_uid','request_sha256']}]
        else:arguments['no_event_reason']='read-only'
        return self.tool(f,'integrity_turn_memory_close',arguments)

    def event_count(self):
        with self.al.open_db() as db:return db.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    def stop(self):
        for f in reversed(self.facades):f.close()
        self.http.shutdown();self.http.server_close();self.worker.join(timeout=3)
        assert not (self.root/'native/keys').exists()
