# SPDX-License-Identifier: Apache-2.0
"""Fixed-path Linux hook assembly. Existing Unix owner and peer transports only."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import stat
import struct
import subprocess
import secrets
import sys
import time
from types import ModuleType

ROOT=Path(_integrity_value('path_421d7209bec4'))
USER_ROOT=Path(_integrity_value('path_672ada16776c'))
CONFIG=USER_ROOT/'delegation-config.json'
SOCKET=Path(_integrity_value('path_2570ca9aa91a'))
HOSTS=Path(_integrity_value('path_8c0a5bb8b07c'))
READS=frozenset({'thread/read','thread/turns/list'})
MAX_NATIVE_EXECUTABLE=512*1024*1024

"""Safe owner-error projection; scope comes only from an authenticated owner reply."""
def owner_thread_class(result, thread_id):
    thread=result.get('thread') if isinstance(result,dict) else None
    if not isinstance(thread,dict) or thread.get('id')!=thread_id or thread.get('truncated') or thread.get('itemsTruncated'):
        return 'unknown'
    source=thread.get('source')
    if isinstance(source,dict) and set(source)=={'subAgent'} and isinstance(source['subAgent'],(dict,str)):
        return 'non-owner'
    if source=='exec':return 'non-owner'
    if source in ('vscode','cli'):return 'direct-owner'
    return 'unknown'

def safe_owner_error(error):
    # Never preserve error.data or arbitrary free-form text. Known static parts
    # remain legible; everything else is a digest, even when the text is short.
    data=error if isinstance(error,dict) else {}
    code=data.get('code')
    symbolic={'THREAD_NOT_FOUND','THREAD_NOT_LOADED','PERMISSION_DENIED','METHOD_NOT_FOUND','INVALID_REQUEST','INTERNAL_ERROR'}
    if not (type(code) is int and -(2**31)<=code<2**31 or isinstance(code,str) and code in symbolic):
        code='redacted'
    message=data.get('message')
    if not isinstance(message,str):message=''
    bounded=message[:4096]
    safe='owner error message redacted'
    # The captured text consists solely of these static templates, no suffix.
    patterns=[r'thread not found',r'thread is not loaded',r'thread not loaded',
              r'cannot list turns for (?:an? )?unloaded thread',r'permission denied',
              r'unknown thread',r'invalid request',r'method not found']
    for pattern in patterns:
        match=re.search(pattern,bounded,re.I)
        if match:
            safe=match.group(0);break
    return {'owner_error_code':code,'owner_error_message':safe[:256],
            'owner_error_message_sha256':hashlib.sha256(bounded.encode('utf-8',errors='replace')).hexdigest(),
            'owner_error_message_truncated':len(message)>256,
            'owner_error_message_redacted':safe!=message}

def copy_owner_trace(prior, trace):
    if not isinstance(prior,dict):return
    if prior.get('code') not in {'linux_owner_read_rejected','linux_non_owner_read_rejected'}:return
    for key in ('owner_error_code','owner_error_message','owner_error_message_sha256',
                'owner_error_message_truncated','owner_error_message_redacted','owner_thread_class'):
        if key in prior:trace[key]=prior[key]


class RuntimeErrorSafe(ValueError):pass

SAFE_CODES=frozenset({'native_response_frame_exceeds_limit','native_owner_connection_closed_without_close_frame',
    'native_evidence_deadline','linux_owner_read_rejected','linux_non_owner_read_rejected','linux_owner_peer_uid_invalid',
    'linux_owner_peer_image_invalid','linux_owner_socket_changed','linux_owner_socket_custody_invalid',
    'linux_runtime_path_invalid','linux_runtime_file_custody_invalid','linux_runtime_private_custody_invalid',
    'linux_runtime_module_pin_invalid','linux_receiving_infrastructure_failed','native_read_unavailable'})

def safe_failure(error,stage):
    code=str(error)
    trace={'stage':stage,'code':code if code in SAFE_CODES else 'provider_exception_redacted',
        'exception_class':type(error).__name__ if type(error).__name__ in {'RuntimeErrorSafe','ConnectionClosedError',
            'TimeoutError','OSError','ValueError','LinuxProviderError','AdapterError'} else 'ProviderError'}
    prior=getattr(error,'safe_trace',None)
    if isinstance(error,RuntimeErrorSafe) and isinstance(prior,dict):
        if isinstance(prior.get('code'),str) and prior['code'] in SAFE_CODES:trace['code']=prior['code']
        if isinstance(prior.get('exception_class'),str) and prior['exception_class'] in {'ConnectionClosedError','TimeoutError','OSError'}:
            trace['exception_class']=prior['exception_class']
        if isinstance(prior.get('native_method'),str) and prior['native_method'] in READS:trace['native_method']=prior['native_method']
    for name in ('sent','rcvd'):
        close=getattr(error,name,None)
        if close is not None and isinstance(getattr(close,'code',None),int):
            trace[name+'_close_code']=int(close.code)
            reason=getattr(close,'reason','')
            if close.code==1009 and re.fullmatch(r'(?:frame with \d+ bytes |frame )?exceeds limit of \d+ bytes',reason):
                trace['code']='native_response_frame_exceeds_limit'
                trace['frame_sizes']=[int(x) for x in re.findall(r'\d+',reason)[:3]]
    if trace['exception_class']=='ConnectionClosedError' and not any(k.endswith('close_code') for k in trace):
        trace['code']='native_owner_connection_closed_without_close_frame'
    copy_owner_trace(prior,trace)
    return trace

def write_safe_trace(trace,payload):
    # This is diagnostic metadata only, never a Native proof or lease.
    ids=[]
    for key in ('session_id','turn_id'):
        value=payload.get(key)
        if not isinstance(value,str) or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value) is None:
            return
        ids.append(value)
    root=USER_ROOT/'runtime-diagnostics'
    root.mkdir(mode=0o700,exist_ok=True)
    need(root.resolve(strict=True)==root and not root.is_symlink(),'linux_runtime_path_invalid')
    path=root/(hashlib.sha256(':'.join(ids).encode()).hexdigest()+'.json')
    if path.exists():need(not path.is_symlink() and path.is_file(),'linux_runtime_path_invalid')
    temporary=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump({**trace,'thread_id_sha256':hashlib.sha256(ids[0].encode()).hexdigest(),
                'turn_id_sha256':hashlib.sha256(ids[1].encode()).hexdigest()},stream,sort_keys=True)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()

def need(value,code):
    if not value:raise RuntimeErrorSafe(code)

def protected_bytes(path,*,private=False):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path,'linux_runtime_path_invalid')
    info=path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid in {0,os.getuid()}
        and not stat.S_IMODE(info.st_mode)&0o022,'linux_runtime_file_custody_invalid')
    if private:need(info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o077,'linux_runtime_private_custody_invalid')
    raw=path.read_bytes()
    need(len(raw)<=2*1024*1024,'linux_runtime_file_bound')
    return raw

def executable_digest(path):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path,'linux_runtime_path_invalid')
    info=path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid in {0,os.getuid()}
        and not stat.S_IMODE(info.st_mode)&0o022 and 0<info.st_size<=MAX_NATIVE_EXECUTABLE,
        'linux_owner_peer_image_invalid')
    total=0;digest=hashlib.sha256()
    with path.open('rb') as stream:
        opened=os.fstat(stream.fileno())
        need((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)==
             (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns),'linux_owner_peer_image_changed')
        while True:
            chunk=stream.read(1024*1024)
            if not chunk:break
            total+=len(chunk);need(total<=MAX_NATIVE_EXECUTABLE,'linux_owner_peer_image_invalid');digest.update(chunk)
        after=os.fstat(stream.fileno())
    need(total==info.st_size and (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==
         (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns),'linux_owner_peer_image_changed')
    return digest.hexdigest()

def module(name,path,digest):
    raw=protected_bytes(path)
    need(isinstance(digest,str) and hashlib.sha256(raw).hexdigest()==digest,'linux_runtime_module_pin_invalid')
    result=ModuleType(name);result.__file__=str(path);sys.modules[name]=result
    exec(compile(raw,str(path),'exec'),result.__dict__)
    return result


def _owner_uid():
    uid = int(_integrity_value('native_owner_uid'))
    need(0 <= uid < 2**31, 'linux_owner_uid_configuration_invalid')
    return uid

def _verify_peer_uid(peer_uid, caller_uid):
    need(peer_uid == caller_uid == _owner_uid(), 'linux_owner_peer_uid_invalid')

def owner_socket_snapshot():
    """Validate only the fixed owner endpoint and its measured proxy transport."""
    need(os.getuid()==_owner_uid(),'linux_owner_socket_custody_invalid')
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                info.st_mtime_ns,info.st_ctime_ns)
    parents=[]
    for raw,uid,mode in ((_integrity_value('native_home_parent'),0,0o755),(_integrity_value('path_863c29bb9a6e'),_owner_uid(),int(_integrity_value('native_home_mode'),8)),
                        (_integrity_value('path_d92be9924882'),_owner_uid(),0o700),
                        (_integrity_value('path_0a58ddc7612c'),_owner_uid(),0o700)):
        path=Path(raw);info=path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid
             and stat.S_IMODE(info.st_mode)==mode and path.resolve(strict=True)==path,
             'linux_owner_socket_custody_invalid')
        parents.append((raw,identity(info)))
    proxy=SOCKET.lstat();link=None;target=SOCKET
    if stat.S_ISLNK(proxy.st_mode):
        link=os.readlink(SOCKET)
        need(proxy.st_uid==_owner_uid() and stat.S_IMODE(proxy.st_mode)==0o777
             and re.fullmatch(re.escape(_integrity_value('native_daemon_directory')) + r'/[0-9a-f]{64}',link) is not None,
             'linux_owner_socket_custody_invalid')
        for raw,uid,mode in (('/tmp',0,0o1777),(_integrity_value('native_daemon_directory'),_owner_uid(),0o700)):
            path=Path(raw);info=path.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid
                 and stat.S_IMODE(info.st_mode)==mode and path.resolve(strict=True)==path,
                 'linux_owner_socket_custody_invalid')
            parents.append((raw,identity(info)))
        target=Path(link)
    info=target.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid==_owner_uid()
         and stat.S_IMODE(info.st_mode)==0o600 and target.resolve(strict=True)==target
         and SOCKET.resolve(strict=True)==target,'linux_owner_socket_custody_invalid')
    return {'target':str(target),'proxy':identity(proxy),'link':link,
            'socket':identity(info),'parents':tuple(parents)}

class UnixOwnerSDK:
    def __init__(self,thread_id,deadline,profile):
        self.thread_id,self.deadline,self.profile=thread_id,deadline,profile
        self.connection=None;self.sequence=0
    def remaining(self,maximum):
        value=min(maximum,self.deadline-time.monotonic())
        need(value>0,'native_evidence_deadline');return value
    def peer_check(self):
        pid,uid,_gid=struct.unpack('3i',self.connection.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        _verify_peer_uid(uid, os.getuid())
        executable=Path(f'/proc/{pid}/exe').resolve(strict=True)
        expected=Path(self.profile['native_owner_executable'])
        need(executable==expected and expected.is_absolute()
            and str(expected).startswith(_integrity_value('path_4b105e55cc7d')),
            'linux_owner_peer_image_invalid')
        need(executable_digest(expected)==self.profile['native_owner_sha256'],
            'linux_owner_peer_image_invalid')
    def open(self):
        from websockets.sync.client import unix_connect
        observed=owner_socket_snapshot()
        self.connection=unix_connect(observed['target'],open_timeout=self.remaining(3),close_timeout=1,max_size=2*1024*1024)
        try:
            need(owner_socket_snapshot()==observed,'linux_owner_socket_changed')
            self.peer_check()
        except Exception:
            self.close();raise
        self._request('initialize',{'clientInfo':{'name':'integrity-linux-delegation-reader','version':'1'},
            'capabilities':{'optOutNotificationMethods':['remoteControl/status/changed']}},self.remaining(5))
        self.connection.send(json.dumps({'method':'initialized'}))
    def _request(self,method,params,timeout):
        deadline=time.monotonic()+self.remaining(timeout)
        self.sequence+=1;sequence=self.sequence
        self.peer_check()
        self._wire_request_method=method
        self._wire_request_id=sequence
        self._wire_arguments_sha256=hashlib.sha256(json.dumps(params,sort_keys=True,
            separators=(',',':'),allow_nan=False).encode()).hexdigest()
        self.connection.send(json.dumps({'id':sequence,'method':method,'params':params}))
        while time.monotonic()<deadline:
            value=json.loads(self.connection.recv(timeout=max(.001,deadline-time.monotonic())))
            if value.get('id')!=sequence:continue
            self.peer_check();self.remaining(timeout)
            if 'error' in value:
                scope=getattr(self,'_owner_thread_class','unknown')
                code='linux_non_owner_read_rejected' if scope=='non-owner' and method in READS else 'linux_owner_read_rejected'
                error=RuntimeErrorSafe(code)
                error.safe_trace={'code':code,'owner_thread_class':scope,**safe_owner_error(value.get('error'))}
                raise error
            need(isinstance(value.get('result'),dict),'linux_owner_read_rejected')
            if method=='thread/read':
                self._owner_thread_class=owner_thread_class(value['result'],self.thread_id)
            return value['result']
        raise RuntimeErrorSafe('native_evidence_deadline')
    def request(self,method,params,timeout):
        need(method in READS and isinstance(params,dict) and params.get('threadId')==self.thread_id,
            'linux_owner_method_not_allowed')
        if method=='thread/read':need(params=={'threadId':self.thread_id,'includeTurns':False},'linux_owner_arguments_invalid')
        else:need(set(params)<={'threadId','limit','sortDirection','itemsView','cursor'}
            and type(params.get('limit')) is int and 1<=params['limit']<=10
            and params.get('sortDirection')=='desc'
            and (params.get('itemsView')=='full' or
                 params.get('itemsView')=='notLoaded' and params['limit']==1
                 and 'cursor' not in params),'linux_owner_arguments_invalid')
        try:
            if self.connection is None:self.open()
            return self._request(method,params,timeout)
        except Exception as error:
            trace=safe_failure(error,'native-owner-rpc');trace['native_method']=method
            # Content-free, bounded evidence for this exact request. Never a proof.
            trace['request_id']=self.sequence
            trace['arguments_sha256']=hashlib.sha256(json.dumps(params,sort_keys=True,
                separators=(',',':'),allow_nan=False).encode()).hexdigest()
            trace['items_view']=params.get('itemsView')
            trace['response_limit_bytes']=2*1024*1024
            # open() may fail while initializing, before the requested read.
            trace['wire_method']=getattr(self,'_wire_request_method',None)
            trace['wire_request_id']=getattr(self,'_wire_request_id',None)
            trace['wire_arguments_sha256']=getattr(self,'_wire_arguments_sha256',None)
            try:write_safe_trace(trace,{'session_id':self.thread_id,'turn_id':getattr(self,'turn_id',None)})
            except (OSError,ValueError):pass
            failure=RuntimeErrorSafe(trace['code']);failure.safe_trace=trace
            raise failure from None
    def close(self):
        if self.connection is not None:self.connection.close();self.connection=None

def peer_exchange(config,raw,timeout):
    need(type(config.get('port')) is int and 1<=config['port']<=65535,'linux_peer_profile_invalid')
    deadline=time.monotonic()+timeout
    with socket.create_connection(('127.0.0.1',config['port']),timeout=min(5,timeout)) as peer:
        remaining=deadline-time.monotonic();need(remaining>0,'native_evidence_deadline')
        peer.settimeout(remaining);peer.sendall(raw+b'\n')
        with peer.makefile('rb') as stream:reply=stream.readline(1024*1024+1)
        need(len(reply)<=1024*1024 and reply.endswith(b'\n'),'linux_private_peer_frame_invalid')
        need(time.monotonic()<deadline,'native_evidence_deadline')
        return reply

def load_components(config):
    need(config.get('target_machine_id')=='node-linux','linux_runtime_host_invalid')
    pins=config['linux_module_pins']
    # Pinned modules are loaded before any Native call. Runtime arguments and
    # proof objects never come from the hook/model payload.
    for name in ('native_evidence_peer_auth','native_evidence_facade','linux_native_peer_client',
                 'linux_delegation_provider','linux_admission_seam','linux_scope_capture','linux_admission_dispatcher',
                 'linux_terminal_peer_bridge'):
        module(name,ROOT/(name+'.py'),pins[name])
    core=module('integrity_delegation_core',ROOT/'integrity_delegation_core.py',config['core_sha256'])
    adapter=module('integrity_delegation_codex',ROOT/'integrity_delegation_codex.py',config['adapter_sha256'])
    scope=module('integrity_scope_linux',ROOT/'integrity_scope_synapse.py',config['scope_module_sha256'])
    adapter.validate_config(config)
    return {'core':core,'adapter':adapter,'scope':scope,'provider':sys.modules['linux_delegation_provider'],
        'terminal_bridge':sys.modules['linux_terminal_peer_bridge']}

def peer_config():
    hosts=json.loads(protected_bytes(HOSTS,private=True))
    need(hosts.get('local_host')=='node-linux','linux_peer_profile_invalid')
    config=hosts['hosts']['owner-host']
    need(config.get('transport')=='ssh_reverse_loopback','linux_peer_profile_invalid')
    return config

def peer_key():return protected_bytes(Path(peer_config()['token_file']),private=True).decode('ascii').strip()

def make_private_peer(config):
    return sys.modules['linux_native_peer_client'].AuthenticatedNativePeerClient(
        lambda raw,timeout:peer_exchange(peer_config(),raw,timeout),peer_key)

def _run(event,payload,baseline):
    config=json.loads(protected_bytes(CONFIG,private=True))
    loaded=load_components(config);core,adapter,scope=loaded['core'],loaded['adapter'],loaded['scope']
    peer=make_private_peer(config)
    scope_sync=sys.modules['linux_scope_capture'].LinuxScopeCapture(scope,core,config,scope.Store(USER_ROOT/'scope-synapse'))
    def receiver(own_payload,operation_id=None):
        thread=baseline.session_id(own_payload);turn=baseline.turn_id(own_payload)
        if thread!=config['target_thread_id']:
            return {'status':'absent'}
        deadline=time.monotonic()+min(65,float(config.get('native_budget_seconds',65)))
        sdk=UnixOwnerSDK(thread,deadline,config)
        sdk.turn_id=turn
        try:
            reader=sys.modules['linux_delegation_provider'].LinuxReceivingReader(sdk,peer,adapter,config,
                thread_id=thread,turn_id=turn,deadline=deadline)
            return sys.modules['linux_delegation_provider'].receive_pretool(own_payload,config,core,adapter,reader,
                operation_id=operation_id)
        finally:sdk.close()
    seam=sys.modules['linux_admission_seam'].LinuxAdmissionSeam(baseline,receiver,config,core,scope_sync=scope_sync)
    def schedule_terminal(operation_id,thread_id,turn_id):
        worker=ROOT/'linux_terminal_worker.py'
        need(hashlib.sha256(protected_bytes(worker)).hexdigest()==config['linux_module_pins']['linux_terminal_worker'],
            'linux_terminal_worker_pin_invalid')
        need(executable_digest(Path(sys.executable).resolve(strict=True))==config['python_sha256'],'linux_python_pin_invalid')
        subprocess.Popen([sys.executable,'-B','-X','utf8',str(worker),'--operation-id',operation_id,
            '--thread-id',thread_id,'--turn-id',turn_id],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
    return sys.modules['linux_admission_dispatcher'].dispatch(event,payload,baseline,seam,
        schedule_terminal=schedule_terminal)

BASELINE_HOOK_SAFE_CODES=frozenset(['compact_admission_changed', 'compact_admission_content_invalid', 'compact_admission_custody_invalid', 'compact_admission_digest_mismatch', 'compact_admission_path_invalid', 'compact_admission_reference_invalid', 'connector_input_closed', 'connector_input_lost', 'connector_output_closed', 'invalid_hook_payload', 'invalid_mcp_transport', 'invalid_rpc_result', 'invalid_session_state', 'invalid_tool_content', 'invalid_tool_value', 'json_rpc_error', 'lifecycle_deadline_exhausted', 'linux_hook_native_caller_mismatch', 'mcp_registration_unavailable', 'missing_machine_id', 'missing_session_id', 'missing_user_prompt', 'model_mcp_architecture_capsule_boundary_invalid', 'model_mcp_architecture_custody_invalid', 'model_mcp_architecture_digest_invalid', 'model_mcp_architecture_envelope_invalid', 'model_mcp_architecture_mind_binding_invalid', 'model_mcp_architecture_protocol_invalid', 'model_mcp_architecture_stop_invalid', 'model_mcp_architecture_unavailable_invalid', 'model_mcp_authority_contract_invalid', 'model_mcp_capabilities_invalid', 'model_mcp_context_boundary_invalid', 'model_mcp_context_capability_invalid', 'model_mcp_context_capsule_boundary_invalid', 'model_mcp_context_capsule_digest_mismatch', 'model_mcp_context_capsule_protocol_invalid', 'model_mcp_context_capsule_size_mismatch', 'model_mcp_context_capsule_source_invalid', 'model_mcp_context_mode_invalid', 'model_mcp_context_presentation_mismatch', 'model_mcp_context_presentation_not_bound', 'model_mcp_context_protocol_invalid', 'model_mcp_context_receipt_missing', 'model_mcp_context_selection_boundary_invalid', 'model_mcp_context_selection_bounds_invalid', 'model_mcp_context_selection_counts_invalid', 'model_mcp_context_selection_missing', 'model_mcp_context_selection_policy_invalid', 'model_mcp_context_selection_protocol_invalid', 'model_mcp_context_selection_receipt_invalid', 'model_mcp_context_selection_receipt_mismatch', 'model_mcp_context_selection_source_mismatch', 'model_mcp_context_selection_stop_reason_invalid', 'model_mcp_context_selection_truncation_invalid', 'model_mcp_context_source_projection_invalid', 'model_mcp_context_source_projection_mismatch', 'model_mcp_contract_identity_invalid', 'model_mcp_facade_capabilities_invalid', 'model_mcp_mind_envelope_invalid', 'model_mcp_projection_digest_invalid', 'model_mcp_prompt_binding_mismatch', 'model_mcp_prompt_binding_missing', 'model_mcp_session_capabilities_invalid', 'native_turn_identity_missing', 'observed_native_input_invalid', 'response_stream_closed', 'response_timeout', 'server_identity_mismatch', 'session_state_lock_timeout', 'session_state_lock_unavailable', 'tool_contract_core_missing', 'tool_contract_invalid', 'tool_contract_mismatch', 'tool_contract_unavailable', 'tool_input_json_invalid', 'transport_type_mismatch', 'turn_registration_intent_missing', 'turn_registration_invalid', 'turn_registration_prompt_missing', 'turn_registration_receipt_missing', 'turn_registration_turn_missing', 'unsafe_state_file', 'unsafe_state_root', 'user_prompt_exceeds_256_kib', 'verified_linux_delegation_requires_actual_pretool_event'])
ENVELOPE_LITERAL_CODES={'00326d104cbd976352058f0c03a479aa2ea39ae8a26a40eb1cde6ce3afdbdf80': 'linux_envelope_00326d104cbd9763', '0053de199d53ee01a32639890bb9abb5d09356d37151704b4517212a8d516bdf': 'linux_envelope_0053de199d53ee01', '02533d41c849759527334cd1d6a0d4556e3f3b47969e414f29d6316b922b31cc': 'linux_envelope_02533d41c8497595', '03bb6fbe807655cc77ad84076d059e929993ea817b15f293910b607768456112': 'linux_envelope_03bb6fbe807655cc', '0550f8c88e483e84d166145204d552ff81d6ac4826b6c3b00649dfc19f4ff417': 'linux_envelope_0550f8c88e483e84', '098e8c433deeddfe4d791205836e2021c997046c01b929a106a001f2d80d4db6': 'linux_envelope_098e8c433deeddfe', '098f01026f853f86f50b72e082bd503f65603cdaff91033591fac3cad3847e76': 'linux_envelope_098f01026f853f86', '09f5175f06041b64025961286f09eb883507707ccfd7ffd11c33228359493fc3': 'linux_envelope_09f5175f06041b64', '0c2a6845f96afc450a49258fe7465e128964f43d94cd438098936b4d85b186ef': 'linux_envelope_0c2a6845f96afc45', '0c7a4b7adc813c1f2d41f6831c33f44fa2dc85995b370233be4577a4157c84b9': 'linux_envelope_0c7a4b7adc813c1f', '0cffbc851b5f8934ef93cf7b3665ef256b0d9e4f6e5385d48e96cebf0a9a6302': 'linux_envelope_0cffbc851b5f8934', '0f0589356e63c3a61b4c88b26ae271d8f3c7c0a66675fadad9b28e971b32c349': 'linux_envelope_0f0589356e63c3a6', '0f325df231025bfe4a7003f67464fca3a2f72a1c778b2b182005ffd20a1a3ad7': 'linux_envelope_0f325df231025bfe', '0f8d337b744e63c635f22160d3324b7e168574dd3af8c528026e6a15fd6ad23e': 'linux_envelope_0f8d337b744e63c6', '0ff7d712fc06eadc6b32106f10b7387391cb60c11fb8905a4cf95cee3e82a4fd': 'linux_envelope_0ff7d712fc06eadc', '13ac326ed929274e3d62f64f0171499b91f0c926adcefa378ce54a0fcddf1f40': 'linux_envelope_13ac326ed929274e', '141b5de8e0919b2057dae87dec4a7c73d1c9633a1e0054fd6db506b149f52632': 'linux_envelope_141b5de8e0919b20', '153250a135f83214c8790a3fecef152048fc5f98660adc46cae5b14ed96ee0dc': 'linux_envelope_153250a135f83214', '179429f64aa7dcac8117f16b0498962eadd3539c10a165cdb75d9863df718786': 'linux_envelope_179429f64aa7dcac', '1867b98fe1f4a5d80cb8aa3503b9aac75957453bc1cb0ca979ffbc008868a1bd': 'linux_envelope_1867b98fe1f4a5d8', '1b0aca529ecfb292aa972c7c7a75a8c17e7db4d12b4b9cb9eb3123145d6b8900': 'linux_envelope_1b0aca529ecfb292', '1e5a75d446926789e22402349555cb91b032cb666b10e5f6a4d01561b6f26098': 'linux_envelope_1e5a75d446926789', '22b378a9cc4dcc4d40d24456afedfe7848acb7b38cf4be8d2185d866c8a1d338': 'linux_envelope_22b378a9cc4dcc4d', '22e63655ad1db542d117e621c4ff7e454172158159ee0844a49cc67b6416c4e4': 'linux_envelope_22e63655ad1db542', '287a3b964e7159b0ea496e7b1d3cf86a5672ec93b9aa2b71f053941112545a8e': 'linux_envelope_287a3b964e7159b0', '2af991394cf46ddf8ee5d6bfd60512612c1747e8b749b2d93d81371f211d3551': 'linux_envelope_2af991394cf46ddf', '2c2bb1b53d36dcb221e41e0bac970f3000a6eb1e0143d68c8db9b5d7dc3be8d4': 'linux_envelope_2c2bb1b53d36dcb2', '2c804afa2ae4d6ae9382681a8472a622689214b845954e50aa2578481e7ebead': 'linux_envelope_2c804afa2ae4d6ae', '31450d4f317e4db770cce05af25b91d3cbc0b1525c6301fcbb048d02f149a878': 'linux_envelope_31450d4f317e4db7', '316e1fdff30b06353917f5823386c1e36540ac142c2f34d98a482df0f3bfe078': 'linux_envelope_316e1fdff30b0635', '369627b3a25ec8821fdb8c47b3c5f6fc5feae9d2dcf0ec867e031821c253c891': 'linux_envelope_369627b3a25ec882', '370c5ee1a4b3115125b7bfd79162bb98c89ce37e1de05080932cf445e06dfc9c': 'linux_envelope_370c5ee1a4b31151', '37ec3e8c939dca74148ef644a5a7a2ad2dd0438bbf371e4c2636ce7f578faab1': 'linux_envelope_37ec3e8c939dca74', '39443cb10d213582f4df0312673b6438ed91d4dd7c6c794270d3d4cf55c33b4f': 'linux_envelope_39443cb10d213582', '39ee8374a63441d1172e7ac96388cfa6b00198e19b378bd857ed183c96fb5caa': 'linux_envelope_39ee8374a63441d1', '3af275117c33f8a574bcfabec2897ef98158c0670dd684998934a44d0a3b98c6': 'linux_envelope_3af275117c33f8a5', '40328919864777808f7c1225e14b6e86669448db9dab03df6401e711322ce5f1': 'linux_envelope_4032891986477780', '415745738af961fcd35b916dfdcedeb434036a0240ba539f56f50d99a5c2e7c6': 'linux_envelope_415745738af961fc', '41f249668377caa31c59d0d8b92536116394fc7688d9148bbd6bcb20928e2ea0': 'linux_envelope_41f249668377caa3', '42d20b1625673b3905c722980068e7435c0feae9927805ab87d632d7f5284c35': 'linux_envelope_42d20b1625673b39', '4347d383d2793237c6c804d91a6c072782ea3b97da77c8001a78321861b4ecf9': 'linux_envelope_4347d383d2793237', '4609654a696398be3b2c171480db516b825370f1671b38c61234cacf9dc86806': 'linux_envelope_4609654a696398be', '471c202ff554b44c116a799fa9585f2a4f9c47f7a77a6cede1c6ee78a811e9f1': 'linux_envelope_471c202ff554b44c', '4920945b907307448f750c5b889da0f44190139de5d9ec50485e34ba17094000': 'linux_envelope_4920945b90730744', '4ce5ae0272ef13e8bd1ee5c7ed7f4a0ec4de46964b325c5046bfd0873b4973a6': 'linux_envelope_4ce5ae0272ef13e8', '4d70937211227b1c57be38c03123aa73a08b9a7b81adfb8937807768c9592ba2': 'linux_envelope_4d70937211227b1c', '4e172997219c54ccb6da2036fb08b2c7e6b2f9505ea6a6655acb89697f5540c0': 'linux_envelope_4e172997219c54cc', '4e83d637a51481310be136e3e51c18caa318013f962e6272cbdaecd53c2900d6': 'linux_envelope_4e83d637a5148131', '4eee6b20c5742757010faf226dcc5a3b89f52ce52022d084a6efb0ce978eefd6': 'linux_envelope_4eee6b20c5742757', '5050149e427d9c93caae4888f5ea3df5cd1b83cfff2a331b1233ec15a0b52584': 'linux_envelope_5050149e427d9c93', '53db3bfbf5b45be3249e31905e0eb54bea06fd2a2492b021aadb7dd36ff00799': 'linux_envelope_53db3bfbf5b45be3', '5451ed3ef5171812bed1e701c7ccc67f317b29892e19d553617618f6b551fe0b': 'linux_envelope_5451ed3ef5171812', '549d7d72b46b9154a5ae6d297039d0c3b908c53c6c2a88824a82f2c66d041f7b': 'linux_envelope_549d7d72b46b9154', '5b1b0f04d74348881d1c1cf91e8f7fc78ef2bb04fd2b19caa75703d849ac6682': 'linux_envelope_5b1b0f04d7434888', '5c6898cd303b98c4c2c79037eef2ccd2262b6fc96c20a613dbbfdff2b56a92fa': 'linux_envelope_5c6898cd303b98c4', '5fde7f1ea88b5fd8ef26c0c197aabccf2ad251271c9c53d4b7f4b6d691c8648b': 'linux_envelope_5fde7f1ea88b5fd8', '62864ce87a48f77a94d92f6d81abc01aee224b7ff17a8e8f8b7098d755c6e653': 'linux_envelope_62864ce87a48f77a', '6420ae13590280ffcdd860b86a256502174a799faf4caf031f5dc336ab1e56fe': 'linux_envelope_6420ae13590280ff', '6a21b0b08f85d910ac3665b3baa8a58560f796d812f1da6987630b548b660410': 'linux_envelope_6a21b0b08f85d910', '6b34a976aba5690c383ec1d6a07336f362a8e683898d1c42780fd01f4af7e9f7': 'linux_envelope_6b34a976aba5690c', '6c4c9d77f801cea0ff8e24c03650e04730766f3dfb8e4540c7e2035530ad88da': 'linux_envelope_6c4c9d77f801cea0', '6e148f2c12c02572937bb740fafcfdbcd58c18cde31d9aafd1e4d0d6465649e2': 'linux_envelope_6e148f2c12c02572', '6ec07c7d0a1006bd6d937d4507b0892ebefcc6057ecd994a2d1b0b497aadd858': 'linux_envelope_6ec07c7d0a1006bd', '7009ab49335921966e0a1398d4dafb7fe05d2ee14cf0c1a70e19d255ddbb25bd': 'linux_envelope_7009ab4933592196', '704470382d71af9969a981eccae48cf2417b79430f5ef9edbd3cc979833b2c27': 'linux_envelope_704470382d71af99', '724aa95a9e1d580ff3428b4f1296d9cbeed0e1b1046561043a1271ed9336e54d': 'linux_envelope_724aa95a9e1d580f', '73a9873f3fe87fd1256677831927faa9025fdffedfb0ff14506b211074c587ca': 'linux_envelope_73a9873f3fe87fd1', '757a7b61e8f58dc0f724ca411c244262eb7a80e6dbc5fe6bec03413b68c02b54': 'linux_envelope_757a7b61e8f58dc0', '79323550e9d5a268caac9f9c3fab25efe6bb8c9ddc53c4009d8699b2ec1ea8fa': 'linux_envelope_79323550e9d5a268', '7a1507cd84734907f18d3c6435b0aa837fab1fb26d5b1f6f7960003765ccde19': 'linux_envelope_7a1507cd84734907', '7e108139d83af4d30e9ab2537e72346a783942e3f86d2e573fb9daaf9625d1d4': 'linux_envelope_7e108139d83af4d3', '80579e2aa7353bb8dab574c28071f038ca07f87972fabeb5ffe15e114dda2c84': 'linux_envelope_80579e2aa7353bb8', '8247ca5d712a124890778b9c0b0742bd0a1b8372f1822599a76d6d04e2931d03': 'linux_envelope_8247ca5d712a1248', '85b51e8e94e426436e88327ee8a929e6155884c76b8b26273b7d1491d2bcb41b': 'linux_envelope_85b51e8e94e42643', '85b941b3a1a7e906191534275fb75dfe75784b2e5dde512f6698d28303d439c5': 'linux_envelope_85b941b3a1a7e906', '8612a1c2e5f880dc649e70dddad447a5f14066e9d3fb2f6823f7f92177e86560': 'linux_envelope_8612a1c2e5f880dc', '88f3c91daec58305b5a8a0b6f086acf261dabe731c456672db68abf1dba71f01': 'linux_envelope_88f3c91daec58305', '891b49dd06a14b59ac9ec20575ef0e7aea9ddea52e70674c34df8b6013aac87d': 'linux_envelope_891b49dd06a14b59', '89f60eb65e8fa8deec59b3294e5d05c3ec11a46a006a109ebd55ce1fe4ca6240': 'linux_envelope_89f60eb65e8fa8de', '8bbbf24c53130c5cb8019480e18809e22017fb8cdc2299d9b91c7e1b6fc67f96': 'linux_envelope_8bbbf24c53130c5c', '90a9ca2e444040a6622d88eda435e0a2d6bb7a23e5a7ea95e4c5158deb923ed9': 'linux_envelope_90a9ca2e444040a6', '91d1a2d78563f113280c3753cd2e5a6cfcd8234dc5389e5d674e8c2d1ba48cfe': 'linux_envelope_91d1a2d78563f113', '91e595cf81d3402e9c525b67b79aa644c352bc4e7b7cb944ade9d3d2b4aa9a98': 'linux_envelope_91e595cf81d3402e', '9477dddef8180dc7cce944926ffd9f449f5ed1f2634d2f40c5bc55ce5c865a56': 'linux_envelope_9477dddef8180dc7', '959550b12a945e00cd4d16d521f62c3484df1e4bc13ce5d4eb8c41f5b416179c': 'linux_envelope_959550b12a945e00', '95b588e159b9dbd06736e7c9a2532a414d9b3b48c80aff4d4935a1a0490fa546': 'linux_envelope_95b588e159b9dbd0', '9675fc5f5df6fd763265b86bc8f2ac10f12e8a7e8b5b5596ec6ab51697c50037': 'linux_envelope_9675fc5f5df6fd76', '97901bb0f24598e41608a8fee1ae57b4eb0151aca53e4102de489e43c788e7b9': 'linux_envelope_97901bb0f24598e4', '98c8e64c0ba6526b94d1c669d784f33bcded471c3bfb154d8f27e9b9c858c0ca': 'linux_envelope_98c8e64c0ba6526b', '9a8d4c90c6b6f154deeb580fd8ceaa0a9c37363e478fe63693657436c744b2df': 'linux_envelope_9a8d4c90c6b6f154', '9ac67fd9a190824badaab1df778810be0a02f980a8ecdc368087c11a7b8ade13': 'linux_envelope_9ac67fd9a190824b', '9b7af6e6f71e545c9f918458bf74ca96ea04b189f9f42efb85232338869be8f9': 'linux_envelope_9b7af6e6f71e545c', '9c72a090b70b75bfff7322aca3e1750c2503c16d4d5c73e95e03759f5fa8820b': 'linux_envelope_9c72a090b70b75bf', '9f57cc3a783e356c1c45294001feb9b4ebe9286595c41755f23c51afad7ed0e2': 'linux_envelope_9f57cc3a783e356c', '9f92bcc492e759204b6954bbec867109c6224e8d828e8ebf700108671177d33a': 'linux_envelope_9f92bcc492e75920', 'a1be58810a895d27d99f56e4411d59102f524fce3cab5d2b83bdde4f9e8e6885': 'linux_envelope_a1be58810a895d27', 'a431e0bf48c134e09dc708fceeb72084d83ba7492da702dc88063acbda26bed7': 'linux_envelope_a431e0bf48c134e0', 'a52a015c5050b9cc7d6e34673fd702d111c883930d8f0a4526005f7b15dca0c8': 'linux_envelope_a52a015c5050b9cc', 'a547b0b8b407fbff5aa040c3ecea7aa709859c90c0c2d5fa1e1b72f688242deb': 'linux_envelope_a547b0b8b407fbff', 'a548291452cf2af944e23b28a15eac09e0c5feaa860b648db4b64ce4a2f32198': 'linux_envelope_a548291452cf2af9', 'a580896b94859d8efa484173f0ccddca4f691ff99ef984f782477e2151feecd8': 'linux_envelope_a580896b94859d8e', 'a65584790612d47e1380f173dd96284368396098b5447b9ac8d6bb873bff88c7': 'linux_envelope_a65584790612d47e', 'a6891a7793b9cdd338773ebd4a0f4ed225412def4559471afa08fe74f384b343': 'linux_envelope_a6891a7793b9cdd3', 'a6f856a663664c61a5b2173bb284a4b57466040a392e3c0dcb479a5ee4f4211d': 'linux_envelope_a6f856a663664c61', 'a7504aef47510fa50b748879e86f4306cb73f3b8ba56cb5de02bfda8d2142dc7': 'linux_envelope_a7504aef47510fa5', 'afe071080966c4dfcbb7d456fd4bf07fdf31e1ee8bfa077c38ecf6788f6b98fe': 'linux_envelope_afe071080966c4df', 'b04bf46af330a00cec4292c4b980c12e79dbea1b965ee0ae130cfc8457a7c5dc': 'linux_envelope_b04bf46af330a00c', 'b07a8df15052e33f9e8aa57029fe4b0302be73e6d62fc07c5281ee544ef17143': 'linux_envelope_b07a8df15052e33f', 'b1be40dd63cac3d676231d9d5eac5bf7c99b3834c7ea52ba8e1991d3d5c62e48': 'linux_envelope_b1be40dd63cac3d6', 'b232a0ea788627e6d1e74f7d99f81ae6485c65cd0da25c5eff1b73e592874177': 'linux_envelope_b232a0ea788627e6', 'b2ada2df826a3086af0c49be19befea439655a65abb8bb09182be5998d28ed1b': 'linux_envelope_b2ada2df826a3086', 'b4b829136e3bb199b6e9562b815495a4df127e835d5b854fe4ad4068145c9775': 'linux_envelope_b4b829136e3bb199', 'b5c8616ceab2f90c7c413526fdb0b3583620a890854cf103d97cc4a209032256': 'linux_envelope_b5c8616ceab2f90c', 'b6f0d249782061c75062f63cb3d873f89a4e0be6037324a7561e4a5b416690bc': 'linux_envelope_b6f0d249782061c7', 'b76f7b3302996941b73d3a050a8706ea4ecaee709f6b049f734df87e32af30dd': 'linux_envelope_b76f7b3302996941', 'b7eb36236ed5c8262a8488a3b7ee0de75d4bce89e6c4cc58c73e4a893b57e2cd': 'linux_envelope_b7eb36236ed5c826', 'b831dc7a32d132e06645bfe28bf41e7dfef02088cc880648f86d15eab008d4bb': 'linux_envelope_b831dc7a32d132e0', 'ba0cb99d30bed44f92522637fc6cd75531d17937a670adb9591c2aaefcf3f7d3': 'linux_envelope_ba0cb99d30bed44f', 'ba110c360a24243a2069bc0ce4160b3cb1bae93da7c3f5dd7e6e8dec9c7f86b1': 'linux_envelope_ba110c360a24243a', 'baba3e09d5d06fe3f957d1e5fada926be6f12befc2b3dcc7bc8d371d11ac20d4': 'linux_envelope_baba3e09d5d06fe3', 'bb9535d2c52806b767ebf916918d0ed4f2578ba7bb7084e679c82c6da2c9ee8a': 'linux_envelope_bb9535d2c52806b7', 'c0185b12a650f65e1c20a2dd263fe7c7ade1d9638d9c10911d17d79bb8142e90': 'linux_envelope_c0185b12a650f65e', 'c13a3c66930f24b3f44806abd02f23bde6a0f7a1515892bd72714338e946b091': 'linux_envelope_c13a3c66930f24b3', 'c2785d156a0b2e9cb1547cf1a08917010b789af7e7d0b4a94819b161a386fa64': 'linux_envelope_c2785d156a0b2e9c', 'c3278dc7f050cc84fbfb7d2d2fc41bc15f1f63eab79d4317481b5e4c81304fd9': 'linux_envelope_c3278dc7f050cc84', 'c37adf10c7e9240ba30becc1ba897c2fc7cd3c9c961359ad986ee40bbf284df1': 'linux_envelope_c37adf10c7e9240b', 'c81769c443f0e1fe50d14b36395442eacdb4a876d969a23967c164f00c54afd5': 'linux_envelope_c81769c443f0e1fe', 'c8c2fc9ca0b31edeb211f071347b9dc63bf7edfc22403fb39ae903b7e75fa9a9': 'linux_envelope_c8c2fc9ca0b31ede', 'cbcd3eed32b827550983f8ac9b007eb221d9071930172a47a689f733aca850d1': 'linux_envelope_cbcd3eed32b82755', 'cd1859f7f2992d141a703a9bd903c8e9ba9c813a447785875b43c300e2fe2f33': 'linux_envelope_cd1859f7f2992d14', 'cd942d714134eaf439b904198c240455a39cc81f172477187e6bdd4ca3a64b2a': 'linux_envelope_cd942d714134eaf4', 'ce85aaab5e9190e1abccac647e8f5ecc18b0055cecc48822af623947d8d4272f': 'linux_envelope_ce85aaab5e9190e1', 'cf269141e4c8b01b8acadc6d04213cf977e6b5b8de499d8194589c947a6265a6': 'linux_envelope_cf269141e4c8b01b', 'd19e702d3c7d6c2bc77cb0d315f6e418ac166b0047c888a7422b77d9a790e93d': 'linux_envelope_d19e702d3c7d6c2b', 'd211f3ee4011802b25169b340ebdd4bf9509b6eba1a716ada2133d595a84af6f': 'linux_envelope_d211f3ee4011802b', 'd28944ac8d4f123c69aacfa956319ec75622599ffb734e3b2ce6055ff5a72d63': 'linux_envelope_d28944ac8d4f123c', 'd8e8b0c6e83116636102fb59f6e41b26f768e87dd201c5dd46747f68a1e31fac': 'linux_envelope_d8e8b0c6e8311663', 'db723d5b32ff2c8ad98671d8348d4bd17b2807fce8821ed3f42c87e654912c66': 'linux_envelope_db723d5b32ff2c8a', 'dd2a47a5135e3d1310419bb133a2e5c11be45636ead2beada4b9c7c4048aeb49': 'linux_envelope_dd2a47a5135e3d13', 'de1336d276be035956c53a0a611bb8898f39216d7e208e14cfc1c5657d49c8ae': 'linux_envelope_de1336d276be0359', 'deafe45e563b48786e2393f80ce932b3eaf623158606fe92de3aecdb408129c6': 'linux_envelope_deafe45e563b4878', 'dfea10c699390e80720f32b1940f7268656434e6651d8edd27c152f910c511c3': 'linux_envelope_dfea10c699390e80', 'dff33c4e224f4014e961b62c1d0d50ff3bd643766cff86729c8a62f30939e07f': 'linux_envelope_dff33c4e224f4014', 'e03c2521938ba1fe976b85244bc2ded712f9dc8ed8cba0fa11c1acdccbe4b242': 'linux_envelope_e03c2521938ba1fe', 'e2d1f0ded23eef355913a46f2975c302d83efc9efe677be43e714c1fd22b55d3': 'linux_envelope_e2d1f0ded23eef35', 'e3e39016c5183812bd37503814de92a8dcd38a0379594640d2e3887eefd72db8': 'linux_envelope_e3e39016c5183812', 'e405b38a26d539a66737d2a4e21c86bed1757234650390e67bd21753564cbe13': 'linux_envelope_e405b38a26d539a6', 'e43089ebbdc92d23097c019d9bb77896ba1792e1905cf00100d499fdd04f9891': 'linux_envelope_e43089ebbdc92d23', 'e50d204a40f1e03d13f2d29a55eda13b73360e6c4f446e1a896da3120981db4d': 'linux_envelope_e50d204a40f1e03d', 'e71c740cd5070350d7035815261de96bd15d8c4b8fc44b1445e27586652e34f0': 'linux_envelope_e71c740cd5070350', 'e7f9d9f52a446e7a90958a75c50e381b0631d415467f77ac222c2852c95b5f51': 'linux_envelope_e7f9d9f52a446e7a', 'eb5aa14d87b8c7f55aa0a856d5fcceaf42e13ecdbfc91b20a3d4625eb6baa551': 'linux_envelope_eb5aa14d87b8c7f5', 'ec8a7fbfa02aa06c6818db6713d84bce1d0aa7d30be0d223e416d6a18b1e872e': 'linux_envelope_ec8a7fbfa02aa06c', 'ed752b247c3252f78a1699a278e6a40314983f45ef700e29ea7e4f7abb16062a': 'linux_envelope_ed752b247c3252f7', 'ee07da6a58456eea3c46ab08076f5cd2b5abddf19d3d7026266cfe7682255f80': 'linux_envelope_ee07da6a58456eea', 'f1455905daea52a83be10864a68ce09b970c029990de1e2f359c3166fb6e310b': 'linux_envelope_f1455905daea52a8', 'f1a4cd96b406ee301f3a6faeeb8414064f3090b900ab2d69f80042fa82401db9': 'linux_envelope_f1a4cd96b406ee30', 'f1c0f97ecbfa0a287aceff8b7f43a6b85045cd16b3c72cf8badb3f29861ea665': 'linux_envelope_f1c0f97ecbfa0a28', 'f5a565c95ad7dbdfed3fa7f67403fb572aaa126d0cc6fe62ebeb66f4dba22e90': 'linux_envelope_f5a565c95ad7dbdf', 'f5abab9074a14e7b09bfea3642f7319a17fb4c302c6200e7eef9a15d93b96ff3': 'linux_envelope_f5abab9074a14e7b', 'f89cf4caaafafa44a6bbfa75ebec89fb7a26a8e1e9b3a17c9ae7d5448eb86e61': 'linux_envelope_f89cf4caaafafa44', 'f8ef0e3c63262be6bd1b443df3b89f333e5ccf5c4d9cd80e20250a188966fc52': 'linux_envelope_f8ef0e3c63262be6', 'fb580a728b2e9dcfe608f962b2efafb9a7c203bbf8b981dbf797f92a0b07f4bf': 'linux_envelope_fb580a728b2e9dcf', 'fbed5c8416470323e94c646ff70daf55b2cf77f8cae63784c7be095e7bd98297': 'linux_envelope_fbed5c8416470323', 'fc76a338c75bbcef61e1aa4a3fb9a7ce615bf735e340417a45f6e98d39bde882': 'linux_envelope_fc76a338c75bbcef', 'ff3bdf587fa21058bbfc8e4a8e2387e9e07506c70607a4cbeb9142d5b94686eb': 'linux_envelope_ff3bdf587fa21058', 'ff90dcf0f0eb8608efa10837512110b1bfef8bc1e89db235f9c092498d24cf8c': 'linux_envelope_ff90dcf0f0eb8608'}

def diagnostic_frames(error):
    frames=[];current=error.__traceback__;walked=0
    while current is not None and walked<64:
        code=current.tb_frame.f_code;name=code.co_filename
        if isinstance(name,str) and name.startswith(str(ROOT) + os.sep) and '..' not in Path(name).parts:
            base=Path(name).name;function=code.co_name
            if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',base) and re.fullmatch(r'[A-Za-z0-9_<>]{1,100}',function):
                frames.append({'file':base,'function':function,'line':int(current.tb_lineno)})
        current=current.tb_next;walked+=1
    return frames[-8:]

def typed_diagnostic(error,baseline):
    trace={'traceback_frames':diagnostic_frames(error)}
    builtin_classes={TypeError,KeyError,AttributeError,NameError,ImportError,
        ModuleNotFoundError,SyntaxError,RuntimeError}
    if type(error) in builtin_classes:trace['exception_class']=type(error).__name__
    if isinstance(error,baseline.HookError):
        value=str(error);transport_type=getattr(baseline,'HookTransportError',None)
        transport=isinstance(transport_type,type) and isinstance(error,transport_type)
        trace.update(code=value if value in BASELINE_HOOK_SAFE_CODES else 'linux_baseline_hook_failed',
            exception_class='HookTransportError' if transport else 'HookError')
        return trace
    envelope_type=getattr(getattr(baseline,'turn_envelope',None),'TurnEnvelopeError',None)
    if isinstance(envelope_type,type) and isinstance(error,envelope_type):
        message=str(error);bounded=message[:4096]
        digest=hashlib.sha256(bounded.encode('utf-8',errors='replace')).hexdigest()
        trace.update(code=ENVELOPE_LITERAL_CODES.get(digest,'linux_native_envelope_failed'),
            exception_class='TurnEnvelopeError',safe_message_sha256=digest,
            message_literal_known=digest in ENVELOPE_LITERAL_CODES,message_truncated=len(message)>4096)
        return trace
    builtin_os_types={OSError,FileNotFoundError,PermissionError,IsADirectoryError,NotADirectoryError,
        FileExistsError,InterruptedError,BlockingIOError,TimeoutError,ConnectionError,
        BrokenPipeError,ConnectionAbortedError,ConnectionRefusedError,ConnectionResetError,ProcessLookupError}
    if type(error) in builtin_os_types:
        trace.update(code='linux_local_os_error',exception_class=type(error).__name__)
        if type(error.errno) is int and 0<=error.errno<=4096:trace['errno']=error.errno
    return trace

def run(event,payload,baseline):
    try:
        return _run(event,payload,baseline)
    except Exception as error:
        trace=safe_failure(error,'linux-hook-runtime')
        detail=typed_diagnostic(error,baseline);trace.update(detail)
        try:write_safe_trace(trace,payload)
        except (OSError,ValueError):pass
        code=(detail.get('code') or (str(error) if isinstance(error,RuntimeErrorSafe) and re.fullmatch(r'[a-z0-9_]{1,80}',str(error)) else 'linux_receiving_infrastructure_failed'))
        # Exit 2 is essential: an uncaught exit 1 may be advisory in hook hosts.
        if event=='PreToolUse':baseline.deny('delegation runtime denied: '+code)
        raise baseline.HookError(code) from None

def bootstrap_controls(maximum,budget):
    """Explicit source observation only; never admission or operation claim."""
    need(type(maximum)is int and 1<=maximum<=100 and type(budget)is int and 1<=budget<=600,
        'linux_source_bootstrap_bound_invalid')
    config=json.loads(protected_bytes(CONFIG,private=True));loaded=load_components(config)
    adapter,core=loaded['adapter'],loaded['core'];peer=make_private_peer(config);deadline=time.monotonic()+budget
    class SourceReader:
        read_phase='read-source';context_thread_id=config['target_thread_id']
        def read(self,thread_id,host_id,*,cursor=None,limit=10,outputs=False):
            need(thread_id==config['source_thread_id'] and host_id==config['source_host_id']
                and type(limit)is int and 1<=limit<=10,'linux_source_bootstrap_scope_invalid')
            remaining=deadline-time.monotonic();need(remaining>0,'native_evidence_deadline')
            args={'purpose':'controls','execution_host':'node-linux','thread_id':thread_id,'host_id':host_id,'limit':limit}
            if cursor is not None:args['cursor']=cursor
            value=peer.call('_integrity_delegation_native_page',args,timeout=min(35,remaining))
            need(value.get('protocol')=='integrity/private-native-evidence-page/v1'
                and value.get('provider_host')=='owner-host' and value.get('purpose')=='controls'
                and value.get('execution_host')=='node-linux' and value.get('thread_id')==thread_id
                and value.get('native_host_id')==host_id and value.get('execute') is False
                and value.get('sent') is False and value.get('action_authority')=='not-evaluated',
                'linux_source_bootstrap_result_invalid')
            need(time.monotonic()<deadline,'native_evidence_deadline')
            return sys.modules['native_evidence_facade'].checked_page(value['native_page'],thread_id,host_id)
    result=adapter.backfill_controls(config,core,SourceReader(),dry_run=False,maximum=maximum)
    # The detailed progress/cursors stay in the protected common ledger.
    public={key:result[key] for key in ('protocol','mode','status','execute','claims_mutated','frontier_advanced') if key in result}
    if 'observation' in result:public['observation']=result['observation']
    public.update(source_thread_id=config['source_thread_id'],action_authority='not-evaluated')
    return public

if __name__ == "__main__":
    _integrity_require_config()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--bootstrap-controls',action='store_true',required=True)
    parser.add_argument('--max-pages',type=int,default=50);parser.add_argument('--budget',type=int,default=300)
    args=parser.parse_args()
    try:print(json.dumps(bootstrap_controls(args.max_pages,args.budget),sort_keys=True))
    except Exception:print(json.dumps({'status':'source-observation-unavailable','execute':False,'claims_mutated':False}));raise SystemExit(2) from None
