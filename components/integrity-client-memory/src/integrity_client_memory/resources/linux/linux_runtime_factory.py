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

def run(event,payload,baseline):
    try:
        return _run(event,payload,baseline)
    except Exception as error:
        trace=safe_failure(error,'linux-hook-runtime')
        try:write_safe_trace(trace,payload)
        except (OSError,ValueError):pass
        code=str(error) if isinstance(error,RuntimeErrorSafe) and re.fullmatch(r'[a-z0-9_]{1,80}',str(error)) else 'linux_receiving_infrastructure_failed'
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
