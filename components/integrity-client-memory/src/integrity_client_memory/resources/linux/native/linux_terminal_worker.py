# SPDX-License-Identifier: Apache-2.0
"""One bounded detached observer; no task execution retry or new service."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse
import json
import os
import hashlib
import secrets
import re
from pathlib import Path
import sys
import time
import linux_runtime_factory as runtime

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--operation-id',required=True);parser.add_argument('--thread-id',required=True);parser.add_argument('--turn-id',required=True)
    args=parser.parse_args(argv)
    started=time.monotonic();config=None;terminal=None;opened=[];stage='worker-config'
    return run_worker(args,started,opened)

def run_worker(args,started,opened):
    config=None;terminal=None;stage='worker-config'
    progress={}
    try:
        return _run_worker(args,started,opened,progress)
    except Exception as error:
        # A failure must leave an outcome even when stdout/stderr are detached.
        trace=runtime.safe_failure(error,'worker-exception')
        fallback_outcome(args,trace,time.monotonic()-started,progress)
        return 2
    finally:
        for sdk in opened:sdk.close()

def fallback_outcome(args,trace,elapsed,progress):
    # Does not load failed components or need a usable config/claim. Fixed own
    # metadata custody is independent of execution, Memory close and callback.
    for value in (args.thread_id,args.turn_id):
        if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value) is None:
            raise ValueError('worker_native_locator_invalid')
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,127}',args.operation_id) is None:
        raise ValueError('worker_operation_invalid')
    parent=runtime.USER_ROOT/'delegation-state'
    if parent.resolve(strict=True)!=parent or parent.is_symlink():raise ValueError('worker_receipt_parent_invalid')
    root=parent/'terminal-receipts';root.mkdir(mode=0o700,exist_ok=True)
    if root.resolve(strict=True)!=root or root.is_symlink():raise ValueError('worker_receipt_root_invalid')
    sha=lambda value:hashlib.sha256(value.encode()).hexdigest()
    path=root/(sha(args.operation_id)+'.json')
    if path.exists() and (path.is_symlink() or not path.is_file()):raise ValueError('worker_receipt_file_invalid')
    payload={'protocol':'integrity/delegation-terminal-worker-outcome/v1','operation_id_sha256':sha(args.operation_id),
        'thread_id_sha256':sha(args.thread_id),'turn_id_sha256':sha(args.turn_id),'status':'observer-unavailable',
        'recovery_state':'recovery-error','deadline_seconds':150,'worker_pid':os.getpid(),
        'observed_at':int(time.time()),'elapsed_seconds':round(max(0,elapsed),3),**trace}
    if 'return_sent' in progress:
        payload['return_sent']=progress['return_sent']
    elif not progress.get('reconcile_started'):
        payload['return_sent']=False
    else:
        payload['return_outcome']='unknown-readback-required-no-resend'
    if progress.get('return_attempted'):payload['return_attempted']=True
    temporary=root/(sha(args.operation_id)+'.'+secrets.token_hex(8)+'.tmp')
    descriptor=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(descriptor,'w') as stream:
            json.dump(payload,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()

def _run_worker(args,started,opened,progress):
    config=json.loads(runtime.protected_bytes(runtime.CONFIG,private=True))
    loaded=runtime.load_components(config)
    core,adapter=loaded['core'],loaded['adapter'];deadline=time.monotonic()+150
    terminal=runtime.module('integrity_delegation_terminal',runtime.ROOT/'integrity_delegation_terminal.py',config['terminal_sha256'])
    peer=runtime.make_private_peer(config);public=loaded['terminal_bridge'].PublicResultPeer(
        lambda raw,timeout:runtime.peer_exchange(runtime.peer_config(),raw,timeout),runtime.peer_key)
    def factory(reader_deadline):
        sdk=runtime.UnixOwnerSDK(args.thread_id,reader_deadline,config);opened.append(sdk)
        sdk.turn_id=args.turn_id
        reader=loaded['provider'].LinuxReceivingReader(sdk,peer,adapter,config,thread_id=args.thread_id,
            turn_id=args.turn_id,deadline=reader_deadline,terminal=True)
        reader.bridge=loaded['terminal_bridge'].LinuxResultBridge(public,thread_id=args.thread_id,turn_id=args.turn_id,
            remaining=lambda:max(0,deadline-time.monotonic()))
        reader.host=None
        return reader
    progress['reconcile_started']=True
    result=terminal.reconcile(config,args.operation_id,args.thread_id,args.turn_id,core=core,adapter=adapter,
        reader_factory=factory,deadline_seconds=150)
    for key in ('return_sent','return_attempted'):
        if key in result:progress[key]=result[key]
    terminal.write_outcome_receipt(config,operation_id=args.operation_id,thread_id=args.thread_id,
        turn_id=args.turn_id,result=result,elapsed=150-max(0,deadline-time.monotonic()))
    return 2 if result.get('status')=='observer-unavailable' else 0

if __name__ == "__main__":
    _integrity_require_config()

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:raise SystemExit(2) from None
