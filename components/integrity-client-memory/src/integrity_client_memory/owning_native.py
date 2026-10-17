# SPDX-License-Identifier: Apache-2.0
"""Linux owning Native head via the existing verified Unix owner, never Windows."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib,importlib.util,json,os,re,stat,time
from pathlib import Path
ROOT=Path(_integrity_value('path_421d7209bec4'))
FACTORY_SHA=_integrity_value('pin_49aaeb94d0ae')
UUID=re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
def need(ok,code):
    if not ok:raise ValueError(code)
def verified_current_head(thread_id):
    """Read-only primitive; no registration, lease, claim, append or execution."""
    need(os.name=='posix' and UUID.fullmatch(thread_id),'linux_native_subject_invalid')
    path=ROOT/'linux_runtime_factory.py';details=path.lstat()
    need(not path.is_symlink() and stat.S_ISREG(details.st_mode) and details.st_uid==0
        and not stat.S_IMODE(details.st_mode)&0o022,'linux_native_factory_custody_invalid')
    raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==FACTORY_SHA,'linux_native_factory_pin_changed')
    spec=importlib.util.spec_from_file_location('owning_linux_verified_factory',path)
    factory=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),factory.__dict__)
    profile=json.loads(factory.protected_bytes(factory.CONFIG,private=True))
    sdk=factory.UnixOwnerSDK(thread_id,time.monotonic()+18,profile)
    try:
        metadata=sdk.request('thread/read',{'threadId':thread_id,'includeTurns':False},6)
        need(metadata.get('thread',{}).get('id')==thread_id,'linux_native_thread_mismatch')
        # Verify the current subject using metadata; never load turn contents here.
        # Full item provenance is a separate read and remains unchanged.
        page=sdk.request('thread/turns/list',{'threadId':thread_id,'limit':1,
            'sortDirection':'desc','itemsView':'notLoaded'},10)
        rows=page.get('data');need(isinstance(rows,list) and len(rows)==1,'linux_native_head_missing')
        turn=rows[0]
        need(UUID.fullmatch(str(turn.get('id'))) and turn.get('status') in
            {'inProgress','completed','failed','interrupted'} and not turn.get('truncated')
            and not turn.get('itemsTruncated'),'linux_native_head_invalid')
        return {'id':turn['id'],'status':turn['status']}
    finally:sdk.close()
def current_owning_turn(thread_id):
    need(os.environ.get('CODEX_THREAD_ID')==thread_id,'linux_native_caller_mismatch')
    return verified_current_head(thread_id)
