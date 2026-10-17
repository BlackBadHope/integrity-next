# SPDX-License-Identifier: Apache-2.0
"""Private, conversation-bound hook/broker handoff. No ambient active thread."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
import uuid
import integrity_client_turn_envelope as envelopes

UUID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
ROOT = Path(_integrity_value('private_state_root'))
ROUTE_FIELD = '_antigravity_route'

def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()

def conv_id(value):
    if not isinstance(value,str) or not UUID.fullmatch(value):raise ValueError('conversation-id-invalid')
    return value

def load(root,conversation):
    p=Path(root)/'admission-state'/ (conv_id(conversation)+'.json')
    if not p.exists():return {}
    if p.is_symlink():raise ValueError('state-link-refused')
    result=json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(result,dict) or result.get('conversation_id')!=conversation:raise ValueError('state-binding-invalid')
    return result

def atomic(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('state-link-refused')
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with temporary.open('x',encoding='utf-8',newline='\n') as f:
            f.write(canonical(value));f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)

def save(root,conversation,value):
    atomic(Path(root)/'admission-state'/(conv_id(conversation)+'.json'),value)

@contextmanager
def locked(root,conversation):
    directory=Path(root)/'locks'/conv_id(conversation)
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    with envelopes._exclusive_root_lock(directory):yield

def stage_route(root,state,tool,arguments):
    if ROUTE_FIELD in arguments:raise ValueError('route-field-reserved')
    route=secrets.token_hex(32)
    atomic(Path(root)/'routes'/(route+'.json'),{'conversation_id':state['conversation_id'],'generation':state['generation'],'model_name':state['model_name'],'tool':tool,'arguments_sha256':digest(arguments),'expires_at':time.time()+180})
    return route

def consume_route(root,route,tool,arguments):
    if not isinstance(route,str) or not re.fullmatch('[0-9a-f]{64}',route):raise ValueError('hook-route-required')
    path=Path(root)/'routes'/(route+'.json')
    if path.is_symlink():raise ValueError('route-link-refused')
    # Rename first: one invocation wins, even across two public broker processes.
    used=path.with_suffix('.used')
    if used.exists():raise ValueError('hook-route-already-used')
    os.rename(path,used)
    value=json.loads(used.read_text(encoding='utf-8'))
    if value['tool']!=tool or value['arguments_sha256']!=digest(arguments) or value['expires_at']<=time.time():raise ValueError('hook-route-binding-invalid')
    conv_id(value['conversation_id'])
    return value

def unwrap(result):
    if not isinstance(result,dict) or result.get('isError'):raise ValueError('upstream-tool-error')
    if isinstance(result.get('structuredContent'),dict):return result['structuredContent']
    content=result.get('content',[])
    for row in content:
        if row.get('type')=='text':
            value=json.loads(row['text'])
            if isinstance(value,dict):return value
    raise ValueError('upstream-result-missing')

def signed(receipt,protocol=None):
    if not isinstance(receipt,dict) or not DIGEST.fullmatch(str(receipt.get('receipt_id',''))):return False
    s=receipt.get('signature',{})
    return (not protocol or receipt.get('protocol')==protocol) and s.get('algorithm')=='ed25519' and bool(s.get('key_id')) and bool(s.get('value'))

class EnvelopeStore:
    def __init__(self,root):self.root=Path(root)
    def resolve(self,ref):return envelopes.resolve(ref,root=self.root)
    def release_claim(self,ref,claim):return envelopes.release_claim(ref,claim,root=self.root)
    def commit(self,ref,claim):return envelopes.commit(ref,claim,root=self.root)
    def retire(self,ref,**kwargs):return envelopes.retire(ref,root=self.root,**kwargs)
