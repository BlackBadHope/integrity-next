# SPDX-License-Identifier: Apache-2.0
"""Fixed Medor DATA result return over the existing public peer route."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib
import json
import re
import uuid
import native_evidence_peer_auth as strict_json

MEDOR=_integrity_value('binding_medor')
PROTOCOL='integrity/delegated-task-result/v1'
OPAQUE=re.compile(r'turnref:[A-Za-z0-9_-]{43}')

class ReturnError(ValueError):pass

def need(value,code):
    if not value:raise ReturnError(code)

class PublicResultPeer:
    """Legacy public PeerClient wire is retained, with a bounded caller timeout."""
    host_id='owner-host'
    def __init__(self,exchange,key_loader):self.exchange,self.key_loader=exchange,key_loader
    def call(self,name,arguments,request_id,*,timeout):
        need(name=='codex_send_prompt' and set(arguments)=={'thread_id','prompt'}
            and arguments['thread_id']==MEDOR,'linux_return_route_invalid')
        key=self.key_loader()
        need(isinstance(key,str) and 32<=len(key)<=4096,'linux_return_key_invalid')
        raw=json.dumps({'host_id':'owner-host','name':name,'arguments':arguments,
            'request_id':request_id,'token':key},ensure_ascii=False,separators=(',',':')).encode()
        reply=strict_json.decode(self.exchange(raw,timeout))
        need(reply.get('host_id')=='owner-host' and 'error' not in reply and 'result' in reply,'linux_return_ack_unavailable')
        return reply['result']

class LinuxResultBridge:
    def __init__(self,peer,*,thread_id,turn_id,remaining):
        need(getattr(peer,'host_id',None)=='owner-host','linux_return_route_invalid')
        self.peer,self.thread_id,self.turn_id,self.remaining=peer,thread_id,turn_id,remaining
    def _host_tool_json(self,_host,name,arguments,context_thread):
        need(name=='send_message_to_thread' and context_thread==self.thread_id
            and set(arguments)=={'threadId','hostId','prompt'} and arguments['threadId']==MEDOR
            and arguments['hostId']=='durable','linux_return_route_invalid')
        text=arguments['prompt'];need(isinstance(text,str) and 0<len(text.encode())<=8000 and not OPAQUE.search(text),
            'linux_return_content_invalid')
        body=strict_json.decode(text)
        need(body.get('protocol')==PROTOCOL and set(body)=={'protocol','operation_id','request_digest','status','receiver','result','result_digest'}
            and body['status'] in {'completed','failed','unknown'}
            and body['receiver']=={'host_id':'node-linux','thread_id':self.thread_id,'turn_id':self.turn_id}
            and isinstance(body['result'],dict) and body['result'].get('independent_effect_verified') is False
            and 'claim_token' not in body['result'] and 'turn_ref' not in body['result'], 'linux_return_content_invalid')
        request_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'integrity/linux-result/v1:'+body['operation_id']+':'+hashlib.sha256(text.encode()).hexdigest()))
        result=self.peer.call('codex_send_prompt',{'thread_id':MEDOR,'prompt':text},request_id,
            timeout=min(45,self.remaining()))
        if isinstance(result,dict) and isinstance(result.get('content'),list):
            values=[block['text'] for block in result['content'] if isinstance(block,dict) and block.get('type')=='text' and isinstance(block.get('text'),str)]
            need(len(values)==1,'linux_return_ack_invalid');result=strict_json.decode(values[0])
        need(isinstance(result,dict) and result.get('accepted') is True and result.get('thread_id')==MEDOR,
            'linux_return_ack_invalid')
        # An API acknowledgement is not independent proof of delivered action.
        return {'threadId':MEDOR,'hostId':'durable','request_id':request_id,'independent_effect_verified':False}
