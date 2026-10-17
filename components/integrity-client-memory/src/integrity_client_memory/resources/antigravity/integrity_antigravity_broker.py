#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Managed Antigravity broker, isolated by conversationId; no ambient subject."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse
import copy
import json
from pathlib import Path
import re
import sys
import antigravity_state as store
import turn_broker_core as core
HERE=Path(__file__).resolve().parent

class ConversationBroker:
    def __init__(self,config,contract,*,root=store.ROOT,factory=None):
        self.root=Path(root);self.config=Path(config);self.contract=contract
        self.control=core.TurnBroker(self.config,'integrity-upstream',contract)
        self.factory=factory or (lambda:core.TurnBroker(self.config,'integrity-upstream',contract))
        self.contexts={};self.pending=[]

    def worker(self,conversation,state):
        if conversation not in self.contexts:
            worker=self.factory();worker.initialize_params=self.control.initialize_params.copy()
            worker.envelopes=store.EnvelopeStore(self.root/'turn-envelopes'/conversation)
            self.contexts[conversation]=worker
        worker=self.contexts[conversation];worker.model_name=state['model_name']
        return worker

    def dispatch(self,message,*,defer_replay_ack_until_public_delivery=False):
        if message.get('method')!='tools/call':
            response=self.control.dispatch(message)
            if message.get('method')=='tools/list' and response and 'result' in response:
                response=copy.deepcopy(response)
                for tool in response['result'].get('tools',[]):
                    tool['inputSchema'].setdefault('properties',{})[store.ROUTE_FIELD]={'type':'string','description':'Reserved local hook route; supplied by PreToolUse, never by the model.'}
            return response
        request=copy.deepcopy(message);params=request.get('params',{});name=params.get('name');arguments=params.get('arguments',{})
        try:
            route=arguments.pop(store.ROUTE_FIELD,None);binding=store.consume_route(self.root,route,name,arguments);conversation=binding['conversation_id']
            with store.locked(self.root,conversation):
                state=store.load(self.root,conversation)
                if not state or state['generation']!=binding['generation'] or state['model_name']!=binding['model_name'] or state.get('stopped'):raise ValueError('hook-route-generation-stale')
                worker=self.worker(conversation,state)
                if name=='integrity_context_admission_current_turn':
                    state['admission_verified']=False
                    store.save(self.root,conversation,state)
                if name=='integrity_context_admission':raise ValueError('free-admission-disabled')
                if name=='integrity_append_event' and (not state.get('admission_verified') or not state.get('registration_id') or state.get('turn_memory_closed') or arguments.get('context_admission_id')!=state.get('admission_id')):raise ValueError('current-admission-and-live-registration-required')
                if name=='integrity_turn_memory_open':raise ValueError('registration-open-is-broker-owned')
                if name in {'integrity_turn_memory_close','integrity_turn_memory_gap'} and arguments.get('registration_id')!=state.get('registration_id'):raise ValueError('foreign-registration-refused')
                response=worker.dispatch(request,defer_replay_ack_until_public_delivery=defer_replay_ack_until_public_delivery)
                if defer_replay_ack_until_public_delivery and worker not in self.pending:self.pending.append(worker)
                if response is None:return None
                result=response.get('result',{})
                if name=='integrity_context_admission_current_turn':
                    state['admission_verified']=False;value=store.unwrap(result);admission=value.get('admission',value)
                    snapshot=admission.get('snapshot');snapshot_id=admission.get('snapshot_id') or (snapshot.get('snapshot_id') if isinstance(snapshot,dict) else None)
                    if not store.DIGEST.fullmatch(str(admission.get('context_admission_id',''))) or not store.DIGEST.fullmatch(str(snapshot_id or '')):raise ValueError('admission-receipt-invalid')
                    state.update(admission_verified=True,admission_id=admission['context_admission_id'],snapshot_id=snapshot_id)
                    opened_args={k:state[k] for k in ('machine_id','turn_id','prompt_sha256')};opened_args['thread_id']=conversation
                    state['registration_open_attempted']=True;store.save(self.root,conversation,state)
                    try:
                        opened=store.unwrap(worker._standalone_turn_memory_call('integrity_turn_memory_open',opened_args));receipt=opened.get('receipt',{})
                        identity={k:opened_args[k] for k in ('machine_id','thread_id','turn_id')}
                        if not store.signed(receipt,'integrity-guardian/turn-memory-registration/v1') or receipt.get('identity')!=identity or receipt.get('prompt_sha256')!=state['prompt_sha256'] or receipt.get('production_authority') is not False or receipt.get('terminal_required') is not True:raise ValueError('registration-receipt-invalid')
                        state['registration_id']=receipt['receipt_id'];state['registration_receipt']=receipt
                        tm_info={'registration_id':receipt['receipt_id'],'receipt':receipt,'close_required':True}
                        if state.get('bus_pointers'):tm_info['llm_bus_pointers']=state['bus_pointers']
                        result.setdefault('content',[]).append({'type':'text','text':json.dumps({'antigravity_turn_memory':tm_info},ensure_ascii=False)})
                    except Exception:
                        state['coverage_status']='registration-unresolved'
                        result.setdefault('content',[]).append({'type':'text','text':'TURN MEMORY registration unavailable; canonical reads remain available; append gated. Do not repeat open on unknown outcome.'})
                elif not result.get('isError'):
                    if name=='integrity_turn_memory_close':
                        receipt=store.unwrap(result).get('receipt',{})
                        if not store.signed(receipt,'integrity-guardian/turn-memory-terminal-receipt/v1') or receipt.get('registration_id')!=state.get('registration_id'):raise ValueError('terminal-receipt-invalid')
                        state.update(turn_memory_closed=True,terminal_receipt_id=receipt['receipt_id'],coverage_status='closed')
                    if state.get('bus_pointers'):
                        result.setdefault('content',[]).append({'type':'text','text':json.dumps({'antigravity_bus_pointers':state['bus_pointers']},ensure_ascii=False)})
                store.save(self.root,conversation,state)
                return response
        except (OSError,ValueError,KeyError,TypeError) as error:
            code=str(error) if isinstance(error,ValueError) and re.fullmatch(r'[a-z0-9-]{3,80}',str(error)) else type(error).__name__
            return {'jsonrpc':'2.0','id':message.get('id'),'result':{'isError':True,'content':[{'type':'text','text':'integrity: broker rejected request: '+code+'. Report this code to the owner; do not debug the broker or hooks yourself.'}]}}

    def confirm_public_response_delivery(self):
        pending,self.pending=self.pending,[]
        for worker in pending:worker.confirm_public_response_delivery()
    def close(self):
        for worker in self.pending:worker.close()
        self.pending=[]
    def shutdown(self):
        self.control.shutdown()
        for worker in self.contexts.values():worker.shutdown()

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--tools-contract',type=Path,required=True);a=p.parse_args()
    return core.serve(ConversationBroker(a.config,core._load_tools_contract(a.tools_contract)))
if __name__ == "__main__":
    _integrity_require_config()

if __name__=='__main__':raise SystemExit(main())
