# SPDX-License-Identifier: Apache-2.0
"""Claim-bound full-task capture through a pinned actual Linux Scope baseline.

The pending fence is written before task capture. No epoch/lease/barrier reset,
owner event fabrication, Native call or model-supplied receipt grants occur here.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib
from pathlib import Path
from linux_admission_seam import validate_owned_result, LinuxAdmissionError

class LinuxScopeCapture:
    def __init__(self, engine, core, config, store):
        expected=config.get('scope_module_sha256')
        if not isinstance(expected,str) or hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest()!=expected:
            raise LinuxAdmissionError('linux_scope_module_pin_invalid')
        self.engine,self.core,self.config,self.store=engine,core,config,store

    def __call__(self, delegation, payload):
        validate_owned_result(delegation,payload,self.config,self.core)
        session=payload.get('session_id') or payload.get('thread_id')
        turn=payload.get('turn_id') or payload.get('turnId')
        binding={'operation_id':delegation['operation_id'],'request_digest':delegation['request_digest'],
            'actual_turn_id':turn,'scope_receipt_digest':self.core.digest(delegation['scope_receipt']),
            'task_digest':self.core.text_digest(delegation['request']['task'])}
        with self.store.locked(session):
            state=self.store.load(session) or self.engine.new_state(session)
            existing=state.get('delegation_capture')
            if existing is not None and all(existing.get(k)==v for k,v in binding.items()):
                if (state.get('delegation_capture_pending') or state.get('delegation_capture_fault')
                    or state.get('anchor_digest')!=self.engine.anchor_digest(state)):
                    raise LinuxAdmissionError('linux_scope_capture_incomplete')
                return {**binding,'status':'current','anchor_digest':state['anchor_digest'],
                    'action_authority':'not-evaluated'}
            pending=state.get('delegation_capture_pending')
            if pending is not None and pending!=binding:
                raise LinuxAdmissionError('linux_scope_capture_pending_conflict')
            state['delegation_capture_pending']=binding
            self.store.save(session,state)
            try:
                task=delegation['request']['task']
                self.engine.record_prompt(state,task,turn,force_task=True)
                # Exact full bytes are retained even when the legacy normal
                # owner path strips input or truncates long instructions.
                state['instructions'][0]['text']=task
                state['instructions'][0]['truncated']=False
                state['anchor_digest']=self.engine.anchor_digest(state)
                state['delegation_capture']=binding
                self.store.save(session,state)
                actual=self.store.load(session)
                if (actual is None or actual.get('delegation_capture')!=binding
                    or actual.get('delegation_capture_pending')!=binding
                    or actual.get('anchor_digest')!=self.engine.anchor_digest(actual)
                    or len(actual['instructions'])!=1 or actual['instructions'][0]['text']!=task
                    or actual['instructions'][0]['truncated'] is not False):
                    raise LinuxAdmissionError('linux_scope_capture_readback_invalid')
                actual.pop('delegation_capture_pending',None)
                actual.pop('delegation_capture_fault',None)
                self.store.save(session,actual)
                verified=self.store.load(session)
                if (verified is None or verified.get('delegation_capture')!=binding
                    or verified.get('delegation_capture_pending') or verified.get('delegation_capture_fault')
                    or verified.get('anchor_digest')!=self.engine.anchor_digest(verified)):
                    raise LinuxAdmissionError('linux_scope_capture_readback_invalid')
                return {**binding,'status':'captured','anchor_digest':verified['anchor_digest'],
                    'action_authority':'not-evaluated'}
            except Exception:
                # A failed write is never converted into a successful capture.
                # The already persisted pending fence remains authoritative.
                raise LinuxAdmissionError('linux_scope_capture_incomplete') from None
