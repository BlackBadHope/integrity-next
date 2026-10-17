# SPDX-License-Identifier: Apache-2.0
"""Source-only seam for actual Linux admission2392. Runtime factory is mandatory.

Receiver and Scope sync are pinned assembly callbacks, not JSON input/proof. No
owner event is fabricated; accepted work is staged during its real PreToolUse.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import json

class LinuxAdmissionError(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise LinuxAdmissionError(code)

def is_carrier(payload):
    prompt = payload.get('prompt') or payload.get('user_prompt')
    return isinstance(prompt, str) and prompt.lstrip().startswith(('BEGIN_INTEGRITY_DELEGATED_TASK','<codex_delegation'))

def defer_context(event, context):
    need(event == 'PreToolUse', 'linux_delegation_event_invalid')
    print(json.dumps({'hookSpecificOutput':{'hookEventName':event,
        'permissionDecision':'deny','permissionDecisionReason':'Fresh own delegated admission is required before this tool.',
        'additionalContext':context}}, ensure_ascii=False))

def validate_owned_result(delegation, payload, config, core):
    need(isinstance(delegation, dict) and delegation.get('status') == 'accepted'
        and delegation.get('protocol') == 'integrity/delegation-codex-receiving/v1', 'linux_verified_delegation_required')
    thread = payload.get('session_id') or payload.get('thread_id')
    turn = payload.get('turn_id') or payload.get('turnId')
    request = delegation.get('request')
    core.parse_request(request, source_thread_id=config['source_thread_id'],
        receiving_host_id='node-linux', receiving_thread_id=thread,
        allowed_owner_threads=set(config['allowed_owner_threads']))
    need(isinstance(turn, str) and bool(turn) and request['target']['host_id'] == config['target_machine_id'],
        'linux_own_binding_identity_mismatch')
    state = core.Ledger(config['ledger_path']).status(request['operation_id'])
    delivery = state.get('delivery') or {}
    need(state.get('found') and state.get('state') == 'executing' and not state.get('revoked')
        and state.get('request_digest') == core.digest(request)
        and delegation.get('request_digest') == core.digest(request)
        and delegation.get('scope_receipt') == state.get('binding')
        and delivery.get('target_thread_id') == thread and delivery.get('receiving_turn_id') == turn,
        'linux_own_claim_binding_invalid')
    need(isinstance(delegation.get('admission_prompt'), str) and bool(delegation['admission_prompt']),
        'linux_own_admission_prompt_missing')
    return delegation

def synchronize_scope(delegation, payload, *, scope_sync):
    # Linux legacy fede40 has no force_task/pending-capture contract. Refuse an
    # unconfigured Scope adapter rather than silently considering it compatible.
    need(callable(scope_sync), 'linux_verified_scope_adapter_required')
    receipt = scope_sync(delegation, payload)
    need(isinstance(receipt, dict) and receipt.get('operation_id') == delegation['operation_id']
        and receipt.get('actual_turn_id') == (payload.get('turn_id') or payload.get('turnId'))
        and receipt.get('status') in {'captured','current'} and receipt.get('action_authority') == 'not-evaluated',
        'linux_verified_scope_receipt_invalid')
    return receipt

class LinuxAdmissionSeam:
    def __init__(self, baseline, receiver, config, core, *, scope_sync):
        need(callable(receiver) and callable(scope_sync), 'linux_pinned_receiver_scope_required')
        self.baseline, self.receiver, self.config, self.core = baseline, receiver, config, core
        self.scope_sync = scope_sync

    def pretool(self, payload, identity, state):
        turn = self.baseline.turn_id(payload)
        need(identity == self.baseline.session_id(payload) and isinstance(turn, str) and bool(turn),
            'linux_hook_identity_missing')
        child = payload.get('agent_id')
        if child not in (None, '', identity):
            # Never operate on a delegated parent's admission file from a child.
            if state.get('delegation_operation_id'):
                self.baseline.deny('child cannot borrow a delegated parent binding')
            raise LinuxAdmissionError('linux_child_binding_unsupported')
        operation = state.get('delegation_operation_id') if state.get('turn_id') == turn else None
        result = self.receiver(payload, operation_id=operation)
        status = result.get('status')
        if status in {'denied','duplicate'}:
            self.baseline.deny('delegation rejected: '+str(result.get('code',status)))
        if status == 'accepted':
            validate_owned_result(result, payload, self.config, self.core)
            self.baseline.handle_prompt('PreToolUse', payload, identity, result,
                scope_sync=self.scope_sync, delegation_config=self.config, delegation_core=self.core)
            return 'staged-first-tool-cancelled'
        if status == 'current':
            need(operation == result.get('operation_id') and state.get('delegation_receiving_turn_id') == turn
                and isinstance(state.get('turn_ref'), str) and bool(state['turn_ref']), 'linux_own_binding_missing')
            if state.get('model_mcp_admission_status') != 'ready' and not self.baseline.CURRENT_CONTEXT_TOOL_RE.search(self.baseline.tool_name(payload)):
                self.baseline.deny('fresh own current-turn admission required')
        elif status != 'absent':
            raise LinuxAdmissionError('linux_receiver_status_invalid')
        self.baseline.handle_pre_tool(payload, identity, state)
        return 'baseline'
