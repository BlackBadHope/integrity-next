# SPDX-License-Identifier: Apache-2.0
"""Event seam for the existing Linux hook, assembled only from pinned callbacks."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from linux_admission_seam import is_carrier, LinuxAdmissionError

def dispatch(event,payload,baseline,seam,*,schedule_terminal):
    identity=baseline.session_id(payload)
    if event=='SessionStart':
        notice=baseline.degraded_health_notice() if hasattr(baseline,'degraded_health_notice') else None
        baseline.output_context(event,((notice+'\n') if notice else '')+'INTEGRITY client SESSION PENDING INTENT ADMISSION. No Seed snapshot was opened at startup.')
        return 0
    with baseline.session_state_lock(identity):
        state=baseline.load_state(identity)
        child=payload.get('agent_id')
        # Child lifecycle notifications must never retire or replace the
        # parent's admission, whether or not that parent is delegated.
        if event in {'SubagentStart','SubagentStop','Stop'} and child not in (None,'',identity):
            return 0
        if event=='UserPromptSubmit' and is_carrier(payload):
            # Text reception is not proof and must not replace owner intent.
            baseline.output_context(event,'Delegated transport awaits actual Native proof and fresh own admission at PreToolUse.')
            return 0
        if event in {'UserPromptSubmit','SubagentStart'}:
            baseline.handle_prompt(event,payload,identity)
            return 0
        if event=='PreToolUse':
            seam.pretool(payload,identity,state)
        elif event=='PostToolUse':
            baseline.handle_post_tool(event,payload,identity,state)
        elif event in {'Stop','SubagentStop'}:
            try:
                baseline.handle_stop(event,identity,state)
            finally:
                operation=state.get('delegation_operation_id')
                receiving=state.get('delegation_receiving_turn_id')
                if operation and receiving and receiving==state.get('turn_id'):
                    if not callable(schedule_terminal):
                        raise LinuxAdmissionError('linux_terminal_scheduler_required')
                    schedule_terminal(operation_id=operation,thread_id=identity,turn_id=receiving)
        else:
            raise LinuxAdmissionError('linux_hook_event_invalid')
    return 0
