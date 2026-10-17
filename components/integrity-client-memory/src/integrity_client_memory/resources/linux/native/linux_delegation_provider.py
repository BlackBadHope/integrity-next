# SPDX-License-Identifier: Apache-2.0
"""Linux provider candidate: own SDK reads plus existing authenticated peer data.

Runtime assembly supplies protected RPC clients/config and pinned common modules.
There is deliberately no shell, process launcher, model proof import or fallback.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from copy import deepcopy
import time
from native_evidence_facade import PRIVATE_METHOD, PROTOCOL, checked_page, checked_linux_current_head
from native_evidence_peer_auth import REQUEST as PRIVATE_AUTH_PROTOCOL

class LinuxProviderError(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise LinuxProviderError(code)

class LinuxReceivingReader:
    def __init__(self, sdk_rpc, source_peer, adapter, config, *, thread_id, turn_id, deadline, terminal=False):
        adapter.validate_config(config)
        need(config['target_machine_id'] == 'node-linux'
            and adapter.target_native_host_id(config) == 'local', 'linux_protected_host_profile_invalid')
        adapter.identity(thread_id, 'linux_hook_thread_missing')
        adapter.identity(turn_id, 'linux_hook_turn_missing')
        need(thread_id not in config['allowed_owner_threads'], 'linux_owner_receiving_route_ambiguous')
        need(getattr(source_peer, 'host_id', None) == 'owner-host', 'linux_source_peer_host_invalid')
        need(getattr(source_peer, 'authentication_protocol', None) == PRIVATE_AUTH_PROTOCOL,
            'linux_mutual_private_peer_required')
        need(type(terminal) is bool, 'linux_terminal_mode_invalid')
        self.sdk, self.peer, self.adapter = sdk_rpc, source_peer, adapter
        self.config = deepcopy(config)
        self.thread_id, self.turn_id, self.deadline = thread_id, turn_id, deadline
        self.context_thread_id = thread_id
        self.read_phase = 'read-current'
        self.last_read = None
        self.sequence = 0
        self.terminal = terminal

    def remaining(self):
        value = self.deadline - time.monotonic()
        need(value > 0, 'native_evidence_deadline')
        return value

    def read(self, thread_id, host_id, *, cursor=None, limit=10, outputs=False):
        need(type(limit) is int and 1 <= limit <= 10, 'linux_native_limit_invalid')
        need(cursor is None or isinstance(cursor, str) and bool(cursor), 'linux_native_cursor_invalid')
        self.remaining()
        self.sequence += 1
        started = time.monotonic()
        self.last_read = {'phase':self.read_phase, 'status':'started', 'sequence':self.sequence, 'attempt':1}
        try:
            if thread_id == self.thread_id:
                need(host_id == 'local', 'linux_receiving_host_mismatch')
                metadata = self.sdk.request('thread/read', {'threadId':thread_id, 'includeTurns':False},
                    min(20, self.remaining()))
                # The exact receiving head is sufficient. Three full turns
                # exceeded the pinned owner's 2 MiB response frame in the audit
                # repair diagnostic; never widen that safety bound.
                params = {'threadId':thread_id,'limit':1,'sortDirection':'desc','itemsView':'full'}
                if cursor is not None:
                    params['cursor'] = cursor
                turns = self.sdk.request('thread/turns/list', params, min(30, self.remaining()))
                # Admission reads require actual head. No historical turn fallback.
                need(cursor is None, 'linux_receiving_history_not_current')
                if self.terminal:
                    self.check_terminal_page(metadata, turns)
                else:
                    checked_linux_current_head(metadata, turns, actual_host=self.config['target_machine_id'],
                        expected_host='node-linux', expected_thread=self.thread_id, expected_turn=self.turn_id)
                next_cursor = turns.get('nextCursor')
                need(next_cursor is None or isinstance(next_cursor, str) and bool(next_cursor),
                    'linux_receiving_cursor_invalid')
                # Native SDK pagination is converted only from the actual returned
                # nextCursor. Raw clipping was checked before constructing this page.
                page = {'thread':{'id':metadata['thread']['id'],'hostId':'local','kind':'codex'},
                    'page':{'order':'newest_first','hasMore':next_cursor is not None,'nextCursor':next_cursor},
                    'turns':deepcopy(turns['data'])}
            else:
                context = self.config['allowed_owner_threads'].get(thread_id)
                need(context is not None and context['host_id'] == host_id, 'linux_source_thread_not_allowed')
                arguments = {'purpose':'source' if thread_id == self.config['source_thread_id'] else 'owner',
                    'execution_host':'node-linux','thread_id':thread_id,'host_id':host_id,'limit':limit}
                if cursor is not None:
                    arguments['cursor'] = cursor
                result = self.peer.call(PRIVATE_METHOD, arguments, timeout=min(35, self.remaining()))
                need(isinstance(result, dict) and result.get('protocol') == PROTOCOL
                    and result.get('provider_host') == 'owner-host' and result.get('execution_host') == 'node-linux'
                    and result.get('thread_id') == thread_id and result.get('native_host_id') == host_id
                    and result.get('purpose') == arguments['purpose'] and result.get('execute') is False
                    and result.get('sent') is False and result.get('action_authority') == 'not-evaluated',
                    'linux_source_peer_result_invalid')
                page = checked_page(result.get('native_page'), thread_id, host_id)
            self.remaining()
            self.adapter.check_page(page, thread_id, host_id)
            self.last_read.update(status='completed',elapsed_ms=int((time.monotonic()-started)*1000))
            return page
        except Exception as error:
            self.last_read.update(status='failed',elapsed_ms=int((time.monotonic()-started)*1000),
                fault_kind='rpc-result-invalid',fault_class='ValueError')
            if isinstance(error, (LinuxProviderError, self.adapter.AdapterError)):
                raise
            # This candidate does not infer tool-failed from a generic peer error,
            # and never retries a source failure through another host/provider.
            failure=self.adapter.AdapterError('native_read_unavailable')
            trace=getattr(error,'safe_trace',None)
            if isinstance(trace,dict):
                allowed={'native_response_frame_exceeds_limit','native_owner_connection_closed_without_close_frame','native_evidence_deadline'}
                code=trace.get('code')
                failure.safe_trace={'code':code if isinstance(code,str) and code in allowed else 'native_read_unavailable',
                    'exception_class':trace.get('exception_class') if isinstance(trace.get('exception_class'),str) and trace['exception_class'] in {'ConnectionClosedError','TimeoutError','OSError'} else 'ProviderError'}
            raise failure from None

    def check_terminal_page(self, metadata, turns):
        need(isinstance(metadata, dict) and isinstance(metadata.get('thread'), dict)
            and metadata['thread'].get('id') == self.thread_id
            and not metadata.get('truncated') and not metadata['thread'].get('truncated')
            and not metadata['thread'].get('itemsTruncated'), 'linux_terminal_thread_incomplete')
        need(isinstance(turns, dict) and isinstance(turns.get('data'), list) and bool(turns['data'])
            and not turns.get('truncated') and not turns.get('itemsTruncated'), 'linux_terminal_page_incomplete')
        ids=set()
        matched=False
        for turn in turns['data'][:3]:
            need(isinstance(turn, dict) and isinstance(turn.get('id'),str) and turn['id'] not in ids,
                'linux_terminal_page_incomplete')
            ids.add(turn['id'])
            need(turn.get('itemsView')=='full' and isinstance(turn.get('items'),list)
                and not turn.get('truncated') and not turn.get('itemsTruncated'), 'linux_terminal_page_incomplete')
            if turn['id']==self.turn_id:
                need(turn.get('status') in {'inProgress','completed','failed','interrupted'}, 'linux_terminal_turn_status_invalid')
                for item in turn['items']:
                    need(isinstance(item,dict) and isinstance(item.get('type'),str),'linux_terminal_input_incomplete')
                    if item['type']=='userMessage':
                        need(not item.get('truncated') and not item.get('contentTruncated')
                            and isinstance(item.get('content'),list)
                            and all(isinstance(block,dict) and not block.get('truncated')
                                and (block.get('type')!='text' or isinstance(block.get('text'),str))
                                for block in item['content']), 'linux_terminal_input_incomplete')
                    elif item['type']=='functionCallOutput' and item.get('namespace')=='codex_app' and item.get('name')=='send_message_to_thread':
                        need(not item.get('truncated') and not item.get('inputTruncated')
                            and isinstance(item.get('output'),dict) and not item['output'].get('truncated')
                            and isinstance(item['output'].get('text'),str),'linux_terminal_input_incomplete')
                matched=True
        need(matched, 'linux_terminal_receiving_turn_not_observed')

def receive_pretool(payload, config, core, adapter, reader, *, operation_id=None):
    need(isinstance(payload, dict), 'linux_hook_payload_invalid')
    thread = payload.get('session_id') or payload.get('thread_id')
    turn = payload.get('turn_id') or payload.get('turnId')
    need(thread == reader.thread_id and turn == reader.turn_id, 'linux_hook_receiving_identity_mismatch')
    need(payload.get('agent_id') in (None, '', thread), 'linux_child_binding_unsupported')
    return adapter.handle('PreToolUse', payload, config, core, reader, operation_id=operation_id)
