# SPDX-License-Identifier: Apache-2.0
"""Private peer read facade candidate. No process, shell, files, claims or grants.

The caller must wire envelope_after_verified_peer ONLY after the existing Node
HMAC gate. Profile and NativeReader are protected server assembly, never RPC args.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from copy import deepcopy
import json
import re
import time
from types import MappingProxyType

PRIVATE_METHOD = '_integrity_delegation_native_page'
PROTOCOL = 'integrity/private-native-evidence-page/v1'
MEDOR = _integrity_value('binding_medor')
IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z')
HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z')
MAX_FRAME = 1024 * 1024
MAX_NATIVE_PAGE_SECONDS = 35

class FacadeError(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise FacadeError(code)

def sender(item):
    if item.get('type') != 'mcpToolCall' or item.get('status') != 'completed':
        return False
    return (item.get('server') == 'codex_app' and item.get('tool') == 'send_message_to_thread'
        or item.get('server') == 'codex_apps' and item.get('tool') in
            {'codex_send_prompt', 'integrity_private_memory_v2.codex_send_prompt'})

def checked_page(page, thread_id, host_id):
    need(isinstance(page, dict) and isinstance(page.get('thread'), dict)
        and page['thread'].get('id') == thread_id and page['thread'].get('hostId') == host_id
        and page['thread'].get('kind') == 'codex', 'native_page_identity_mismatch')
    metadata = page.get('page')
    need(isinstance(metadata, dict) and metadata.get('order') == 'newest_first'
        and type(metadata.get('hasMore')) is bool, 'native_page_incomplete')
    cursor = metadata.get('nextCursor')
    need(metadata['hasMore'] == (cursor is not None)
        and (cursor is None or isinstance(cursor, str) and 0 < len(cursor) <= 20000)
        and not page.get('truncated') and not metadata.get('truncated'), 'native_page_incomplete')
    need(isinstance(page.get('turns'), list) and len(page['turns']) <= 10, 'native_page_incomplete')
    turn_ids = set()
    for turn in page['turns']:
        need(isinstance(turn, dict) and isinstance(turn.get('id'), str)
            and IDENTITY.fullmatch(turn['id']) and turn['id'] not in turn_ids
            and isinstance(turn.get('items'), list) and not turn.get('truncated')
            and not turn.get('itemsTruncated'), 'native_page_incomplete')
        turn_ids.add(turn['id'])
        item_ids = set()
        for item in turn['items']:
            need(isinstance(item, dict) and isinstance(item.get('id'), str)
                and IDENTITY.fullmatch(item['id']) and item['id'] not in item_ids
                and isinstance(item.get('type'), str), 'native_page_incomplete')
            item_ids.add(item['id'])
            if item['type'] == 'userMessage' or sender(item):
                need(not item.get('truncated'), 'native_page_incomplete')
                if item['type'] == 'userMessage':
                    need(isinstance(item.get('content'), list)
                        and all(isinstance(block, dict) and not block.get('truncated')
                            for block in item['content']), 'native_page_incomplete')
    return page

def provenance_projection(page):
    """Preserve owner/control text and sender args; suppress unrelated tool refs."""
    result = deepcopy(page)
    for turn in result['turns']:
        for index, item in enumerate(turn['items']):
            if item['type'] == 'userMessage':
                continue
            allowed = {'id', 'type', 'status', 'server', 'tool', 'namespace', 'name', 'truncated'}
            if sender(item):
                allowed.add('arguments')
            turn['items'][index] = {key:value for key,value in item.items() if key in allowed}
    return result

class NativeEvidenceFacade:
    def __init__(self, native_reader_factory, *, native_context_thread_id, owner_contexts,
                 execution_hosts=('node-linux',)):
        need(isinstance(native_context_thread_id, str) and IDENTITY.fullmatch(native_context_thread_id),
            'protected_native_context_invalid')
        need(callable(native_reader_factory), 'protected_native_factory_invalid')
        need(isinstance(owner_contexts, dict) and owner_contexts.get(MEDOR) ==
            {'host_id':'durable', 'room_id':_integrity_value('binding_93cc9ba645aa')}, 'protected_source_profile_invalid')
        contexts = {}
        for thread, context in owner_contexts.items():
            need(isinstance(thread, str) and IDENTITY.fullmatch(thread)
                and isinstance(context, dict) and set(context) == {'host_id','room_id'}
                and isinstance(context['host_id'], str) and HOST.fullmatch(context['host_id'])
                and (context['room_id'] is None or isinstance(context['room_id'], str)
                    and HOST.fullmatch(context['room_id'])),
                'protected_owner_profile_invalid')
            contexts[thread] = MappingProxyType(dict(context))
        need(isinstance(execution_hosts, tuple) and execution_hosts
            and all(isinstance(host, str) and HOST.fullmatch(host) for host in execution_hosts),
            'protected_execution_profile_invalid')
        self.reader_factory = native_reader_factory
        self.native_context_thread_id = native_context_thread_id
        self.contexts = MappingProxyType(contexts)
        self.execution_hosts = frozenset(execution_hosts)

    def read(self, arguments):
        required = {'purpose','execution_host','thread_id','host_id'}
        need(isinstance(arguments, dict) and required <= set(arguments)
            and set(arguments) <= required | {'cursor','limit'}, 'private_evidence_arguments_invalid')
        purpose = arguments['purpose']
        need(purpose in {'source','owner','controls'}, 'private_evidence_purpose_invalid')
        need(arguments['execution_host'] in self.execution_hosts, 'private_evidence_execution_host_invalid')
        thread, host = arguments['thread_id'], arguments['host_id']
        context = self.contexts.get(thread) if isinstance(thread, str) else None
        need(context is not None and host == context['host_id']
            and (purpose != 'source' or thread == MEDOR), 'private_evidence_thread_not_allowed')
        cursor, limit = arguments.get('cursor'), arguments.get('limit', 10)
        need(cursor is None or isinstance(cursor, str) and 0 < len(cursor) <= 20000,
            'private_evidence_cursor_invalid')
        need(type(limit) is int and 1 <= limit <= 10, 'private_evidence_limit_invalid')
        started = time.monotonic()
        try:
            # A long-lived peer service must never retain an already spent
            # NativeReader deadline. The protected factory creates one per page;
            # the Linux receiving reader separately owns its whole proof budget.
            reader = self.reader_factory()
            need(getattr(reader, 'context_thread_id', None) == self.native_context_thread_id,
                'protected_native_context_mismatch')
            deadline = getattr(reader, 'deadline', None)
            need(type(deadline) in (int, float) and started < deadline <= started + MAX_NATIVE_PAGE_SECONDS,
                'protected_native_deadline_invalid')
            page = reader.read(thread, host, cursor=cursor, limit=limit, outputs=True)
        except FacadeError:
            raise
        except Exception:
            raise FacadeError('native_evidence_read_unavailable') from None
        need(time.monotonic() < deadline, 'native_evidence_read_deadline')
        checked_page(page, thread, host)
        result = {'protocol':PROTOCOL, 'provider_host':'owner-host', 'purpose':purpose,
            'execution_host':arguments['execution_host'], 'thread_id':thread, 'native_host_id':host,
            'native_page':provenance_projection(page), 'execute':False, 'sent':False,
            'action_authority':'not-evaluated', 'unrelated_tool_arguments_removed':True}
        need(len(json.dumps(result, ensure_ascii=False).encode('utf-8')) < MAX_FRAME - 256,
            'native_evidence_page_oversized')
        return result

    def envelope_after_verified_peer(self, request, physical_host):
        """Must be invoked after actual existing peer authentication, not Node.call."""
        need(physical_host == 'owner-host' and isinstance(request, dict)
            and set(request) == {'host_id','name','arguments','request_id'}
            and request['host_id'] == physical_host and request['name'] == PRIVATE_METHOD
            and request['request_id'] is None, 'private_evidence_envelope_invalid')
        try:
            result = self.read(request['arguments'])
            return {'host_id':physical_host, 'result':result}
        except FacadeError as error:
            return {'host_id':physical_host, 'error':str(error)}

def checked_linux_current_head(metadata, turns, *, actual_host, expected_host,
                               expected_thread, expected_turn):
    """Own SDK read result, not source facade DATA or a model-supplied receipt."""
    need(actual_host == expected_host == 'node-linux', 'linux_receiving_host_mismatch')
    need(isinstance(expected_thread, str) and IDENTITY.fullmatch(expected_thread)
        and isinstance(expected_turn, str) and IDENTITY.fullmatch(expected_turn), 'linux_receiving_identity_invalid')
    need(isinstance(metadata, dict) and isinstance(metadata.get('thread'), dict)
        and metadata['thread'].get('id') == expected_thread, 'linux_receiving_thread_mismatch')
    need(not metadata.get('truncated') and not metadata['thread'].get('truncated')
        and not metadata['thread'].get('itemsTruncated'), 'linux_receiving_incomplete')
    need(isinstance(turns, dict) and isinstance(turns.get('data'), list) and turns['data']
        and isinstance(turns['data'][0], dict) and turns['data'][0].get('id') == expected_turn
        and turns['data'][0].get('status') == 'inProgress', 'linux_receiving_turn_not_current')
    current = turns['data'][0]
    need(not turns.get('truncated') and not turns.get('itemsTruncated')
        and current.get('itemsView') == 'full' and isinstance(current.get('items'), list)
        and not current.get('truncated') and not current.get('itemsTruncated'), 'linux_receiving_incomplete')
    for item in current['items']:
        need(isinstance(item, dict) and isinstance(item.get('type'), str), 'linux_receiving_incomplete')
        if item['type'] == 'userMessage':
            need(not item.get('truncated') and not item.get('contentTruncated')
                and isinstance(item.get('content'), list)
                and all(isinstance(block, dict) and not block.get('truncated')
                    and (block.get('type') != 'text' or isinstance(block.get('text'), str))
                    for block in item['content']), 'linux_receiving_incomplete')
        elif item['type'] == 'functionCallOutput' and item.get('namespace') == 'codex_app' and item.get('name') == 'send_message_to_thread':
            need(not item.get('truncated') and not item.get('inputTruncated')
                and isinstance(item.get('output'), dict) and not item['output'].get('truncated')
                and isinstance(item['output'].get('text'), str), 'linux_receiving_incomplete')
    return deepcopy(current)
