"""Local presentation/ack boundary; never forwards proof tools upstream."""
from __future__ import annotations

import hashlib
import json

ACK = 'integrity_context_delivery_ack'
STATUS = 'integrity_context_delivery_status'
ANNOTATIONS = {'destructiveHint': False, 'idempotentHint': False,
               'openWorldHint': False, 'readOnlyHint': True}
TOOLS = [
    {'name': ACK,
     'description': 'After current-turn admission and own OPEN, answer the one-use model_delivery_challenge from that admission. Proves one canonical event lookup in the current model-owned MCP session, not complete semantic understanding. Never repeat a failed acknowledgement.',
     'inputSchema': {'type': 'object', 'additionalProperties': False,
                     'properties': {'challenge_id': {'type': 'string'},
                                    'nonce': {'type': 'string'},
                                    'event_id': {'type': 'integer', 'minimum': 1}},
                     'required': ['challenge_id', 'nonce', 'event_id']},
     'annotations': ANNOTATIONS},
    {'name': STATUS,
     'description': 'Read the process-local model delivery receipt for this own current turn and immutable snapshot. Ready transport alone remains unverified. A broker restart loses this bounded proof.',
     'inputSchema': {'type': 'object', 'additionalProperties': False,
                     'properties': {}},
     'annotations': {**ANNOTATIONS, 'idempotentHint': True}},
]


def upstream_tools(tools):
    """Keep the negotiated upstream surface exactly unchanged."""
    local = {t['name']: t for t in TOOLS}
    result = []
    for tool in tools:
        if tool.get('name') in local:
            expected = local[tool['name']]
            if any(tool.get(k) != expected[k] for k in ('inputSchema', 'annotations')):
                raise ValueError('local model delivery tool contract changed')
        else:
            result.append(tool)
    return result


def install(namespace, module):
    Broker, envelope = (namespace[k] for k in ('TurnBroker', 'turn_envelope'))
    original = Broker.dispatch

    def current_owner(broker):
        binding = broker._own_turn_binding
        target = broker.upstream
        process = getattr(target, 'process', None)
        if (not broker.bound or not isinstance(binding, dict)
                or binding.get('admitted') is not True
                or getattr(broker, '_context_reattach_read_only', False)
                or process is None or process.poll() is not None):
            raise module.ModelDeliveryError('current live model-owned admission required')
        identity = envelope._resume_identity()
        state = envelope._resume_read_state(identity)
        head = envelope._native_owning_head(identity)
        sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
        expected = {'machine_id': sha(envelope._machine_id()), 'thread_id': sha(identity),
                    'turn_id': sha(str(state.get('turn_id', '')))}
        if (binding.get('hashes') != expected
                or state.get('turn_memory_generation') != binding.get('generation')
                or state.get('turn_memory_intent_id') != binding.get('intent_id')
                or state.get('prompt_sha256') != binding.get('prompt_sha256')
                or envelope._ref_digest(state.get('turn_ref', '')) != binding.get('turn_ref_digest')
                or state.get('model_mcp_admission_status') != 'ready'
                or state.get('model_mcp_context_admission_id') != binding.get('context_admission_id')
                or not broker._own_registration_content(state, binding)
                or state.get('turn_memory_terminal_receipt_id') is not None
                or not isinstance(head, dict) or head.get('id') != state.get('turn_id')
                or head.get('status') != 'inProgress'):
            raise module.ModelDeliveryError('current Native owner proof changed')
        return binding

    def dispatch(broker, message, *args, **kwargs):
        # Preserve the original JSON-RPC validation and notification semantics
        # before any proof can be issued, consumed or reset.
        if (not isinstance(message, dict) or message.get('jsonrpc') != '2.0'
                or 'id' not in message or not isinstance(message.get('method'), str)
                or message['method'].startswith('notifications/')
                or not isinstance(message.get('params', {}), dict)):
            return original(broker, message, *args, **kwargs)
        params = message.get('params', {})
        if (message['method'] == 'tools/call'
                and (not isinstance(params.get('name'), str)
                     or not isinstance(params.get('arguments', {}), dict))):
            return original(broker, message, *args, **kwargs)
        name = params.get('name') if message.get('method') == 'tools/call' else None
        if name in {ACK, STATUS}:
            request_id = message.get('id')
            try:
                if name not in broker.tool_names:
                    raise module.ModelDeliveryError('model delivery tool not enabled')
                arguments = params.get('arguments', {})
                binding = current_owner(broker)
                verifier = getattr(broker, '_model_delivery_verifier', None)
                snapshot = getattr(broker, '_model_delivery_snapshot', None)
                if verifier is None or snapshot is None:
                    raise module.ModelDeliveryError('current model delivery presentation unavailable')
                if name == ACK:
                    receipt = verifier.verify(arguments, binding)
                    value = {'context_delivery': verifier.status(binding, snapshot), 'receipt': receipt}
                else:
                    if arguments != {}:
                        raise module.ModelDeliveryError('model delivery status accepts no arguments')
                    value = {'context_delivery': verifier.status(binding, snapshot)}
                value.update(canonical_writes=0, external_action_authority=False)
                result = {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False)}],
                          'isError': False}
            except (module.ModelDeliveryError, OSError, ValueError, KeyError, TypeError,
                    envelope.TurnEnvelopeError):
                result = {'content': [{'type': 'text', 'text': json.dumps({
                    'protocol': 'integrity-model-delivery-denial/v1',
                    'model_delivery_verified': False, 'reason': 'current model delivery proof unavailable or rejected',
                    'automatic_retry_allowed': False, 'canonical_writes': 0,
                    'external_action_authority': False})}], 'isError': True}
            return {'jsonrpc': '2.0', 'id': request_id, 'result': result}
        admission = name in {'integrity_context_admission', namespace['CURRENT_TURN_CONTEXT_TOOL']}
        if admission:
            broker._model_delivery_verifier = None
            broker._model_delivery_snapshot = None
        response = original(broker, message, *args, **kwargs)
        if admission and name == namespace['CURRENT_TURN_CONTEXT_TOOL'] and ACK in broker.tool_names:
            try:
                result = response['result']
                if result.get('isError') is True or not broker.bound:
                    return response
                public = json.loads(result['content'][0]['text'])
                snapshot = public['admission']['snapshot_id']
                if public['admission']['context_admission_id'] != broker._own_turn_binding['context_admission_id']:
                    raise module.ModelDeliveryError('model delivery presentation join changed')
                verifier = module.ModelDeliveryVerifier()
                public['model_delivery_challenge'] = verifier.issue(broker._own_turn_binding, snapshot, public)
                broker._model_delivery_verifier = verifier
                broker._model_delivery_snapshot = snapshot
                public['context_delivery'] = {**public.get('context_delivery', {}),
                    'model_delivery_verified': False,
                    'model_delivery_verification_status': 'awaiting-current-model-canary',
                    'model_delivery_verification_scope': 'one-canonical-event-lookup'}
                result = {**result, 'content': [{'type': 'text', 'text': json.dumps(public, ensure_ascii=False)}]}
                response = {**response, 'result': result}
            except (module.ModelDeliveryError, ValueError, KeyError, TypeError):
                # Optional proof absence never hides successful canonical reads.
                pass
        return response

    Broker.dispatch = dispatch
