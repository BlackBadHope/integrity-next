# SPDX-License-Identifier: Apache-2.0
"""Request-local, read-only AL admission. No canonical writes or ambient identity.

The admitted local broker is the identity authority within the existing reader
trust boundary. The proof authenticates transport binding, not target authority.
"""
from __future__ import annotations

from integrity_action_log.configuration import value as _integrity_value, require_config as _integrity_require_config

import datetime as dt
import hashlib
import hmac
import json
import re

PROTOCOL = 'integrity-reader-session/v1'
MAX_TTL_SECONDS = 300
HEX = re.compile(r'[a-f0-9]{64}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
KEYS = {'protocol', 'identity_hashes', 'agent_product', 'agent_id', 'session_id',
        'turn_ref_digest', 'prompt_sha256', 'declared_at', 'expires_at',
        'external_action_authority'}


class ReadSessionError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ReadSessionError('reader session timestamp invalid')
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ReadSessionError('reader session timestamp invalid') from None
    if result.tzinfo is None or result.utcoffset() != dt.timedelta(0):
        raise ReadSessionError('reader session requires UTC')
    return result


def validate(value, *, prompt_sha256=None, turn_ref_digest=None, now=None):
    if not isinstance(value, dict):
        raise ReadSessionError('reader session shape invalid')
    extra = {'agent_vendor', 'model_name'} if value.get('agent_product') == 'antigravity' else set()
    if set(value) != KEYS | extra:
        raise ReadSessionError('reader session shape invalid')
    hashes = value.get('identity_hashes')
    if (value.get('protocol') != PROTOCOL or not isinstance(hashes, dict)
            or set(hashes) != {'machine_id', 'thread_id', 'turn_id'}
            or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in hashes.values())
            or value.get('agent_product') not in {'codex', 'claude', 'antigravity'}
            or value.get('external_action_authority') is not False):
        raise ReadSessionError('reader session identity invalid')
    if extra and value.get('agent_vendor') != vendor_for_model(value.get('model_name')):
        raise ReadSessionError('reader session model vendor mismatch')
    expected_session = 'reader:' + value['agent_product'] + ':' + hashes['machine_id'] + ':' + hashes['thread_id']
    expected_agent = value['agent_product'] + ':' + hashes['machine_id']
    if (value.get('session_id') != expected_session or value.get('agent_id') != expected_agent
            or not isinstance(value.get('prompt_sha256'), str)
            or not HEX.fullmatch(value['prompt_sha256'])
            or not isinstance(value.get('turn_ref_digest'), str)
            or not DIGEST.fullmatch(value['turn_ref_digest'])
            or prompt_sha256 is not None and value['prompt_sha256'] != prompt_sha256
            or turn_ref_digest is not None and value['turn_ref_digest'] != turn_ref_digest):
        raise ReadSessionError('reader session binding mismatch')
    start, end = timestamp(value['declared_at']), timestamp(value['expires_at'])
    current = now if now is not None else dt.datetime.now(dt.timezone.utc)
    if not 0 < (end - start).total_seconds() <= MAX_TTL_SECONDS or not start <= current < end:
        raise ReadSessionError('reader session expired or outside its window')
    return json.loads(canonical(value))


def issue(envelope, *, product, model_name=None, now=None):
    """Called only after native claim/owning-head revalidation by the broker."""
    current = now if now is not None else dt.datetime.now(dt.timezone.utc)
    hashes = envelope['native_identity_hashes']
    end = min(timestamp(envelope['expires_utc']), current + dt.timedelta(seconds=MAX_TTL_SECONDS))
    value = {'protocol': PROTOCOL, 'identity_hashes': hashes, 'agent_product': product,
             'agent_id': product + ':' + hashes['machine_id'],
             'session_id': 'reader:' + product + ':' + hashes['machine_id'] + ':' + hashes['thread_id'],
             'turn_ref_digest': envelope['turn_ref_digest'], 'prompt_sha256': envelope['prompt_sha256'],
             'declared_at': current.isoformat().replace('+00:00', 'Z'),
             'expires_at': end.isoformat().replace('+00:00', 'Z'),
             'external_action_authority': False}
    if product == 'antigravity':
        value.update(model_name=model_name, agent_vendor=vendor_for_model(model_name))
    return validate(value, now=current)


def request_proof(declaration, *, snapshot_event_id, token):
    if not isinstance(token, str) or not token:
        raise ReadSessionError('reader session authentication required')
    if isinstance(snapshot_event_id, bool) or not isinstance(snapshot_event_id, int) or snapshot_event_id < 1:
        raise ReadSessionError('reader session snapshot invalid')
    material = {'declaration': declaration, 'snapshot_event_id': snapshot_event_id}
    return hmac.new(token.encode(), PROTOCOL.encode() + b'\0' + canonical(material), hashlib.sha256).hexdigest()


def accept(payload, *, token, now=None):
    """Authenticate before AL projection/recall; proof never leaves this request."""
    if not isinstance(payload, dict) or set(payload) != {'declaration', 'proof', 'snapshot_event_id'}:
        raise ReadSessionError('reader session request invalid')
    declaration = validate(payload['declaration'], now=now)
    proof = payload.get('proof')
    expected = request_proof(declaration, snapshot_event_id=payload['snapshot_event_id'], token=token)
    if not isinstance(proof, str) or not hmac.compare_digest(expected, proof):
        raise ReadSessionError('reader session proof mismatch')
    return declaration


def speaker(declaration):
    return {'agent_id': declaration['agent_id'], 'agent_product': declaration['agent_product'],
            'agent_vendor': declaration['agent_vendor'] if declaration['agent_product'] == 'antigravity' else ('OpenAI' if declaration['agent_product'] == 'codex' else 'Anthropic'),
            'admission_id': 'sha256:' + hashlib.sha256(canonical(declaration)).hexdigest(),
            'admission_declared_at': declaration['declared_at'],
            'admission_expires_at': declaration['expires_at'],
            'capability_class': ['context-read'], 'admitted_agents': []}


def vendor_for_model(model_name):
    """Owner identity contract; never infer a vendor for an unknown model."""
    if isinstance(model_name, str) and 0 < len(model_name) <= 128:
        if model_name.startswith('gemini-'):
            return 'Google'
        if model_name.startswith('claude-'):
            return 'Anthropic'
    raise ReadSessionError('reader session model unsupported')
