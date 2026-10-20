# SPDX-License-Identifier: Apache-2.0
"""Verify and retain an own signed close before a Claude return is queued."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import base64, hashlib, json, os, re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
SESSION = _integrity_value('claude_session_id')
NAMESPACE = _integrity_value('pin_dd9fa64be3f2')
KEY_ID = 'key:database:51513dbba953ee4f50a54bcac3db9375543aeb9628a47e5466325b00688827ce:checkpoint'
PUBLIC_KEY = 'VXOU3YRkPf9l4sRm1QbUT0TN_b4DyXaQSZfdxYj1zWg'
UUID = re.compile('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\\Z')
ROOT = Path(_integrity_value('path_5337709e82f6'))

class TerminalMemoryError(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise TerminalMemoryError(code)

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def un64(text):
    need(isinstance(text, str) and text and ('=' not in text), 'terminal_base64_invalid')
    raw = base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)
    need(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == text, 'terminal_base64_invalid')
    return raw

def verify(receipt, *, machine_id, thread_id, native_turn_id, registration_id=None):
    need(isinstance(receipt, dict) and receipt.get('protocol') == 'integrity-guardian/turn-memory-terminal-receipt/v1' and (receipt.get('namespace_fingerprint') == NAMESPACE) and (receipt.get('production_authority') is False), 'terminal_scope_invalid')
    identity = receipt.get('identity')
    need(isinstance(identity, dict) and identity.get('machine_id') == machine_id and (identity.get('thread_id') == thread_id) and (identity.get('turn_id') == native_turn_id) and UUID.fullmatch(native_turn_id or ''), 'terminal_native_subject_mismatch')
    need(registration_id is None or receipt.get('registration_id') == registration_id, 'terminal_registration_mismatch')
    signature = receipt.get('signature')
    need(isinstance(signature, dict) and signature.get('algorithm') == 'ed25519' and (signature.get('key_id') == KEY_ID), 'terminal_signer_mismatch')
    unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
    try:
        Ed25519PublicKey.from_public_bytes(un64(PUBLIC_KEY)).verify(un64(signature['value']), b'integrity-guardian\x00signed-object-v1\x00' + canonical(unsigned))
    except Exception:
        raise TerminalMemoryError('terminal_signature_invalid') from None
    need(receipt.get('outcome') in {'events', 'no-event'}, 'terminal_outcome_invalid')
    if receipt['outcome'] == 'events':
        need(isinstance(receipt.get('events'), list) and bool(receipt['events']), 'terminal_events_missing')
    else:
        need(isinstance(receipt.get('no_event_reason'), str) and (not receipt.get('events')), 'terminal_no_event_reason_missing')
    need(re.fullmatch('sha256:[a-f0-9]{64}', str(receipt.get('receipt_id'))), 'terminal_receipt_id_invalid')
    return receipt

def safe_directory(path, *, create=False):
    for member in (path, *path.parents):
        if member.exists():
            need(not member.is_symlink() and (not getattr(member.stat(), 'st_file_attributes', 0) & 1024), 'terminal_archive_reparse')
    if create:
        path.mkdir(parents=True, exist_ok=True)
    need(path.is_dir(), 'terminal_archive_missing')

def archive(receipt, state, *, root=ROOT):
    native = state.get('turn_id')
    registration = state.get('turn_memory_registration_id')
    verify(receipt, machine_id='machine:owner-host', thread_id=SESSION, native_turn_id=native, registration_id=registration)
    need(receipt['identity'].get('intent_id') == state.get('turn_memory_intent_id') and receipt.get('prompt_sha256') == state.get('prompt_sha256'), 'terminal_current_intent_mismatch')
    operation = state.get('delegation_operation_id')
    need(isinstance(operation, str) and state.get('delegation_receiving_turn_id') == native, 'terminal_operation_binding_missing')
    target = root / native
    safe_directory(target, create=True)
    need(len(list(target.glob('*.json'))) < 64, 'terminal_archive_bound')
    path = target / (receipt['receipt_id'][7:] + '.json')
    raw = canonical({'protocol': 'integrity/claude-own-terminal-archive/v1', 'operation_id': operation, 'native_turn_id': native, 'registration_id': registration, 'receipt': receipt}) + b'\n'
    if path.exists():
        need(path.is_file() and (not path.is_symlink()) and (path.read_bytes() == raw), 'terminal_archive_conflict')
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise TerminalMemoryError('terminal_archive_write_uncertain') from None

def read_own_closed(*, operation_id, native_turn_id, root=ROOT):
    need(UUID.fullmatch(native_turn_id or ''), 'terminal_native_invalid')
    folder = root / native_turn_id
    safe_directory(folder)
    files = list(folder.glob('*.json'))
    need(0 < len(files) <= 64, 'terminal_archive_missing_or_bound')
    matches = []
    for path in files:
        need(path.is_file() and (not path.is_symlink()) and (not getattr(path.stat(), 'st_file_attributes', 0) & 1024) and (path.stat().st_size <= 65536), 'terminal_archive_file_invalid')
        value = json.loads(path.read_bytes())
        if value.get('operation_id') != operation_id:
            continue
        need(value.get('protocol') == 'integrity/claude-own-terminal-archive/v1' and value.get('native_turn_id') == native_turn_id, 'terminal_archive_subject_mismatch')
        receipt = verify(value.get('receipt'), machine_id='machine:owner-host', thread_id=SESSION, native_turn_id=native_turn_id, registration_id=value.get('registration_id'))
        matches.append(receipt)
    need(bool(matches), 'own_canonical_terminal_missing')
    return matches
