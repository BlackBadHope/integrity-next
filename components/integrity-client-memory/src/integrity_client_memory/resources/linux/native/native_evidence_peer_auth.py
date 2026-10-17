# SPDX-License-Identifier: Apache-2.0
"""Mutual private read authentication with the existing peer key, never a bearer.

Transport nonce is unrelated to delegation operation/frame identity. No Native
calls, files, listeners, logs, secret reprs or action grants live in this module.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

METHOD = '_integrity_delegation_native_page'
REQUEST = 'integrity/native-evidence-peer-request/v1'
RESPONSE = 'integrity/native-evidence-peer-response/v1'
REQ_DOMAIN = b'integrity/native-evidence-peer/v1/request\0'
RESP_DOMAIN = b'integrity/native-evidence-peer/v1/response\0'
MAX_WIRE = 1024 * 1024
MAX_TTL = 45
MAX_FUTURE_SKEW = 5
HEX = re.compile(r'[a-f0-9]{64}\Z')

class PeerAuthError(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise PeerAuthError(code)

def key_bytes(secret):
    try:
        value = secret.encode('ascii') if isinstance(secret, str) else secret
    except UnicodeError:
        raise PeerAuthError('private_auth_key_invalid') from None
    need(isinstance(value, bytes) and 32 <= len(value) <= 4096, 'private_auth_key_invalid')
    return value

def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
            separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise PeerAuthError('private_auth_json_invalid') from None

def _unique(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, 'private_auth_duplicate_json')
        result[name] = value
    return result

def decode(raw):
    need(isinstance(raw, (bytes, str)), 'private_auth_raw_json_required')
    try:
        encoded = raw.encode('utf-8') if isinstance(raw, str) else raw
        need(0 < len(encoded) <= MAX_WIRE, 'private_auth_frame_invalid')
        value = json.loads(encoded.decode('utf-8'), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(PeerAuthError('private_auth_json_invalid')))
    except PeerAuthError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise PeerAuthError('private_auth_json_invalid') from None
    need(isinstance(value, dict), 'private_auth_object_required')
    return value

def _now(value):
    value = int(time.time()) if value is None else value
    need(type(value) is int and value >= 0, 'private_auth_clock_invalid')
    return value

def _mac(secret, domain, value):
    return hmac.new(key_bytes(secret), domain + canonical(value), hashlib.sha256).hexdigest()

def _unsigned_request(value, expected_host, now):
    need(set(value) == {'protocol','host_id','name','arguments','request_id','auth'}
        and value['protocol'] == REQUEST and value['host_id'] == expected_host
        and value['name'] == METHOD and value['request_id'] is None
        and isinstance(value['arguments'], dict), 'private_auth_request_invalid')
    auth = value['auth']
    need(isinstance(auth, dict) and set(auth) == {'nonce','created','expires','mac'}
        and isinstance(auth['nonce'], str) and HEX.fullmatch(auth['nonce'])
        and isinstance(auth['mac'], str) and HEX.fullmatch(auth['mac']), 'private_auth_request_invalid')
    created, expires = auth['created'], auth['expires']
    need(type(created) is int and type(expires) is int and 0 <= created < expires
        and expires - created <= MAX_TTL and created <= now + MAX_FUTURE_SKEW
        and now < expires, 'private_auth_request_expired')
    unsigned = dict(value)
    unsigned['auth'] = {key:auth[key] for key in ('nonce','created','expires')}
    return unsigned

class ReplayGuard:
    """Per-service private READ nonce fence; never an operation/action ledger."""
    def __init__(self, maximum=512):
        need(type(maximum) is int and 1 <= maximum <= 4096, 'private_auth_replay_limit_invalid')
        self.maximum, self.entries, self.lock = maximum, {}, threading.Lock()

    def record(self, nonce, expires, now):
        with self.lock:
            self.entries = {key:expiry for key,expiry in self.entries.items() if expiry > now}
            need(nonce not in self.entries, 'private_auth_request_replayed')
            need(len(self.entries) < self.maximum, 'private_auth_replay_fence_full')
            self.entries[nonce] = expires

def make_request(arguments, secret, *, host_id='owner-host', nonce=None, now=None, lifetime=MAX_TTL):
    now = _now(now)
    need(host_id == 'owner-host' and isinstance(arguments, dict)
        and type(lifetime) is int and 1 <= lifetime <= MAX_TTL, 'private_auth_request_invalid')
    nonce = secrets.token_hex(32) if nonce is None else nonce
    need(isinstance(nonce, str) and HEX.fullmatch(nonce), 'private_auth_nonce_invalid')
    unsigned = {'protocol':REQUEST,'host_id':host_id,'name':METHOD,
        'arguments':arguments,'request_id':None,'auth':{'nonce':nonce,'created':now,'expires':now+lifetime}}
    result = dict(unsigned)
    result['auth'] = {**unsigned['auth'],'mac':_mac(secret,REQ_DOMAIN,unsigned)}
    raw = canonical(result)
    need(len(raw) <= MAX_WIRE, 'private_auth_frame_invalid')
    return raw

def verify_request(raw, secret, *, expected_host='owner-host', replay_guard, now=None):
    now = _now(now)
    need(expected_host == 'owner-host' and isinstance(replay_guard, ReplayGuard), 'private_auth_profile_invalid')
    value = decode(raw)
    unsigned = _unsigned_request(value, expected_host, now)
    need(hmac.compare_digest(value['auth']['mac'], _mac(secret,REQ_DOMAIN,unsigned)), 'private_auth_request_mac_invalid')
    replay_guard.record(unsigned['auth']['nonce'], unsigned['auth']['expires'], now)
    digest = hashlib.sha256(canonical(unsigned)).hexdigest()
    # Only this stripped request enters the read facade after verified auth.
    request = {key:value[key] for key in ('host_id','name','arguments','request_id')}
    return request, {'nonce':unsigned['auth']['nonce'],'request_digest':digest,
        'host_id':expected_host,'expires':unsigned['auth']['expires']}

def make_response(body, binding, secret):
    need(isinstance(body, dict) and isinstance(binding, dict)
        and set(binding) == {'nonce','request_digest','host_id','expires'}
        and binding['host_id'] == 'owner-host', 'private_auth_response_invalid')
    unsigned = {'protocol':RESPONSE,'host_id':binding['host_id'],'nonce':binding['nonce'],
        'request_digest':binding['request_digest'],'body':body}
    result = {**unsigned,'mac':_mac(secret,RESP_DOMAIN,unsigned)}
    raw = canonical(result)
    need(len(raw) <= MAX_WIRE, 'private_auth_frame_invalid')
    return raw

def verify_response(raw, request_raw, secret, *, expected_host='owner-host', now=None):
    now = _now(now)
    request = decode(request_raw)
    unsigned_request = _unsigned_request(request, expected_host, now)
    need(hmac.compare_digest(request['auth']['mac'],_mac(secret,REQ_DOMAIN,unsigned_request)),
        'private_auth_request_mac_invalid')
    value = decode(raw)
    need(set(value) == {'protocol','host_id','nonce','request_digest','body','mac'}
        and value['protocol'] == RESPONSE and value['host_id'] == expected_host
        and value['nonce'] == unsigned_request['auth']['nonce']
        and value['request_digest'] == hashlib.sha256(canonical(unsigned_request)).hexdigest()
        and isinstance(value['body'], dict) and isinstance(value['mac'], str)
        and HEX.fullmatch(value['mac']), 'private_auth_response_binding_invalid')
    unsigned = {key:value[key] for key in value if key != 'mac'}
    need(hmac.compare_digest(value['mac'],_mac(secret,RESP_DOMAIN,unsigned)), 'private_auth_response_mac_invalid')
    return value['body']
