# SPDX-License-Identifier: Apache-2.0
"""Private read client over the existing protected peer connection.

Assembly supplies the existing key loader and bounded socket exchange. Neither
callback is model input. Public PeerClient calls and their bearer wire are unused.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import math
import time
import native_evidence_peer_auth as auth

class PrivatePeerError(ValueError):
    pass

class AuthenticatedNativePeerClient:
    host_id = 'owner-host'
    authentication_protocol = auth.REQUEST

    def __init__(self, exchange, key_loader):
        if not callable(exchange) or not callable(key_loader):
            raise PrivatePeerError('private_peer_assembly_invalid')
        self.exchange, self.key_loader = exchange, key_loader

    def call(self, name, arguments, *, timeout):
        if name != auth.METHOD or not isinstance(arguments, dict):
            raise PrivatePeerError('private_peer_method_invalid')
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise PrivatePeerError('private_peer_deadline_invalid')
        deadline = time.monotonic() + timeout
        try:
            key = self.key_loader()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PrivatePeerError('native_evidence_deadline')
            request = auth.make_request(arguments, key, lifetime=min(auth.MAX_TTL, max(1, math.ceil(remaining))))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PrivatePeerError('native_evidence_deadline')
            # Existing loopback/SSH transport is reused; no new listener or retry.
            raw = self.exchange(request, remaining)
            if time.monotonic() >= deadline:
                raise PrivatePeerError('native_evidence_deadline')
            reply = auth.verify_response(raw, request, key)
            if reply.get('host_id') != self.host_id:
                raise PrivatePeerError('private_peer_result_invalid')
            if 'error' in reply or 'result' not in reply:
                raise PrivatePeerError('private_peer_read_denied')
            if not isinstance(reply['result'], dict):
                raise PrivatePeerError('private_peer_result_invalid')
            return reply['result']
        except (PrivatePeerError, auth.PeerAuthError):
            raise
        except Exception:
            raise PrivatePeerError('private_peer_read_unavailable') from None
