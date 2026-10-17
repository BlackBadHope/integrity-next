"""OAuth 2.1 resource metadata and fail-closed RS256 access-token checks."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import math
import re
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from integrity_chronicle.json_integrity import (
    DuplicateJsonKeyError,
    loads_json_strict,
)

from .secure_https import SecureHTTPSClient, SecureHTTPSError
from .tenant import VerifiedOAuthPrincipal


_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SCOPE_RE = re.compile(r"^[a-z][a-z0-9:_-]{0,127}$")
_DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


class OAuthVerificationError(ValueError):
    """Public-safe access-token validation failure."""


def _https_uri(value: Any, *, field: str, allow_query: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise OAuthVerificationError(f"{field} is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise OAuthVerificationError(f"{field} is invalid")
    return value


@dataclass(frozen=True)
class OAuthResourceConfig:
    issuer: str
    resource: str
    jwks_url: str
    protected_resource_metadata_url: str
    scopes_supported: tuple[str, ...] = (
        "memory:read",
        "memory:write",
        "memory:import",
    )
    clock_skew_seconds: int = 60
    max_token_lifetime_seconds: int = 3_600
    jwks_cache_seconds: int = 300

    def __post_init__(self) -> None:
        object.__setattr__(self, "issuer", _https_uri(self.issuer, field="issuer"))
        object.__setattr__(
            self, "resource", _https_uri(self.resource, field="resource")
        )
        object.__setattr__(
            self, "jwks_url", _https_uri(self.jwks_url, field="JWKS URL")
        )
        object.__setattr__(
            self,
            "protected_resource_metadata_url",
            _https_uri(
                self.protected_resource_metadata_url,
                field="protected resource metadata URL",
            ),
        )
        if (
            not isinstance(self.scopes_supported, tuple)
            or not self.scopes_supported
            or len(self.scopes_supported) > 64
            or any(
                not isinstance(scope, str)
                or _SCOPE_RE.fullmatch(scope) is None
                for scope in self.scopes_supported
            )
            or len(set(self.scopes_supported)) != len(self.scopes_supported)
        ):
            raise OAuthVerificationError("supported OAuth scopes are invalid")
        for value, lower, upper, label in (
            (self.clock_skew_seconds, 0, 300, "clock skew"),
            (
                self.max_token_lifetime_seconds,
                60,
                86_400,
                "maximum token lifetime",
            ),
            (self.jwks_cache_seconds, 0, 3_600, "JWKS cache lifetime"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise OAuthVerificationError(f"{label} is invalid")

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": list(self.scopes_supported),
            "bearer_methods_supported": ["header"],
        }

    def challenge(
        self,
        *,
        error: str | None = None,
        scope: str | None = None,
    ) -> str:
        parts = [
            "Bearer " + f'resource_metadata="{self.protected_resource_metadata_url}"'
        ]
        if error is not None:
            if error not in {"invalid_token", "insufficient_scope"}:
                raise OAuthVerificationError("OAuth challenge error is invalid")
            parts.append(f'error="{error}"')
        if scope is not None:
            if _SCOPE_RE.fullmatch(scope) is None:
                raise OAuthVerificationError("OAuth challenge scope is invalid")
            parts.append(f'scope="{scope}"')
        return ", ".join(parts)


def _decode_base64url(value: Any, *, field: str, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _BASE64URL_RE.fullmatch(value) is None
    ):
        raise OAuthVerificationError(f"token {field} is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as err:
        raise OAuthVerificationError(f"token {field} is invalid") from err
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise OAuthVerificationError(f"token {field} is invalid")
    return decoded


def _json_segment(value: str, *, field: str, maximum: int) -> Mapping[str, Any]:
    raw = _decode_base64url(value, field=field, maximum=maximum)
    try:
        parsed = loads_json_strict(raw.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as err:
        raise OAuthVerificationError(f"token {field} is invalid") from err
    if not isinstance(parsed, Mapping) or any(
        not isinstance(key, str) for key in parsed
    ):
        raise OAuthVerificationError(f"token {field} is invalid")
    return parsed


def _numeric_date(claims: Mapping[str, Any], field: str) -> int:
    value = claims.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OAuthVerificationError(f"token {field} claim is invalid")
    if (
        not math.isfinite(float(value))
        or not (-1e15 < value < 1e15)
        or (isinstance(value, float) and not value.is_integer())
    ):
        raise OAuthVerificationError(f"token {field} claim is invalid")
    return int(value)


def _jwk_integer(value: Any, *, field: str, maximum: int) -> int:
    raw = _decode_base64url(value, field=field, maximum=maximum)
    if not raw or (len(raw) > 1 and raw[0] == 0):
        raise OAuthVerificationError(f"JWKS {field} is invalid")
    return int.from_bytes(raw, "big")


def _verify_rs256(
    signing_input: bytes,
    signature: bytes,
    *,
    modulus: int,
    exponent: int,
) -> None:
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width:
        raise OAuthVerificationError("token signature is invalid")
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= modulus:
        raise OAuthVerificationError("token signature is invalid")
    encoded = pow(signature_integer, exponent, modulus).to_bytes(width, "big")
    expected_tail = _DIGEST_INFO_SHA256 + sha256(signing_input).digest()
    padding_length = width - len(expected_tail) - 3
    if padding_length < 8:
        raise OAuthVerificationError("token signature is invalid")
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + expected_tail
    if not hmac.compare_digest(encoded, expected):
        raise OAuthVerificationError("token signature is invalid")


class OAuthTokenVerifier:
    """Verify an IdP-issued JWT before any tenant path is selected."""

    def __init__(
        self,
        config: OAuthResourceConfig,
        *,
        https_client: SecureHTTPSClient | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(config, OAuthResourceConfig):
            raise OAuthVerificationError("OAuth resource configuration is required")
        if not callable(clock):
            raise OAuthVerificationError("OAuth clock is invalid")
        self.config = config
        self._client = https_client or SecureHTTPSClient()
        self._clock = clock
        self._cached_keys: dict[str, tuple[int, int]] = {}
        self._cache_expires_at = 0.0
        self._lock = threading.RLock()

    def _load_keys(self, *, force: bool = False) -> dict[str, tuple[int, int]]:
        with self._lock:
            now = self._clock()
            if not isinstance(now, (int, float)) or not math.isfinite(float(now)):
                raise OAuthVerificationError("OAuth clock is invalid")
            if not force and self._cached_keys and now < self._cache_expires_at:
                return self._cached_keys
            try:
                payload = self._client.get_json(
                    self.config.jwks_url, max_bytes=512 * 1024
                )
            except SecureHTTPSError as err:
                raise OAuthVerificationError(
                    "OAuth signing keys are unavailable"
                ) from err
            raw_keys = payload.get("keys")
            if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 64:
                raise OAuthVerificationError("OAuth signing keys are invalid")
            keys: dict[str, tuple[int, int]] = {}
            for raw in raw_keys:
                if not isinstance(raw, Mapping):
                    raise OAuthVerificationError("OAuth signing keys are invalid")
                kid = raw.get("kid")
                if (
                    not isinstance(kid, str)
                    or not kid
                    or len(kid) > 256
                    or kid in keys
                    or raw.get("kty") != "RSA"
                    or raw.get("alg") not in (None, "RS256")
                    or raw.get("use") not in (None, "sig")
                ):
                    raise OAuthVerificationError("OAuth signing keys are invalid")
                modulus = _jwk_integer(
                    raw.get("n"), field="modulus", maximum=2_048
                )
                exponent = _jwk_integer(
                    raw.get("e"), field="exponent", maximum=16
                )
                if (
                    not 2_048 <= modulus.bit_length() <= 8_192
                    or exponent < 3
                    or exponent % 2 == 0
                    or exponent.bit_length() > 32
                ):
                    raise OAuthVerificationError("OAuth signing keys are invalid")
                keys[kid] = (modulus, exponent)
            self._cached_keys = keys
            self._cache_expires_at = now + self.config.jwks_cache_seconds
            return keys

    def verify(self, token: str) -> VerifiedOAuthPrincipal:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16_384
            or token.count(".") != 2
        ):
            raise OAuthVerificationError("access token is invalid")
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = _json_segment(
            encoded_header, field="header", maximum=4_096
        )
        claims = _json_segment(
            encoded_claims, field="claims", maximum=12_288
        )
        if (
            header.get("alg") != "RS256"
            or header.get("typ") not in (None, "JWT", "at+jwt")
            or "crit" in header
            or any(field in header for field in ("jku", "jwk", "x5u", "x5c"))
        ):
            raise OAuthVerificationError("access token header is invalid")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise OAuthVerificationError("access token header is invalid")
        keys = self._load_keys()
        key = keys.get(kid)
        if key is None:
            raise OAuthVerificationError("access token signing key is unknown")
        signature = _decode_base64url(
            encoded_signature, field="signature", maximum=12_288
        )
        _verify_rs256(
            f"{encoded_header}.{encoded_claims}".encode("ascii"),
            signature,
            modulus=key[0],
            exponent=key[1],
        )

        issuer = claims.get("iss")
        subject = claims.get("sub")
        if issuer != self.config.issuer:
            raise OAuthVerificationError("access token issuer is invalid")
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 512
            or any(ord(character) < 32 for character in subject)
        ):
            raise OAuthVerificationError("access token subject is invalid")
        raw_audience = claims.get("aud")
        if isinstance(raw_audience, str):
            audience = (raw_audience,)
        elif (
            isinstance(raw_audience, list)
            and 1 <= len(raw_audience) <= 16
            and all(
                isinstance(value, str) and value and len(value) <= 512
                for value in raw_audience
            )
            and len(set(raw_audience)) == len(raw_audience)
        ):
            audience = tuple(raw_audience)
        else:
            raise OAuthVerificationError("access token audience is invalid")
        resource_claim = claims.get("resource")
        if (
            self.config.resource not in audience
            and resource_claim != self.config.resource
        ):
            raise OAuthVerificationError("access token audience is invalid")

        raw_now = self._clock()
        if not isinstance(raw_now, (int, float)) or not math.isfinite(float(raw_now)):
            raise OAuthVerificationError("OAuth clock is invalid")
        now = int(raw_now)
        issued_at = _numeric_date(claims, "iat")
        expires_at = _numeric_date(claims, "exp")
        not_before = (
            _numeric_date(claims, "nbf") if "nbf" in claims else issued_at
        )
        skew = self.config.clock_skew_seconds
        if issued_at > now + skew or not_before > now + skew:
            raise OAuthVerificationError("access token is not active")
        if expires_at <= now - skew:
            raise OAuthVerificationError("access token has expired")
        if (
            expires_at <= issued_at
            or expires_at - issued_at > self.config.max_token_lifetime_seconds
        ):
            raise OAuthVerificationError("access token lifetime is invalid")

        raw_scope = claims.get("scope", claims.get("scp"))
        if isinstance(raw_scope, str):
            scopes = raw_scope.split()
        elif isinstance(raw_scope, list):
            scopes = raw_scope
        else:
            raise OAuthVerificationError("access token scopes are invalid")
        if (
            not scopes
            or len(scopes) > 64
            or any(
                not isinstance(scope, str)
                or _SCOPE_RE.fullmatch(scope) is None
                for scope in scopes
            )
            or len(set(scopes)) != len(scopes)
            or any(scope not in self.config.scopes_supported for scope in scopes)
        ):
            raise OAuthVerificationError("access token scopes are invalid")
        return VerifiedOAuthPrincipal(
            issuer=issuer,
            subject=subject,
            audience=audience,
            scopes=frozenset(scopes),
        )


__all__ = [
    "OAuthResourceConfig",
    "OAuthTokenVerifier",
    "OAuthVerificationError",
]
