"""Independent read-only page-state observer for BrowserAdapter."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .adapter_sdk import ADAPTER_SDK_VERSION
from .browser_adapter import (
    BrowserAdapterError,
    browser_action_manifest_digest,
    verify_browser_action_manifest,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature
from .webdriver_transport import GeckoWebDriverSession


def _freeze(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise BrowserAdapterError("browser page witness rejected") from exc
    if not isinstance(candidate, dict):
        raise BrowserAdapterError("browser page witness rejected")
    return candidate


def _identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("witness_id", None)
    core.pop("signature", None)
    suffix = digest_object(core, domain="browser-page-witness-identity-v1").split(":", 1)[1]
    return f"browser-page-witness:{suffix}"


def browser_page_witness_digest(witness: Mapping[str, Any]) -> str:
    return digest_object(dict(witness), domain="browser-page-witness-v1")


def build_browser_page_witness(
    *,
    action_manifest: Mapping[str, Any],
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    action_key: TrustedKey,
    executor_id: str,
    executor_artifact_digest: str,
    executor_key_id: str,
    observer_id: str,
    observer_artifact_digest: str,
    observed_at: str,
    signer: Ed25519Signer,
    geckodriver_launcher: Path = Path("/snap/bin/geckodriver"),
) -> dict[str, Any]:
    action = verify_browser_action_manifest(
        action_manifest,
        capability_manifest=capability_manifest,
        adapter_key=adapter_key,
        action_key=action_key,
    )
    if (
        executor_id == observer_id
        or executor_artifact_digest == observer_artifact_digest
        or executor_key_id == signer.key_id
    ):
        raise BrowserAdapterError("browser executor/witness separation rejected")
    context = action["context"]
    with GeckoWebDriverSession(
        geckodriver_launcher=geckodriver_launcher,
        proxy_host=action["transport"]["proxy_host"],
        proxy_port=action["transport"]["proxy_port"],
        timeout_seconds=action["limits"]["timeout_seconds"],
        viewport_width=context["viewport"]["width"],
        viewport_height=context["viewport"]["height"],
        locale=context["locale"],
    ) as browser:
        browser_version = str(browser.capabilities.get("browserVersion", ""))
        browser.navigate(action["target"]["expected_url"])
        current_url = browser.current_url()
        elements = browser.find_elements(action["action"]["expected_selector"])
        text_digest = None
        if len(elements) == 1:
            text_digest = digest_object(
                browser.element_text(elements[0]),
                domain="browser-expected-text-v1",
            )
        request_count = browser.request_count
        profile_temporary = browser.profile_is_temporary
    core = {
        "protocol": "integrity-guardian/browser-page-witness/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "action": {
            "action_id": action["action_id"],
            "action_manifest_digest": browser_action_manifest_digest(action),
        },
        "target": {
            "node_id": action["target"]["node_id"],
            "zone_id": action["target"]["zone_id"],
            "environment_digest": action["target"]["environment_digest"],
            "origin": action["target"]["origin"],
        },
        "executor": {
            "actor_id": executor_id,
            "artifact_digest": executor_artifact_digest,
            "key_id": executor_key_id,
        },
        "observer": {
            "actor_id": observer_id,
            "artifact_digest": observer_artifact_digest,
            "key_id": signer.key_id,
        },
        "observed": {
            "url": current_url,
            "selector_digest": action["action"]["expected_selector_digest"],
            "match_count": len(elements),
            "text_digest": text_digest,
            "browser_version": browser_version,
            "temporary_profile": profile_temporary,
            "webdriver_request_count": request_count,
            "raw_page_content_retained": False,
        },
        "result": {
            "expected_url_observed": current_url == action["target"]["expected_url"],
            "expected_selector_observed": len(elements) == 1,
            "expected_text_observed": (
                text_digest == action["action"]["expected_text_digest"]
            ),
            "executor_claim_trusted": False,
            "external_causality_proven": False,
        },
        "controls": {
            "action_invocations": 0,
            "read_only": True,
            "loopback_webdriver": True,
            "external_egress": False,
            "credentials": False,
            "home_profile": False,
            "production_authority": False,
        },
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"witness_id": _identity(core), **core})
    validate("browser-page-witness", signed)
    return signed


def verify_browser_page_witness(
    witness: Mapping[str, Any],
    *,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(witness)
    try:
        validate("browser-page-witness", candidate)
    except Exception as exc:
        raise BrowserAdapterError("browser page witness schema rejected") from exc
    if candidate["witness_id"] != _identity(candidate):
        raise BrowserAdapterError("browser page witness identity mismatch")
    if (
        candidate["signer_id"] != observer_key.key_id
        or candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise BrowserAdapterError("browser page witness signature rejected")
    if (
        candidate["executor"]["actor_id"] == candidate["observer"]["actor_id"]
        or candidate["executor"]["artifact_digest"]
        == candidate["observer"]["artifact_digest"]
        or candidate["executor"]["key_id"] == candidate["observer"]["key_id"]
    ):
        raise BrowserAdapterError("browser executor/witness separation rejected")
    return candidate


__all__ = [
    "browser_page_witness_digest",
    "build_browser_page_witness",
    "verify_browser_page_witness",
]
