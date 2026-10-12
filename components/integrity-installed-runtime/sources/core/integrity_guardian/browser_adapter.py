"""Exact non-production Firefox action over the shared Adapter SDK lifecycle."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .adapter_conformance import (
    require_adapter_conformance_readiness,
    verify_adapter_conformance_receipt,
)
from .adapter_runtime import (
    AdapterDispatchPermit,
    AdapterRuntimeError,
    _verify_envelope_signature,
    build_adapter_execution_report,
)
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterReportedOutcome,
    adapter_capability_manifest_digest,
    adapter_execution_envelope_digest,
    adapter_operation_binding_digest,
    adapter_target_operation_digest,
    verify_adapter_capability_manifest,
    verify_adapter_operation_binding,
    verify_adapter_target_operation,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .operation_audit import write_operation_document
from .schemas import load_schema, validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .webdriver_transport import GeckoWebDriverSession, WebDriverTransportError

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SELECTOR = re.compile(r"^#[A-Za-z][A-Za-z0-9_-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BROWSER_EXECUTION_RECEIPT_ARTIFACT = "browser-execution-receipt.json"


class BrowserAdapterError(AdapterRuntimeError):
    """Raised before a browser action can be widened or overstated."""


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise BrowserAdapterError(f"browser {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise BrowserAdapterError(f"browser {field} rejected")
    return candidate


def _identity(
    document: Mapping[str, Any],
    *,
    field: str,
    prefix: str,
    domain: str,
) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    return prefix + digest_object(core, domain=domain).split(":", 1)[1]


def _artifact_digest(path: Path) -> str:
    if not path.is_absolute():
        raise BrowserAdapterError("browser executable path rejected")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BrowserAdapterError("browser executable unavailable") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o022:
            raise BrowserAdapterError("browser executable custody rejected")
        hasher = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()
    finally:
        os.close(descriptor)


def _strict_nonproduction_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or not parsed.hostname.endswith(".invalid")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise BrowserAdapterError("browser non-production origin rejected")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BrowserAdapterError("browser origin port rejected") from exc
    if port not in {None, 80}:
        raise BrowserAdapterError("browser origin port rejected")
    return f"http://{parsed.hostname}"


def _selector_digest(selector: str) -> str:
    return digest_object(selector, domain="browser-css-selector-v1")


def browser_action_schema_digest() -> str:
    return digest_object(
        load_schema("browser-action-manifest"),
        domain="browser-action-manifest-schema-v1",
    )


def browser_action_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(dict(manifest), domain="browser-action-manifest-v1")


def browser_execution_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="browser-execution-receipt-v1")


def browser_resource_ids(manifest: Mapping[str, Any]) -> list[str]:
    origin = str(manifest["target"]["origin"])
    selector = str(manifest["action"]["selector"])
    return [
        "browser-origin:"
        + digest_object(origin, domain="browser-origin-resource-v1").split(":", 1)[1],
        "browser-selector:"
        + digest_object(selector, domain="browser-selector-resource-v1").split(":", 1)[1],
    ]


def build_browser_action_manifest(
    *,
    tenant_id: str,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    intent_operation_digest: str,
    target_node_id: str,
    target_zone_id: str,
    environment_digest: str,
    origin: str,
    proxy_port: int,
    browser_version: str,
    firefox_executable_digest: str,
    geckodriver_executable_digest: str,
    context_id: str,
    selector: str,
    expected_selector: str,
    expected_text: str,
    created_at: str,
    signer: Ed25519Signer,
    timeout_seconds: int = 30,
    viewport_width: int = 1280,
    viewport_height: int = 720,
    locale: str = "en-US",
) -> dict[str, Any]:
    capability = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    normalized_origin = _strict_nonproduction_origin(origin)
    if (
        _ID.fullmatch(tenant_id) is None
        or _ID.fullmatch(target_node_id) is None
        or _ID.fullmatch(target_zone_id) is None
        or _ID.fullmatch(context_id) is None
        or _DIGEST.fullmatch(intent_operation_digest) is None
        or _DIGEST.fullmatch(environment_digest) is None
        or _DIGEST.fullmatch(firefox_executable_digest) is None
        or _DIGEST.fullmatch(geckodriver_executable_digest) is None
        or _SELECTOR.fullmatch(selector) is None
        or _SELECTOR.fullmatch(expected_selector) is None
        or not isinstance(expected_text, str)
        or not expected_text
        or len(expected_text) > 1024
        or not 1 <= proxy_port <= 65535
        or not 1 <= timeout_seconds <= 120
        or not 320 <= viewport_width <= 3840
        or not 240 <= viewport_height <= 2160
        or not browser_version
        or len(browser_version) > 64
        or not locale
        or len(locale) > 32
    ):
        raise BrowserAdapterError("browser action input rejected")
    channels = {
        "api": False,
        "browser_control": True,
        "computer_use": False,
        "credentials": False,
        "network": True,
        "service_control": False,
        "shell": False,
    }
    if capability["declared_channels"] != channels:
        raise BrowserAdapterError("browser channel declaration rejected")
    start_url = normalized_origin + "/"
    expected_url = normalized_origin + "/result"
    core = {
        "protocol": "integrity-guardian/browser-action-manifest/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": tenant_id,
        "manifest": {
            "manifest_id": capability["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(capability),
            "adapter_id": capability["adapter_id"],
            "adapter_artifact_digest": capability["adapter_artifact_digest"],
        },
        "intent_operation_digest": intent_operation_digest,
        "target": {
            "node_id": target_node_id,
            "zone_id": target_zone_id,
            "environment_digest": environment_digest,
            "origin": normalized_origin,
            "start_url": start_url,
            "expected_url": expected_url,
        },
        "browser": {
            "name": "firefox",
            "version": browser_version,
            "firefox_executable_digest": firefox_executable_digest,
            "webdriver_name": "geckodriver",
            "geckodriver_executable_digest": geckodriver_executable_digest,
        },
        "context": {
            "context_id": context_id,
            "profile_policy": "fresh-ephemeral",
            "headless": True,
            "viewport": {"width": viewport_width, "height": viewport_height},
            "locale": locale,
        },
        "action": {
            "kind": "click",
            "selector_kind": "css",
            "selector": selector,
            "selector_digest": _selector_digest(selector),
            "maximum_matches": 1,
            "expected_selector": expected_selector,
            "expected_selector_digest": _selector_digest(expected_selector),
            "expected_text_digest": digest_object(
                expected_text,
                domain="browser-expected-text-v1",
            ),
        },
        "transport": {
            "webdriver_host": "127.0.0.1",
            "webdriver_port_policy": "ephemeral-loopback",
            "proxy_host": "127.0.0.1",
            "proxy_port": proxy_port,
            "proxy_policy": "all-browser-traffic",
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "maximum_navigation_count": 2,
            "maximum_click_count": 1,
            "maximum_response_bytes": 2 * 1024 * 1024,
        },
        "controls": {
            "external_egress": False,
            "credential_reference": None,
            "home_profile": False,
            "raw_page_content_retained": False,
            "downloads": False,
            "browser_extensions": False,
            "production_authority": False,
            "max_invocations": 1,
            "automatic_retry_after_unknown": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "action_id": _identity(
            core,
            field="action_id",
            prefix="browser-action:",
            domain="browser-action-manifest-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("browser-action-manifest", signed)
    return signed


def verify_browser_action_manifest(
    manifest: Mapping[str, Any],
    *,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    action_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(manifest, "action manifest")
    try:
        validate("browser-action-manifest", candidate)
    except Exception as exc:
        raise BrowserAdapterError("browser action manifest schema rejected") from exc
    if candidate["action_id"] != _identity(
        candidate,
        field="action_id",
        prefix="browser-action:",
        domain="browser-action-manifest-identity-v1",
    ):
        raise BrowserAdapterError("browser action identity mismatch")
    if (
        candidate["signer_id"] != action_key.key_id
        or candidate["signature"]["key_id"] != action_key.key_id
        or not verify_signature(candidate, action_key.public_key)
    ):
        raise BrowserAdapterError("browser action signature rejected")
    capability = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    if candidate["manifest"] != {
        "manifest_id": capability["manifest_id"],
        "manifest_digest": adapter_capability_manifest_digest(capability),
        "adapter_id": capability["adapter_id"],
        "adapter_artifact_digest": capability["adapter_artifact_digest"],
    }:
        raise BrowserAdapterError("browser adapter manifest mismatch")
    if (
        _strict_nonproduction_origin(candidate["target"]["origin"])
        != candidate["target"]["origin"]
        or candidate["target"]["start_url"] != candidate["target"]["origin"] + "/"
        or candidate["target"]["expected_url"]
        != candidate["target"]["origin"] + "/result"
        or candidate["action"]["selector_digest"]
        != _selector_digest(candidate["action"]["selector"])
        or candidate["action"]["expected_selector_digest"]
        != _selector_digest(candidate["action"]["expected_selector"])
    ):
        raise BrowserAdapterError("browser action semantic binding mismatch")
    return candidate


def _receipt_identity(core: Mapping[str, Any]) -> str:
    return _identity(
        core,
        field="receipt_id",
        prefix="browser-execution:",
        domain="browser-execution-receipt-identity-v1",
    )


def _build_execution_receipt(
    *,
    envelope: Mapping[str, Any],
    target_operation: Mapping[str, Any],
    action_manifest: Mapping[str, Any],
    executor_id: str,
    executor_artifact_digest: str,
    click_request_sent: bool,
    start_url_observed: str | None,
    final_url_observed: str | None,
    initial_match_count: int | None,
    final_match_count: int | None,
    final_text_digest: str | None,
    browser_version_observed: str | None,
    webdriver_request_count: int,
    profile_is_temporary: bool,
    reported_outcome: AdapterReportedOutcome,
    reason_code: str,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    core = {
        "protocol": "integrity-guardian/browser-execution-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "envelope": {
            "envelope_id": envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(envelope),
        },
        "operation": {
            "target_operation_id": target_operation["operation_id"],
            "target_operation_digest": adapter_target_operation_digest(target_operation),
            "action_id": action_manifest["action_id"],
            "action_manifest_digest": browser_action_manifest_digest(action_manifest),
        },
        "executor": {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": signer.key_id,
        },
        "observed": {
            "start_url": start_url_observed,
            "final_url": final_url_observed,
            "initial_match_count": initial_match_count,
            "final_match_count": final_match_count,
            "final_text_digest": final_text_digest,
            "browser_version": browser_version_observed,
            "temporary_profile": profile_is_temporary,
            "webdriver_request_count": webdriver_request_count,
            "raw_page_content_retained": False,
        },
        "result": {
            "reported_outcome": reported_outcome.value,
            "reason_code": reason_code,
            "click_request_sent": click_request_sent,
            "expected_url_observed": (
                final_url_observed == action_manifest["target"]["expected_url"]
            ),
            "expected_text_observed": (
                final_text_digest == action_manifest["action"]["expected_text_digest"]
            ),
            "action_replayed": False,
            "automatic_retry_allowed": False,
        },
        "controls": {
            "loopback_webdriver": True,
            "all_browser_traffic_proxy": True,
            "external_egress": False,
            "credentials": False,
            "home_profile": False,
            "downloads": False,
            "production_authority": False,
        },
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"receipt_id": _receipt_identity(core), **core})
    validate("browser-execution-receipt", signed)
    return signed


def verify_browser_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    executor_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(receipt, "execution receipt")
    try:
        validate("browser-execution-receipt", candidate)
    except Exception as exc:
        raise BrowserAdapterError("browser execution receipt schema rejected") from exc
    if candidate["receipt_id"] != _receipt_identity(candidate):
        raise BrowserAdapterError("browser execution receipt identity mismatch")
    if (
        candidate["signer_id"] != executor_key.key_id
        or candidate["signature"]["key_id"] != executor_key.key_id
        or not verify_signature(candidate, executor_key.public_key)
    ):
        raise BrowserAdapterError("browser execution receipt signature rejected")
    return candidate


class BrowserAdapter:
    """One exact Firefox click under the shared ASDK crash boundary."""

    def __init__(
        self,
        *,
        capability_manifest: Mapping[str, Any],
        adapter_key: TrustedKey,
        conformance_profile: Mapping[str, Any],
        conformance_profile_key: TrustedKey,
        conformance_receipt: Mapping[str, Any],
        conformance_evidence: Sequence[Mapping[str, Any]],
        conformance_evidence_keys: Mapping[str, TrustedKey],
        conformance_receipt_key: TrustedKey,
        proposal: Mapping[str, Any],
        proposer_key: TrustedKey,
        operation_binding: Mapping[str, Any],
        target_operation: Mapping[str, Any],
        operation_key: TrustedKey,
        action_manifest: Mapping[str, Any],
        action_key: TrustedKey,
        coordinator_key: TrustedKey,
        executor_id: str,
        executor_artifact_digest: str,
        executor_key: TrustedKey,
        signer: Ed25519Signer,
        evidence_directory: Path,
        geckodriver_launcher: Path = Path("/snap/bin/geckodriver"),
        geckodriver_artifact: Path = Path(
            "/snap/firefox/current/usr/lib/firefox/geckodriver"
        ),
        firefox_artifact: Path = Path("/snap/firefox/current/usr/lib/firefox/firefox"),
    ) -> None:
        manifest = verify_adapter_capability_manifest(
            capability_manifest,
            adapter_key=adapter_key,
        )
        conformance = verify_adapter_conformance_receipt(
            conformance_receipt,
            profile=conformance_profile,
            profile_key=conformance_profile_key,
            manifest=manifest,
            adapter_key=adapter_key,
            evidence_documents=conformance_evidence,
            evidence_keys=conformance_evidence_keys,
            receipt_key=conformance_receipt_key,
        )
        require_adapter_conformance_readiness(conformance, minimum="source-ready")
        action = verify_browser_action_manifest(
            action_manifest,
            capability_manifest=manifest,
            adapter_key=adapter_key,
            action_key=action_key,
        )
        operation = verify_adapter_target_operation(
            target_operation,
            manifest=manifest,
            adapter_key=adapter_key,
            operation_key=operation_key,
        )
        binding = verify_adapter_operation_binding(
            operation_binding,
            manifest=manifest,
            adapter_key=adapter_key,
            proposal=proposal,
            proposer_key=proposer_key,
            operation_manifest=operation,
            operation_key=operation_key,
            binding_key=coordinator_key,
            used_at=operation_binding["created_at"],
        )
        if (
            executor_key.key_id != signer.key_id
            or public_key_fingerprint(executor_key.public_key)
            != public_key_fingerprint(signer.public_key)
        ):
            raise BrowserAdapterError("browser executor signer binding mismatch")
        if binding["executor"] != {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": executor_key.key_id,
        }:
            raise BrowserAdapterError("browser executor binding mismatch")
        if (
            operation["payload"]
            != {
                "schema_id": "browser-action-manifest/v1",
                "schema_digest": browser_action_schema_digest(),
                "document_digest": browser_action_manifest_digest(action),
            }
            or operation["blast_radius"]["resource_kind"] != "browser-context"
            or operation["blast_radius"]["allowed_resource_ids"]
            != browser_resource_ids(action)
            or action["intent_operation_digest"] != operation["intent_operation_digest"]
            or action["target"]["node_id"] != operation["target"]["node_id"]
            or action["target"]["zone_id"] != operation["target"]["zone_id"]
            or action["target"]["environment_digest"]
            != operation["target"]["environment_digest"]
        ):
            raise BrowserAdapterError("browser typed operation mismatch")
        if _artifact_digest(geckodriver_artifact) != action["browser"][
            "geckodriver_executable_digest"
        ] or _artifact_digest(firefox_artifact) != action["browser"][
            "firefox_executable_digest"
        ]:
            raise BrowserAdapterError("browser executable artifact mismatch")
        evidence = evidence_directory.resolve(strict=True)
        mode = stat.S_IMODE(evidence.stat().st_mode)
        if not evidence.is_dir() or mode & 0o077:
            raise BrowserAdapterError("browser evidence custody rejected")
        self.manifest = manifest
        self.conformance = conformance
        self.binding = binding
        self.operation = operation
        self.action = action
        self.coordinator_key = coordinator_key
        self.executor_id = executor_id
        self.executor_artifact_digest = executor_artifact_digest
        self.signer = signer
        self.evidence_directory = evidence
        self.geckodriver_launcher = geckodriver_launcher
        self._used: set[str] = set()

    def execute(
        self,
        envelope: Mapping[str, Any],
        *,
        dispatch_permit: AdapterDispatchPermit,
        recorded_at: str,
    ) -> dict[str, Any]:
        candidate = _verify_envelope_signature(
            envelope,
            coordinator_key=self.coordinator_key,
        )
        if candidate["manifest"] != {
            "manifest_id": self.manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(self.manifest),
            "adapter_id": self.manifest["adapter_id"],
            "adapter_artifact_digest": self.manifest["adapter_artifact_digest"],
        } or candidate["operation_binding"] != {
            "binding_id": self.binding["binding_id"],
            "binding_digest": adapter_operation_binding_digest(self.binding),
            "conformance_receipt_id": self.binding["conformance"]["receipt_id"],
            "conformance_receipt_digest": self.binding["conformance"]["receipt_digest"],
            "conformance_readiness": self.binding["conformance"]["readiness"],
            "operation_kind": self.binding["operation"]["kind"],
            "operation_manifest_id": self.binding["operation"]["manifest_id"],
            "operation_manifest_digest": self.binding["operation"]["manifest_digest"],
            "executor_id": self.binding["executor"]["executor_id"],
            "executor_artifact_digest": self.binding["executor"][
                "executor_artifact_digest"
            ],
            "executor_key_id": self.binding["executor"]["key_id"],
        }:
            raise BrowserAdapterError("browser envelope mismatch")
        if candidate["envelope_id"] in self._used:
            raise BrowserAdapterError("browser replay rejected")
        dispatch_permit.consume(envelope=candidate)
        self._used.add(candidate["envelope_id"])
        click_sent = False
        start_url: str | None = None
        final_url: str | None = None
        initial_matches: int | None = None
        final_matches: int | None = None
        final_text_digest: str | None = None
        browser_version: str | None = None
        profile_temporary = False
        request_count = 0
        outcome = AdapterReportedOutcome.REPORTED_FAILURE
        reason = "pre-action-browser-failure"
        action = self.action
        context = action["context"]
        try:
            with GeckoWebDriverSession(
                geckodriver_launcher=self.geckodriver_launcher,
                proxy_host=action["transport"]["proxy_host"],
                proxy_port=action["transport"]["proxy_port"],
                timeout_seconds=action["limits"]["timeout_seconds"],
                viewport_width=context["viewport"]["width"],
                viewport_height=context["viewport"]["height"],
                locale=context["locale"],
            ) as browser:
                browser_version = str(browser.capabilities.get("browserVersion", ""))
                profile_temporary = browser.profile_is_temporary
                if browser_version != action["browser"]["version"]:
                    raise BrowserAdapterError("browser version drift")
                browser.navigate(action["target"]["start_url"])
                start_url = browser.current_url()
                elements = browser.find_elements(action["action"]["selector"])
                initial_matches = len(elements)
                if start_url != action["target"]["start_url"] or len(elements) != 1:
                    raise BrowserAdapterError("browser precondition mismatch")
                click_sent = True
                browser.click(elements[0])
                deadline = time.monotonic() + action["limits"]["timeout_seconds"]
                while time.monotonic() < deadline:
                    final_url = browser.current_url()
                    if final_url == action["target"]["expected_url"]:
                        break
                    time.sleep(0.05)
                final_elements = browser.find_elements(
                    action["action"]["expected_selector"]
                )
                final_matches = len(final_elements)
                if final_matches == 1:
                    final_text_digest = digest_object(
                        browser.element_text(final_elements[0]),
                        domain="browser-expected-text-v1",
                    )
                request_count = browser.request_count
                success = (
                    final_url == action["target"]["expected_url"]
                    and final_matches == 1
                    and final_text_digest == action["action"]["expected_text_digest"]
                )
                outcome = (
                    AdapterReportedOutcome.REPORTED_SUCCESS
                    if success
                    else AdapterReportedOutcome.REPORTED_FAILURE
                )
                reason = (
                    "expected-page-state-observed"
                    if success
                    else "post-action-page-state-mismatch"
                )
        except (BrowserAdapterError, WebDriverTransportError):
            if click_sent:
                outcome = AdapterReportedOutcome.OUTCOME_UNKNOWN
                reason = "post-click-observation-unknown"
            else:
                outcome = AdapterReportedOutcome.REPORTED_FAILURE
                reason = "pre-action-browser-failure"
        receipt = _build_execution_receipt(
            envelope=candidate,
            target_operation=self.operation,
            action_manifest=action,
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
            click_request_sent=click_sent,
            start_url_observed=start_url,
            final_url_observed=final_url,
            initial_match_count=initial_matches,
            final_match_count=final_matches,
            final_text_digest=final_text_digest,
            browser_version_observed=browser_version,
            webdriver_request_count=request_count,
            profile_is_temporary=profile_temporary,
            reported_outcome=outcome,
            reason_code=reason,
            recorded_at=recorded_at,
            signer=self.signer,
        )
        verified = verify_browser_execution_receipt(
            receipt,
            executor_key=TrustedKey(self.signer.key_id, self.signer.public_key),
        )
        write_operation_document(
            self.evidence_directory / BROWSER_EXECUTION_RECEIPT_ARTIFACT,
            verified,
            schema="browser-execution-receipt",
        )
        return build_adapter_execution_report(
            envelope=candidate,
            coordinator_key=self.coordinator_key,
            adapter_id=self.manifest["adapter_id"],
            adapter_artifact_digest=self.manifest["adapter_artifact_digest"],
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
            operation_binding=self.binding,
            conformance_receipt=self.conformance,
            operation_evidence_reference={
                "schema_id": "browser-execution-receipt/v1",
                "receipt_id": verified["receipt_id"],
                "receipt_digest": browser_execution_receipt_digest(verified),
            },
            evidence_artifact_count=1,
            reported_outcome=verified["result"]["reported_outcome"],
            recorded_at=recorded_at,
            signer=self.signer,
            network_used=True,
        )


__all__ = [
    "BROWSER_EXECUTION_RECEIPT_ARTIFACT",
    "BrowserAdapter",
    "BrowserAdapterError",
    "browser_action_manifest_digest",
    "browser_action_schema_digest",
    "browser_execution_receipt_digest",
    "browser_resource_ids",
    "build_browser_action_manifest",
    "verify_browser_action_manifest",
    "verify_browser_execution_receipt",
]
