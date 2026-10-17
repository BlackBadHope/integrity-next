"""The ONLY authority path: exact descriptor -> full SDK verify -> durable attempt -> one-use permit.

Used for the launch and for every mediated tool effect (reads included: a read exports
data to the provider). The sequence uses the public Adapter SDK facade exactly:

    require_guardian()
    verify_adapter_execution_envelope(envelope, **context, used_at)     # nothing durable yet
    AdapterAttemptJournal.prepare_new(...)                              # grant claimed
    journal.mark_dispatching(...) -> AdapterDispatchStart(permit)       # durable before effect
    permit.consume(envelope=verified)                                   # one-use, genuine type
    effect()
    build_adapter_execution_report(...) ; journal.record_executor_report(...)

Thread affinity: SDK custody uses sqlite3 connections bound to their creating thread.
An ``SdkAuthority`` therefore runs the provider, every SDK call, the effect and the
provider's finalizer on ONE owning thread (the first caller); other threads are
refused. The evidence deadline is checked, not pre-emptive: a late provider answer is
finalized on the same thread and refused before anything is claimed.

This module creates no grant, key or envelope. If the exact SDK is unavailable
(``require_guardian`` fails, as on the current base) every call is refused before any
effect. An executor report is a signed claim, never observed or closed success.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .canonical import (Rejected, Unknown, canonical_bytes, digest_object, need, sha256_bytes,
                        strict_loads)
from .custody import AttemptCustody

REPORTED = ("reported-success", "reported-failure", "outcome-unknown")
_SIGNED_DOCUMENTS = ("manifest", "proposal", "operation_binding", "operation_manifest")


class AuthoritySpent(Exception):
    """Grant claimed/permit consumed, effect NOT started. Not reusable; never retried."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class StopToken:
    """Persistent stop + absolute deadline, checked atomically at the dispatch boundary.

    Once ``stop()`` returns, no NEW effect can begin (claim/consume/effect checkpoints all
    consult it under one lock). ``stop()`` reports whether an effect was already running.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stopped = False
        self._active = False

    def stop(self) -> bool:
        with self._lock:
            self._stopped = True
            return self._active

    def open(self, deadline: float | None) -> bool:
        with self._lock:
            return not self._stopped and (deadline is None or time.monotonic() < deadline)

    @contextmanager
    def effect(self, deadline: float | None):
        with self._lock:
            if self._stopped or (deadline is not None and time.monotonic() >= deadline):
                raise AuthoritySpent("stopped_before_effect")
            self._active = True
        try:
            yield
        finally:
            with self._lock:
                self._active = False


@dataclass(frozen=True)
class Channel:
    """Facts signed into the executor report. Declared per effect kind, never defaulted."""
    network: bool
    credentials: bool


LAUNCH_CHANNEL = Channel(network=True, credentials=True)   # subscription CLI: network + OAuth
FILE_CHANNEL = Channel(network=False, credentials=False)   # local handle I/O only


@dataclass(frozen=True)
class EffectEvidence:
    """Host-supplied genuine SDK evidence for exactly one descriptor. Never built here."""
    envelope: Any
    verification: dict           # verify_adapter_execution_envelope kwargs except used_at
    attempt_path: Any            # unique path for this effect's AdapterAttemptJournal
    dispatch_registry: Any
    registry_checkpoint: Any
    coordinator_key: Any
    journal_signer: Any
    checkpoint_signer: Any
    report: dict                 # adapter_id, adapter_artifact_digest, executor_id,
                                 # executor_artifact_digest, conformance_receipt,
                                 # executor_signer, executor_key
    finalize: Callable[[], None] | None = None   # same-thread release of provider resources


@dataclass(frozen=True)
class EffectOutcome:
    value: Any
    reported_outcome: str
    report_digest: str
    attempt_path: str
    verified_success: bool = False   # never true here: observer + closure own that


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_sdk():
    """Exact SDK or refusal. Tests may replace this with an unsigned double."""
    try:
        import integrity_adapter_sdk as sdk
        sdk.require_guardian()
    except Exception:
        raise Rejected("exact_sdk_unavailable") from None
    return sdk


def _frozen(value) -> Any:
    try:
        return strict_loads(canonical_bytes(value))
    except Rejected:
        raise Rejected("evidence_document") from None


def payload_expectation(schema_id: str, schema_bytes: bytes, document: dict) -> dict:
    return {"schema_id": schema_id,
            "schema_digest": digest_object("integrity-claude-code-schema-v1", strict_loads(schema_bytes)),
            "document_digest": sha256_bytes(canonical_bytes(document))}


class SdkAuthority:
    def __init__(self, evidence_provider: Callable[[dict], EffectEvidence], custody: AttemptCustody,
                 *, evidence_timeout_seconds: int = 30):
        need(callable(evidence_provider), "evidence_provider")
        need(isinstance(custody, AttemptCustody), "custody_type")
        need(type(evidence_timeout_seconds) is int and 1 <= evidence_timeout_seconds <= 600,
             "evidence_timeout")
        self._provider = evidence_provider
        self._custody = custody
        self._timeout = evidence_timeout_seconds
        self._owner: int | None = None
        self._busy = threading.Lock()

    def _enter(self) -> None:
        ident = threading.get_ident()
        if self._owner is None:
            self._owner = ident
        need(self._owner == ident, "authority_thread_affinity")
        need(self._busy.acquire(blocking=False), "authority_busy")

    def execute(self, *, schema_id: str, schema: dict, document: dict, channel: Channel,
                effect: Callable[[], tuple], stop: StopToken | None = None,
                deadline: float | None = None) -> EffectOutcome:
        """``effect`` returns (value, reported_outcome, receipt_dict) and runs at most once.

        ``deadline`` is an absolute ``time.monotonic()`` value; with ``stop`` it is checked
        before the claim, before the consume and atomically at the start of the effect.
        """
        need(isinstance(channel, Channel), "channel")
        need(stop is None or isinstance(stop, StopToken), "stop_token")
        self._enter()
        try:
            self._stop = stop or StopToken()
            self._deadline = deadline
            return self._execute(schema_id, canonical_bytes(schema), _frozen(document), channel, effect)
        finally:
            self._busy.release()

    def _obtain(self, frozen: dict) -> EffectEvidence:
        started = time.monotonic()
        try:
            evidence = self._provider(_frozen(frozen))
        except Exception:
            raise Rejected("evidence_unavailable") from None
        if type(evidence) is not EffectEvidence:
            raise Rejected("evidence_type")
        if time.monotonic() - started > self._timeout:
            self._finalize(evidence)  # late answer: release on the owning thread, claim nothing
            raise Rejected("evidence_timeout")
        return evidence

    @staticmethod
    def _finalize(evidence: EffectEvidence) -> None:
        if evidence.finalize is not None:
            try:
                evidence.finalize()
            except Exception:
                pass

    def _execute(self, schema_id, schema_bytes, frozen, channel, effect) -> EffectOutcome:
        sdk = _load_sdk()
        expected = payload_expectation(schema_id, schema_bytes, frozen)
        evidence = self._obtain(frozen)
        try:
            return self._dispatch(sdk, evidence, expected, frozen, channel, effect)
        finally:
            self._finalize(evidence)

    def _dispatch(self, sdk, evidence, expected, frozen, channel, effect) -> EffectOutcome:
        # Deep snapshots of every signed document; keys/grant/registry stay trusted objects.
        envelope = _frozen(evidence.envelope)
        context = dict(evidence.verification)
        need("used_at" not in context and all(name in context for name in _SIGNED_DOCUMENTS),
             "evidence_shape")
        for name in _SIGNED_DOCUMENTS:
            context[name] = _frozen(context[name])
        need(context["operation_manifest"].get("payload") == expected, "sdk_payload_mismatch")
        need(self._stop.open(self._deadline), "stopped_before_claim")
        try:
            verified = sdk.adapter_sdk.verify_adapter_execution_envelope(envelope, **context,
                                                                         used_at=_now())
        except Exception:
            raise Rejected("envelope_rejected") from None
        need(verified == envelope, "envelope_snapshot")
        runtime = sdk.adapter_runtime
        path = str(evidence.attempt_path)
        document_sha256 = sha256_bytes(canonical_bytes(frozen))
        try:
            journal, checkpoint = runtime.AdapterAttemptJournal.prepare_new(
                evidence.attempt_path, envelope=envelope,
                coordinator_key=evidence.coordinator_key, journal_signer=evidence.journal_signer,
                checkpoint_signer=evidence.checkpoint_signer,
                dispatch_registry=evidence.dispatch_registry,
                expected_dispatch_registry_checkpoint=evidence.registry_checkpoint,
                recorded_at=_now())
        except Exception:
            raise AuthoritySpent("prepare_failed") from None  # registry claim may be durable
        try:
            try:
                self._custody.record(path, document_sha256=document_sha256, envelope=envelope,
                                     phase="prepared", checkpoint=checkpoint)
                start = journal.mark_dispatching(checkpoint=checkpoint, recorded_at=_now())
                self._custody.record(path, phase="dispatching", checkpoint=start.checkpoint)
                need(type(start.permit) is runtime.AdapterDispatchPermit, "genuine_sdk_permit_required")
                need(self._stop.open(self._deadline), "stopped_before_consume")
                start.permit.consume(envelope=verified)
            except Exception:
                raise AuthoritySpent("dispatch_failed") from None
            try:
                with self._stop.effect(self._deadline):  # atomic stop/dispatch boundary
                    try:
                        value, reported, receipt = effect()
                        need(reported in REPORTED, "reported_outcome")
                        receipt = _frozen(receipt)
                    except BaseException:
                        failed = True
                    else:
                        failed = False
            except AuthoritySpent:  # stopped after consume, before the effect: nothing ran
                self._report(runtime, evidence, verified, context, journal, start.checkpoint,
                             "reported-failure", {"effect": "not_started"}, channel, path)
                raise
            if failed:
                self._report(runtime, evidence, verified, context, journal, start.checkpoint,
                             "outcome-unknown", {"effect": "exception"}, channel, path)
                raise Unknown("effect_outcome_unknown_no_retry") from None
            digest = self._report(runtime, evidence, verified, context, journal, start.checkpoint,
                                  reported, receipt, channel, path)
            if digest is None:
                raise Unknown("executor_report_not_recorded_no_retry")
            closed = self._close(journal)
            if not closed:
                raise Unknown("journal_close_failed_no_retry")
            return EffectOutcome(value=value, reported_outcome=reported, report_digest=digest,
                                 attempt_path=path)
        finally:
            self._close(journal)

    @staticmethod
    def _close(journal) -> bool:
        try:
            journal.close()
            return True
        except Exception:
            return False

    def _report(self, runtime, evidence, verified, context, journal, checkpoint, reported,
                receipt, channel, path) -> str | None:
        """Signed executor report; failure leaves the attempt UNKNOWN (safe, never replayed)."""
        try:
            receipt_digest = sha256_bytes(canonical_bytes(receipt))
            fields = evidence.report
            report = runtime.build_adapter_execution_report(
                envelope=verified, coordinator_key=evidence.coordinator_key,
                adapter_id=fields["adapter_id"],
                adapter_artifact_digest=fields["adapter_artifact_digest"],
                executor_id=fields["executor_id"],
                executor_artifact_digest=fields["executor_artifact_digest"],
                operation_binding=context["operation_binding"],
                conformance_receipt=_frozen(fields["conformance_receipt"]),
                operation_evidence_reference={
                    "schema_id": "integrity-claude-code/effect-receipt/v1",
                    "receipt_id": "effect-receipt:" + receipt_digest.split(":", 1)[1][:32],
                    "receipt_digest": receipt_digest},
                evidence_artifact_count=1, reported_outcome=reported, recorded_at=_now(),
                signer=fields["executor_signer"], network_used=channel.network,
                credentials_used=channel.credentials)
            after = journal.record_executor_report(report, coordinator_key=evidence.coordinator_key,
                                                   executor_key=fields["executor_key"],
                                                   checkpoint=checkpoint, recorded_at=_now())
            digest = runtime.adapter_execution_report_digest(report)
            self._custody.record(path, phase="executor-returned", checkpoint=after,
                                 report=_frozen(report), report_digest=digest)
            return digest
        except Exception:
            return None


def recover_attempt(sdk, custody: AttemptCustody, attempt_path: str, *, coordinator_key,
                    journal_key, checkpoint_key, terminal_receipt=None, receipt_key=None,
                    executor_key=None):
    """Host reopen of one attempt from trusted custody; returns the SDK recovery verdict.

    Opens the SDK journal read-only with the stored envelope and latest checkpoint and
    calls ``recover``. It never re-dispatches: an incomplete attempt stays UNKNOWN.
    """
    stored = custody.get(attempt_path)
    journal = sdk.adapter_runtime.AdapterAttemptJournal.open(
        attempt_path, envelope=stored["envelope"], coordinator_key=coordinator_key,
        journal_key=journal_key, checkpoint=stored["checkpoint"], checkpoint_key=checkpoint_key)
    try:
        return journal.recover(terminal_receipt=terminal_receipt, receipt_key=receipt_key,
                               executor_key=executor_key)
    finally:
        journal.close()
