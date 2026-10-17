"""Independent observation (H) and the host terminal-receipt / closure boundary.

Two layers, deliberately separate:

1. ``observe_workspace`` runs ``observer_main.py`` as its OWN process (pinned
   interpreter + pinned observer script; a different artifact from the executor,
   relay and coordinator) in a Job, reading the workspace directly. ``evaluate``
   compares pre/post observations with the coordinator's mediated write receipts. Any
   skipped, unreadable or unstable file, a bound hit, an invalid HEAD, or a
   pre/post workspace mismatch yields ``outcome-unknown``. The result is an UNSIGNED
   same-account observation: not a witness, never a completion.

2. ``terminal_receipt`` is the host boundary. The host supplies a genuine
   ``VerifiedAdapterWitness`` and its keys; this module calls only the PUBLIC SDK
   (``adapter_runtime.build_adapter_transition_receipt_from_report`` and
   ``adapter_sdk.verify_adapter_transition_receipt``, which verify proof and
   actor/observer independence themselves), binds the result to THIS run's descriptor,
   stored envelope and executor report, and returns an issued immutable
   ``VerifiedTerminal``. ``closure_handoff`` accepts only that object -- never a dict --
   and produces the content-free routing document for the EXISTING closure route.
   No canonical append happens here; ``task_complete`` is always false.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import authority as _authority
from .canonical import Rejected, canonical_bytes, digest_object, need, sha256_bytes, strict_loads
from .custody import AttemptCustody
from .descriptor import descriptor_digest
from .identity import executable_identity, require_plain_path

OUTCOMES = ("expected-transition-observed", "pre-state-retained", "unexpected-state-observed",
            "outcome-unknown")
MAX_OBSERVATION = 8 * 1024 * 1024
_HEAD = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_KEYS = {"schema", "root", "head", "files", "truncated", "skipped", "unreadable", "unstable"}
_ISSUER = object()


@dataclass(frozen=True)
class WorkspaceObservation:
    """Unsigned observation held as immutable canonical bytes; ``document`` is a fresh copy."""
    document_bytes: bytes
    digest: str
    observer_artifact_sha256: str
    signed: bool = False   # never a witness by itself

    @property
    def document(self) -> dict:
        return strict_loads(self.document_bytes, MAX_OBSERVATION)


def _validate(document) -> dict:
    need(type(document) is dict and set(document) == _KEYS
         and document["schema"] == "integrity-claude-code/workspace-observation/v1", "observer_output")
    need(type(document["root"]) is str and type(document["files"]) is dict
         and type(document["truncated"]) is bool, "observer_output")
    need(document["head"] is None or type(document["head"]) is str, "observer_output")
    for key in ("skipped", "unreadable", "unstable"):
        need(type(document[key]) is int and document[key] >= 0, "observer_output")
    need(all(type(p) is str and type(d) is str and _DIGEST.fullmatch(d)
             for p, d in document["files"].items()), "observer_digest")
    return document


def observe_workspace(*, python: Path, python_sha256: str, script: Path, script_sha256: str,
                      workspace: Path, workdir: Path, environment: dict) -> WorkspaceObservation:
    from .winjob import JobProcess  # Windows-only

    need(executable_identity(Path(python))["sha256"] == python_sha256, "observer_python_digest")
    source = require_plain_path(Path(script), "observer_script")
    need(sha256_bytes(source.read_bytes()) == script_sha256, "observer_script_digest")
    buffer = bytearray()
    limits = {"deadline_seconds": 120, "stop_grace_seconds": 5, "max_stdout_bytes": MAX_OBSERVATION,
              "max_stderr_bytes": 64 * 1024, "job_memory_bytes": 1024 * 1024 * 1024, "max_processes": 4}
    job = JobProcess(executable=Path(python), executable_sha256=python_sha256,
                     argv=["-I", "-S", "-B", str(source), str(Path(workspace))], cwd=Path(workdir),
                     environment=environment, stdin=b"", limits=limits, stdout_sink=buffer.extend,
                     cancel=threading.Event()).run()
    need(job.stop_verified and job.termination is None and job.exit_code == 0, "observer_failed")
    document = _validate(strict_loads(bytes(buffer), MAX_OBSERVATION))
    return WorkspaceObservation(document_bytes=canonical_bytes(document, MAX_OBSERVATION),
                                digest=digest_object("integrity-claude-code-observation-v1", document),
                                observer_artifact_sha256=script_sha256)


def _checked(observation: WorkspaceObservation) -> dict:
    """Re-validate and re-derive the digest; a substituted document/identity is refused."""
    need(type(observation) is WorkspaceObservation and observation.signed is False, "observation_type")
    document = _validate(observation.document)
    need(digest_object("integrity-claude-code-observation-v1", document) == observation.digest,
         "observation_tampered")
    return document


def _exact(document: dict) -> bool:
    return (not document["truncated"] and document["skipped"] == 0 and document["unreadable"] == 0
            and document["unstable"] == 0 and type(document["head"]) is str
            and _HEAD.fullmatch(document["head"]) is not None)


def evaluate(pre: WorkspaceObservation, post: WorkspaceObservation, effects: list) -> dict:
    """Unsigned comparison of observed change against mediated write receipts."""
    need(type(effects) is list, "effects_shape")
    expected = {}
    for effect in effects:
        need(type(effect) is dict and effect.get("tool") in ("write_file", "edit_file")
             and _DIGEST.fullmatch(str(effect.get("post_sha256"))), "effect_shape")
        expected[effect["path"]] = effect["post_sha256"]
    first, second = _checked(pre), _checked(post)
    if not (_exact(first) and _exact(second)) or first["root"] != second["root"] \
            or pre.observer_artifact_sha256 != post.observer_artifact_sha256:
        outcome = "outcome-unknown"
    else:
        before, after = first["files"], second["files"]
        changed = {path for path in set(before) | set(after) if before.get(path) != after.get(path)}
        if first["head"] != second["head"]:
            outcome = "unexpected-state-observed"
        elif not changed and not expected:
            outcome = "pre-state-retained"
        elif changed == set(expected) and all(after.get(p) == d for p, d in expected.items()):
            outcome = "expected-transition-observed"
        else:
            outcome = "unexpected-state-observed"
    body = {"schema": "integrity-claude-code/observation-evaluation/v1", "outcome": outcome,
            "pre_observation": pre.digest, "post_observation": post.digest,
            "effects": len(effects), "observer_artifact_sha256": post.observer_artifact_sha256,
            "signed": False, "witness": False}
    return {**body, "digest": digest_object("integrity-claude-code-evaluation-v1", body)}


@dataclass(frozen=True)
class TransitionEvidence:
    """Host-supplied genuine inputs for the SDK terminal receipt (never built here)."""
    envelope: Any
    verification: dict   # manifest, adapter_key, proposal, proposer_key, operation_binding,
                         # operation_manifest, binding_key, coordinator_key, verified_grant
                         # (operation_key optional)
    executor_key: Any
    witness: Any         # VerifiedAdapterWitness from the host's independent observer, or None
    signer: Any          # host receipt signer
    receipt_key: Any


@dataclass(frozen=True)
class VerifiedTerminal:
    """Issued only by ``terminal_receipt`` after public-SDK verification and run binding."""
    descriptor_sha256: str
    attempt_path: str
    envelope_digest: str
    report_digest: str
    receipt_digest: str
    outcome: str
    witness_present: bool
    receipt_bytes: bytes = field(repr=False, default=b"")  # exact verified signed receipt
    _issuer: object = field(repr=False, compare=False, default=None)

    def receipt(self) -> dict:
        """Fresh copy of the verified signed receipt, for the host to persist and pass to
        AdapterAttemptJournal.record_terminal_receipt / recover and the closure route."""
        return strict_loads(self.receipt_bytes)


def terminal_receipt(custody: AttemptCustody, attempt_path: str, evidence: TransitionEvidence, *,
                     descriptor: dict) -> VerifiedTerminal:
    """Build + verify the SDK terminal receipt for THIS run's recorded report (public SDK)."""
    need(type(evidence) is TransitionEvidence, "transition_evidence")
    stored = custody.get(attempt_path)
    need(stored["phase"] == "executor-returned" and stored["report"] is not None
         and stored["report_digest"], "report_missing")
    need(stored["document_sha256"] == sha256_bytes(canonical_bytes(descriptor)), "foreign_run_descriptor")
    envelope = strict_loads(canonical_bytes(evidence.envelope))
    need(envelope == stored["envelope"], "foreign_run_envelope")
    sdk = _authority._load_sdk()
    try:
        receipt = sdk.adapter_runtime.build_adapter_transition_receipt_from_report(
            report=stored["report"], executor_key=evidence.executor_key, envelope=envelope,
            witness=evidence.witness, recorded_at=datetime.now(timezone.utc).isoformat(),
            signer=evidence.signer, **dict(evidence.verification))
        verified = sdk.adapter_sdk.verify_adapter_transition_receipt(
            receipt, receipt_key=evidence.receipt_key, executor_key=evidence.executor_key)
    except Exception:
        raise Rejected("terminal_receipt_rejected") from None
    envelope_digest = sdk.adapter_sdk.adapter_execution_envelope_digest(envelope)
    need(verified["envelope"] == {"envelope_id": envelope["envelope_id"],
                                  "envelope_digest": envelope_digest}, "terminal_receipt_binding")
    return VerifiedTerminal(descriptor_sha256=descriptor_digest(descriptor), attempt_path=attempt_path,
                            envelope_digest=envelope_digest, report_digest=stored["report_digest"],
                            receipt_digest=sha256_bytes(canonical_bytes(verified)),
                            outcome=verified["result"]["outcome"],
                            witness_present=evidence.witness is not None,
                            receipt_bytes=canonical_bytes(verified), _issuer=_ISSUER)


def closure_handoff(*, run_result: dict, terminal: VerifiedTerminal | None, evaluation: dict | None) -> dict:
    """Content-free routing document for the EXISTING closure route; never a completion.

    ``ready_for_closure_route`` requires an issued ``VerifiedTerminal`` bound to the same
    descriptor, a confirmed-success SDK outcome with a witness, and a local observation
    that does not contradict it. Dicts, foreign receipts or missing witnesses never set it.
    """
    issued = type(terminal) is VerifiedTerminal and terminal._issuer is _ISSUER
    bound = issued and terminal.descriptor_sha256 == run_result.get("descriptor_sha256")
    consistent = evaluation is not None and evaluation.get("outcome") in (
        "expected-transition-observed", "pre-state-retained")
    ready = bool(bound and terminal.outcome == "confirmed-success" and terminal.witness_present
                 and consistent)
    return {"schema": "integrity-claude-code/closure-handoff/v1",
            "descriptor_sha256": run_result.get("descriptor_sha256"),
            "provider_claim": run_result.get("classification"),
            "local_observation": None if evaluation is None else evaluation.get("outcome"),
            "local_observation_digest": None if evaluation is None else evaluation.get("digest"),
            "terminal_receipt_outcome": terminal.outcome if issued else None,
            "terminal_receipt_digest": terminal.receipt_digest if issued else None,
            "attempt_report_digest": terminal.report_digest if issued else None,
            "ready_for_closure_route": ready,
            "canonical_append_performed": False, "task_complete": False}
