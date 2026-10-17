"""One governed headless run.

    snapshot inputs -> rebind -> durable claim -> SDK launch authority (permit consumed)
      -> durable ``dispatching`` -> coordinator + relay config -> Job spawn -> supervise
      -> signed executor report + journal close -> ONLY THEN the ledger terminal state

The terminal (cacheable/resumable) ledger state is written only after the SDK
lifecycle completed. If the report, custody or journal close fails after the effect,
the run is recorded UNKNOWN and the session lease is held: duplicates and resumes are
refused. There is no caller-supplied gate; all inputs are deep-copied at construction.

Public entrypoint: ``ClaudeRun(...)`` -- native CLI profile only, and only with a
``VerifiedActivation`` for the policy's pinned activation artifact and a fresh
``AuthAttestation`` from ``auth.preflight_auth`` for this exact binary/environment.
``ClaudeRun._offline_fixture`` is an INTERNAL offline-test constructor (fixture profile,
interpreter prefix); it cannot run the native profile and grants nothing.
"""
from __future__ import annotations

import threading
from pathlib import Path

from .activation import VerifiedActivation
from .auth import AuthAttestation
from .authority import LAUNCH_CHANNEL, AuthoritySpent, SdkAuthority
from .canonical import Rejected, Unknown, canonical_bytes, need, sha256_bytes, strict_loads
from .coordinator import Coordinator
from .descriptor import _FIELDS, RUN_SCHEMA, rebind, run_argv
from .identity import environment_identity, executable_identity, is_within, require_plain_path
from .ledger import HOLDING, IN_FLIGHT, RunLedger
from .policy import CLI_PROFILE, FIXTURE_PROFILE, SERVER, TOOL_NAMES, ExecutorPolicy, cli_profile_blocker
from .record import empty_record, reason_of, validate_record
from .stream import ClaudeStream, classify

RUN_SCHEMA_DOCUMENT = {"schema_id": RUN_SCHEMA, "fields": sorted(_FIELDS)}
_REPORTED = {"completed": None, "not_started": "reported-failure",
             "cancelled_stopped": "reported-failure", "unknown": "outcome-unknown",
             "stop_unverified": "outcome-unknown"}


class ClaudeRun:
    def __init__(self, *, ledger: RunLedger, launch_authority: SdkAuthority,
                 tool_authority: SdkAuthority, policy: ExecutorPolicy, descriptor: dict,
                 executable: Path, cwd: Path, state_dir: Path, environment: dict, prompt: bytes,
                 relay_python: Path, relay_script: Path, activation: VerifiedActivation,
                 auth: AuthAttestation):
        """Production: native CLI profile, verified activation, fresh auth attestation."""
        self._setup(ledger=ledger, launch_authority=launch_authority, tool_authority=tool_authority,
                    policy=policy, descriptor=descriptor, executable=executable, cwd=cwd,
                    state_dir=state_dir, environment=environment, prompt=prompt,
                    relay_python=relay_python, relay_script=relay_script, prefix_tokens=())
        need(self.descriptor["profile"] == CLI_PROFILE, "production_requires_cli_profile")
        blocker = cli_profile_blocker(policy)
        need(blocker is None, blocker or "cli_profile")
        need(type(activation) is VerifiedActivation and activation.matches(policy, self.descriptor),
             "cli_activation_unverified")
        need(type(auth) is AuthAttestation, "auth_attestation_required")
        self._auth = auth
        self._check_auth()

    @classmethod
    def _offline_fixture(cls, *, prefix_tokens: tuple, **kwargs) -> "ClaudeRun":
        """INTERNAL, offline tests only: fixture profile with an interpreter prefix."""
        run = cls.__new__(cls)
        run._setup(prefix_tokens=prefix_tokens, **kwargs)
        need(run.descriptor["profile"] == FIXTURE_PROFILE, "offline_helper_requires_fixture_profile")
        run._auth = None
        return run

    def _check_auth(self, *, launching: bool = False) -> None:
        if self._auth is None:  # offline fixture profile only
            return
        need(self._auth.valid_for(executable_sha256=self.descriptor["executable"]["sha256"],
                                  environment_sha256=self.descriptor["environment"]["sha256"],
                                  policy_sha256=self._policy.digest()),
             "auth_attestation_stale_synthetic_or_foreign")
        if launching:  # managed policy must STILL match its pin at the moment of launch
            need(self._auth.managed_still_matches(self._policy), "managed_policy_changed")

    def _setup(self, *, ledger: RunLedger, launch_authority: SdkAuthority,
               tool_authority: SdkAuthority, policy: ExecutorPolicy, descriptor: dict,
               executable: Path, cwd: Path, state_dir: Path, environment: dict, prompt: bytes,
               relay_python: Path, relay_script: Path, prefix_tokens: tuple) -> None:
        need(type(launch_authority) is SdkAuthority and type(tool_authority) is SdkAuthority
             and launch_authority is not tool_authority, "authority_type")
        need(isinstance(policy, ExecutorPolicy), "policy_type")
        need(type(prompt) is bytes, "prompt_bytes")
        environment_identity(environment)  # validates names/values before snapshot
        self.ledger = ledger
        self._launch_authority, self._tool_authority = launch_authority, tool_authority
        self._policy = policy  # frozen dataclass of immutables
        self._descriptor = canonical_bytes(descriptor)            # immutable snapshot
        self._environment = tuple(sorted(dict(environment).items()))
        self._prompt = bytes(prompt)
        self._prefix = tuple(str(token) for token in prefix_tokens)
        self._executable, self._cwd = Path(executable), Path(cwd)
        self._state_dir = Path(state_dir)
        self._relay = (Path(relay_python), Path(relay_script))
        # Relay identity is checked before any claim/permit (and again by the coordinator).
        need(executable_identity(self._relay[0])["sha256"] == policy.relay_python_sha256,
             "relay_python_digest")
        need(sha256_bytes(require_plain_path(self._relay[1], "relay_script").read_bytes())
             == policy.relay_script_sha256, "relay_script_digest")
        self.binding: str | None = None
        self._claim = None
        self._pending: tuple | None = None     # (target, record, reason) awaiting SDK lifecycle
        self._cancel = threading.Event()
        self._lock = threading.Lock()          # ledger transitions
        self._launch_lock = threading.Lock()   # cancel vs. dispatch/resume serialization
        self.effects: list[dict] = []          # applied write receipts (for the observer)
        self.launch_attempt: str | None = None  # SDK attempt path of this launch

    @property
    def descriptor(self) -> dict:
        return strict_loads(self._descriptor)

    # -- ledger helpers -----------------------------------------------------------
    def _state(self) -> str:
        return self.ledger.run(self._claim.request_id)["state"]

    def _finish(self, target: str, record: dict, *, reason: str | None = None) -> dict:
        with self._lock:
            state = self._state()
            if target == "cancelled_stopped" and state == "running":
                self.ledger.advance(self._claim, "running", "cancel_requested")
                state = "cancel_requested"
            self.ledger.advance(self._claim, state, target, reason=reason, result=record)
        return {"cached": False, "state": target, **record}

    def _not_started_record(self, code: str) -> tuple:
        reason, winerror = reason_of(code)
        return ("not_started", empty_record("not_started", self.binding, reason=reason,
                                            winerror=winerror), reason)

    def _settle_unknown(self) -> None:
        """Post-effect SDK failure: durable UNKNOWN (lease held), never a cacheable state."""
        with self._lock:
            state = self._state()
        if state not in IN_FLIGHT:
            return
        if self._pending is None:
            record = empty_record("supervisor_error", self.binding, reason="launch_outcome_unknown")
            target = "unknown"
        else:
            target, record, _ = self._pending
            record = validate_record({**record, "reason": "launch_outcome_unknown"})
            target = target if target in HOLDING else "unknown"
        self._finish(target, record, reason="launch_outcome_unknown")

    # -- public ---------------------------------------------------------------------
    def cancel(self) -> dict:
        """Signal cancellation; durably record it when a process may exist. Never raises."""
        recorded = False
        try:
            with self._launch_lock:
                self._cancel.set()
                if self._claim is not None:
                    with self._lock:
                        state = self._state()
                        if state in ("dispatching", "running"):
                            self.ledger.advance(self._claim, state, "cancel_requested")
                            recorded = True
                        else:
                            recorded = state == "cancel_requested"
        except Exception:
            recorded = False
        finally:
            self._cancel.set()
        return {"signaled": True, "recorded": recorded}

    def execute(self) -> dict:
        need(not is_within(self.ledger.path, self._cwd), "ledger_inside_agent_workspace")
        self._check_auth(launching=True)  # fresh attestation + unchanged managed state
        descriptor = self.descriptor
        self.binding = rebind(descriptor, policy=self._policy, executable=self._executable,
                              cwd=self._cwd, state_dir=self._state_dir,
                              environment=dict(self._environment), prompt=self._prompt,
                              prefix_tokens=self._prefix)
        claim = self.ledger.claim(descriptor)
        if not claim["claimed"]:
            return {"cached": True, "state": claim["state"], **claim["result"]}
        self._claim = claim["claim"]
        need(self._claim.binding == self.binding, "binding_mismatch")
        if self._cancel.is_set():
            target, record, reason = self._not_started_record("cancelled_before_start")
            return self._finish(target, record, reason=reason)
        try:
            outcome = self._launch_authority.execute(
                schema_id=RUN_SCHEMA, schema=RUN_SCHEMA_DOCUMENT, document=descriptor,
                channel=LAUNCH_CHANNEL, effect=self._launch)
        except Rejected:
            target, record, reason = self._not_started_record("authority_denied")
            return self._finish(target, record, reason=reason)
        except AuthoritySpent:
            target, record, reason = self._not_started_record("authority_spent_not_started")
            return self._finish(target, record, reason=reason)
        except Unknown:
            self._settle_unknown()
            raise
        self.launch_attempt = outcome.attempt_path
        target, record, reason = self._pending  # SDK report + close succeeded
        result = self._finish(target, record, reason=reason)
        if target in HOLDING:
            raise Unknown("run_outcome_unknown_no_retry")
        return result

    # -- effect (runs after the launch permit was consumed) ------------------------
    def _launch(self) -> tuple:
        with self._launch_lock:
            cancelled = self._cancel.is_set()
            if not cancelled:
                with self._lock:
                    self.ledger.advance(self._claim, "claimed", "dispatching")
        self._pending = self._not_started_record("cancelled_before_start") if cancelled else self._spawn()
        target, record, _ = self._pending
        reported = _REPORTED[target] or (
            "reported-success" if record["classification"] == "reported_success" else "reported-failure")
        receipt = {"state": target, "classification": record["classification"],
                   "descriptor_sha256": self.binding}
        return target, reported, receipt

    def _spawn(self) -> tuple:
        from .winjob import JobProcess, NotStarted, StopUnverified, SupervisorFault  # Windows-only

        descriptor, limits = self.descriptor, self.descriptor["limits"]
        parser = ClaudeStream(descriptor["session_id"], max_line_bytes=limits["max_line_bytes"],
                              max_events=limits["max_events"], expected_model=descriptor["model"],
                              expected_tools=TOOL_NAMES, expected_mcp_servers=(SERVER,),
                              expected_version=descriptor["executable"]["version"],
                              expected_api_key_source=self._policy.expected_api_key_source,
                              expected_permission_mode="dontAsk")
        coordinator = None
        try:
            coordinator = Coordinator(
                authority=self._tool_authority, policy=self._policy, workspace=self._cwd,
                run_sha256=self.binding, session_id=descriptor["session_id"],
                run_id=descriptor["run_id"], config_path=Path(descriptor["mcp_config"]),
                relay_python=self._relay[0], relay_script=self._relay[1], on_unknown=self.cancel)
            coordinator.write_config()

            def started() -> None:
                with self._lock:
                    if self._state() == "dispatching":
                        self.ledger.advance(self._claim, "dispatching", "running")

            process = JobProcess(executable=self._executable,
                                 executable_sha256=descriptor["executable"]["sha256"],
                                 argv=run_argv(descriptor, self._policy, self._prefix), cwd=self._cwd,
                                 environment=dict(self._environment), stdin=self._prompt,
                                 limits=limits, stdout_sink=parser.feed, cancel=self._cancel,
                                 on_started=started, launch_lock=self._launch_lock)
            coordinator.start(process.contains_process)
        except (Rejected, OSError):
            if coordinator is not None:
                coordinator.stop(0)  # closes pipe, joins nothing started, removes config+nonce
            return self._not_started_record("preflight_rejected")
        try:
            job = process.run()
        except NotStarted as exc:
            return self._not_started_record(exc.code)
        except StopUnverified as exc:
            record = empty_record("supervisor_error", self.binding, reason="suspended_kill_unverified")
            record["stop"] = exc.stop
            return ("stop_unverified", validate_record(record), "suspended_kill_unverified")
        except SupervisorFault as exc:
            record = empty_record("supervisor_error", self.binding, reason="supervisor_exception")
            record.update(started=True, stop=exc.stop, stop_verified=exc.stop_verified)
            return ("unknown" if exc.stop_verified else "stop_unverified", validate_record(record),
                    "supervisor_exception")
        finally:
            coordinator.stop(limits["stop_grace_seconds"])
            self.effects = list(coordinator.effects)
        parser.finish()
        stream = parser.summary()
        classification = classify(stream, {"termination": job.termination, "exit_code": job.exit_code,
                                           "stdin_complete": job.stdin["complete"]})
        record = validate_record({
            "classification": classification, "reason": None, "winerror": None,
            "violation": stream["violation"], "descriptor_sha256": self.binding,
            "exit_code": job.exit_code, "termination": job.termination, "started": job.started,
            "stop_verified": job.stop_verified, "stop": job.stop,
            "orphans_terminated": job.orphans_terminated, "stdin": job.stdin,
            "stdout": job.stdout, "stderr": job.stderr, "events": stream["events"],
            "event_types": stream["event_types"], "init": stream["init"],
            "provider_result": stream["result"], "provider_claim_only": True,
            "verified_success": False, "tool_uses": stream["tool_uses"],
            "mediation": dict(coordinator.stats)})
        with self._lock:
            state = self._state()
        if not job.stop_verified:
            return ("stop_unverified", record, "stop_not_verified")
        if coordinator.unknown.is_set() or coordinator.failure:
            reason = "tool_effect_unknown" if coordinator.unknown.is_set() else "coordinator_failure"
            return ("unknown", record, reason)
        if state == "dispatching":  # resumed, but the durable running mark never landed
            return ("unknown", record, "running_mark_missing")
        if state == "cancel_requested" or job.termination == "cancelled":
            return ("cancelled_stopped", record, None)
        return ("completed", record, None)
