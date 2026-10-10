"""Staging serial coordinator. No enabled production adapters or command runner.

Read/draft workers can prepare concurrently using check_preparation(). Only a
ready immutable batch can claim the queue and acquire the existing v2 writer.
One batch owns that writer through all actions, release, and the paired verified
checkpoint. A process crash/lost token needs separately reviewed recovery; there
is intentionally no resume, timeout takeover, automatic retry, or backup bypass.
"""
from dataclasses import dataclass, field
import hashlib
import json
import threading
from typing import Protocol

from checkpoint_pair import ExpectedPair, verify_pair
from dispatch_gate import (CommandResult, DispatchGate, GateBlocked, HASH,
                           LedgerIdentity, PENDING, action_id, canonical,
                           completed_json, parse_json, payload_hash, require,
                           successful)
from queue_core import QueueCore, QueueError, SlotError


def _copy(value):
    """Adapters cannot mutate the coordinator's hash-bound nested payload."""
    return parse_json(canonical(value))


class LedgerAdapter(Protocol):
    identity: LedgerIdentity

    def execute(self, command: str, **arguments) -> CommandResult:
        """Run ONLY this pinned ledger; preserve v2's actual JSON response shape.

        The token argument must stay private, never in logged command transcripts.
        No implemented adapter or subprocess execution is shipped in this staging.
        """
        ...


class BrowserAdapter(Protocol):
    def observe(self, binding: dict) -> CommandResult: ...
    def preflight(self, action: dict, binding: dict) -> CommandResult: ...
    def mutate(self, action: dict, binding: dict, intent_id: str, *,
               slot_start: int, slot_deadline: int) -> CommandResult:
        """Exactly one separately authorized mutation; atomically check binding.

        Must never switch to a replacement tab/account, retry, or invoke a backup
        action. Return definitive denial as ok=false, outcome=denied; ambiguity
        must not be described as submission. Exceptions consume the permit.
        Pin BOTH provided slot boundaries and check slot_start <= current_time <
        slot_deadline immediately before the actual tool dispatch, including after
        any internal delay. An expired or rolled-back clock must never dispatch.
        """
        ...
    def readback(self, action: dict, binding: dict, intent_id: str) -> CommandResult: ...


class AuthorizationAdapter(Protocol):
    def authorize_batch(self, job: dict, actions: list[dict]) -> CommandResult:
        """Attest existing role-specific kinds and remaining per-run/per-kind quota.

        The 100-action technical serialization bound is NEVER user permission or
        an increased quota. A reviewed adapter must enforce the actual user's
        current policy and historical usage for the scheduled run; it must not
        derive approval/limits from this proposed batch. No such adapter ships.
        """
        ...

    def authorize(self, job: dict, action: dict) -> CommandResult:
        """Recheck exact authorization and the same role/quota policy reference."""
        ...


class UnavailableAdapter:
    """Safe default: there is no browser or production ledger integration."""
    identity = None

    def __getattr__(self, name):
        def unavailable(*args, **kwargs):
            raise GateBlocked("No reviewed adapter is enabled in staging")
        return unavailable


@dataclass(frozen=True)
class CoordinationResult:
    state: str
    job_id: str | None = None
    reason: str = ""
    checkpoint_sequence: int | None = None


@dataclass
class _Run:
    claim: object = field(repr=False)
    job: dict = field(repr=False)
    owner: str
    policy: dict = field(default_factory=dict, repr=False)
    token: str | None = field(default=None, repr=False)
    session: str | None = None
    initial_checkpoint_sequence: int | None = None
    active_action: str | None = None
    checkpoint_sequence: int | None = None
    result_digest: str | None = None
    checkpoint_id: str | None = None
    state: str = "dispatching"


class SerialCoordinator:
    def __init__(self, queue: QueueCore, ledger_identity: LedgerIdentity, *, clock,
                 dispatcher_id="staging-central-dispatcher", ledger=None,
                 browser=None, authorization=None):
        self.queue = queue
        self.gate = DispatchGate(ledger_identity, clock)
        self.clock = clock
        self.dispatcher_id = dispatcher_id
        self.ledger = ledger or UnavailableAdapter()
        self.browser = browser or UnavailableAdapter()
        self.authorization = authorization or UnavailableAdapter()
        self._run = None
        self._lock = threading.Lock()

    def _execute(self, command, **arguments):
        require(self.ledger.identity == self.gate.identity, "Ledger adapter identity is unpinned")
        return self.ledger.execute(command, **arguments)

    def _status(self):
        return self.gate.status(self._execute("status"))

    def check_preparation(self):
        """Valid status permits read/draft preparation despite writer/STOP/backup.

        This grants no browser mutation and does not acquire either writer.
        Individual role workers still own only their fixed registered tab.
        """
        return self._status()

    @staticmethod
    def _binding(job):
        return {"role": job["role"], "worker_id": job["worker_id"],
                "browser_id": job["browser_id"], "tab_id": job["tab_id"],
                "account": job["expected_account"]}

    def _record_binding(self, binding, observation):
        self.gate.binding(observation, binding)
        return self.queue.record_observation(
            binding["role"], worker_id=binding["worker_id"], browser_id=binding["browser_id"],
            tab_id=binding["tab_id"], observed_account=observation["account"],
            tab_exists=observation["exists"], observed_at=observation["observed_at"],
            now=self.clock())

    def _observe(self, binding):
        value = successful(self.browser.observe(dict(binding)))
        return self._record_binding(binding, value.get("binding"))

    def _actions(self, job):
        payload = parse_json(job["payload_json"])
        require(type(payload) is dict and set(payload) == {"actions"} and
                type(payload["actions"]) is list and len(payload["actions"]) <= 100,
                "Exact bounded prepared action batch required")
        result, seen = [], set()
        for value in payload["actions"]:
            require(type(value) is dict and set(value) ==
                    {"kind", "target", "payload", "authorization_id"},
                    "Exact action/target/payload/authorization reference required")
            require(type(value["authorization_id"]) is str and bool(value["authorization_id"]),
                    "An authorization reference is required")
            require(type(value["payload"]) is dict and value["payload"].get("target") == value["target"],
                    "Canonical outbound payload must include the exact target")
            value = dict(value)
            value["payload_hash"] = payload_hash(value["payload"])
            value["action_id"] = action_id(self.gate.identity.account, value["kind"], value["target"])
            require(value["action_id"] not in seen, "Duplicate actions within one prepared batch")
            seen.add(value["action_id"])
            result.append(value)
        return result

    def _authorize(self, run, action):
        value = successful(self.authorization.authorize(_copy(run.job), _copy(action)))
        expected = {"authorized": True, "account": self.gate.identity.account,
                    "role": run.job["role"], "authorization_id": action["authorization_id"],
                    "kind": action["kind"], "target": action["target"],
                    "payload_hash": action["payload_hash"],
                    "policy_reference": run.policy["policy_reference"]}
        require(all(type(value.get(k)) is type(v) and value.get(k) == v for k, v in expected.items()),
                "Exact authorized action, target, and payload do not match")

    def _authorize_batch(self, job, actions):
        value = successful(self.authorization.authorize_batch(_copy(job), _copy(actions)))
        expected = {"authorized": True, "account": self.gate.identity.account,
                    "role": job["role"], "batch_payload_hash": job["payload_hash"]}
        require(all(type(value.get(k)) is type(v) and value.get(k) == v for k, v in expected.items()),
                "Existing scheduled role/batch authorization does not match")
        require(type(value.get("policy_reference")) is str and bool(value["policy_reference"]),
                "Existing role and quota policy reference required")
        kinds, quota = value.get("allowed_kinds"), value.get("per_kind_limits")
        require(type(kinds) is list and all(type(kind) is str for kind in kinds) and
                len(kinds) == len(set(kinds)) and type(quota) is dict and
                set(quota) == set(kinds) and all(type(n) is int and n >= 0 for n in quota.values()),
                "Exact role-specific action kinds and remaining per-kind quotas required")
        require(type(value.get("max_actions")) is int and value["max_actions"] >= len(actions),
                "Prepared batch exceeds the existing authorized remaining run quota")
        counts = {}
        for action in actions:
            kind = action["kind"]
            require(kind in kinds, "Prepared action kind is not authorized for this role")
            counts[kind] = counts.get(kind, 0) + 1
        require(all(count <= quota[kind] for kind, count in counts.items()),
                "Prepared actions exceed the existing authorized per-kind quota")
        return value

    def _owned_status(self, run):
        return self.gate.write_status(self._status(), run.owner, run.job["role"], run.session)

    def _progress(self, run, action, state, **result):
        return self.queue.record_action_progress(run.claim, action, state,
                                                 result=result, now=self.clock())

    def _block(self, run, reason, *, unknown=False, denied=False):
        # Never include raw adapter errors/output: acquire may contain a token.
        if run is not None:
            if run.active_action:
                if unknown and run.token:
                    try:
                        self.gate.transition(self._execute("unknown", owner=run.owner,
                            token=run.token, action=run.active_action, reason=reason),
                            run.active_action, "unknown")
                    except Exception:
                        pass  # Existing intent and queue ownership still block everything.
                try:
                    self._progress(run, run.active_action,
                                   "denied_unresolved" if denied else "uncertain", reason=reason)
                except Exception:
                    pass
            try:
                self.queue.block_claim(run.claim, reason, now=self.clock())
            except Exception:
                pass
            run.state = "blocked"
        return CoordinationResult("blocked", run.claim.job_id if run else None, reason)

    def run_once(self):
        """Dispatch one prepared batch or return wait/idle/blocked/needs_checkpoint.

        A WAIT is bounded by each queued job's own next-same-role slot, never by a
        writer lease. The next call expires only unclaimed preparation, not owners.
        """
        if not self._lock.acquire(blocking=False):
            return CoordinationResult("wait", reason="Central dispatcher is already running")
        try:
            if self._run is not None:
                return CoordinationResult(self._run.state, self._run.claim.job_id,
                    "Existing batch retains queue ownership", self._run.checkpoint_sequence)
            snapshot = self.queue.snapshot()
            require(snapshot["meta"]["ledger_db_id"] == self.gate.identity.db_id,
                    "Queue pins a different ledger database")
            if snapshot["dispatcher"]["job_id"] is not None:
                owned = next((j for j in snapshot["jobs"] if
                              j["job_id"] == snapshot["dispatcher"]["job_id"]), None)
                if owned is not None and owned["state"] == "blocked":
                    return CoordinationResult("blocked", owned["job_id"],
                                              "Existing unresolved queue owner requires audit; no takeover")
                return CoordinationResult("wait", reason="Existing queue owner must finish its checkpoint")
            status = self._status()
            if status["stops"] or any(a["state"] in PENDING for a in status["actions"]):
                return CoordinationResult("blocked", reason="Ledger STOP/unresolved action remains")
            jobs = sorted((j for j in snapshot["jobs"] if j["state"] == "ready" and
                           self.clock() < j["next_same_role_at"]),
                          key=lambda j: (j["scheduled_at"], j["created_at"], j["role"]))
            if not jobs:
                # claim_next performs durable expiry without acquiring a writer.
                self.queue.claim_next(self.dispatcher_id, {}, now=self.clock())
                return CoordinationResult("idle", reason="No ready unexpired batch")
            if status["writer"] is not None or status["checkpoint_pending"]:
                return CoordinationResult("wait", reason="Ledger writer/checkpoint remains occupied")
            self.gate.write_status(status)
            job = jobs[0]
            actions = self._actions(job)  # Validate immutable shape before ownership.
            policy = self._authorize_batch(job, actions)
            evidence = self._observe(self._binding(job))
            claim = self.queue.claim_next(self.dispatcher_id, {job["role"]: evidence}, now=self.clock())
            if claim is None:
                return CoordinationResult("wait", reason="Another dispatcher already owns the queue")
            job = self.queue.inspect_job(claim.job_id)
            require(job["payload_hash"] == policy["batch_payload_hash"] and job["role"] == policy["role"],
                    "Claimed batch differs from authorized batch")
            run = self._run = _Run(claim, job, f'{job["role"]}.{job["scheduled_at"]}', policy)
            self.queue.register_action_manifest(claim, [action["action_id"] for action in self._actions(job)],
                                                now=self.clock())
            self.queue.validate_action_start(claim, evidence, now=self.clock())
            self.gate.write_status(self._status())
            acquired = self.gate.acquired(self._execute("acquire", owner=run.owner,
                                                       role=job["role"]), run.owner)
            run.token, run.session = acquired["token"], acquired["session"]
            run.initial_checkpoint_sequence = self._owned_status(run)["checkpoint_seq"]
            return self._dispatch_batch(run)
        except Exception:
            return self._block(self._run, "Strict dispatch gate or adapter failed; no automatic retry")
        finally:
            self._lock.release()

    def _dispatch_batch(self, run):
        binding = self._binding(run.job)
        for action in self._actions(run.job):
            key = action["action_id"]
            if self.clock() >= run.job["next_same_role_at"]:
                self._progress(run, key, "cancelled", reason="Unstarted action expired in its same-role slot")
                continue
            run.active_action = key
            self._authorize(run, action)
            self._owned_status(run)
            evidence_id = self._observe(binding)
            self.queue.validate_action_start(run.claim, evidence_id, now=self.clock())
            claimed = self.gate.claim(self._execute("claim", owner=run.owner, token=run.token,
                kind=action["kind"], target=action["target"], payload_hash=action["payload_hash"]), key)
            if claimed["duplicate"]:
                self._progress(run, key, "duplicate", ledger_state=claimed["state"],
                               payload_matches=claimed["payload_matches"])
                run.active_action = None
                continue
            self._progress(run, key, "reserved")
            preflight = successful(self.browser.preflight(_copy(action), dict(binding)))
            outcome = preflight.get("evidence", {}).get("outcome")
            require(outcome in ("absent", "present"), "Preflight must establish actual presence/absence")
            evidence_path = self.gate.evidence(preflight, action, binding, None, outcome)
            evidence_id = self._record_binding(binding, preflight["binding"])
            self._owned_status(run)
            if outcome == "present":
                self.gate.transition(self._execute("verify", owner=run.owner, token=run.token,
                    action=key, evidence=evidence_path), key, "already_present")
                self._progress(run, key, "already_present")
                run.active_action = None
                continue
            if self.clock() >= run.job["next_same_role_at"]:
                self.gate.transition(self._execute("cancel", owner=run.owner, token=run.token,
                    action=key), key, "cancelled")
                self._progress(run, key, "cancelled", reason="Reservation expired before write intent")
                run.active_action = None
                continue
            self.queue.validate_action_start(run.claim, evidence_id, now=self.clock())
            permit = self.gate.intent(self._execute("begin-write", owner=run.owner, token=run.token,
                action=key, evidence=evidence_path), key, run.job["next_same_role_at"],
                not_before=run.job["scheduled_at"])
            self._progress(run, key, "intent", intent_id=permit.intent_id)
            # Recheck the attested fixed binding and deadline immediately before
            # the callback; adapter must also refuse any changed browser identity.
            self.gate.binding(preflight["binding"], binding)
            self.queue.validate_action_start(run.claim, evidence_id, now=self.clock())
            try:
                require(payload_hash(action["payload"]) == action["payload_hash"],
                        "Outbound action payload changed after authorization")
                raw = permit.dispatch(lambda: self.browser.mutate(_copy(action), dict(binding), permit.intent_id,
                    slot_start=run.job["scheduled_at"], slot_deadline=run.job["next_same_role_at"]))
                result = completed_json(raw)
                if (result.get("ok") is False and result.get("outcome") == "denied" and
                        result.get("action_id") == key and result.get("intent_id") == permit.intent_id):
                    return self._block(run, "Definitive reviewer denial awaits separately authorized audit finalization",
                                       unknown=True, denied=True)
                require(result.get("ok") is True and result.get("outcome") == "submitted" and
                        result.get("action_id") == key and result.get("intent_id") == permit.intent_id,
                        "Browser submission result is uncertain")
            except Exception:
                return self._block(run, "Browser result uncertain; do not retry", unknown=True)
            self.gate.transition(self._execute("submitted", owner=run.owner, token=run.token,
                                               action=key), key, "submitted_unverified")
            self._progress(run, key, "submitted", intent_id=permit.intent_id)
            # A passed slot deadline cannot interrupt an already-started readback.
            readback = successful(self.browser.readback(_copy(action), dict(binding), permit.intent_id))
            path = self.gate.evidence(readback, action, binding, permit.intent_id, "present")
            self.gate.transition(self._execute("verify", owner=run.owner, token=run.token,
                                               action=key, evidence=path), key, "verified")
            self._progress(run, key, "verified", intent_id=permit.intent_id)
            run.active_action = None
        require(self._owned_status(run)["checkpoint_seq"] == run.initial_checkpoint_sequence,
                "Checkpoint sequence changed while this batch owned the writer")
        release = self.gate.release(self._execute("release", owner=run.owner, token=run.token))
        require(release["checkpoint_seq"] == run.initial_checkpoint_sequence + 1,
                "Release did not advance exactly one checkpoint sequence")
        run.token = None
        status = self._status()
        require(status["checkpoint_pending"] is True and status["writer"] is None and
                status["checkpoint_seq"] == release["checkpoint_seq"] and not status["stops"] and
                not any(a["state"] in PENDING | {"reserved"} for a in status["actions"]),
                "Released ledger checkpoint boundary is not confirmed")
        progress = self.queue.list_action_progress(run.claim)
        run.result_digest = hashlib.sha256(canonical(progress).encode()).hexdigest()
        run.checkpoint_sequence = release["checkpoint_seq"]
        run.checkpoint_id = f'{self.gate.identity.db_id}:{run.checkpoint_sequence}'
        self.queue.enter_checkpoint_wait(run.claim, run.checkpoint_id, run.result_digest, now=self.clock())
        run.state = "needs_checkpoint"
        return CoordinationResult("needs_checkpoint", run.claim.job_id,
                                  "Released ledger; paired verified checkpoint still required",
                                  run.checkpoint_sequence)

    def complete_checkpoint(self, *, receipt_path, receipt_sha256,
                            pair_manifest, expected_pair: ExpectedPair):
        """No upload here. Caller supplies independently pinned, reviewed snapshots.

        Both verified downloads AND the unchanged ledger checkpoint-ack plus fresh
        exact status are required. Caller flags such as verified=True are rejected.
        An uncertain ack is not automatically retried by this coordinator.
        """
        with self._lock:
            run = self._run
            try:
                require(run is not None and run.state == "needs_checkpoint",
                        "No completed batch is waiting for its checkpoint")
                expected_pair.validate()
                require((expected_pair.account, expected_pair.ledger_db_id,
                         expected_pair.queue_db_id, expected_pair.checkpoint_id,
                         expected_pair.checkpoint_sequence, expected_pair.result_digest,
                         expected_pair.registry_revision) ==
                        (self.gate.identity.account, self.gate.identity.db_id,
                         self.queue.identity.db_id, run.checkpoint_id,
                         run.checkpoint_sequence, run.result_digest, run.job["generation"]),
                        "Checkpoint pair does not bind this exact completed batch")
                # Successful prior queue boundaries are the local anchor for all
                # later companion replacements.  The first boundary remains an
                # explicitly pinned trusted-transport responsibility.
                snapshot = self.queue.snapshot()
                prior = [parse_json(job["checkpoint_proof_json"]) for job in snapshot["jobs"]
                         if job["state"] == "done"]
                require(all(type(p) is dict and type(p.get("checkpoint_sequence")) is int
                            for p in prior), "Prior companion checkpoint proof is malformed")
                if prior:
                    last = max(prior, key=lambda p: p["checkpoint_sequence"])
                    require(last["checkpoint_sequence"] == snapshot["meta"]["last_checkpoint_sequence"]
                            and sum(p["checkpoint_sequence"] == last["checkpoint_sequence"] for p in prior) == 1,
                            "Prior companion checkpoint boundary is ambiguous or inconsistent")
                    require(expected_pair.queue_library_file_id == last.get("queue_library_file_id")
                            and expected_pair.queue_previous_version == last.get("queue_library_version")
                            and expected_pair.queue_library_version != last.get("queue_library_version"),
                            "Companion Library identity or exact version chain does not continue")
                else:
                    require(snapshot["meta"]["last_checkpoint_sequence"] == 0,
                            "Prior completed companion checkpoint proof is missing")
                verified_pair = verify_pair(pair_manifest, expected_pair, now=self.clock())
                data = self.gate._bounded_file(receipt_path)
                require(HASH.fullmatch(receipt_sha256) and
                        hashlib.sha256(data).hexdigest() == receipt_sha256,
                        "Checkpoint receipt file hash mismatch")
                receipt = parse_json(data.decode("utf-8"))
                expected_fields = {"account": expected_pair.account,
                    "schema": "library-checkpoint-roundtrip-v1",
                    "db_id": expected_pair.ledger_db_id, "checkpoint_seq": run.checkpoint_sequence,
                    "checkpoint_hash": expected_pair.ledger_checkpoint_hash,
                    "archive_sha256": expected_pair.ledger_archive_sha256,
                    "library_file_id": expected_pair.ledger_library_file_id,
                    "library_version": expected_pair.ledger_library_version,
                    "previous_version": expected_pair.ledger_previous_version,
                    "downloaded_archive": expected_pair.ledger_downloaded_archive,
                    "transport_reference": verified_pair.ledger_transport_reference}
                require(type(receipt) is dict and all(type(receipt.get(k)) is type(v) and
                        receipt.get(k) == v for k, v in expected_fields.items()),
                        "Ledger ack receipt differs from verified pair")
                require(type(receipt.get("verified_at")) is int and
                        self.clock() - 300 <= receipt["verified_at"] <= self.clock(),
                        "Ledger checkpoint receipt is stale or future-dated")
                # Mark an attempt before issuing it. A lost response requires audit;
                # a repeated public call cannot blindly retry the acknowledgement.
                run.state = "checkpoint_ack_in_progress"
                ack = successful(self._execute("checkpoint-ack", record=receipt_path, sha256=receipt_sha256))
                require(ack.get("checkpoint_pending") is False and
                        type(ack.get("checkpoint_seq")) is int and ack["checkpoint_seq"] == run.checkpoint_sequence and
                        ack.get("checkpoint_hash") == expected_pair.ledger_checkpoint_hash and
                        ack.get("archive_sha256") == expected_pair.ledger_archive_sha256 and
                        ack.get("may_dispatch") is False, "Wrong checkpoint-ack response")
                status = self._status()
                require(status["checkpoint_pending"] is False and status["writer"] is None
                        and not status["stops"] and not any(a["state"] in PENDING | {"reserved"}
                        for a in status["actions"]), "Post-ack status remains unsafe")
                require((status["checkpoint_seq"], status.get("checkpoint_archive_hash"),
                         status.get("checkpoint_library_id"), status.get("checkpoint_library_version")) ==
                        (run.checkpoint_sequence, expected_pair.ledger_archive_sha256,
                         expected_pair.ledger_library_file_id, expected_pair.ledger_library_version),
                        "Post-ack status differs from exact pair")
                fields = verified_pair.checkpoint_proof_fields()
                keys = ("checkpoint_id", "result_digest", "ledger_db_id", "account",
                        "checkpoint_sequence", "checkpoint_hash", "library_file_id", "library_version",
                        "archive_sha256", "pair_manifest_sha256", "queue_archive_sha256",
                        "queue_library_file_id", "queue_library_version", "queue_previous_version")
                proof = {key: fields[key] for key in keys}
                proof.update(pending=False, writer=None, stop=False, unresolved=False)
                self.queue.acknowledge_checkpoint(run.claim, proof, now=self.clock())
                job_id = run.claim.job_id
                self._run = None
                return CoordinationResult("done", job_id, "Ledger and queue checkpoint pair verified")
            except Exception:
                if run is not None and run.state == "needs_checkpoint":
                    return CoordinationResult("needs_checkpoint", run.claim.job_id,
                        "Checkpoint pair validation failed; ownership retained", run.checkpoint_sequence)
                return self._block(run, "Checkpoint acknowledgement uncertain or mismatched; audit required")
