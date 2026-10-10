"""Staging-only goal coordinator and pure reviewed-candidate planner.

No browser/client, remote database, scheduler, activation or authorization
producer is present. The dispatch method is the frozen core method with only
three goal-related additions. Its byte-for-byte baseline is pinned below.
"""
from dataclasses import dataclass, asdict
import hashlib
from pathlib import Path
import re

import coordinator as frozen_coordinator
from coordinator import SerialCoordinator, CoordinationResult, _copy
from dispatch_gate import (PENDING, action_id, canonical, completed_json,
                           parse_json, payload_hash, require, successful)

FROZEN_COORDINATOR_SHA256 = "d740ea1c456f6e418aa2feeaff95c70ea9f6481260d4e2cbe4984c8198cd3785"
OBJECTIVE_BY_ROLE = {"spreader": ("repost", 5), "publisher": ("publish", 1)}
RAW_ACTION_KEYS = {"kind", "target", "payload", "authorization_id"}
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")


def validated_objective(policy, role):
    """Validate trusted adapter output; this does not authenticate that adapter."""
    require(type(policy) is dict, "Exact batch policy required")
    if role == "commenter":
        require(policy.get("objective") is None, "Commenter has no numeric goal")
        return None
    require(role in OBJECTIVE_BY_ROLE and "objective" in policy,
            "Explicit reviewed role goal and current-run history required")
    obj = policy["objective"]
    require(type(obj) is dict and set(obj) ==
            {"kind", "newly_verified_goal", "already_newly_verified"},
            "Exact reviewed objective fields required")
    kind, goal = OBJECTIVE_BY_ROLE[role]
    require(type(obj["kind"]) is str and obj["kind"] == kind and
            type(obj["newly_verified_goal"]) is int and obj["newly_verified_goal"] == goal and
            type(obj["already_newly_verified"]) is int and
            0 <= obj["already_newly_verified"] <= goal,
            "Objective must match exact role and bounded independent run history")
    return dict(obj)


def _plan_digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _plan_reference(value):
    require(type(value) is str and _REFERENCE.fullmatch(value) is not None,
            "Bounded non-secret review reference required")
    return value


def _raw_action(value, account):
    require(type(value) is dict and set(value) == RAW_ACTION_KEYS,
            "Exact reviewed raw action required")
    value = _copy(value)
    require(value["kind"] in {"repost", "like", "reply", "follow"},
            "Spreader planner accepts only reviewed spreader actions")
    p = value["payload"]
    expected = {"target", "text"} if value["kind"] == "reply" else {"target"}
    require(type(p) is dict and set(p) == expected and p.get("target") == value["target"],
            "Exact target and payload required before planning")
    if value["kind"] == "reply":
        require(type(p["text"]) is str and bool(p["text"].strip()), "Reviewed reply text required")
    _plan_reference(value["authorization_id"])
    return value, action_id(account, value["kind"], value["target"])


@dataclass(frozen=True)
class CandidatePlan:
    """Immutable local sidecar, never an approval or extra outbound payload field."""
    plan_id: str
    account: str
    scheduled_at: int
    next_same_role_at: int
    already_newly_verified: int
    manifest_json: str
    groups_json: str
    observations_json: str
    reserve_target: int
    source_exhausted: bool

    @property
    def selected_reposts(self):
        return sum(a["kind"] == "repost" for a in parse_json(self.manifest_json)["actions"])

    @property
    def required_new(self):
        return 5 - self.already_newly_verified

    @property
    def goal_shortfall(self):
        return max(0, self.required_new - self.selected_reposts)

    @property
    def reserve_count(self):
        return max(0, self.selected_reposts - self.required_new)

    @property
    def batch_payload_hash(self):
        return payload_hash(parse_json(self.manifest_json))

    def _identity(self):
        return {"schema": "reviewed-repost-candidate-plan-v1", "account": self.account,
                "role": "spreader", "scheduled_at": self.scheduled_at,
                "next_same_role_at": self.next_same_role_at,
                "already_newly_verified": self.already_newly_verified,
                "manifest": parse_json(self.manifest_json),
                "groups": parse_json(self.groups_json),
                "observations": parse_json(self.observations_json),
                "reserve_target": self.reserve_target, "source_exhausted": self.source_exhausted}

    def validate(self):
        require(_plan_digest(self._identity()) == self.plan_id, "Immutable plan identity mismatch")
        ids, auths, reposts = set(), set(), []
        body = parse_json(self.manifest_json)
        require(type(body) is dict and set(body) == {"actions"} and
                type(body["actions"]) is list and len(body["actions"]) <= 100,
                "Exact bounded plan manifest required")
        for raw in body["actions"]:
            action, key = _raw_action(raw, self.account)
            require(key not in ids and action["authorization_id"] not in auths,
                    "Duplicate canonical action or authorization in plan")
            ids.add(key); auths.add(action["authorization_id"])
            if action["kind"] == "repost": reposts.append(key)
        groups = parse_json(self.groups_json)
        require(type(groups) is list and all(type(g) is dict and set(g) ==
                {"group_id", "review_reference", "action_ids"} and type(g["action_ids"]) is list and
                bool(g["action_ids"]) and g["action_ids"][0] == g["group_id"] for g in groups) and
                [g.get("group_id") for g in groups] == reposts and
                [key for g in groups for key in g.get("action_ids", [])] ==
                [action_id(self.account, a["kind"], a["target"]) for a in body["actions"]],
                "Plan groups must cover the ordered unique manifest exactly")
        return self

    def prepared_payload(self, *, allow_shortfall=False):
        self.validate()
        require(type(allow_shortfall) is bool, "Explicit partial-plan decision required")
        require(self.goal_shortfall == 0 or allow_shortfall,
                f"Reviewed supply is short by {self.goal_shortfall} new repost(s)")
        return parse_json(self.manifest_json)

    def summary(self):
        return {"plan_id": self.plan_id, "reviewed_candidates": len(parse_json(self.observations_json)),
                "selected_reposts": self.selected_reposts, "required_new": self.required_new,
                "pre_reviewed_reserves": self.reserve_count, "goal_shortfall": self.goal_shortfall,
                "source_exhausted": self.source_exhausted,
                "status": "sufficient_reviewed_supply" if self.goal_shortfall == 0 else "insufficient_reviewed_supply"}


class NativeRepostPlanner:
    """Ingest sequential trusted read-review observations before mark_ready.

    It performs no tools/I/O and never fetches candidates or supplies permission.
    The native reviewer supplies exact target/payload and a review reference.
    Keep reviewing while needs_more_reviews is true, unless supply is exhausted.
    Each accepted root and its independently reviewed conditional actions form
    one canonical group. Repeated canonical replies are removed across groups.
    """
    def __init__(self, account, scheduled_at, next_same_role_at, *,
                 already_newly_verified=0, reserve_target=2):
        require(type(account) is str and re.fullmatch(r"[a-z0-9_.]{1,64}", account),
                "Canonical account required")
        require(type(scheduled_at) is int and scheduled_at >= 0 and
                type(next_same_role_at) is int and next_same_role_at > scheduled_at,
                "Exact same-role slot boundaries required")
        validated_objective({"objective": {"kind": "repost", "newly_verified_goal": 5,
            "already_newly_verified": already_newly_verified}}, "spreader")
        require(type(reserve_target) is int and 0 <= reserve_target <= 95, "Bounded explicit reserves required")
        self.account, self.scheduled_at, self.next_same_role_at = account, scheduled_at, next_same_role_at
        self.already_newly_verified, self.reserve_target = already_newly_verified, reserve_target
        self._actions, self._groups, self._observations = [], [], []
        self._seen_candidates, self._action_ids, self._auth_ids, self._reviews = set(), set(), set(), set()
        self._frozen = False

    @property
    def needs_more_reviews(self):
        required = 5 - self.already_newly_verified
        return not self._frozen and required > 0 and len(self._groups) < required + self.reserve_target and len(self._actions) < 100

    def review(self, action, *, review_reference, qualified, already_present=False,
               ledger_duplicate=False, related_actions=()):
        require(not self._frozen, "Plan is frozen; no silent append after mark_ready")
        require(self.needs_more_reviews, "Requested reviewed supply is already full")
        _plan_reference(review_reference)
        require(review_reference not in self._reviews, "Review reference has already been consumed")
        require(all(type(x) is bool for x in (qualified, already_present, ledger_duplicate)),
                "Exact reviewed candidate facts required")
        require(type(related_actions) in (tuple, list), "Explicit reviewed conditional action list required")
        root, key = _raw_action(action, self.account)
        require(root["kind"] == "repost", "Candidate root must be a native repost")
        related = [_raw_action(a, self.account) for a in related_actions]
        require(all(a["kind"] != "repost" for a, _ in related), "Each group has exactly one repost candidate")
        reason = ("duplicate_candidate" if key in self._seen_candidates else
                  "already_present" if already_present else "ledger_duplicate" if ledger_duplicate else
                  "unqualified" if not qualified else None)
        if reason is not None:
            self._reviews.add(review_reference); self._seen_candidates.add(key)
            self._observations.append({"review_reference": review_reference, "group_id": key,
                                       "outcome": reason, "skipped_related": []})
            return False
        additions, added_ids, auths, skipped = [(root, key)], {key}, {root["authorization_id"]}, []
        require(root["authorization_id"] not in self._auth_ids, "Authorization reference reused across actions")
        for item, item_id in related:
            if item_id in self._action_ids or item_id in added_ids:
                skipped.append({"action_id": item_id, "reason": "duplicate_canonical_action"})
                continue
            require(item["authorization_id"] not in self._auth_ids | auths,
                    "Authorization reference reused across actions")
            additions.append((item, item_id)); added_ids.add(item_id); auths.add(item["authorization_id"])
        require(len(self._actions) + len(additions) <= 100, "Reviewed group exceeds immutable technical batch bound")
        self._reviews.add(review_reference); self._seen_candidates.add(key)
        self._actions.extend(item for item, _ in additions)
        self._action_ids.update(added_ids); self._auth_ids.update(auths)
        self._groups.append({"group_id": key, "review_reference": review_reference,
                             "action_ids": [item_id for _, item_id in additions]})
        self._observations.append({"review_reference": review_reference, "group_id": key,
                                   "outcome": "selected", "skipped_related": skipped})
        return True

    def freeze(self, *, source_exhausted=False):
        require(not self._frozen and type(source_exhausted) is bool, "Exact one-time plan freeze required")
        require(not self.needs_more_reviews or source_exhausted,
                "Continue reviewing candidates/reserves before marking ready, or attest supply exhaustion")
        plan = CandidatePlan("", self.account, self.scheduled_at, self.next_same_role_at,
            self.already_newly_verified, canonical({"actions": self._actions}), canonical(self._groups),
            canonical(self._observations), self.reserve_target, source_exhausted)
        plan = CandidatePlan(**{**asdict(plan), "plan_id": _plan_digest(plan._identity())})
        plan.validate(); self._frozen = True
        return plan


@dataclass(frozen=True)
class GoalReport:
    job_id: str
    plan_id: str
    kind: str
    goal: int
    already_newly_verified: int
    newly_verified_this_batch: int
    newly_verified_total: int
    goal_shortfall: int
    goal_reached: bool
    coordination_state: str
    duplicate_candidates: int
    already_present_candidates: int
    cancelled_candidates: int

    def as_dict(self):
        return asdict(self)


class GoalCoordinator(SerialCoordinator):
    """Same frozen single-writer/checkpoint protocol plus exact verified goals."""
    def __init__(self, *args, plan=None, **kwargs):
        require(hashlib.sha256(Path(frozen_coordinator.__file__).read_bytes()).hexdigest() ==
                FROZEN_COORDINATOR_SHA256, "Frozen coordinator changed; goal fork requires review")
        require(plan is None or type(plan) is CandidatePlan, "Exact immutable candidate plan required")
        self.plan = plan.validate() if plan is not None else None
        self.last_goal_report = None
        super().__init__(*args, **kwargs)

    def _authorize_batch(self, job, actions):
        require(job["role"] != "spreader" or self.plan is not None or
                all(a["kind"] == "repost" for a in actions),
                "Spreader conditional actions require an immutable candidate grouping plan")
        policy = super()._authorize_batch(job, actions)
        objective = validated_objective(policy, job["role"])
        if self.plan is not None:
            self.plan.validate()
            require(job["role"] == "spreader" and self.plan.account == job["expected_account"] and
                    (self.plan.scheduled_at, self.plan.next_same_role_at) ==
                    (job["scheduled_at"], job["next_same_role_at"]) and
                    self.plan.manifest_json == job["payload_json"] and
                    self.plan.batch_payload_hash == job["payload_hash"] and
                    self.plan.already_newly_verified == objective["already_newly_verified"],
                    "Immutable reviewed plan differs from authorized exact job/history")
        return policy

    def _goal_cancel_reason(self, run, action, objective):
        if objective is None:
            return None
        if action["kind"] == objective["kind"]:
            if self._verified_total(run, objective) >= objective["newly_verified_goal"]:
                return "goal_reached"
            return None
        if run.job["role"] == "spreader":
            require(self.plan is not None, "Conditional candidate action has no reviewed grouping")
            groups = parse_json(self.plan.groups_json)
            roots = [g["group_id"] for g in groups if action["action_id"] in g["action_ids"]]
            require(len(roots) == 1, "Conditional action must belong to exactly one reviewed candidate")
            progress = self.queue.list_action_progress(run.claim)
            root = next((r for r in progress if r["action_id"] == roots[0]), None)
            require(root is not None, "Candidate root must reach an outcome before its conditional actions")
            if root["state"] == "cancelled" and parse_json(root["result_json"]).get("reason") == "goal_reached":
                return "goal_reached_group"
        return None

    def _verified_total(self, run, objective):
        kind_ids = {a["action_id"] for a in self._actions(run.job) if a["kind"] == objective["kind"]}
        progress = self.queue.list_action_progress(run.claim)
        return objective["already_newly_verified"] + sum(
            row["action_id"] in kind_ids and row["state"] == "verified" for row in progress)

    def _report(self, run, state):
        obj = validated_objective(run.policy, run.job["role"])
        if obj is None: return None
        kind_ids = {a["action_id"] for a in self._actions(run.job) if a["kind"] == obj["kind"]}
        progress = [r for r in self.queue.list_action_progress(run.claim) if r["action_id"] in kind_ids]
        new = sum(r["state"] == "verified" for r in progress)
        total = obj["already_newly_verified"] + new
        plan_id = self.plan.plan_id if self.plan is not None else _plan_digest({
            "schema": "immutable-goal-batch-v1", "account": run.job["expected_account"],
            "role": run.job["role"], "scheduled_at": run.job["scheduled_at"],
            "next_same_role_at": run.job["next_same_role_at"], "payload_hash": run.job["payload_hash"]})
        return GoalReport(run.claim.job_id, plan_id, obj["kind"], obj["newly_verified_goal"],
            obj["already_newly_verified"], new, total, max(0, obj["newly_verified_goal"] - total),
            total == obj["newly_verified_goal"], state, sum(r["state"] == "duplicate" for r in progress),
            sum(r["state"] == "already_present" for r in progress), sum(r["state"] == "cancelled" for r in progress))

    def _with_report(self, result):
        report = self.last_goal_report
        if report is None or result.job_id != report.job_id: return result
        summary = (f"Newly verified {report.kind}: {report.newly_verified_total}/{report.goal}; "
                   f"goal shortfall {report.goal_shortfall}")
        return CoordinationResult(result.state, result.job_id, result.reason + "; " + summary,
                                  result.checkpoint_sequence)

    def run_once(self):
        result = super().run_once()
        if self._run is not None:
            self.last_goal_report = self._report(self._run, result.state)
        return self._with_report(result)

    def complete_checkpoint(self, **kwargs):
        result = super().complete_checkpoint(**kwargs)
        if self.last_goal_report is not None and result.job_id == self.last_goal_report.job_id:
            self.last_goal_report = GoalReport(**{**asdict(self.last_goal_report), "coordination_state": result.state})
        return self._with_report(result)

    def _dispatch_batch(self, run):
        binding = self._binding(run.job)
        objective = validated_objective(run.policy, run.job["role"])
        for action in self._actions(run.job):
            key = action["action_id"]
            # Goal-only delta from the frozen coordinator: do not consume an
            # authorization or claim a reserve after the verified objective.
            cancel_reason = self._goal_cancel_reason(run, action, objective)
            if cancel_reason is not None:
                self._progress(run, key, "cancelled", reason=cancel_reason)
                continue
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
            if objective is not None:
                require(self._verified_total(run, objective) <= objective["newly_verified_goal"],
                        "Verified goal ceiling exceeded")
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
