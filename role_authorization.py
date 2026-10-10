"""Staging-only consumer/producer of exact, independently reviewed authorizations.

This module validates a trusted supplied review, then produces the coordinator's
CommandResult envelopes. It never turns proposed actions into permission. A hash
inside an untrusted file is NOT authentication. The caller must authenticate the
pin, source provenance, current policy callback, and replay-store lifetime.
No browser, network, credentials, production activation, or policy solver exists.
"""
from dataclasses import dataclass
from collections import Counter
import hashlib
import re
import threading
from urllib.parse import urlsplit

from dispatch_gate import (CommandResult, GateBlocked, HASH, action_id, canonical,
                           parse_json, payload_hash, require)

SCHEMA = "exact-reviewed-role-batch-v1"
EVIDENCE_SCHEMA = "exact-role-review-evidence-v1"
MAX_FRESHNESS = 300
# These are permission ceilings by role, not approvals or standing numeric caps.
ROLE_KINDS = {
    "publisher": frozenset({"publish"}),
    "spreader": frozenset({"repost", "like", "reply", "follow"}),
    "commenter": frozenset({"reply"}),
}
ROLE_OFFSET = {"spreader": 0, "publisher": 1200, "commenter": 2400}
OBJECTIVES = {
    "publisher": {"metric": "verified_publish_bundles", "target": 1},
    "spreader": {"metric": "newly_verified_native_reposts", "target": 5},
    "commenter": {"metric": "existing_conversation_replies", "target": None},
}
CONDITIONS = {
    ("publisher", "publish"): frozenset({"role_policy_satisfied", "four_part_bundle_reviewed",
        "original_image_reviewed", "first_reply_preview_planned"}),
    ("spreader", "repost"): frozenset({"role_policy_satisfied", "native_repost_reviewed",
        "repost_not_already_present"}),
    ("spreader", "like"): frozenset({"role_policy_satisfied", "like_condition_satisfied"}),
    ("spreader", "reply"): frozenset({"role_policy_satisfied", "reply_condition_satisfied"}),
    ("spreader", "follow"): frozenset({"role_policy_satisfied", "follow_condition_satisfied"}),
    ("commenter", "reply"): frozenset({"role_policy_satisfied", "existing_conversation_verified",
        "reply_condition_satisfied"}),
}
BASE_FACT = {"policy": "current_role_policy_reviewed", "approval": "exact_batch_approved",
             "usage": "scheduled_run_usage_reviewed"}
BINDING_KEYS = {"role", "worker_id", "browser_id", "tab_id", "account"}
SLOT_KEYS = {"scheduled_at", "next_same_role_at"}
ACTION_KEYS = {"kind", "target", "payload", "authorization_id", "payload_hash", "action_id"}
RAW_ACTION_KEYS = ACTION_KEYS - {"payload_hash", "action_id"}
PUBLISH_KEYS = {"target", "article_id", "blog_url", "root", "replies", "root_image_path",
                "root_image_url", "image_sha256", "preview_reply_index"}
_SAFE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
# No schema field accepts credentials. Reject common accidental secret carriers
# in opaque payloads too; this is defense in depth, not a secret detector.
_SECRET_KEYS = frozenset({"password", "passwd", "secret", "api_key", "apikey", "token",
    "access_token", "refresh_token", "authorization", "cookie", "cookies", "credentials",
    "credit_card", "ssn", "private_key"})


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _keys(value, expected, reason):
    require(type(value) is dict and set(value) == expected, reason)


def _reference(value):
    require(type(value) is str and _SAFE_REFERENCE.fullmatch(value) is not None,
            "Non-secret bounded public reference required")
    return value


def _digest(value):
    require(type(value) is str and HASH.fullmatch(value) is not None, "Exact SHA-256 required")
    return value


def _integer(value):
    require(type(value) is int and value >= 0, "Nonnegative integer required")
    return value


def _no_credentials(value):
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str and key.lower().replace("-", "_") not in _SECRET_KEYS,
                    "Credential-bearing data is prohibited")
            _no_credentials(item)
    elif type(value) is list:
        for item in value:
            _no_credentials(item)
    elif type(value) is str:
        require("-----BEGIN " not in value and
                not re.search(r"(?i)(?:bearer\s|(?:password|access_token|api_key)=)", value),
                "Credential-bearing data is prohibited")


def _json_bytes(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8_000_000, "Complete bounded review bytes required")
    try:
        value = parse_json(raw.decode("utf-8"))
        _no_credentials(value)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise GateBlocked("Invalid review or evidence JSON") from error


def _fresh(timestamp, now, freshness):
    require(type(timestamp) is int and now - freshness <= timestamp <= now,
            "Review or conditional evidence is stale or future-dated")


@dataclass(frozen=True)
class ReviewContext:
    """Independently supplied expected identities and immutable job manifest."""
    role: str
    worker_id: str
    browser_id: str
    tab_id: str
    account: str
    job_id: str
    generation: int
    scheduled_at: int
    next_same_role_at: int
    batch_payload_hash: str
    actions_hash: str
    already_newly_verified: int | None = None

    def binding(self):
        return {key: getattr(self, key) for key in BINDING_KEYS}

    def slot(self):
        return {key: getattr(self, key) for key in SLOT_KEYS}

    def objective(self):
        if self.role == "commenter":
            return None
        return {"kind": "repost" if self.role == "spreader" else "publish",
                "newly_verified_goal": OBJECTIVES[self.role]["target"],
                "already_newly_verified": self.already_newly_verified}

    def validate(self):
        require(self.role in ROLE_KINDS, "Unknown role")
        for name in ("worker_id", "browser_id", "tab_id", "job_id"):
            _reference(getattr(self, name))
        require(type(self.account) is str and re.fullmatch(r"[a-z0-9_.]{1,64}", self.account),
                "Canonical account required")
        _integer(self.generation)
        _integer(self.scheduled_at)
        _integer(self.next_same_role_at)
        require(self.scheduled_at % 3600 == ROLE_OFFSET[self.role] and
                self.next_same_role_at == self.scheduled_at + 3600,
                "Exact hourly :00/:20/:40 same-role slot required")
        _digest(self.batch_payload_hash)
        _digest(self.actions_hash)
        if self.role == "commenter":
            require(self.already_newly_verified is None, "Commenter has no invented numeric standing quota")
        else:
            require(type(self.already_newly_verified) is int and
                    0 <= self.already_newly_verified <= OBJECTIVES[self.role]["target"],
                    "Independent exact scheduled-run verified history required")


@dataclass(frozen=True)
class TrustedReviewPin:
    """Trust must originate outside the reviewed file, through the parent.

    Computing this pin from an untrusted proposal/review does not authenticate it.
    All identifiers and digests are public-safe; no secret is accepted or needed.
    """
    review_sha256: str
    producer_reference: str
    policy_reference: str
    policy_sha256: str
    context: ReviewContext

    def validate(self):
        require(type(self.context) is ReviewContext, "Independent expected context required")
        self.context.validate()
        _digest(self.review_sha256)
        _digest(self.policy_sha256)
        _reference(self.producer_reference)
        _reference(self.policy_reference)


class StagingReplayStore:
    """Explicit in-memory staging store; must be shared by ALL adapter instances.

    Process restart/new stores lose replay protection. Production would require
    an independently reviewed durable transactional implementation; none ships.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._digests, self._decisions, self._runs = set(), set(), set()

    def consume_batch(self, review_sha256, decision_id, context):
        run = (context.account, context.role, context.scheduled_at)
        with self._lock:
            require(review_sha256 not in self._digests and decision_id not in self._decisions
                    and run not in self._runs, "Reviewed batch or scheduled run was already consumed")
            self._digests.add(review_sha256)
            self._decisions.add(decision_id)
            self._runs.add(run)


class ExactRoleAuthorization:
    """Strict AuthorizationAdapter backed ONLY by a supplied reviewed decision.

    current_policy returns the trusted current (public reference, SHA-256) pair.
    It is consulted for every batch/action decision, never inferred from actions.
    source_bytes maps references to complete, pinned evidence JSON bytes. No file
    discovery, arbitrary code names in JSON, native handlers, or I/O is supported.
    """
    def __init__(self, review_bytes, *, pin, source_bytes, current_policy, clock,
                 replay_store, freshness=MAX_FRESHNESS):
        require(type(pin) is TrustedReviewPin, "Trusted independent review pin required")
        pin.validate()
        require(type(freshness) is int and 0 < freshness <= MAX_FRESHNESS,
                "Freshness cannot exceed five minutes")
        require(callable(current_policy) and callable(clock), "Trusted current policy and clock required")
        require(type(replay_store) is StagingReplayStore, "Explicit shared staging replay store required")
        require(type(source_bytes) is dict and all(type(v) is bytes for v in source_bytes.values()),
                "Complete independently supplied evidence bytes required")
        require(type(review_bytes) is bytes and _sha(review_bytes) == pin.review_sha256,
                "Reviewed decision differs from trusted external pin")
        self._pin, self._clock, self._freshness = pin, clock, freshness
        self._current_policy, self._replay = current_policy, replay_store
        self._record = _json_bytes(review_bytes)
        self._sources_raw = dict(source_bytes)
        self._sources = {}
        self._lock, self._batch_used, self._used_actions = threading.Lock(), False, set()
        self._last_checked_at = None
        self._validate_record()
        self._runtime_check()

    def _validate_record(self):
        r, pin, c = self._record, self._pin, self._pin.context
        _keys(r, {"schema", "decision_id", "producer_reference", "issued_at", "expires_at",
            "policy", "binding", "slot", "job", "role_objective", "run_progress", "standing_quota",
            "batch_grant", "decisions", "sources"}, "Complete exact reviewed decision required")
        require(r["schema"] == SCHEMA and r["producer_reference"] == pin.producer_reference,
                "Review schema/producer mismatch")
        _reference(r["decision_id"])
        _integer(r["issued_at"]); _integer(r["expires_at"])
        require(c.scheduled_at <= r["issued_at"] < r["expires_at"] <= c.next_same_role_at and
                r["expires_at"] <= r["issued_at"] + self._freshness,
                "Decision lifetime exceeds current same-role slot or freshness")
        _keys(r["binding"], BINDING_KEYS, "Exact role/worker/browser/tab/account binding required")
        _keys(r["slot"], SLOT_KEYS, "Exact scheduled slot required")
        require(canonical(r["binding"]) == canonical(c.binding()) and canonical(r["slot"]) == canonical(c.slot()), "Independent role/binding/slot mismatch")
        _keys(r["job"], {"job_id", "generation", "batch_payload_hash", "actions_hash"}, "Exact immutable job required")
        require(canonical(r["job"]) == canonical({name: getattr(c, name) for name in r["job"]}), "Independent job/manifest mismatch")
        _keys(r["policy"], {"reference", "sha256", "source_reference"}, "Exact policy source required")
        require(r["policy"]["reference"] == pin.policy_reference and
                r["policy"]["sha256"] == pin.policy_sha256, "Current policy pin mismatch")
        require(canonical(r["role_objective"]) == canonical(OBJECTIVES[c.role]), "Role objective differs from reviewed scope")
        require(canonical(r["run_progress"]) == canonical(c.objective()),
                "Independent exact run history/goal mismatch")
        # No standing numerical caps are fabricated. Every grant below is exact,
        # single-batch permission supplied by the reviewed producer.
        require(r["standing_quota"] == {"status": "not_asserted", "source_reference": r["policy"]["source_reference"]},
                "This adapter cannot invent or assert standing numeric quotas")
        grant = r["batch_grant"]
        _keys(grant, {"scope", "allowed_kinds", "per_kind_limits", "max_actions",
                      "approval_source", "usage_source"}, "Explicit exact batch grant required")
        require(grant["scope"] == "exact_reviewed_batch", "Standing or unbounded batch grants are prohibited")
        kinds, limits = grant["allowed_kinds"], grant["per_kind_limits"]
        require(type(kinds) is list and all(type(k) is str for k in kinds) and
                kinds == sorted(set(kinds)) and set(kinds) <= ROLE_KINDS[c.role] and
                type(limits) is dict and set(limits) == set(kinds) and
                all(type(n) is int and n > 0 for n in limits.values()),
                "Exact finite role-specific per-kind limits required")
        require(type(grant["max_actions"]) is int and 1 <= grant["max_actions"] <= 100,
                "Finite exact batch limit required; technical ceiling is not permission")
        sources = r["sources"]
        require(type(sources) is list and 3 <= len(sources) <= 103, "Complete policy/approval/usage/action sources required")
        for src in sources:
            _keys(src, {"reference", "sha256"}, "Exact source reference/digest required")
            ref = _reference(src["reference"]); _digest(src["sha256"])
            require(ref not in self._sources and ref in self._sources_raw, "Duplicate or missing source bytes")
            raw = self._sources_raw[ref]
            require(_sha(raw) == src["sha256"], "Evidence bytes differ from pinned source")
            doc = _json_bytes(raw)
            _keys(doc, {"schema", "reference", "origin_reference", "category", "recorded_at",
                "policy_reference", "binding", "slot", "action_id", "payload_hash", "run_progress", "facts"},
                "Complete structured review evidence required")
            require(doc["schema"] == EVIDENCE_SCHEMA and doc["reference"] == ref and
                    doc["category"] in {"policy", "approval", "usage", "observation"} and
                    doc["policy_reference"] == pin.policy_reference and
                    canonical(doc["binding"]) == canonical(c.binding()) and canonical(doc["slot"]) == canonical(c.slot()),
                    "Evidence source is bound to another policy/role/worker/browser/tab/account/slot")
            _reference(doc["origin_reference"]); _integer(doc["recorded_at"])
            require(doc["recorded_at"] <= r["issued_at"], "Evidence cannot postdate the reviewed decision")
            if doc["category"] in {"usage", "observation"}:
                require(c.scheduled_at <= doc["recorded_at"], "Run evidence predates its exact slot")
            facts = doc["facts"]
            require(type(facts) is list and all(type(f) is str for f in facts) and
                    len(facts) == len(set(facts)) and len(facts) > 0, "Exact evidence facts required")
            require(canonical(doc["run_progress"]) == canonical(c.objective() if doc["category"] == "usage" else None),
                    "Usage evidence differs from independent exact verified history")
            if doc["category"] != "observation":
                require(doc["action_id"] is None and doc["payload_hash"] is None and
                        facts == [BASE_FACT[doc["category"]]], "Wrong role-level evidence facts")
            else:
                _digest(doc["action_id"]); _digest(doc["payload_hash"])
            self._sources[ref] = doc
        require(set(self._sources_raw) == set(self._sources), "Unexpected or unpinned source bytes")
        policy_source = self._source(r["policy"]["source_reference"], "policy")
        require(_sha(self._sources_raw[policy_source["reference"]]) == pin.policy_sha256,
                "Policy bytes do not match independent current policy pin")
        self._source(grant["approval_source"], "approval")
        self._source(grant["usage_source"], "usage")
        decisions = r["decisions"]
        require(type(decisions) is list and len(decisions) == grant["max_actions"], "Exact complete reviewed action decisions required")
        seen_auth, seen_action, counts, used_sources = set(), set(), Counter(), {
            r["policy"]["source_reference"], grant["approval_source"], grant["usage_source"]}
        for d in decisions:
            _keys(d, {"authorization_id", "action_id", "kind", "target", "payload_hash",
                "decision", "reviewed_at", "conditions"}, "Exact independently reviewed action decision required")
            _reference(d["authorization_id"]); _digest(d["action_id"]); _digest(d["payload_hash"])
            require(d["decision"] == "allow" and d["kind"] in ROLE_KINDS[c.role] and
                    d["authorization_id"] not in seen_auth and d["action_id"] not in seen_action,
                    "Denied, duplicate, or wrong-role action decision")
            require(d["action_id"] == action_id(c.account, d["kind"], d["target"]), "Reviewed target/action identity mismatch")
            require(type(d["reviewed_at"]) is int and c.scheduled_at <= d["reviewed_at"] <= r["issued_at"],
                    "Action review is outside its scheduled run")
            conditions = d["conditions"]
            require(type(conditions) is list, "Explicit reviewed conditional evidence required")
            found = set()
            for condition in conditions:
                _keys(condition, {"condition", "source_reference"}, "Exact conditional evidence reference required")
                name = condition["condition"]
                require(type(name) is str and name not in found, "Duplicated condition")
                source = self._source(condition["source_reference"], "observation")
                require(source["action_id"] == d["action_id"] and source["payload_hash"] == d["payload_hash"]
                        and name in source["facts"] and source["recorded_at"] <= d["reviewed_at"],
                        "Conditional evidence does not attest this exact reviewed action")
                require(set(source["facts"]) <= CONDITIONS[(c.role, d["kind"])], "Unknown action evidence facts")
                found.add(name); used_sources.add(condition["source_reference"])
            require(found == CONDITIONS[(c.role, d["kind"])], "Required role/action conditional evidence is missing")
            counts[d["kind"]] += 1
            seen_auth.add(d["authorization_id"]); seen_action.add(d["action_id"])
        require(dict(counts) == limits and set(counts) == set(kinds),
                "Supplied grant must match exact reviewed decisions, without spare permission")
        require(used_sources == set(self._sources), "Unreferenced source evidence is prohibited")
        if c.role == "publisher":
            require(counts == {"publish": 1}, "Publisher review must authorize exactly one complete bundle")

    def _source(self, reference, category):
        _reference(reference)
        require(reference in self._sources and self._sources[reference]["category"] == category,
                "Missing or wrong-category independent source")
        return self._sources[reference]

    def _time_check(self):
        """Fresh clock sample; never reuse time from before a blocking callback.

        Calls are serialized by the adapter lock (or occur during construction).
        The high-water mark is retained even after a failed expiry check so a
        later clock rollback cannot revive this reviewed decision.
        """
        now = self._clock()
        _integer(now)
        require(self._last_checked_at is None or now >= self._last_checked_at,
                "Authorization clock moved backwards")
        self._last_checked_at = now
        c, r = self._pin.context, self._record
        require(c.scheduled_at <= now < c.next_same_role_at and r["issued_at"] <= now < r["expires_at"],
                "Decision is not live in its exact current same-role slot; no catch-up")
        _fresh(r["issued_at"], now, self._freshness)
        for source in self._sources.values():
            if source["category"] in {"usage", "observation"}:
                _fresh(source["recorded_at"], now, self._freshness)
        for decision in r["decisions"]:
            _fresh(decision["reviewed_at"], now, self._freshness)
        return now

    def _runtime_check(self):
        self._time_check()
        try:
            current = self._current_policy()
        except Exception as error:
            self._time_check()
            raise GateBlocked("Current independent policy is unavailable") from error
        # The trusted callback may block or advance/roll back a supplied clock.
        # Its result is usable only at a fresh post-callback time sample.
        now = self._time_check()
        require(type(current) is tuple and current == (self._pin.policy_reference, self._pin.policy_sha256),
                "Current independent policy reference or digest changed")
        return now

    def _job_actions(self, job, actions=None):
        require(type(job) is dict, "Exact coordinator job required")
        c = self._pin.context
        expected = {"job_id": c.job_id, "generation": c.generation, "role": c.role,
            "worker_id": c.worker_id, "browser_id": c.browser_id, "tab_id": c.tab_id,
            "expected_account": c.account, "scheduled_at": c.scheduled_at,
            "next_same_role_at": c.next_same_role_at, "payload_hash": c.batch_payload_hash}
        require(all(type(job.get(k)) is type(v) and job.get(k) == v for k, v in expected.items()),
                "Coordinator job differs from independent role/job/binding/slot pin")
        body = parse_json(job.get("payload_json"))
        _keys(body, {"actions"}, "Exact immutable prepared batch required")
        require(type(body["actions"]) is list and 1 <= len(body["actions"]) <= 100 and
                payload_hash(body) == c.batch_payload_hash, "Immutable batch hash mismatch")
        expanded = []
        for raw in body["actions"]:
            _keys(raw, RAW_ACTION_KEYS, "Exact immutable raw action required")
            _no_credentials(raw)
            require(raw["kind"] in ROLE_KINDS[c.role] and type(raw["payload"]) is dict and
                    raw["payload"].get("target") == raw["target"], "Wrong role or outbound target")
            item = dict(raw)
            item["payload_hash"] = payload_hash(raw["payload"])
            item["action_id"] = action_id(c.account, raw["kind"], raw["target"])
            expanded.append(item)
            if raw["kind"] == "publish":
                self._publish_shape(raw)
            elif raw["kind"] == "reply":
                _keys(raw["payload"], {"target", "text"}, "Exact reply target/text payload required")
                require(type(raw["payload"]["text"]) is str and
                        0 < len(raw["payload"]["text"]) <= 4000 and bool(raw["payload"]["text"].strip()),
                        "Bounded nonempty reply text required")
            else:
                _keys(raw["payload"], {"target"}, "Exact non-text action target payload required")
        require(_sha(canonical(expanded).encode("utf-8")) == c.actions_hash,
                "Immutable ordered action-list hash mismatch")
        require(len(expanded) == len(self._record["decisions"]), "Review decision count differs from proposed batch")
        for item, decision in zip(expanded, self._record["decisions"]):
            for key in ("authorization_id", "action_id", "kind", "target", "payload_hash"):
                require(type(item[key]) is type(decision[key]) and item[key] == decision[key],
                        "Proposal differs from exact producer-approved action or order")
        if actions is not None:
            require(type(actions) is list and canonical(actions) == canonical(expanded),
                    "Coordinator supplied actions differ from exact immutable manifest")
        return expanded

    @staticmethod
    def _publish_shape(action):
        p = action["payload"]
        _keys(p, PUBLISH_KEYS, "Publisher must carry complete root/three-part/image/preview bundle")
        article = int(urlsplit(action["target"]).path.rstrip("/").split("/")[-1])
        require(type(p["article_id"]) is int and p["article_id"] == article and
                p["blog_url"] == action["target"] and type(p["root"]) is str and bool(p["root"].strip()) and
                type(p["replies"]) is list and len(p["replies"]) == 3 and
                all(type(text) is str and bool(text.strip()) for text in p["replies"]),
                "Publisher article or four-part bundle is incomplete")
        require(type(p["preview_reply_index"]) is int and p["preview_reply_index"] == 1 and
                action["target"] in p["replies"][0], "First reply must include exact article preview destination")
        _digest(p["image_sha256"])
        require(type(p["root_image_path"]) is str and bool(p["root_image_path"]), "Pinned original image path required")
        require(type(p["root_image_url"]) is str, "Original image source required")
        try:
            url = urlsplit(p["root_image_url"])
            require(url.scheme == "https" and bool(url.hostname) and url.username is None and
                    url.password is None and url.port is None and not url.query and not url.fragment,
                    "Public-safe original image URL required")
        except ValueError as error:
            raise GateBlocked("Invalid original image URL") from error

    def authorize_batch(self, job, actions):
        with self._lock:
            self._runtime_check()
            require(not self._batch_used, "Exact batch response has already been consumed")
            self._job_actions(job, actions)
            r, c = self._record, self._pin.context
            grant = r["batch_grant"]
            result = CommandResult(True, 0, canonical({"ok": True, "authorized": True,
                "account": c.account, "role": c.role, "batch_payload_hash": c.batch_payload_hash,
                "policy_reference": self._pin.policy_reference,
                "allowed_kinds": grant["allowed_kinds"], "per_kind_limits": grant["per_kind_limits"],
                "max_actions": grant["max_actions"], "quota_scope": "exact_reviewed_batch",
                "standing_quota_asserted": False, "objective": r["run_progress"],
                "review_sha256": self._pin.review_sha256}))
            # Validation/serialization may have taken time. Recheck policy and
            # time immediately before consumption, then resample after a possible
            # replay-store lock delay. Lost/expired results stay consumed.
            self._runtime_check()
            self._time_check()
            self._replay.consume_batch(self._pin.review_sha256, r["decision_id"], c)
            self._batch_used = True
            self._time_check()
            return result

    def authorize(self, job, action):
        with self._lock:
            self._runtime_check()
            require(self._batch_used, "Batch must be independently authorized first")
            expanded = self._job_actions(job)
            require(type(action) is dict and set(action) == ACTION_KEYS, "Exact action shape required")
            matches = [item for item in expanded if canonical(item) == canonical(action)]
            require(len(matches) == 1, "Action is not an exact member of the reviewed immutable batch")
            item = matches[0]
            require(item["authorization_id"] not in self._used_actions, "Action authorization has already been consumed")
            c = self._pin.context
            result = CommandResult(True, 0, canonical({"ok": True, "authorized": True,
                "account": c.account, "role": c.role, "authorization_id": item["authorization_id"],
                "kind": item["kind"], "target": item["target"], "payload_hash": item["payload_hash"],
                "policy_reference": self._pin.policy_reference, "review_sha256": self._pin.review_sha256}))
            self._runtime_check()
            self._time_check()
            self._used_actions.add(item["authorization_id"])
            self._time_check()
            return result

    def recheck_consumed_action(self, job, action):
        """Read-only recheck for a native boundary; never grants another mutation.

        Requires this exact action's authorization to have been consumed already
        by this adapter. Call immediately before each separately permitted native
        step, not as a substitute for the one-use intent or bridge request. The
        returned snapshot cannot be cached as permission: current policy may be
        revoked before its time limit, requiring another fresh invocation.
        """
        with self._lock:
            self._runtime_check()
            require(self._batch_used, "A consumed reviewed batch is required for recheck")
            expanded = self._job_actions(job)
            require(type(action) is dict and set(action) == ACTION_KEYS, "Exact action shape required")
            matches = [item for item in expanded if canonical(item) == canonical(action)]
            require(len(matches) == 1 and matches[0]["authorization_id"] in self._used_actions,
                    "Only an exact already-consumed action decision may be rechecked")
            item, c, r = matches[0], self._pin.context, self._record
            # _fresh accepts equality at timestamp + freshness. This exclusive
            # boundary therefore adds one second for integer epoch clocks.
            evidence_expiries = [source["recorded_at"] + self._freshness + 1
                for source in self._sources.values() if source["category"] in {"usage", "observation"}]
            review_expiries = [decision["reviewed_at"] + self._freshness + 1 for decision in r["decisions"]]
            expires = min(r["expires_at"], c.next_same_role_at, *evidence_expiries, *review_expiries)
            result = {"schema": "consumed-authorization-recheck-v1", "binding": c.binding(), "slot": c.slot(),
                "job_id": c.job_id, "generation": c.generation, "batch_payload_hash": c.batch_payload_hash,
                "actions_hash": c.actions_hash, "authorization_id": item["authorization_id"],
                "action_id": item["action_id"], "kind": item["kind"], "target": item["target"],
                "payload_hash": item["payload_hash"], "policy_reference": self._pin.policy_reference,
                "policy_sha256": self._pin.policy_sha256, "review_sha256": self._pin.review_sha256,
                "decision_id": r["decision_id"], "checked_at": None, "review_expires_at": r["expires_at"],
                "expires_at": expires}
            self._runtime_check()
            result["checked_at"] = self._time_check()
            return result
