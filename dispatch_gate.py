"""Fail-closed, staging-only gates for the unchanged reconstructed ledger v2.

No subprocess, browser, network, upload, or production adapter lives here.  Transport
adapters are trusted boundaries and must report final completion truthfully.  The
v2 CLI's sparse mutation responses are checked against a freshly identity-pinned
status and the exact request, rather than inventing new CLI response fields.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Callable, Any
from urllib.parse import urlsplit
from settings import BLOG_HOST


HASH = re.compile(r"[a-f0-9]{64}\Z")
DB_ID = re.compile(r"[a-f0-9]{32}\Z")
ROLES = frozenset(("publisher", "spreader", "commenter"))
KINDS = frozenset(("publish", "reply", "self_reply", "like", "repost", "follow"))
PENDING = frozenset(("intent", "submitted_unverified", "unknown"))
STATES = PENDING | frozenset(("historical_observed", "current_observed", "reserved",
                              "verified", "already_present", "cancelled"))


class GateBlocked(RuntimeError):
    """A gate failed.  The caller must not continue with browser operations."""


def require(condition, reason):
    if not condition:
        raise GateBlocked(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def payload_hash(payload):
    require(type(payload) is dict, "Canonical outbound payload must be an object")
    return hashlib.sha256(canonical(payload).encode()).hexdigest()


@dataclass(frozen=True)
class CommandResult:
    completed: bool
    exit_code: int | None
    stdout: str = field(repr=False)
    truncated: bool = False
    session_id: str | int | None = None
    stderr: str = field(default="", repr=False)


def _object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON field")
        value[key] = item
    return value


def parse_json(text):
    require(type(text) is str and 0 < len(text) <= 8_000_000,
            "Missing or oversized complete JSON")
    try:
        return json.loads(text, object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              GateBlocked("Non-finite JSON value")))
    except (ValueError, TypeError, RecursionError) as error:
        raise GateBlocked("Malformed or non-single JSON output") from error


def completed_json(result):
    require(isinstance(result, CommandResult), "Transport completion envelope required")
    require(result.completed is True and result.session_id is None,
            "Command has not finally completed")
    require(type(result.exit_code) is int and result.exit_code == 0,
            "Command did not exit successfully")
    require(result.truncated is False and result.stderr == "",
            "Command output is incomplete or contains unexpected stderr")
    value = parse_json(result.stdout)
    require(type(value) is dict, "Command must return one JSON object")
    return value


def successful(result):
    value = completed_json(result)
    require(value.get("ok") is True, "Command must return ok=true")
    return value


def action_id(account, kind, target):
    """Exactly the v2 duplicate-key semantics, including reply/self_reply aliases."""
    require(kind in KINDS and type(target) is str, "Unknown action kind/target")
    try:
        url = urlsplit(target)
        require(url.scheme == "https" and url.username is None and
                url.password is None and url.port is None and not url.query and
                not url.fragment, "Exact public HTTPS target required")
    except ValueError as error:
        raise GateBlocked("Invalid target URL") from error
    path = url.path.rstrip("/")
    if kind == "publish":
        require(url.hostname == BLOG_HOST and
                re.fullmatch(r"/[1-9][0-9]*", path), "Numeric article target required")
        key = "blog:article:" + path[1:]
    else:
        require(url.hostname in ("threads.com", "www.threads.com", "threads.net",
                                 "www.threads.net"), "Exact Threads target required")
        if kind == "follow":
            match = re.fullmatch(r"/@([A-Za-z0-9_.]{1,64})", path)
            require(match is not None, "Exact account profile required")
            key = "threads:account:" + match[1].lower()
        else:
            match = re.fullmatch(r"/@([A-Za-z0-9_.]{1,64})/post/([A-Za-z0-9_-]{1,100})", path)
            require(match is not None, "Exact post permalink required")
            key = "threads:post:" + match[2]
    return hashlib.sha256(canonical([account, "reply" if kind == "self_reply" else kind,
                                     key]).encode()).hexdigest()


@dataclass(frozen=True)
class LedgerIdentity:
    account: str
    db_id: str

    def __post_init__(self):
        require(type(self.account) is str and re.fullmatch(r"[a-z0-9_.]{1,64}", self.account),
                "Pinned canonical account required")
        require(type(self.db_id) is str and DB_ID.fullmatch(self.db_id),
                "Pinned ledger database ID required")


class OneUsePermit:
    """Consumes before callback entry, including denial, exception, and lost output."""
    def __init__(self, action, intent_id, not_before, deadline, clock):
        require(type(not_before) is int and type(deadline) is int and 0 <= not_before < deadline,
                "Exact same-role slot boundaries required")
        self.action_id = action
        self.intent_id = intent_id
        self._deadline = deadline
        self._not_before = not_before
        self._clock = clock
        self._used = False
        self._lock = threading.Lock()

    def dispatch(self, callback: Callable[[], Any]):
        with self._lock:
            require(not self._used, "Write permit has already been consumed")
            self._used = True
            now = self._clock()
            require(type(now) is int and self._not_before <= now < self._deadline,
                    "Clock is outside the exact same-role action slot")
        return callback()

    @property
    def used(self):
        return self._used


class DispatchGate:
    def __init__(self, identity: LedgerIdentity, clock, freshness=300):
        require(type(freshness) is int and 0 < freshness <= 300, "Invalid freshness bound")
        self.identity = identity
        self.clock = clock
        self.freshness = freshness
        self._intents = set()
        self._intent_lock = threading.Lock()

    def status(self, result):
        value = successful(result)
        require(value.get("account") == self.identity.account and
                value.get("db_id") == self.identity.db_id, "Ledger identity mismatch")
        require(value.get("phase") in ("recovery", "sealed", "active") and
                value.get("may_dispatch") is False, "Invalid ledger phase/status")
        require(type(value.get("checkpoint_pending")) is bool and
                type(value.get("checkpoint_seq")) is int and value["checkpoint_seq"] >= 0,
                "Missing checkpoint gate")
        require(type(value.get("actions")) is list and type(value.get("stops")) is list,
                "Missing ledger action/STOP state")
        for action in value["actions"]:
            require(type(action) is dict and HASH.fullmatch(action.get("id", "")) and
                    action.get("account") == self.identity.account and
                    action.get("state") in STATES, "Malformed ledger action")
        require("writer" in value, "Missing writer state")
        writer = value["writer"]
        if writer is not None:
            require(type(writer) is dict and writer.get("account") == self.identity.account
                    and type(writer.get("owner")) is str and bool(writer["owner"])
                    and writer.get("role") in ROLES | {"reconciler"}
                    and DB_ID.fullmatch(writer.get("session", ""))
                    and type(writer.get("acquired_at")) is int,
                    "Malformed writer identity")
        return value

    def write_status(self, value, owner=None, role=None, session=None):
        require(value.get("account") == self.identity.account and
                value.get("db_id") == self.identity.db_id, "Unpinned status")
        require(value["phase"] == "active" and HASH.fullmatch(value.get("backup_hash", "")),
                "Ledger recovery/backup gate blocks writing")
        require(value["checkpoint_pending"] is False and not value["stops"] and
                not any(a["state"] in PENDING for a in value["actions"]),
                "Checkpoint, STOP, or unresolved action blocks writing")
        writer = value["writer"]
        if owner is None:
            require(writer is None, "Writer busy; wait without timeout takeover")
        else:
            require(writer is not None and writer["owner"] == owner and
                    writer["role"] == role and writer["session"] == session,
                    "Writer owner/role/session mismatch")
        return value

    def acquired(self, result, owner):
        value = successful(result)
        require(value.get("owner") == owner and HASH.fullmatch(value.get("token", "")) and
                DB_ID.fullmatch(value.get("session", "")) and
                value.get("may_dispatch") is False and value.get("automatic_expiry") is False,
                "Unexpected acquire response; never repeat uncertain acquire")
        return value

    def claim(self, result, expected_action):
        value = successful(result)
        require(value.get("action_id") == expected_action and
                value.get("may_dispatch") is False and type(value.get("duplicate")) is bool
                and value.get("state") in STATES, "Unexpected claim response")
        if not value["duplicate"]:
            require(value["state"] == "reserved", "New claim must be reserved")
        else:
            require(type(value.get("payload_matches")) is bool,
                    "Duplicate claim lacks payload comparison")
        return value

    def intent(self, result, expected_action, deadline, *, not_before):
        value = successful(result)
        require(value.get("action_id") == expected_action and value.get("state") == "intent"
                and HASH.fullmatch(value.get("intent_id", ""))
                and value.get("may_dispatch") is True
                and value.get("exactly_one_browser_call") is True
                and value.get("lost_response_means_do_not_dispatch") is True,
                "No exact one-use begin-write permission")
        with self._intent_lock:
            require(value["intent_id"] not in self._intents, "Replayed begin-write response")
            self._intents.add(value["intent_id"])
        return OneUsePermit(expected_action, value["intent_id"], not_before, deadline, self.clock)

    def transition(self, result, expected_action, state):
        value = successful(result)
        require(value.get("action_id") == expected_action and value.get("state") == state and
                value.get("may_dispatch") is False, "Wrong action transition response")
        return value

    def binding(self, observation, expected):
        require(type(observation) is dict and type(expected) is dict,
                "Browser binding evidence required")
        for key in ("role", "worker_id", "browser_id", "tab_id", "account"):
            require(key in expected and observation.get(key) == expected[key],
                    "Browser role/worker/tab/account binding mismatch")
        require(expected["account"] == self.identity.account and
                observation.get("logged_in") is True and observation.get("exists") is True,
                "Bound tab missing or logged into wrong account")
        at = observation.get("observed_at")
        require(type(at) is int and self.clock() - self.freshness <= at <= self.clock(),
                "Browser identity proof is stale or future-dated")
        return observation

    def evidence(self, value, action, binding, intent_id, outcome):
        require(type(value) is dict, "Browser evidence required")
        self.binding(value.get("binding"), binding)
        proof = value.get("evidence")
        fields = {"schema", "account", "kind", "target", "payload_hash", "intent_id",
                  "outcome", "observed_at", "reference", "proof_file", "proof_sha256",
                  "receipt_urls"}
        require(type(proof) is dict and set(proof) == fields,
                "Complete v2 browser evidence required")
        for key in ("kind", "target", "payload_hash"):
            require(proof[key] == action[key], "Browser evidence action/payload mismatch")
        require(proof["schema"] == "browser-action-evidence-v2" and
                proof["account"] == self.identity.account and proof["intent_id"] == intent_id
                and proof["outcome"] == outcome, "Browser evidence intent/outcome mismatch")
        at = proof["observed_at"]
        require(type(at) is int and self.clock() - self.freshness <= at <= self.clock(),
                "Browser action evidence expired")
        require(type(proof["reference"]) is str and bool(proof["reference"]) and
                type(proof["proof_file"]) is str and bool(proof["proof_file"]) and
                HASH.fullmatch(proof["proof_sha256"]) and type(proof["receipt_urls"]) is list,
                "Actual public proof and receipt fields required")
        require(type(value.get("evidence_path")) is str and bool(value["evidence_path"]),
                "Persisted evidence record path required")
        if outcome == "absent":
            require(not proof["receipt_urls"], "Absence proof cannot contain receipts")
        # The unchanged ledger independently rechecks these actual bytes.  Checking
        # here also prevents the adapter's displayed JSON differing from its file.
        record = self._bounded_file(value["evidence_path"])
        require(canonical(parse_json(record.decode("utf-8"))) == canonical(proof),
                "Persisted evidence differs from returned evidence")
        public_proof = self._bounded_file(proof["proof_file"])
        require(bool(public_proof) and hashlib.sha256(public_proof).hexdigest() ==
                proof["proof_sha256"], "Persisted public proof hash mismatch")
        return value["evidence_path"]

    @staticmethod
    def _unchanged_file(*snapshots):
        require(bool(snapshots) and all(stat.S_ISREG(s.st_mode) for s in snapshots),
                "Evidence changed to a non-regular file")
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(all(identity(s) == identity(snapshots[0]) for s in snapshots[1:]),
                "Evidence file was replaced or changed while reading")

    @staticmethod
    def _bounded_file(path):
        path = Path(path)
        try:
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_size <= 8_000_000,
                    "Evidence must be a bounded regular non-symlink file")
            # O_NOFOLLOW closes the lstat/open symlink-swap window.  Device/inode
            # comparisons also reject replacement with a different regular file.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                DispatchGate._unchanged_file(before, opened)
                data = stream.read(8_000_001)
                after_fd = os.fstat(stream.fileno())
            after_path = path.lstat()
        except OSError as error:
            raise GateBlocked("Evidence file unavailable or changed during read") from error
        DispatchGate._unchanged_file(before, opened, after_fd, after_path)
        require(len(data) <= 8_000_000 and len(data) == before.st_size,
                "Evidence file exceeds bound or changed length")
        return data

    def release(self, result):
        value = successful(result)
        require(value.get("released") is True and value.get("checkpoint_pending") is True
                and type(value.get("checkpoint_seq")) is int and value["checkpoint_seq"] > 0
                and value.get("may_dispatch") is False, "Release lacks checkpoint barrier")
        return value
