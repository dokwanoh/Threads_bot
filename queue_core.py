"""Staging-only companion queue, schema v1. No browser or ledger writes.

DispatchClaim is queue ownership, NEVER permission to write in a browser.
The dispatcher must independently pass its authorization/STOP/ledger gates and
call validate_action_start immediately before EACH new external action. An
already-started action must finish readback even if its slot deadline passes.

Evidence and CheckpointProof are assertions by trusted observation/verification
adapters. This module checks their exact bindings and freshness; it cannot itself
observe a tab or authenticate a Library backup. No boolean 'verified' shortcut
exists. Checkpoint acknowledgement is the only way to release an owned writer.

Only initialize_staging creates a database. Keep its DatabaseIdentity outside the
database and pass the exact identity to every process. Missing/replaced files,
schema damage, orphaned writer state and uncertain dispatches fail closed.
There are no leases, takeover, automatic recovery, or production entrypoints.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator, Mapping
import uuid


from settings import STAGING_ROOT
SCHEMA_VERSION = 1
ROLES = ('publisher', 'spreader', 'commenter')
OPEN_STATES = ('preparing', 'ready', 'dispatching', 'checkpoint_wait')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
SAFE_ACTION_STATES = frozenset(('verified', 'duplicate', 'cancelled', 'already_present'))
UNRESOLVED_ACTION_STATES = frozenset(('uncertain', 'denied_unresolved'))
ACTION_TRANSITIONS = {'reserved': frozenset(('intent', 'already_present', 'cancelled', 'uncertain', 'denied_unresolved')),
                      'intent': frozenset(('submitted', 'uncertain', 'denied_unresolved')),
                      'submitted': frozenset(('verified', 'uncertain', 'denied_unresolved'))}


class QueueError(RuntimeError):
    """Base fail-closed queue error."""


class StateError(QueueError):
    """Absent, corrupt, replaced, inconsistent, or unexpected state."""


class BindingError(QueueError):
    """Stale, mismatched, or duplicate role ownership/evidence."""


class SlotError(QueueError):
    """Future, missed, conflicting, or expired scheduling slot."""


class ConflictError(QueueError):
    """A duplicate request conflicts with immutable prior state."""


class BusyError(QueueError):
    """An existing job or uncertain writer must be resolved first."""


class CheckpointError(QueueError):
    """Checkpoint proof is incomplete, unsafe, stale, or mismatched."""


@dataclass(frozen=True)
class DatabaseIdentity:
    db_id: str
    device: int
    inode: int


@dataclass(frozen=True)
class Binding:
    """Use canonical provider-returned browser and spawned-worker identities.

    Friendly worker names and browser selection aliases are not identities.
    A trusted bootstrap/observation adapter must establish canonical IDs; this
    module never guesses whether different labels refer to one physical tab.
    """
    worker_id: str
    browser_id: str
    tab_id: str
    expected_account: str


@dataclass(frozen=True)
class Schedule:
    """Fixed elapsed-time cadence only, never an approximation of an irregular schedule.

    Deployment must compare each real automation's complete schedule/timezone.
    Active-hour/irregular calendars require an explicitly reviewed scheduler
    adapter; this staged proof does not silently implement them.
    """
    anchor_at: int
    interval_seconds: int

    def current_slot(self, now: int) -> tuple[int, int]:
        if now < self.anchor_at:
            raise SlotError('The schedule has not started; future slots cannot enqueue')
        start = self.anchor_at + ((now - self.anchor_at) // self.interval_seconds) * self.interval_seconds
        return start, start + self.interval_seconds


@dataclass(frozen=True)
class DispatchClaim:
    """Queue ownership only. Not a browser-write permit or an authorization."""
    job_id: str
    dispatcher_id: str
    claim_token: str = field(repr=False)
    generation: int
    payload_hash: str
    evidence_id: str


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise QueueError(f'{label} must be a nonempty, bounded string')
    return value.strip()


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise QueueError(f'{label} must be an integer >= {minimum}')
    return value


def _account(value: Any) -> str:
    normalized = _text(value, 'account').removeprefix('@').casefold()
    if not re.fullmatch(r'[a-z0-9_.]{1,64}', normalized):
        raise BindingError('A valid observed/pinned Threads account handle is required')
    return normalized


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise QueueError('Value must be finite, JSON-serializable data') from exc


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise CheckpointError(f'{label} must be a lowercase SHA-256 digest')
    return value


def _path(path: str | Path) -> Path:
    path = Path(path).absolute()
    if path.is_symlink():
        raise StateError('Symlink database paths are prohibited')
    resolved = path.resolve()
    if not resolved.is_relative_to(STAGING_ROOT.resolve()) or resolved == STAGING_ROOT.resolve():
        raise StateError('Only the dedicated staging directory is permitted')
    return resolved


def _binding(value: Binding | Mapping[str, Any]) -> Binding:
    value = value if isinstance(value, Binding) else Binding(**value)
    browser_id = _text(value.browser_id, 'browser_id')
    if browser_id.casefold() in {'cdp', 'iab', 'extension', 'mcpapps'}:
        raise BindingError('Browser selection aliases are not canonical instance identities')
    return Binding(_text(value.worker_id, 'worker_id'), _text(value.browser_id, 'browser_id'),
                   _text(value.tab_id, 'tab_id'), _account(value.expected_account))


SCHEMA = """
CREATE TABLE meta (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  db_id TEXT NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
  mode TEXT NOT NULL CHECK(mode='staging'), ledger_db_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK(generation>=1),
  evidence_ttl_seconds INTEGER NOT NULL CHECK(evidence_ttl_seconds>0),
  last_checkpoint_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_checkpoint_sequence>=0),
  schema_hash TEXT NOT NULL
);
CREATE TABLE registry (
  role TEXT PRIMARY KEY CHECK(role IN ('publisher','spreader','commenter')),
  worker_id TEXT NOT NULL UNIQUE, browser_id TEXT NOT NULL, tab_id TEXT NOT NULL,
  expected_account TEXT NOT NULL, generation INTEGER NOT NULL,
  anchor_at INTEGER NOT NULL, interval_seconds INTEGER NOT NULL CHECK(interval_seconds>0),
  UNIQUE(browser_id, tab_id)
);
CREATE TABLE evidence (
  evidence_id TEXT PRIMARY KEY, role TEXT NOT NULL REFERENCES registry(role),
  worker_id TEXT NOT NULL, browser_id TEXT NOT NULL, tab_id TEXT NOT NULL,
  observed_account TEXT NOT NULL, tab_exists INTEGER NOT NULL CHECK(tab_exists=1),
  generation INTEGER NOT NULL, observed_at INTEGER NOT NULL, recorded_at INTEGER NOT NULL
);
CREATE TABLE jobs (
  job_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL REFERENCES registry(role), scheduled_at INTEGER NOT NULL,
  next_same_role_at INTEGER NOT NULL CHECK(next_same_role_at>scheduled_at),
  generation INTEGER NOT NULL, worker_id TEXT NOT NULL, browser_id TEXT NOT NULL,
  tab_id TEXT NOT NULL, expected_account TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('preparing','ready','dispatching','checkpoint_wait','done','expired','blocked')),
  payload_json TEXT, payload_hash TEXT, preparation_evidence_id TEXT NOT NULL,
  action_manifest_json TEXT, action_manifest_hash TEXT,
  dispatch_evidence_id TEXT, dispatcher_id TEXT, claim_token_hash TEXT,
  checkpoint_id TEXT, result_digest TEXT, checkpoint_proof_json TEXT,
  checkpoint_proof_hash TEXT, blocked_reason TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE(role, scheduled_at),
  CHECK((payload_json IS NULL AND payload_hash IS NULL) OR (payload_json IS NOT NULL AND payload_hash IS NOT NULL))
);
CREATE UNIQUE INDEX one_open_job_per_role ON jobs(role)
  WHERE state IN ('preparing','ready','dispatching','checkpoint_wait');
CREATE UNIQUE INDEX one_dispatch_owner ON jobs((1))
  WHERE state IN ('dispatching','checkpoint_wait');
CREATE TABLE dispatcher (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  job_id TEXT REFERENCES jobs(job_id), dispatcher_id TEXT, claim_token_hash TEXT,
  CHECK((job_id IS NULL AND dispatcher_id IS NULL AND claim_token_hash IS NULL) OR
        (job_id IS NOT NULL AND dispatcher_id IS NOT NULL AND claim_token_hash IS NOT NULL))
);
CREATE TABLE action_progress (
  job_id TEXT NOT NULL REFERENCES jobs(job_id), action_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','intent','submitted','verified','duplicate','cancelled','already_present','uncertain','denied_unresolved')),
  result_json TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY(job_id, action_id)
);
CREATE UNIQUE INDEX one_inflight_action_per_job ON action_progress(job_id)
  WHERE state IN ('reserved','intent','submitted');
CREATE TABLE audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  event TEXT NOT NULL, job_id TEXT, detail_json TEXT NOT NULL
);
CREATE TRIGGER immutable_payload BEFORE UPDATE OF payload_json,payload_hash ON jobs
WHEN OLD.payload_json IS NOT NULL AND
 (NEW.payload_json IS NOT OLD.payload_json OR NEW.payload_hash IS NOT OLD.payload_hash)
BEGIN SELECT RAISE(ABORT, 'prepared payload is immutable'); END;
CREATE TRIGGER immutable_slot BEFORE UPDATE OF role,scheduled_at,next_same_role_at,generation,
 worker_id,browser_id,tab_id,expected_account,idempotency_key,job_id ON jobs
BEGIN SELECT RAISE(ABORT, 'job identity is immutable'); END;
CREATE TRIGGER immutable_action_manifest BEFORE UPDATE OF action_manifest_json,action_manifest_hash ON jobs
WHEN OLD.action_manifest_json IS NOT NULL AND
 (NEW.action_manifest_json IS NOT OLD.action_manifest_json OR NEW.action_manifest_hash IS NOT OLD.action_manifest_hash)
BEGIN SELECT RAISE(ABORT, 'expected action manifest is immutable'); END;
"""


def _schema_hash(conn: sqlite3.Connection) -> str:
    return _hash(_canonical([tuple(row) for row in conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]))


def _expected_schema_hash() -> str:
    with sqlite3.connect(':memory:') as conn:
        conn.executescript(SCHEMA)
        return _schema_hash(conn)


EXPECTED_SCHEMA_HASH = _expected_schema_hash()


def initialize_staging(path: str | Path, bindings: Mapping[str, Binding | Mapping[str, Any]],
                       schedules: Mapping[str, Schedule | Mapping[str, Any]], *,
                       ledger_db_id: str, evidence_ttl_seconds: int = 30) -> DatabaseIdentity:
    """Explicit, exclusive staging initialization. Never opens or overwrites a file."""
    path = _path(path)
    if set(bindings) != set(ROLES) or set(schedules) != set(ROLES):
        raise BindingError('Exactly publisher, spreader and commenter must be configured')
    normalized = {role: _binding(bindings[role]) for role in ROLES}
    if len({b.worker_id for b in normalized.values()}) != 3 or len({(b.browser_id, b.tab_id) for b in normalized.values()}) != 3:
        raise BindingError('Roles must have distinct workers and browser/tab pairs')
    schedule_values = {}
    for role, value in schedules.items():
        value = value if isinstance(value, Schedule) else Schedule(**value)
        _integer(value.anchor_at, 'anchor_at')
        _integer(value.interval_seconds, 'interval_seconds', 1)
        schedule_values[role] = value
    ledger_db_id = _text(ledger_db_id, 'ledger_db_id')
    _integer(evidence_ttl_seconds, 'evidence_ttl_seconds', 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise StateError('Initialization requires an absent file') from exc
    os.close(fd)
    db_id = str(uuid.uuid4())
    conn = None
    try:
        conn = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, isolation_level=None)
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA synchronous=FULL')
        conn.executescript('BEGIN EXCLUSIVE;\n' + SCHEMA)
        conn.execute('PRAGMA user_version=1')
        conn.execute('INSERT INTO meta VALUES(1,?,1,\'staging\',?,1,?,0,?)', (db_id, ledger_db_id, evidence_ttl_seconds, EXPECTED_SCHEMA_HASH))
        conn.execute('INSERT INTO dispatcher VALUES(1,NULL,NULL,NULL)')
        for role in ROLES:
            b, s = normalized[role], schedule_values[role]
            conn.execute('INSERT INTO registry VALUES(?,?,?,?,?,1,?,?)',
                         (role, b.worker_id, b.browser_id, b.tab_id, b.expected_account, s.anchor_at, s.interval_seconds))
        conn.execute('COMMIT')
    except Exception:
        if conn:
            conn.close()
            conn = None
        path.unlink(missing_ok=True)
        raise
    finally:
        if conn:
            conn.close()
    stat = path.stat()
    identity = DatabaseIdentity(db_id, stat.st_dev, stat.st_ino)
    QueueCore(path, identity)
    return identity


class QueueCore:
    """Short transactional connections support concurrent processes and workers."""

    def __init__(self, path: str | Path, identity: DatabaseIdentity | Mapping[str, Any]):
        self.path = _path(path)
        self.identity = identity if isinstance(identity, DatabaseIdentity) else DatabaseIdentity(**identity)
        with self._tx():
            pass

    def _check_file(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError as exc:
            raise StateError('Queue database is absent; initialization/recovery is never implicit') from exc
        if self.path.is_symlink() or (stat.st_dev, stat.st_ino) != (self.identity.device, self.identity.inode):
            raise StateError('Queue database file was replaced; explicit offline review is required')

    @contextmanager
    def _tx(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        self._check_file()
        conn = None
        try:
            conn = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=15, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA foreign_keys=ON')
            conn.execute('PRAGMA synchronous=FULL')
            conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            self._check_file()
            self._check_state(conn)
            yield conn
            self._check_state(conn)
            self._check_file()
            conn.execute('COMMIT')
        except sqlite3.Error as exc:
            if conn and conn.in_transaction:
                conn.execute('ROLLBACK')
            raise StateError(f'Queue database operation failed closed: {exc}') from exc
        except Exception:
            if conn and conn.in_transaction:
                conn.execute('ROLLBACK')
            raise
        finally:
            if conn:
                conn.close()

    def _check_state(self, conn: sqlite3.Connection) -> None:
        if conn.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or conn.execute('PRAGMA foreign_key_check').fetchone():
            raise StateError('Queue integrity check failed')
        if conn.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
            raise StateError('Unsupported companion queue schema')
        if _schema_hash(conn) != EXPECTED_SCHEMA_HASH:
            raise StateError('Queue schema/guard definitions changed; no implicit migration or repair')
        rows = conn.execute('SELECT * FROM meta').fetchall()
        if len(rows) != 1:
            raise StateError('Queue metadata is missing or ambiguous')
        meta = rows[0]
        if (meta['db_id'] != self.identity.db_id or meta['schema_version'] != SCHEMA_VERSION or
            meta['mode'] != 'staging' or meta['schema_hash'] != EXPECTED_SCHEMA_HASH):
            raise StateError('Queue database identity/schema/mode mismatch')
        registry = conn.execute('SELECT * FROM registry').fetchall()
        if {r['role'] for r in registry} != set(ROLES) or any(r['generation'] != meta['generation'] for r in registry):
            raise StateError('Registry is incomplete or generation is inconsistent')
        for job in conn.execute('SELECT * FROM jobs'):
            ownership = (job['dispatcher_id'], job['claim_token_hash'], job['dispatch_evidence_id'])
            if any(value is None for value in ownership) and not all(value is None for value in ownership):
                raise StateError('Partially lost job ownership state')
            if job['state'] in ('preparing', 'ready', 'expired') and any(value is not None for value in ownership):
                raise StateError('An unclaimed/expired job unexpectedly has dispatch ownership')
            if job['state'] in ('dispatching', 'checkpoint_wait', 'done') and any(value is None for value in ownership):
                raise StateError('Claimed/completed job lost its ownership identity')
            if job['state'] in ('ready', 'dispatching', 'checkpoint_wait', 'done') and job['payload_json'] is None:
                raise StateError('Ready/claimed job lost its immutable preparation')
            if job['state'] in ('preparing', 'ready', 'dispatching', 'checkpoint_wait') and job['generation'] != meta['generation']:
                raise StateError('Open job has an invalid registry generation')
            if job['state'] in ('checkpoint_wait', 'done'):
                if job['checkpoint_id'] is None or job['result_digest'] is None:
                    raise StateError('Checkpoint state lost its exact checkpoint/result binding')
                if conn.execute("SELECT 1 FROM action_progress WHERE job_id=? AND state NOT IN ('verified','duplicate','cancelled','already_present') LIMIT 1", (job['job_id'],)).fetchone():
                    raise StateError('Checkpoint state contains unresolved action progress')
                self._check_action_coverage(conn, job)
            if job['action_manifest_json'] is not None:
                if _hash(job['action_manifest_json']) != job['action_manifest_hash']:
                    raise StateError('Expected action manifest hash mismatch')
                expected = json.loads(job['action_manifest_json'])
                recorded = {r[0] for r in conn.execute('SELECT action_id FROM action_progress WHERE job_id=?', (job['job_id'],))}
                if not recorded.issubset(set(expected)):
                    raise StateError('Recorded action is outside the expected action manifest')
            elif conn.execute('SELECT 1 FROM action_progress WHERE job_id=? LIMIT 1', (job['job_id'],)).fetchone():
                raise StateError('Action progress lost its expected action manifest')
            if job['state'] == 'done' and (job['checkpoint_proof_json'] is None or
                    _hash(job['checkpoint_proof_json']) != job['checkpoint_proof_hash']):
                raise StateError('Completed job lost or changed its exact checkpoint proof')
        writers = conn.execute('SELECT * FROM dispatcher').fetchall()
        if len(writers) != 1:
            raise StateError('Dispatcher ownership row is missing or ambiguous')
        writer = writers[0]
        owned = conn.execute("SELECT * FROM jobs WHERE state IN ('dispatching','checkpoint_wait') OR (state='blocked' AND claim_token_hash IS NOT NULL)").fetchall()
        if writer['job_id'] is None:
            if owned:
                raise StateError('Lost writer ownership; dispatch state cannot be recovered automatically')
        else:
            job = conn.execute('SELECT * FROM jobs WHERE job_id=?', (writer['job_id'],)).fetchone()
            if (job is None or job['state'] not in ('dispatching', 'checkpoint_wait', 'blocked') or
                job['dispatcher_id'] != writer['dispatcher_id'] or job['claim_token_hash'] != writer['claim_token_hash'] or
                any(j['job_id'] != job['job_id'] for j in owned)):
                raise StateError('Dispatcher ownership and job state disagree')
        for row in conn.execute('SELECT payload_json,payload_hash FROM jobs WHERE payload_json IS NOT NULL'):
            if _hash(row['payload_json']) != row['payload_hash']:
                raise StateError('Prepared payload hash mismatch')

    @staticmethod
    def _audit(conn: sqlite3.Connection, now: int, event: str, job_id: str | None = None, **details: Any) -> None:
        conn.execute('INSERT INTO audit(at,event,job_id,detail_json) VALUES(?,?,?,?)',
                     (now, event, job_id, _canonical(details)))

    @staticmethod
    def _role(conn: sqlite3.Connection, role: str) -> sqlite3.Row:
        row = conn.execute('SELECT * FROM registry WHERE role=?', (role,)).fetchone()
        if row is None:
            raise BindingError('Unknown role')
        return row

    @staticmethod
    def _job(conn: sqlite3.Connection, job_id: str) -> sqlite3.Row:
        row = conn.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
        if row is None:
            raise StateError('Unknown job')
        return row

    def _evidence(self, conn: sqlite3.Connection, role: str, evidence_id: str, now: int) -> sqlite3.Row:
        registry = self._role(conn, role)
        evidence = conn.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
        ttl = conn.execute('SELECT evidence_ttl_seconds FROM meta').fetchone()[0]
        if evidence is None or evidence['role'] != role:
            raise BindingError('Missing or wrong-role observation evidence')
        for field in ('generation', 'worker_id', 'browser_id', 'tab_id'):
            if evidence[field] != registry[field]:
                raise BindingError(f'Observation has a stale/mismatched {field}')
        if evidence['observed_account'] != registry['expected_account'] or evidence['tab_exists'] != 1:
            raise BindingError('Account/tab observation does not match registry')
        if not 0 <= now - evidence['observed_at'] <= ttl:
            raise BindingError('Observation is stale or from the future')
        return evidence

    def _job_binding(self, conn: sqlite3.Connection, job: sqlite3.Row) -> None:
        registry = self._role(conn, job['role'])
        if any(job[field] != registry[field] for field in ('generation', 'worker_id', 'browser_id', 'tab_id', 'expected_account')):
            raise BindingError('Registry changed; this job is permanently invalid')

    def record_observation(self, role: str, *, worker_id: str, browser_id: str, tab_id: str,
                           observed_account: str, tab_exists: bool, observed_at: int, now: int) -> str:
        """Record a trusted adapter's fresh observed identity, never an inferred login."""
        _integer(now, 'now'); _integer(observed_at, 'observed_at')
        with self._tx(True) as conn:
            registry = self._role(conn, role)
            if tab_exists is not True or (worker_id, browser_id, tab_id, _account(observed_account)) != (
                    registry['worker_id'], registry['browser_id'], registry['tab_id'], registry['expected_account']):
                raise BindingError('Observed worker/browser/tab/account must exactly match the dedicated role')
            ttl = conn.execute('SELECT evidence_ttl_seconds FROM meta').fetchone()[0]
            if not 0 <= now - observed_at <= ttl:
                raise BindingError('Observation must be fresh and not in the future')
            evidence_id = str(uuid.uuid4())
            conn.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,1,?,?,?)',
                         (evidence_id, role, worker_id, browser_id, tab_id, _account(observed_account), registry['generation'], observed_at, now))
            self._audit(conn, now, 'observation', role=role, evidence_id=evidence_id)
            return evidence_id

    def rebind(self, role: str, binding: Binding | Mapping[str, Any], *, expected_generation: int, reason: str, now: int) -> int:
        """Explicit offline-safe rebind. Invalidates ALL outstanding jobs/evidence."""
        b = _binding(binding); _integer(now, 'now'); _text(reason, 'reason')
        with self._tx(True) as conn:
            self._role(conn, role)
            current = conn.execute('SELECT generation FROM meta').fetchone()[0]
            if current != expected_generation:
                raise BindingError('Registry generation changed since the rebind was reviewed')
            if conn.execute('SELECT job_id FROM dispatcher').fetchone()[0] is not None:
                raise BusyError('Cannot rebind while dispatch or checkpoint ownership exists')
            if conn.execute('SELECT role FROM registry WHERE role<>? AND (worker_id=? OR (browser_id=? AND tab_id=?))',
                            (role, b.worker_id, b.browser_id, b.tab_id)).fetchone():
                raise BindingError('A worker or browser/tab pair is already owned by another role')
            generation = current + 1
            conn.execute('UPDATE registry SET worker_id=?,browser_id=?,tab_id=?,expected_account=? WHERE role=?',
                         (b.worker_id, b.browser_id, b.tab_id, b.expected_account, role))
            conn.execute('UPDATE registry SET generation=?', (generation,))
            conn.execute('UPDATE meta SET generation=?', (generation,))
            conn.execute("UPDATE jobs SET state='blocked',blocked_reason='registry generation changed',updated_at=? WHERE state IN ('preparing','ready')", (now,))
            self._audit(conn, now, 'rebind', role=role, generation=generation, reason=reason)
            return generation

    @staticmethod
    def _expire(conn: sqlite3.Connection, now: int) -> None:
        conn.execute("UPDATE jobs SET state='expired',updated_at=? WHERE state IN ('preparing','ready') AND next_same_role_at<=?", (now, now))

    def enqueue(self, role: str, scheduled_at: int, next_same_role_at: int, *, evidence_id: str, now: int) -> dict[str, Any]:
        """Only this schedule's current slot. Duplicate same-slot triggers share a job."""
        _integer(now, 'now'); _integer(scheduled_at, 'scheduled_at'); _integer(next_same_role_at, 'next_same_role_at')
        with self._tx(True) as conn:
            registry = self._role(conn, role)
            schedule = Schedule(registry['anchor_at'], registry['interval_seconds'])
            if schedule.current_slot(now) != (scheduled_at, next_same_role_at):
                raise SlotError('Only the exact current slot can enqueue; no catch-up or future slots')
            self._evidence(conn, role, evidence_id, now)
            old = conn.execute('SELECT * FROM jobs WHERE role=? AND scheduled_at=?', (role, scheduled_at)).fetchone()
            if old:
                self._job_binding(conn, old)
                if old['next_same_role_at'] != next_same_role_at:
                    raise ConflictError('Duplicate slot has a conflicting deadline')
                return dict(old)
            self._expire(conn, now)
            active = conn.execute("SELECT job_id FROM jobs WHERE role=? AND state IN ('preparing','ready','dispatching','checkpoint_wait')", (role,)).fetchone()
            writer = conn.execute('SELECT job_id FROM dispatcher').fetchone()[0]
            if active or (writer and self._job(conn, writer)['role'] == role):
                raise BusyError('This role still has an open/uncertain job; do not backfill this slot later')
            key = _hash(f'{self.identity.db_id}:{role}:{scheduled_at}')
            job_id = 'job_' + key
            conn.execute('''INSERT INTO jobs(job_id,idempotency_key,role,scheduled_at,next_same_role_at,
                generation,worker_id,browser_id,tab_id,expected_account,state,preparation_evidence_id,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,'preparing',?,?,?)''',
                         (job_id, key, role, scheduled_at, next_same_role_at, registry['generation'], registry['worker_id'],
                          registry['browser_id'], registry['tab_id'], registry['expected_account'], evidence_id, now, now))
            self._audit(conn, now, 'enqueued', job_id)
            return dict(self._job(conn, job_id))

    def mark_ready(self, job_id: str, payload: Any, *, evidence_id: str, now: int) -> dict[str, Any]:
        """Freeze exact prepared JSON. Put immutable object reference+digest in JSON if needed."""
        _integer(now, 'now')
        encoded = _canonical(payload)
        if len(encoded.encode('utf-8')) > 1024 * 1024:
            raise QueueError('Prepared payload exceeds the staging 1 MiB bound')
        digest = _hash(encoded)
        with self._tx(True) as conn:
            job = self._job(conn, job_id)
            self._job_binding(conn, job); self._evidence(conn, job['role'], evidence_id, now)
            if not job['scheduled_at'] <= now < job['next_same_role_at']:
                raise SlotError('Slot deadline passed; preparation cannot advance')
            if job['payload_json'] is not None:
                if job['payload_json'] != encoded or job['payload_hash'] != digest:
                    raise ConflictError('Prepared payload is immutable, including duplicate triggers')
                return dict(job)
            if job['state'] != 'preparing':
                raise StateError('Only a preparing job can become ready')
            conn.execute("UPDATE jobs SET payload_json=?,payload_hash=?,state='ready',preparation_evidence_id=?,updated_at=? WHERE job_id=?",
                         (encoded, digest, evidence_id, now, job_id))
            self._audit(conn, now, 'prepared', job_id, payload_hash=digest)
            return dict(self._job(conn, job_id))

    def claim_next(self, dispatcher_id: str, evidence_by_role: Mapping[str, str], *, now: int) -> DispatchClaim | None:
        """Atomically own one ready job, or return None to WAIT. Never skip/steal a busy writer."""
        dispatcher_id = _text(dispatcher_id, 'dispatcher_id'); _integer(now, 'now')
        with self._tx(True) as conn:
            self._expire(conn, now)
            if conn.execute('SELECT job_id FROM dispatcher').fetchone()[0] is not None:
                return None
            job = conn.execute("SELECT * FROM jobs WHERE state='ready' ORDER BY scheduled_at,created_at,role LIMIT 1").fetchone()
            if job is None:
                return None
            if now < job['scheduled_at']:
                raise SlotError('Clock is before the ready job slot; refusing a future dispatch')
            self._job_binding(conn, job)
            evidence_id = evidence_by_role.get(job['role'], '')
            self._evidence(conn, job['role'], evidence_id, now)
            token = str(uuid.uuid4())
            token_hash = _hash(token)
            conn.execute("UPDATE jobs SET state='dispatching',dispatcher_id=?,claim_token_hash=?,dispatch_evidence_id=?,updated_at=? WHERE job_id=?",
                         (dispatcher_id, token_hash, evidence_id, now, job['job_id']))
            conn.execute('UPDATE dispatcher SET job_id=?,dispatcher_id=?,claim_token_hash=? WHERE singleton=1', (job['job_id'], dispatcher_id, token_hash))
            self._audit(conn, now, 'claimed', job['job_id'], dispatcher_id=dispatcher_id)
            return DispatchClaim(job['job_id'], dispatcher_id, token, job['generation'], job['payload_hash'], evidence_id)

    def _claim(self, conn: sqlite3.Connection, claim: DispatchClaim) -> sqlite3.Row:
        if not isinstance(claim, DispatchClaim):
            raise StateError('A typed DispatchClaim is required')
        writer = conn.execute('SELECT * FROM dispatcher').fetchone()
        job = self._job(conn, claim.job_id)
        if (writer['job_id'], writer['dispatcher_id'], writer['claim_token_hash']) != (claim.job_id, claim.dispatcher_id, _hash(claim.claim_token)):
            raise StateError('Claim is not the current exclusive dispatcher owner')
        if (job['generation'], job['payload_hash'], job['dispatch_evidence_id']) != (claim.generation, claim.payload_hash, claim.evidence_id):
            raise StateError('Claim does not match immutable job bindings/payload/evidence')
        self._job_binding(conn, job)
        return job

    def validate_action_start(self, claim: DispatchClaim, evidence_id: str, *, now: int) -> dict[str, Any]:
        """Recheck just before EACH new action; does not grant browser authorization."""
        _integer(now, 'now')
        with self._tx(True) as conn:
            job = self._claim(conn, claim)
            if job['state'] != 'dispatching':
                raise StateError('No new action in checkpoint_wait or blocked state')
            if not job['scheduled_at'] <= now < job['next_same_role_at']:
                raise SlotError('Deadline reached: no new action; complete existing readback/checkpoint')
            self._evidence(conn, job['role'], evidence_id, now)
            self._audit(conn, now, 'action_start_validated', job['job_id'], evidence_id=evidence_id)
            return dict(job)

    def block_claim(self, claim: DispatchClaim, reason: str, *, now: int) -> dict[str, Any]:
        """Uncertainty holds exclusive ownership indefinitely; NEVER releases writer."""
        _integer(now, 'now'); reason = _text(reason, 'reason')
        with self._tx(True) as conn:
            job = self._claim(conn, claim)
            conn.execute("UPDATE jobs SET state='blocked',blocked_reason=?,updated_at=? WHERE job_id=?", (reason, now, job['job_id']))
            self._audit(conn, now, 'claim_blocked', job['job_id'], reason=reason)
            return dict(self._job(conn, job['job_id']))

    def register_action_manifest(self, claim: DispatchClaim, action_ids: list[str], *, now: int) -> dict[str, Any]:
        """Freeze the gate's computed ordered IDs before any action progress.

        Count must equal the exact prepared actions list. An empty manifest is
        valid only for a genuinely empty actions list. The gate independently
        computes canonical IDs from the frozen outbound action content.
        """
        _integer(now, 'now')
        if type(action_ids) is not list or len(action_ids) > 100:
            raise StateError('An explicit bounded list of expected action IDs is required')
        ids = [_text(value, 'action_id') for value in action_ids]
        if ids != action_ids or len(set(ids)) != len(ids):
            raise StateError('Expected action IDs must be exact and unique')
        encoded = _canonical(ids)
        with self._tx(True) as conn:
            job = self._claim(conn, claim)
            if job['state'] != 'dispatching':
                raise StateError('Only a dispatching claim can register its expected actions')
            payload = json.loads(job['payload_json'])
            if (type(payload) is not dict or type(payload.get('actions')) is not list or
                    len(payload['actions']) != len(ids)):
                raise StateError('Manifest must cover the entire exact prepared action batch')
            if job['action_manifest_json'] is not None:
                if job['action_manifest_json'] != encoded:
                    raise ConflictError('Expected action manifest is immutable')
                return dict(job)
            if conn.execute('SELECT 1 FROM action_progress WHERE job_id=? LIMIT 1', (claim.job_id,)).fetchone():
                raise StateError('Expected actions must be registered before progress')
            conn.execute('UPDATE jobs SET action_manifest_json=?,action_manifest_hash=?,updated_at=? WHERE job_id=?',
                         (encoded, _hash(encoded), now, claim.job_id))
            self._audit(conn, now, 'action_manifest_registered', claim.job_id, count=len(ids), manifest_hash=_hash(encoded))
            return dict(self._job(conn, claim.job_id))

    @staticmethod
    def _check_action_coverage(conn: sqlite3.Connection, job: sqlite3.Row) -> None:
        if job['action_manifest_json'] is None:
            raise CheckpointError('A frozen expected-action manifest is required')
        expected = set(json.loads(job['action_manifest_json']))
        actual = {r[0] for r in conn.execute('SELECT action_id FROM action_progress WHERE job_id=?', (job['job_id'],))}
        if expected != actual:
            raise CheckpointError('Every planned action needs an exact recorded terminal outcome')

    def record_action_progress(self, claim: DispatchClaim, action_id: str, state: str, *,
                               result: Any = None, now: int) -> dict[str, Any]:
        """Durable one-way action guard; authoritative external state lives in ledger.

        No writer/lease/auth tokens belong in result. Unknown/denied outcomes are
        terminal here and retain the dispatcher until explicit offline review;
        they can never be converted into retry permission.
        """
        _integer(now, 'now'); action_id = _text(action_id, 'action_id')
        allowed = set(ACTION_TRANSITIONS) | SAFE_ACTION_STATES | UNRESOLVED_ACTION_STATES
        if state not in allowed:
            raise StateError('Unknown action progress state')
        def check_no_tokens(value: Any) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    if isinstance(key, str) and key.casefold() in {'token','writer_token','lease_token','fence_token','claim_token','access_token','api_key','password'}:
                        raise StateError('Writer/auth tokens must never be persisted in action progress')
                    check_no_tokens(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    check_no_tokens(nested)
        check_no_tokens(result)
        encoded = _canonical(result)
        if len(encoded.encode('utf-8')) > 65536:
            raise StateError('Action result exceeds the staging 64 KiB bound')
        with self._tx(True) as conn:
            job = self._claim(conn, claim)
            if job['state'] not in ('dispatching', 'blocked'):
                raise StateError('Action progress cannot change in checkpoint_wait or done')
            if job['action_manifest_json'] is None or action_id not in json.loads(job['action_manifest_json']):
                raise StateError('Action is absent from the frozen expected action manifest')
            old = conn.execute('SELECT * FROM action_progress WHERE job_id=? AND action_id=?', (claim.job_id, action_id)).fetchone()
            if old and old['state'] == state:
                if old['result_json'] != encoded:
                    raise ConflictError('Repeated action progress has a conflicting result')
                return dict(old)
            if old:
                if state not in ACTION_TRANSITIONS.get(old['state'], ()):
                    raise StateError('Action transition is forbidden; terminal/uncertain actions never retry')
            elif state not in ('reserved', 'duplicate', 'cancelled', 'uncertain'):
                raise StateError('First action state must be reserved, duplicate, cancelled or uncertain')
            if job['state'] == 'blocked' and state not in UNRESOLVED_ACTION_STATES:
                raise StateError('Blocked claims cannot make new action progress')
            if state in ('reserved', 'intent'):
                if not job['scheduled_at'] <= now < job['next_same_role_at']:
                    raise SlotError('Deadline/future slot prohibits new action intent')
                other = conn.execute("SELECT action_id FROM action_progress WHERE job_id=? AND action_id<>? AND state IN ('reserved','intent','submitted')",
                                     (claim.job_id, action_id)).fetchone()
                if other:
                    raise BusyError('Another action must finish readback before a new action starts')
            if old:
                conn.execute('UPDATE action_progress SET state=?,result_json=?,updated_at=? WHERE job_id=? AND action_id=?',
                             (state, encoded, now, claim.job_id, action_id))
            else:
                conn.execute('INSERT INTO action_progress VALUES(?,?,?,?,?,?)', (claim.job_id, action_id, state, encoded, now, now))
            self._audit(conn, now, 'action_progress', claim.job_id, action_id=action_id, state=state, result_hash=_hash(encoded))
            if state in UNRESOLVED_ACTION_STATES:
                conn.execute("UPDATE jobs SET state='blocked',blocked_reason=?,updated_at=? WHERE job_id=?",
                             ('Action ' + action_id + ': ' + state, now, claim.job_id))
            return dict(conn.execute('SELECT * FROM action_progress WHERE job_id=? AND action_id=?', (claim.job_id, action_id)).fetchone())

    def list_action_progress(self, claim: DispatchClaim) -> list[dict[str, Any]]:
        with self._tx() as conn:
            job = self._job(conn, claim.job_id)
            if job['state'] == 'done':
                if (job['claim_token_hash'], job['dispatcher_id'], job['generation'], job['payload_hash'], job['dispatch_evidence_id']) != (
                        _hash(claim.claim_token), claim.dispatcher_id, claim.generation, claim.payload_hash, claim.evidence_id):
                    raise StateError('Claim does not match this completed job')
            else:
                self._claim(conn, claim)
            return [dict(row) for row in conn.execute('SELECT * FROM action_progress WHERE job_id=? ORDER BY created_at,action_id', (claim.job_id,))]

    def enter_checkpoint_wait(self, claim: DispatchClaim, checkpoint_id: str, result_digest: str, *, now: int) -> dict[str, Any]:
        """Bind a readback result to its requested checkpoint. Writer remains owned."""
        _integer(now, 'now'); checkpoint_id = _text(checkpoint_id, 'checkpoint_id'); _digest(result_digest, 'result_digest')
        with self._tx(True) as conn:
            job = self._claim(conn, claim)
            if job['state'] not in ('dispatching', 'checkpoint_wait'):
                raise StateError('Claim cannot enter checkpoint wait')
            if job['checkpoint_id'] is not None and (job['checkpoint_id'], job['result_digest']) != (checkpoint_id, result_digest):
                raise ConflictError('Checkpoint identity and readback result cannot change')
            if conn.execute("SELECT 1 FROM action_progress WHERE job_id=? AND state NOT IN ('verified','duplicate','cancelled','already_present') LIMIT 1", (claim.job_id,)).fetchone():
                raise CheckpointError('Every recorded action must be safely terminal before checkpoint acknowledgement')
            self._check_action_coverage(conn, job)
            conn.execute("UPDATE jobs SET state='checkpoint_wait',checkpoint_id=?,result_digest=?,updated_at=? WHERE job_id=?",
                         (checkpoint_id, result_digest, now, job['job_id']))
            self._audit(conn, now, 'checkpoint_wait', job['job_id'], checkpoint_id=checkpoint_id, result_digest=result_digest)
            return dict(self._job(conn, job['job_id']))

    def acknowledge_checkpoint(self, claim: DispatchClaim, proof: Mapping[str, Any], *, now: int) -> dict[str, Any]:
        """Trusted gate's exact verified proof only; no caller-supplied verified boolean.

        Required fields: checkpoint_id, result_digest, ledger_db_id, account,
        checkpoint_sequence, checkpoint_hash, library_file_id, library_version,
        archive_sha256, pair_manifest_sha256, queue_archive_sha256,
        queue_library_file_id, queue_library_version, queue_previous_version,
        pending=False, writer=None, stop=False, unresolved=False. The external
        adapter must verify the actual ledger/checkpoint/Library object before
        producing this mapping. Schema checks here are not that verification.
        Each subsequent completed boundary must continue this companion's same
        Library identity and exact previous-version chain. The first boundary's
        external baseline is pinned by the trusted transport adapter.
        """
        _integer(now, 'now')
        required = {'checkpoint_id','result_digest','ledger_db_id','account','checkpoint_sequence',
                    'checkpoint_hash','library_file_id','library_version','pending','writer','stop','unresolved',
                    'archive_sha256','pair_manifest_sha256','queue_archive_sha256','queue_library_file_id','queue_library_version',
                    'queue_previous_version'}
        if not isinstance(proof, Mapping) or set(proof) != required:
            raise CheckpointError('Exactly the documented checkpoint proof fields are required')
        proof = dict(proof)
        for field in ('checkpoint_id', 'ledger_db_id', 'library_file_id', 'library_version', 'queue_library_file_id', 'queue_library_version'):
            if _text(proof[field], field) != proof[field]:
                raise CheckpointError('Exact unpadded checkpoint and Library identifiers are required')
        _digest(proof['result_digest'], 'result_digest'); _digest(proof['checkpoint_hash'], 'checkpoint_hash')
        for field in ('archive_sha256', 'pair_manifest_sha256', 'queue_archive_sha256'):
            _digest(proof[field], field)
        previous_version = proof['queue_previous_version']
        if (type(previous_version) is not str or len(previous_version) > 2048 or
                previous_version != previous_version.strip()):
            raise CheckpointError('Exact queue_previous_version string required, empty only for an initial boundary')
        if proof['queue_library_version'] == previous_version:
            raise CheckpointError('Queue Library version must advance beyond its previous version')
        _integer(proof['checkpoint_sequence'], 'checkpoint_sequence', 1)
        if proof['pending'] is not False or proof['writer'] is not None or proof['stop'] is not False or proof['unresolved'] is not False:
            raise CheckpointError('Checkpoint is pending, has a writer, STOP, or unresolved state')
        if proof['account'] != _account(proof['account']):
            raise CheckpointError('Proof account must be normalized by the verification adapter')
        encoded, digest = _canonical(proof), _hash(_canonical(proof))
        with self._tx(True) as conn:
            job = self._job(conn, claim.job_id)
            if job['state'] == 'done':
                if (job['claim_token_hash'], job['dispatcher_id'], job['checkpoint_proof_hash']) != (_hash(claim.claim_token), claim.dispatcher_id, digest):
                    raise ConflictError('Duplicate acknowledgement differs from the completed proof')
                return dict(job)
            job = self._claim(conn, claim)
            if job['state'] != 'checkpoint_wait':
                raise CheckpointError('Explicit checkpoint_wait is required before acknowledgement')
            meta = conn.execute('SELECT * FROM meta').fetchone()
            if (proof['checkpoint_id'], proof['result_digest'], proof['ledger_db_id'], proof['account']) != (
                    job['checkpoint_id'], job['result_digest'], meta['ledger_db_id'], job['expected_account']):
                raise CheckpointError('Proof does not match the checkpoint, result, pinned ledger and account')
            if proof['checkpoint_sequence'] <= meta['last_checkpoint_sequence']:
                raise CheckpointError('Checkpoint sequence did not advance')
            prior_proofs = [json.loads(row[0]) for row in conn.execute(
                "SELECT checkpoint_proof_json FROM jobs WHERE state='done'")]
            if prior_proofs:
                prior = max(prior_proofs, key=lambda value: value['checkpoint_sequence'])
                if prior['checkpoint_sequence'] != meta['last_checkpoint_sequence']:
                    raise StateError('Local successful checkpoint history is incomplete or inconsistent')
                if (proof['queue_library_file_id'] != prior['queue_library_file_id'] or
                        previous_version != prior['queue_library_version']):
                    raise CheckpointError('Companion Library identity and exact prior version must continue the last successful checkpoint')
            elif meta['last_checkpoint_sequence'] != 0:
                raise StateError('Local successful checkpoint history is missing')
            conn.execute("UPDATE jobs SET state='done',checkpoint_proof_json=?,checkpoint_proof_hash=?,updated_at=? WHERE job_id=?", (encoded, digest, now, job['job_id']))
            conn.execute('UPDATE meta SET last_checkpoint_sequence=?', (proof['checkpoint_sequence'],))
            conn.execute('UPDATE dispatcher SET job_id=NULL,dispatcher_id=NULL,claim_token_hash=NULL WHERE singleton=1')
            self._audit(conn, now, 'checkpoint_acknowledged', job['job_id'], proof_hash=digest)
            return dict(self._job(conn, job['job_id']))

    def inspect_job(self, job_id: str) -> dict[str, Any]:
        with self._tx() as conn:
            return dict(self._job(conn, job_id))

    def snapshot(self) -> dict[str, Any]:
        """Read-only inspectable state; not a restorable/verified backup proof."""
        with self._tx() as conn:
            return {'identity': asdict(self.identity),
                    'meta': dict(conn.execute('SELECT * FROM meta').fetchone()),
                    'registry': [dict(r) for r in conn.execute('SELECT * FROM registry ORDER BY role')],
                    'dispatcher': dict(conn.execute('SELECT * FROM dispatcher').fetchone()),
                    'jobs': [dict(r) for r in conn.execute('SELECT * FROM jobs ORDER BY scheduled_at,role')],
                    'action_progress': [dict(r) for r in conn.execute('SELECT * FROM action_progress ORDER BY job_id,created_at,action_id')],
                    'audit': [dict(r) for r in conn.execute('SELECT * FROM audit ORDER BY sequence')]}
