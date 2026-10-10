"""Offline staging queue backup format and semantic verifier. No restore/transport.

Only configured staging roots below are permitted. Trusted source files are
loaded from the repository root, which never authorizes data reads there. A
validated snapshot is historical evidence, never an upload receipt, ledger
acknowledgement or permission
to dispatch. Callers must pin ExpectedBoundary independently of archive contents.
"""
from __future__ import annotations

import builtins
from contextlib import closing
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
from typing import Any
import uuid
import zipfile


from integration_paths import INTEGRATION_ROOT, SOURCE_ROOT

ORIGINAL_ROOT = INTEGRATION_ROOT.parent
PATHS_SOURCE_SHA256 = '25c4285e65f563d20f2d17fd3625a00f83599b9e9d250b5becbd3840d94cd222'
SETTINGS_SOURCE_SHA256 = '1c501fe96394b468b7d0038e44195f0ebd6dbf26aaa6ea44c168fa061127d058'
CORE_SOURCE_SHA256 = 'b647ad561f1558bcb0d41339de6bd9ea36ed65fea5b2749bb9fee072cbfe2395'
GATE_SOURCE_SHA256 = '2cda6b058cb99486b3e6d4b38574139e764847344aa6cc8dd3add3a451419cbf'
FORMAT = 'role-queue-snapshot-v1'
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_DB_BYTES + MAX_MANIFEST_BYTES + 4096
MAX_ROWS = 100000
MEMBERS = ('manifest.json', 'queue.sqlite3')
HASH = re.compile(r'[0-9a-f]{64}\Z')
TABLES = {'meta': 'singleton', 'registry': 'role', 'evidence': 'evidence_id',
          'jobs': 'job_id', 'dispatcher': 'singleton',
          'action_progress': 'job_id,action_id', 'audit': 'sequence',
          'sqlite_sequence': 'name'}


class SnapshotBlocked(ValueError):
    """Invalid or unverified backup; retain all existing barriers."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise SnapshotBlocked(reason)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError) as exc:
        raise SnapshotBlocked('Noncanonical JSON data') from exc


def _no_credentials(value: Any, *, depth: int = 0) -> None:
    _require(depth <= 32, 'Credential inspection nesting limit exceeded')
    if isinstance(value, dict):
        for key, nested in value.items():
            _require(type(key) is str, 'Invalid JSON key')
            name = re.sub(r'[^a-z0-9]', '', key.casefold())
            denied_fragments = ('authorization', 'apikey', 'password', 'secret',
                                'cookie', 'credential', 'privatekey', 'accesskey',
                                'bearer', 'headers')
            allowed_hash = name in {'claimtokenhash', 'dispatcherclaimtokenhash'}
            public_reference = name == 'authorizationid'
            _require((public_reference or not any(word in name for word in denied_fragments)) and
                     ('token' not in name or allowed_hash),
                     'Raw credential key is prohibited')
            if allowed_hash:
                _require(nested is None or (type(nested) is str and HASH.fullmatch(nested)),
                         'claim_token_hash must be a SHA-256 hash')
            if public_reference and nested is not None:
                _require(type(nested) is str and 0 < len(nested) <= 2048 and
                         nested == nested.strip(), 'Invalid public authorization reference')
            _no_credentials(nested, depth=depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _no_credentials(nested, depth=depth + 1)
    elif isinstance(value, str) and value.lstrip().startswith(('{', '[', '"', '\ufeff')):
        # Structured-looking strings are unwrapped repeatedly. Every parse error,
        # including duplicates/nonfinite values, blocks rather than hiding data.
        # This deliberately rejects malformed JSON-looking prose too; callers
        # must not weaken the rule after an export failure.
        nested = _parse_json(value)
        _no_credentials(nested, depth=depth + 1)


def _parse_json(data: str | bytes) -> Any:
    def pairs(items):
        obj = {}
        for key, value in items:
            _require(key not in obj, 'Duplicate JSON key')
            obj[key] = value
        return obj
    try:
        result = json.loads(data, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                SnapshotBlocked('Nonfinite JSON value')))
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, SnapshotBlocked):
            raise
        raise SnapshotBlocked('Malformed JSON') from exc


def _json(data: str | bytes) -> Any:
    result = _parse_json(data)
    _no_credentials(result)
    return result


AUDIT_DETAIL_FIELDS = {
    'observation': {'role', 'evidence_id'},
    'rebind': {'role', 'generation', 'reason'},
    'enqueued': set(),
    'prepared': {'payload_hash'},
    'claimed': {'dispatcher_id'},
    'action_start_validated': {'evidence_id'},
    'claim_blocked': {'reason'},
    'action_manifest_registered': {'count', 'manifest_hash'},
    'action_progress': {'action_id', 'state', 'result_hash'},
    'checkpoint_wait': {'checkpoint_id', 'result_digest'},
    'checkpoint_acknowledged': {'proof_hash'},
}
PAYLOAD_FIELDS = {
    'like': {'target', 'text'}, 'repost': {'target', 'text'},
    'follow': {'target', 'text'}, 'reply': {'target', 'text'},
    'self_reply': {'target', 'text'},
    'publish': {'target', 'text', 'article_id', 'blog_url', 'root', 'replies',
                'root_image_path', 'root_image_url', 'image_sha256', 'preview_reply_index'},
}
RESULT_FIELDS = {
    'verified': {'intent_id'}, 'duplicate': {'ledger_state', 'payload_matches'},
    'already_present': set(), 'cancelled': {'reason'},
}


def _safe_payload(kind: str, payload: dict) -> None:
    _require(kind in PAYLOAD_FIELDS and set(payload) <= PAYLOAD_FIELDS[kind],
             'Unreviewed action payload field is not exportable')
    for key, value in payload.items():
        if key == 'replies':
            _require(type(value) is list and len(value) == 3 and
                     all(type(item) is str for item in value), 'Invalid reply text array')
        elif key in ('article_id', 'preview_reply_index'):
            _require(type(value) is int and value > 0, 'Invalid payload integer')
        else:
            _require(type(value) is str, 'Action payload fields must be plain reviewed types')
    _no_credentials(payload)


def _safe_result(state: str, result: Any) -> None:
    _require(state in RESULT_FIELDS, 'Unsafe action result state')
    if result is None:
        return
    _require(type(result) is dict and set(result) <= RESULT_FIELDS[state],
             'Unreviewed action result field is not exportable')
    for key, value in result.items():
        if key == 'payload_matches':
            _require(type(value) is bool, 'Invalid payload comparison')
        elif key == 'intent_id':
            _require(type(value) is str and HASH.fullmatch(value), 'Invalid intent result')
        elif key == 'ledger_state':
            _require(value in gate.STATES, 'Invalid terminal ledger state')
        else:
            _require(type(value) is str and len(value) <= 2048, 'Invalid result reason')
    _no_credentials(result)


def _safe_path(value: str | Path, *, directory: bool = False) -> Path:
    p = Path(value)
    _require(p.is_absolute() and '..' not in p.parts, 'Absolute staging path required')
    # Resolve no symlinks, including symlink ancestors. Do not silently follow one.
    for ancestor in (p, *p.parents):
        _require(not ancestor.is_symlink(), 'Symlink path prohibited')
    p = p.resolve()
    _require(any(p.is_relative_to(root) and (directory or p != root)
                 for root in (ORIGINAL_ROOT, INTEGRATION_ROOT)),
             'Only configured staging data roots are allowed')
    if directory:
        _require(p.is_dir(), 'Existing staging output directory required')
    return p


def _fingerprint(s: os.stat_result) -> tuple:
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _read_file(p: Path, maximum: int) -> bytes:
    fd = None
    try:
        before = p.lstat()
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                 'Missing, nonregular or oversized file')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        _require(_fingerprint(before) == _fingerprint(opened), 'File changed before read')
        with os.fdopen(fd, 'rb') as handle:
            fd = None
            data = handle.read(maximum + 1)
            after_fd = os.fstat(handle.fileno())
        after = p.lstat()
        _require(len(data) == before.st_size and
                 _fingerprint(before) == _fingerprint(after_fd) == _fingerprint(after),
                 'File changed during read')
        return data
    except OSError as exc:
        raise SnapshotBlocked('Required staging file unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _frozen_module(name: str, filename: str, digest: str, *, settings=None):
    # Source validation is deliberately separate from the data-path allowlist.
    _require(Path(filename).name == filename, 'Plain reviewed source filename required')
    path = SOURCE_ROOT / filename
    for ancestor in (path, *path.parents):
        _require(not ancestor.is_symlink(), 'Symlink source path prohibited')
    source = _read_file(path, 1024 * 1024)
    _require(_sha(source) == digest, 'Frozen implementation source changed')
    # Execute the already verified bytes, avoiding an import-time path race.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    if settings is not None:
        imports = dict(vars(builtins))
        real_import = imports['__import__']

        def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name == 'settings':
                return settings
            return real_import(name, globals, locals, fromlist, level)

        imports['__import__'] = pinned_import
        module.__dict__['__builtins__'] = imports
    exec(compile(source, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


_settings = _frozen_module('_queue_checkpoint_frozen_settings', 'settings.py', SETTINGS_SOURCE_SHA256)
_paths = _frozen_module('_queue_checkpoint_frozen_paths', 'integration_paths.py',
                        PATHS_SOURCE_SHA256, settings=_settings)
_require(_settings.STAGING_ROOT == ORIGINAL_ROOT and
         (_paths.SOURCE_ROOT, _paths.INTEGRATION_ROOT) == (SOURCE_ROOT, INTEGRATION_ROOT),
         'Pinned staging configuration does not match integration root')
core = _frozen_module('_queue_checkpoint_frozen_core', 'queue_core.py', CORE_SOURCE_SHA256,
                      settings=_settings)
gate = _frozen_module('_queue_checkpoint_frozen_gate', 'dispatch_gate.py', GATE_SOURCE_SHA256,
                      settings=_settings)


@dataclass(frozen=True)
class ExpectedBoundary:
    account: str
    ledger_db_id: str
    queue_db_id: str
    registry_generation: int
    job_id: str
    checkpoint_id: str
    checkpoint_sequence: int
    result_digest: str

    def validate(self) -> None:
        _require(type(self.account) is str and
                 re.fullmatch(r'[a-z0-9_.]{1,64}', self.account), 'Invalid pinned account')
        _require(type(self.ledger_db_id) is str and
                 re.fullmatch(r'[0-9a-f]{32}', self.ledger_db_id), 'Invalid pinned ledger ID')
        try:
            valid_uuid = str(uuid.UUID(self.queue_db_id)) == self.queue_db_id
        except (ValueError, TypeError, AttributeError):
            valid_uuid = False
        _require(valid_uuid, 'Invalid pinned queue ID')
        for value in (self.registry_generation, self.checkpoint_sequence):
            _require(type(value) is int and value > 0, 'Invalid pinned generation/sequence')
        _require(type(self.job_id) is str and self.job_id.startswith('job_') and
                 HASH.fullmatch(self.job_id[4:]), 'Invalid pinned job ID')
        _require(self.checkpoint_id == f'{self.ledger_db_id}:{self.checkpoint_sequence}',
                 'Checkpoint ID must bind exact ledger ID and sequence')
        _require(type(self.result_digest) is str and HASH.fullmatch(self.result_digest),
                 'Invalid pinned result digest')


@dataclass(frozen=True)
class ValidatedSnapshot:
    archive_path: str
    archive_sha256: str
    manifest_sha256: str
    database_sha256: str
    expected: ExpectedBoundary
    # Canonical immutable bytes, rather than a mutable "verified" dictionary.
    manifest_json: bytes

    def manifest(self) -> dict[str, Any]:
        return _json(self.manifest_json)


def _connect_readonly(path: Path, *, immutable: bool = False) -> sqlite3.Connection:
    uri = path.as_uri() + '?mode=ro' + ('&immutable=1' if immutable else '')
    conn = sqlite3.connect(uri, uri=True, timeout=2, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if hasattr(conn, 'setconfig'):
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
    conn.execute('PRAGMA query_only=ON')
    conn.execute('PRAGMA trusted_schema=OFF')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _planned_ids(payload: Any, account: str) -> list[str]:
    _require(type(payload) is dict and set(payload) == {'actions'} and
             type(payload['actions']) is list and len(payload['actions']) <= 100,
             'Invalid prepared action batch')
    ids = []
    for action in payload['actions']:
        _require(type(action) is dict and set(action) ==
                 {'kind', 'target', 'payload', 'authorization_id'}, 'Invalid planned action')
        _require(type(action['authorization_id']) is str and
                 0 < len(action['authorization_id']) <= 2048 and
                 action['authorization_id'] == action['authorization_id'].strip(),
                 'Invalid authorization reference')
        _require(type(action['payload']) is dict and
                 action['payload'].get('target') == action['target'], 'Action payload target mismatch')
        _safe_payload(action['kind'], action['payload'])
        ids.append(gate.action_id(account, action['kind'], action['target']))
    _require(len(ids) == len(set(ids)), 'Duplicate planned actions')
    return ids


def _semantic(conn: sqlite3.Connection, expected: ExpectedBoundary) -> dict:
    """Independent checks augment frozen core invariants; all SQL is read-only."""
    expected.validate()
    try:
        _require(conn.execute('PRAGMA integrity_check').fetchall()[0][0] == 'ok',
                 'Database integrity check failed')
        _require(conn.execute('PRAGMA encoding').fetchone()[0] == 'UTF-8',
                 'Unexpected database text encoding')
        # Core checker executes no writes and never opens a connection itself.
        checker = object.__new__(core.QueueCore)
        checker.identity = core.DatabaseIdentity(expected.queue_db_id, 0, 0)
        checker._check_state(conn)
        tables = {}
        for table, order in TABLES.items():
            rows = conn.execute(f'SELECT * FROM {table} ORDER BY {order} LIMIT ?',
                                (MAX_ROWS + 1,)).fetchall()
            _require(len(rows) <= MAX_ROWS, 'Database row bound exceeded')
            tables[table] = [dict(row) for row in rows]
        _no_credentials(tables)
        _require(len(_canonical(tables)) <= MAX_DB_BYTES, 'Logical database is oversized')
        meta = tables['meta'][0]
        _require((meta['ledger_db_id'], meta['generation']) ==
                 (expected.ledger_db_id, expected.registry_generation), 'Ledger/registry identity mismatch')
        _require(0 <= meta['last_checkpoint_sequence'] < expected.checkpoint_sequence,
                 'Checkpoint sequence must advance the previous acknowledged boundary')
        for binding in tables['registry']:
            _require(binding['expected_account'] == expected.account, 'Registry account mismatch')
            _require(binding['anchor_at'] >= 0 and binding['interval_seconds'] > 0,
                     'Invalid registry schedule')
            _require(core._binding(core.Binding(binding['worker_id'], binding['browser_id'],
                       binding['tab_id'], binding['expected_account'])).expected_account == expected.account,
                     'Invalid registry binding')
        _require(len(tables['registry']) == 3, 'Registry role count mismatch')
        registry = {row['role']: row for row in tables['registry']}
        evidence = {row['evidence_id']: row for row in tables['evidence']}
        for row in tables['evidence']:
            _require(row['tab_exists'] == 1 and row['observed_account'] == expected.account and
                     1 <= row['generation'] <= expected.registry_generation and
                     0 <= row['observed_at'] <= row['recorded_at'], 'Invalid observation evidence')
        summaries = []
        target = None
        prior = []
        for job in tables['jobs']:
            _require(job['state'] not in ('dispatching', 'blocked'), 'Unsafe job state')
            _require(job['expected_account'] == expected.account, 'Job account mismatch')
            key = _sha(f"{expected.queue_db_id}:{job['role']}:{job['scheduled_at']}".encode())
            _require(job['idempotency_key'] == key and job['job_id'] == 'job_' + key,
                     'Job identity does not match immutable schedule')
            _require(job['created_at'] <= job['updated_at'] and job['scheduled_at'] >= 0,
                     'Invalid job timestamps')
            if job['generation'] == expected.registry_generation:
                binding = registry[job['role']]
                _require(all(job[k] == binding[k] for k in
                    ('worker_id', 'browser_id', 'tab_id', 'expected_account', 'generation')),
                    'Job registry binding mismatch')
                _require((job['scheduled_at'] - binding['anchor_at']) % binding['interval_seconds'] == 0 and
                         job['scheduled_at'] >= binding['anchor_at'] and
                         job['next_same_role_at'] == job['scheduled_at'] + binding['interval_seconds'],
                         'Job schedule mismatch')
            for field in ('preparation_evidence_id', 'dispatch_evidence_id'):
                if job[field] is not None:
                    observed = evidence.get(job[field])
                    _require(observed is not None and observed['role'] == job['role'] and
                             all(observed[k] == job[k] for k in
                                 ('worker_id', 'browser_id', 'tab_id', 'generation')) and
                             observed['observed_account'] == expected.account,
                             'Job observation identity mismatch')
            payload = None
            if job['payload_json'] is not None:
                _require(len(job['payload_json'].encode()) <= 1024 * 1024, 'Payload oversized')
                payload = _json(job['payload_json'])
                _require(_canonical(payload).decode() == job['payload_json'], 'Noncanonical payload')
                planned = _planned_ids(payload, expected.account)
            else:
                planned = []
            progress = [row for row in tables['action_progress'] if row['job_id'] == job['job_id']]
            progress.sort(key=lambda row: (row['created_at'], row['action_id']))
            for row in progress:
                _require(row['state'] in core.SAFE_ACTION_STATES, 'Unresolved action progress')
                _require(row['created_at'] <= row['updated_at'] and row['created_at'] >= job['created_at'],
                         'Invalid action timestamps')
                _require(len(row['result_json'].encode()) <= 65536, 'Action result oversized')
                result = _json(row['result_json'])
                _safe_result(row['state'], result)
                _require(_canonical(result).decode() == row['result_json'],
                         'Noncanonical action result')
            if job['action_manifest_json'] is not None:
                manifest_ids = _json(job['action_manifest_json'])
                _require(type(manifest_ids) is list and manifest_ids == planned and
                         _canonical(manifest_ids).decode() == job['action_manifest_json'],
                         'Planned action IDs do not bind exact prepared actions')
            else:
                manifest_ids = None
            terminal = job['state'] in ('checkpoint_wait', 'done')
            if terminal:
                _require(manifest_ids is not None and set(planned) == {r['action_id'] for r in progress},
                         'Terminal action coverage incomplete')
                _require(_sha(_canonical(progress)) == job['result_digest'], 'Exact terminal result digest mismatch')
            else:
                _require(not progress and manifest_ids is None and job['checkpoint_id'] is None and
                         job['result_digest'] is None and job['checkpoint_proof_json'] is None and
                         job['checkpoint_proof_hash'] is None, 'Unclaimed job contains terminal/dispatch state')
            if job['state'] == 'checkpoint_wait':
                _require(target is None and job['job_id'] == expected.job_id, 'Wrong or multiple checkpoint owners')
                target = job
                _require(job['checkpoint_proof_json'] is None and job['checkpoint_proof_hash'] is None and
                         job['blocked_reason'] is None, 'Checkpoint owner is not an unacknowledged safe boundary')
            if job['state'] == 'done':
                proof = _json(job['checkpoint_proof_json'])
                proof_keys = {'checkpoint_id','result_digest','ledger_db_id','account','checkpoint_sequence',
                    'checkpoint_hash','library_file_id','library_version','pending','writer','stop','unresolved',
                    'archive_sha256','pair_manifest_sha256','queue_archive_sha256','queue_library_file_id',
                    'queue_library_version','queue_previous_version'}
                _require(type(proof) is dict and set(proof) == proof_keys and
                         _canonical(proof).decode() == job['checkpoint_proof_json'] and
                         proof.get('account') == expected.account and
                         proof.get('ledger_db_id') == expected.ledger_db_id and
                         proof.get('checkpoint_id') == job['checkpoint_id'] and
                         proof.get('result_digest') == job['result_digest'] and
                         type(proof.get('checkpoint_sequence')) is int and
                         0 < proof['checkpoint_sequence'] <= meta['last_checkpoint_sequence'] and
                         proof.get('pending') is False and proof.get('writer') is None and
                         proof.get('stop') is False and proof.get('unresolved') is False,
                         'Unsafe prior acknowledged checkpoint proof')
                _require(proof['checkpoint_id'] == f"{expected.ledger_db_id}:{proof['checkpoint_sequence']}",
                         'Prior checkpoint ID/sequence mismatch')
                for field in ('checkpoint_hash', 'archive_sha256', 'pair_manifest_sha256', 'queue_archive_sha256'):
                    _require(type(proof[field]) is str and HASH.fullmatch(proof[field]),
                             'Prior checkpoint hash missing or invalid')
                for field in ('library_file_id', 'library_version', 'queue_library_file_id', 'queue_library_version'):
                    _require(type(proof[field]) is str and 0 < len(proof[field]) <= 2048 and
                             proof[field] == proof[field].strip(), 'Prior Library identity missing or invalid')
                _require(type(proof['queue_previous_version']) is str and
                         proof['queue_previous_version'] == proof['queue_previous_version'].strip() and
                         proof['queue_library_version'] != proof['queue_previous_version'] and
                         proof['queue_library_file_id'] != proof['library_file_id'],
                         'Prior Library chain identities invalid')
                prior.append(proof)
            summaries.append({'job_id': job['job_id'], 'state': job['state'],
                'payload_sha256': job['payload_hash'], 'planned_action_ids': manifest_ids,
                'planned_action_sha256': job['action_manifest_hash'],
                'progress_count': len(progress), 'progress_sha256': _sha(_canonical(progress)),
                'result_digest': job['result_digest']})
        _require(target is not None, 'Exact checkpoint_wait owner is absent')
        _require((target['checkpoint_id'], target['result_digest'], target['generation']) ==
                 (expected.checkpoint_id, expected.result_digest, expected.registry_generation),
                 'Checkpoint boundary/result mismatch')
        _require(tables['dispatcher'][0]['job_id'] == expected.job_id,
                 'Dispatcher must retain the exact checkpoint owner')
        prior.sort(key=lambda value: value['checkpoint_sequence'])
        _require(len({p['checkpoint_sequence'] for p in prior}) == len(prior),
                 'Duplicate prior checkpoint sequence')
        if prior:
            _require(prior[-1]['checkpoint_sequence'] == meta['last_checkpoint_sequence'],
                     'Acknowledged checkpoint history incomplete')
            for before, after in zip(prior, prior[1:]):
                _require(after.get('queue_library_file_id') == before.get('queue_library_file_id') and
                         after.get('queue_previous_version') == before.get('queue_library_version') and
                         after.get('queue_library_version') != before.get('queue_library_version'),
                         'Prior queue Library chain mismatch')
        else:
            _require(meta['last_checkpoint_sequence'] == 0, 'Missing prior checkpoint history')
        for row in tables['audit']:
            detail = _json(row['detail_json'])
            _require(type(detail) is dict and _canonical(detail).decode() == row['detail_json'],
                     'Noncanonical audit details')
            _require(row['event'] in AUDIT_DETAIL_FIELDS and
                     set(detail) == AUDIT_DETAIL_FIELDS[row['event']],
                     'Unreviewed audit event/details are not exportable')
            for key, value in detail.items():
                _require((type(value) is int and value >= 0) if key in ('count', 'generation')
                         else type(value) is str and len(value) <= 2048,
                         'Audit detail must use its reviewed primitive schema')
        waits = [r for r in tables['audit'] if r['job_id'] == expected.job_id and r['event'] == 'checkpoint_wait']
        _require(waits and all(_json(r['detail_json']) ==
                 {'checkpoint_id': expected.checkpoint_id, 'result_digest': expected.result_digest}
                 for r in waits), 'Checkpoint audit boundary mismatch')
        return {'boundary': asdict(expected), 'queue_schema_version': 1,
            'core_schema_sha256': core.EXPECTED_SCHEMA_HASH,
            'core_source_sha256': CORE_SOURCE_SHA256, 'gate_source_sha256': GATE_SOURCE_SHA256,
            'database_state_sha256': _sha(_canonical(tables)),
            'registry_sha256': _sha(_canonical(tables['registry'])),
            'evidence_sha256': _sha(_canonical(tables['evidence'])),
            'audit_sha256': _sha(_canonical(tables['audit'])),
            'last_checkpoint_sequence': meta['last_checkpoint_sequence'],
            'dispatcher_claim_token_hash': tables['dispatcher'][0]['claim_token_hash'],
            'job_coverage': summaries}
    except (sqlite3.Error, core.QueueError, gate.GateBlocked, KeyError, TypeError,
            ValueError, IndexError, RecursionError) as exc:
        if isinstance(exc, SnapshotBlocked):
            raise
        raise SnapshotBlocked('Queue semantic validation failed closed') from exc


def _zip_bytes(manifest: bytes, database: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, data in (('manifest.json', manifest), ('queue.sqlite3', database)):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(entry, data)
    return stream.getvalue()


def _check_database_bytes(database: bytes) -> None:
    _require(database.startswith(b'SQLite format 3\x00') and len(database) >= 100,
             'Not a SQLite backup')
    _require(database[72:92] == bytes(20), 'Nonzero reserved database header bytes')
    page_size = int.from_bytes(database[16:18], 'big')
    page_size = 65536 if page_size == 1 else page_size
    page_count = int.from_bytes(database[28:32], 'big')
    _require(page_size >= 512 and page_size & (page_size - 1) == 0 and
             page_count * page_size == len(database) and database[32:40] == bytes(8),
             'Uncompacted database, trailing bytes or invalid page boundaries')
    # Also inspect recognizable credential fields outside currently reachable rows.
    # Vacuum removes deleted-page residue; this does not claim arbitrary text DLP.
    for match in re.finditer(rb'"([A-Za-z0-9_ -]{1,100})"\s*:', database):
        key = match[1].decode('ascii')
        name = re.sub(r'[^a-z0-9]', '', key.casefold())
        if name in {'claimtokenhash', 'dispatcherclaimtokenhash'}:
            continue
        _no_credentials({key: None})


def _source_stamp(path: Path) -> tuple:
    stamps = []
    for p in (path, Path(str(path) + '-wal'), Path(str(path) + '-journal')):
        try:
            s = p.lstat()
            _require(stat.S_ISREG(s.st_mode), 'Nonregular SQLite source/sidecar')
            stamps.append(_fingerprint(s))
        except FileNotFoundError:
            stamps.append(None)
    _require(stamps[0] is not None, 'Source is absent; no initialization or recovery')
    return tuple(stamps)


def build_snapshot(source_path: str | Path, identity: Any, expected: ExpectedBoundary,
                   output_dir: str | Path) -> ValidatedSnapshot:
    """Consistent read-only source backup; any concurrent source change rejects.

    identity must be independently retained from explicit staging initialization.
    Only a private backup copy is vacuumed, removing historical freed-page bytes.
    No source repair, source initialization, ledger acknowledgement or upload.
    """
    expected.validate()
    source = _safe_path(source_path)
    output = _safe_path(output_dir, directory=True)
    _require(getattr(identity, 'db_id', None) == expected.queue_db_id and
             type(getattr(identity, 'device', None)) is int and
             type(getattr(identity, 'inode', None)) is int, 'Pinned source identity required')
    conn = sentinel = None
    fd = None
    try:
        before = _source_stamp(source)
        _require(before[0][:2] == (identity.device, identity.inode) and
                 0 < before[0][2] <= MAX_DB_BYTES, 'Source identity/size mismatch')
        _require(before[2] is None, 'Rollback journal exists; recovery is prohibited')
        for suffix in ('-shm', '-wal', '-journal'):
            p = Path(str(source) + suffix)
            _require(not p.is_symlink(), 'Symlink SQLite sidecar prohibited')
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        _require(_fingerprint(os.fstat(fd)) == before[0], 'Source changed before connection')
        sentinel = _connect_readonly(source)
        initial_version = sentinel.execute('PRAGMA data_version').fetchone()[0]
        conn = _connect_readonly(source)
        conn.execute('BEGIN')
        semantic = _semantic(conn, expected)
        with tempfile.TemporaryDirectory(prefix='queue-snapshot-build-', dir=output) as temp:
            temp = Path(temp)
            backup_path, clean_path = temp / 'backup.sqlite3', temp / 'queue.sqlite3'
            with sqlite3.connect(backup_path) as destination:
                conn.backup(destination)
                destination.execute('PRAGMA journal_mode=DELETE')
                destination.execute('PRAGMA secure_delete=ON')
                destination.execute('VACUUM INTO ?', (str(clean_path),))
            os.chmod(clean_path, 0o600)
            with closing(_connect_readonly(clean_path, immutable=True)) as copied:
                _require(_semantic(copied, expected) == semantic, 'Backup changed semantic state')
            database = _read_file(clean_path, MAX_DB_BYTES)
            _check_database_bytes(database)
            manifest = _canonical({'format': FORMAT, 'semantic': semantic,
                                   'database_sha256': _sha(database), 'database_bytes': len(database)})
            _require(len(manifest) <= MAX_MANIFEST_BYTES, 'Manifest oversized')
            archive_data = _zip_bytes(manifest, database)
        _require(_semantic(conn, expected) == semantic, 'Read snapshot boundary changed')
        conn.execute('COMMIT')
        _require(sentinel.execute('PRAGMA data_version').fetchone()[0] == initial_version and
                 _source_stamp(source) == before and _fingerprint(os.fstat(fd)) == before[0],
                 'Source changed during snapshot; reject and retain checkpoint barrier')
        # Final fresh read sees commits that an existing read snapshot could hide.
        with closing(_connect_readonly(source)) as current:
            current.execute('BEGIN')
            _require(_semantic(current, expected) == semantic, 'Source advanced past pinned boundary')
            _require(_source_stamp(source) == before, 'Source replaced or changed at final boundary')
            current.execute('COMMIT')
        digest = _sha(archive_data)
        archive_path = output / f'queue-checkpoint-{digest}.zip'
        try:
            handle = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            _require(_read_file(archive_path, MAX_ARCHIVE_BYTES) == archive_data,
                     'Existing content-addressed artifact differs')
        else:
            with os.fdopen(handle, 'wb') as stream:
                stream.write(archive_data)
                stream.flush()
                os.fsync(stream.fileno())
        return validate_snapshot(archive_path, expected, expected_archive_sha256=digest)
    except (OSError, sqlite3.Error) as exc:
        raise SnapshotBlocked('Source backup failed closed; no source repair attempted') from exc
    finally:
        if conn is not None:
            conn.close()
        if sentinel is not None:
            sentinel.close()
        if fd is not None:
            os.close(fd)


def validate_snapshot(archive_path: str | Path, expected: ExpectedBoundary, *,
                      expected_archive_sha256: str) -> ValidatedSnapshot:
    """Validate exact downloaded bytes and all semantics on a private read-only copy.

    Both expected arguments must come from independently pinned local build and
    boundary evidence, never from the downloaded archive itself. No restoration.
    """
    expected.validate()
    _require(type(expected_archive_sha256) is str and HASH.fullmatch(expected_archive_sha256),
             'Independent expected archive hash required')
    path = _safe_path(archive_path)
    data = _read_file(path, MAX_ARCHIVE_BYTES)
    _require(_sha(data) == expected_archive_sha256, 'Archive bytes mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            _require(len(entries) == 2 and tuple(e.filename for e in entries) == MEMBERS,
                     'Unexpected, duplicate, reordered or unsafe ZIP members')
            _require(not archive.comment, 'ZIP comments are prohibited')
            for entry in entries:
                maximum = MAX_MANIFEST_BYTES if entry.filename == 'manifest.json' else MAX_DB_BYTES
                mode = entry.external_attr >> 16
                _require(entry.create_system == 3 and stat.S_ISREG(mode) and
                         stat.S_IMODE(mode) == 0o600 and not entry.is_dir() and
                         not entry.extra and not entry.comment and not entry.flag_bits & 1 and
                         entry.compress_type == zipfile.ZIP_STORED and
                         0 < entry.file_size <= maximum and entry.compress_size == entry.file_size,
                         'Unsafe ZIP type, attributes, compression or size')
            manifest_bytes = archive.read('manifest.json')
            database = archive.read('queue.sqlite3')
        # Enforce our exact deterministic ZIP envelope, rejecting hidden prefixes,
        # trailing bytes, alternate local names, duplicate directories and extras.
        _require(_zip_bytes(manifest_bytes, database) == data, 'Noncanonical ZIP envelope')
        manifest = _json(manifest_bytes)
        _require(type(manifest) is dict and set(manifest) ==
                 {'format', 'semantic', 'database_sha256', 'database_bytes'} and
                 manifest['format'] == FORMAT and _canonical(manifest) == manifest_bytes,
                 'Invalid/noncanonical manifest')
        _require(type(manifest['database_bytes']) is int and
                 manifest['database_bytes'] == len(database) and
                 manifest['database_sha256'] == _sha(database), 'Database payload hash/size mismatch')
        _check_database_bytes(database)
        with tempfile.TemporaryDirectory(prefix='queue-snapshot-verify-', dir=path.parent) as temp:
            copy = Path(temp) / 'queue.sqlite3'
            copy.write_bytes(database)
            os.chmod(copy, 0o400)
            with closing(_connect_readonly(copy, immutable=True)) as conn:
                semantic = _semantic(conn, expected)
            _require(manifest['semantic'] == semantic and
                     _canonical(manifest['semantic']) == _canonical(semantic),
                     'Manifest semantic hashes/coverage/boundary mismatch')
        return ValidatedSnapshot(str(path), expected_archive_sha256,
                                 _sha(manifest_bytes), _sha(database), expected, manifest_bytes)
    except (OSError, sqlite3.Error, zipfile.BadZipFile, RuntimeError, EOFError,
            ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, SnapshotBlocked):
            raise
        raise SnapshotBlocked('Archive validation failed closed') from exc
