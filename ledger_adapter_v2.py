"""Concrete, in-process STAGING ONLY adapter for the frozen queue coordinator.

Contract: StagingLedgerAdapter(existing_db, LedgerIdentity(account, db_id),
clock=optional_integer_clock). Pass the instance as SerialCoordinator(...,
ledger=adapter). The database and every evidence/receipt/archive input MUST be
under FIXTURE_DATA_ROOT. Initialization, activation, recovery, STOP clearing,
packaging, browser actions, Library calls, and production enablement are absent.

The source-only public baseline is pinned below, including its settings
dependency. Denial commands remain absent
from this adapter. Source changes require explicit review and literal pin updates;
there are no private fixtures, operational database copies, or automatic repins.

CommandResult.stdout/stderr are memory-only compatibility fields, NEVER process
streams. acquire's token is present only in the returned in-memory JSON (required
by DispatchGate.acquired); neither the adapter nor its repr logs/stores it. The
underlying ledger stores its one-way token hash, exactly as its CLI does.

This is a same-process cooperative guard, not a sandbox against malicious Python
or same-UID filesystem tampering. The caller must protect the staging directory
and use this thread-affine adapter only from its creating thread. Portable
configuration selects a disjoint staging root; the adapter accepts only its fixed
disposable subtree. No production adapter, fallback module, subprocess
or retry exists.
"""
from __future__ import annotations

import builtins
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time
import types
import zipfile

import dispatch_gate
from dispatch_gate import CommandResult, GateBlocked, LedgerIdentity


from integration_paths import INTEGRATION_ROOT, SOURCE_ROOT

FIXTURE_SOURCE_ROOT = SOURCE_ROOT
FIXTURE_DATA_ROOT = INTEGRATION_ROOT / 'ledger-v2'
FROZEN_GATE = SOURCE_ROOT / 'dispatch_gate.py'
SOURCE_SHA256 = {
    'integration_paths.py': '25c4285e65f563d20f2d17fd3625a00f83599b9e9d250b5becbd3840d94cd222',
    'ledger.py': '7004c04c9f8867ed92bc8eb3e4d3121e319cab6d68b9730ff99778b2dbd39076',
    'checkpoint.py': 'f34453944ffdd3b7c6c054f6d73635103bf1725da316f06420fb8c0d8461b3be',
    'denial_extension.py': '6cb41cc6d832cd9d656c4a948babd7e2613b98603c11cf90d6481685c65c427d',
    'package_recovery.py': 'c6c96e776f29b84038f02ba98f98ddf6ab73dee371837e9f0feed001359ca007',
    'settings.py': '1c501fe96394b468b7d0038e44195f0ebd6dbf26aaa6ea44c168fa061127d058',
}
GATE_SHA256 = '2cda6b058cb99486b3e6d4b38574139e764847344aa6cc8dd3add3a451419cbf'

# Exact coordinator command surface. No dynamic getattr(command), recovery,
# denial finalization, reconciliation acknowledgement, hash-file, or CLI main.
COMMAND_FIELDS = {
    'status': (),
    'acquire': ('owner', 'role'),
    'claim': ('owner', 'token', 'kind', 'target', 'payload_hash'),
    'begin-write': ('owner', 'token', 'action', 'evidence'),
    'submitted': ('owner', 'token', 'action'),
    'unknown': ('owner', 'token', 'action', 'reason'),
    'cancel': ('owner', 'token', 'action'),
    'verify': ('owner', 'token', 'action', 'evidence'),
    'release': ('owner', 'token'),
    'checkpoint-ack': ('record', 'sha256'),
}


def _require(value, message):
    if not value:
        raise GateBlocked(message)


def _path(value, root):
    _require(type(value) in (str, type(Path('/'))), 'Expected a plain staging file path')
    p = Path(value)
    _require(p.is_absolute() and '..' not in p.parts and p != root,
             'Absolute staging file path required')
    _require(p.is_relative_to(root), 'Path is outside the fixed disposable staging root')
    _require('live.sqlite' not in p.parts, 'Live database paths are prohibited')
    # Reject symlinks in every ancestor, including ancestors of the fixed root.
    for parent in reversed(p.parents):
        st = parent.lstat()
        _require(stat.S_ISDIR(st.st_mode), 'Non-directory or symlinked staging ancestor')
    st = p.lstat()
    _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
             'Expected regular non-symlink non-hardlinked staging file')
    return p, st


def _read_regular(value, root, limit):
    """Bounded read using no-follow openat for every path component."""
    p, before = _path(value, root)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in p.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            st = os.fstat(file_fd)
            _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit
                     and (st.st_dev, st.st_ino) == (before.st_dev, before.st_ino),
                     'Staging file changed or exceeds the size limit')
            with os.fdopen(file_fd, 'rb', closefd=False) as stream:
                data = stream.read(limit + 1)
            after = os.fstat(file_fd)
            _require(len(data) <= limit and
                     (st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
                     (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                     'Staging file changed while reading')
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)
    _, current = _path(value, root)
    _require((st.st_dev, st.st_ino) == (current.st_dev, current.st_ino),
             'Staging file was replaced while reading')
    return data


def _checked_sources():
    result = {}
    for name, expected in SOURCE_SHA256.items():
        data = _read_regular(FIXTURE_SOURCE_ROOT / name, FIXTURE_SOURCE_ROOT, 1_000_000)
        _require(hashlib.sha256(data).hexdigest() == expected,
                 'Reviewed ledger source hash mismatch; no automatic pin update')
        result[name] = data
    _require(Path(dispatch_gate.__file__).absolute() == FROZEN_GATE,
             'The exact frozen dispatch gate module is required')
    gate = _read_regular(FROZEN_GATE, FROZEN_GATE.parent, 1_000_000)
    _require(hashlib.sha256(gate).hexdigest() == GATE_SHA256,
             'Reviewed dispatch gate source hash mismatch')
    return result


def _load_pinned_sources():
    """No sys.path lookup, module cache, bytecode cache, or global alias injection."""
    sources = _checked_sources()
    settings = types.ModuleType('_threads_staging_pinned_settings')
    settings.__file__ = str(FIXTURE_SOURCE_ROOT / 'settings.py')
    exec(compile(sources['settings.py'], settings.__file__, 'exec', dont_inherit=True), settings.__dict__)
    _require(settings.STAGING_ROOT / 'integration' == INTEGRATION_ROOT,
             'Pinned staging configuration does not match integration root')
    ledger = types.ModuleType('_threads_staging_pinned_ledger')
    ledger.__file__ = str(FIXTURE_SOURCE_ROOT / 'ledger.py')
    checkpoint = types.ModuleType('_threads_staging_pinned_checkpoint')
    checkpoint.__file__ = str(FIXTURE_SOURCE_ROOT / 'checkpoint.py')
    imports = dict(vars(builtins))
    real_import = imports['__import__']

    def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'settings':
            return settings
        if level == 0 and name == 'ledger':
            return ledger
        return real_import(name, globals, locals, fromlist, level)

    imports['__import__'] = pinned_import
    ledger.__dict__['__builtins__'] = imports
    exec(compile(sources['ledger.py'], ledger.__file__, 'exec', dont_inherit=True), ledger.__dict__)
    checkpoint.__dict__['__builtins__'] = imports
    exec(compile(sources['checkpoint.py'], checkpoint.__file__, 'exec', dont_inherit=True), checkpoint.__dict__)
    return ledger, checkpoint


class StagingLedgerAdapter:
    """Drop-in LedgerAdapter; explicit identity, fixed disposable paths only."""
    def __init__(self, db_path, identity: LedgerIdentity, *, clock=None):
        _require(type(identity) is LedgerIdentity, 'Explicit frozen LedgerIdentity required')
        self._identity = identity
        self._thread = threading.get_ident()
        self._closed = True
        self._lock = threading.RLock()
        self._ledger_module, self._checkpoint_module = _load_pinned_sources()
        self._path, info = _path(db_path, FIXTURE_DATA_ROOT)
        _require(self._path.suffix == '.sqlite', 'Disposable SQLite filename required')
        self._storage_identity = (info.st_dev, info.st_ino)
        self._validate_sidecars()
        self._clock_source = clock if clock is not None else lambda: int(time.time())
        _require(callable(self._clock_source), 'Clock must be callable')

        # Read-only account/DB pin check happens before constructing the ledger's
        # read-write connection. No initialization and no mutation on a wrong pin.
        self._read_identity()
        # The sole runtime hook confines the reviewed functions' direct AND
        # nested file reads. It does not change ledger state-transition logic.
        self._ledger_module.file_bytes = self._file_bytes
        self._checkpoint_module.file_bytes = self._file_bytes
        self._db = self._ledger_module.Ledger(self._path, identity.account, clock=self._clock)
        try:
            self._preflight()
        except BaseException:
            self._db.close()
            raise
        self._closed = False

    @property
    def identity(self):
        return self._identity

    def __repr__(self):
        return f'StagingLedgerAdapter(identity={self.identity!r}, closed={self._closed!r})'

    def _clock(self):
        now = self._clock_source()
        _require(type(now) is int and now >= 0, 'Integer non-negative clock required')
        return now

    def _validate_sidecars(self):
        for suffix in ('-wal', '-shm', '-journal'):
            p = Path(str(self._path) + suffix)
            if os.path.lexists(p):
                _path(p, FIXTURE_DATA_ROOT)

    def _read_identity(self):
        self._validate_storage()
        db = sqlite3.connect(self._path.as_uri() + '?mode=ro', uri=True, isolation_level=None)
        try:
            db.execute('PRAGMA query_only=ON')
            _require(db.execute('PRAGMA application_id').fetchone()[0] == self._ledger_module.APP_ID
                     and db.execute('PRAGMA user_version').fetchone()[0] == self._ledger_module.VERSION,
                     'Wrong database application/schema')
            values = dict(db.execute("SELECT key,value FROM meta WHERE key IN ('account','db_id')"))
            _require(values == {'account': self.identity.account, 'db_id': self.identity.db_id},
                     'Pinned ledger account/database identity mismatch')
        finally:
            db.close()
        self._validate_storage()

    def _validate_storage(self):
        _, info = _path(self._path, FIXTURE_DATA_ROOT)
        _require((info.st_dev, info.st_ino) == self._storage_identity,
                 'Pinned staging database storage identity changed')
        self._validate_sidecars()

    def _preflight(self):
        _checked_sources()
        self._validate_storage()
        self._db.ensure_storage()
        _require(self._db.get('account') == self.identity.account and
                 self._db.get('db_id') == self.identity.db_id,
                 'Pinned ledger account/database identity mismatch')

    def _file_bytes(self, path, expected=None, limit=8_000_000):
        data = _read_regular(path, FIXTURE_DATA_ROOT, limit)
        digest = hashlib.sha256(data).hexdigest()
        self._ledger_module.must(expected is None or
            (type(expected) is str and self._ledger_module.HASH.fullmatch(expected)
             and secrets.compare_digest(expected, digest)), 'File SHA-256 mismatch')
        return data, digest

    def _error(self, error, token=None):
        # Exact CLI failure keys/location/code. No argument dumps or tracebacks.
        message = str(error)
        if type(token) is str and token:
            message = message.replace(token, '[redacted]')
        value = {'ok': False, 'may_dispatch': False, 'automatic_retry': False, 'error': message}
        return CommandResult(True, 2, '', stderr=self._ledger_module.canonical(value) + '\n')

    def execute(self, command: str, **arguments) -> CommandResult:
        """Execute one allowed command once; no retry even after uncertain failure."""
        with self._lock:
            try:
                _require(threading.get_ident() == self._thread,
                         'Staging ledger adapter is restricted to its creating thread')
                _require(not self._closed, 'Staging ledger adapter is closed')
                _require(type(command) is str and command in COMMAND_FIELDS,
                         'Command is not allowed by the staging coordinator adapter')
                fields = COMMAND_FIELDS[command]
                _require(set(arguments) == set(fields), 'Exact coordinator command arguments required')
                for key in fields:
                    value = arguments[key]
                    _require(type(value) is str or
                             (key in ('record', 'evidence') and type(value) is type(Path('/'))),
                             'Command arguments must be plain strings or approved file paths')
                if command == 'acquire':
                    _require(arguments['role'] in ('publisher', 'spreader', 'commenter'),
                             'Only queue worker roles are allowed; no reconciliation writer')
                self._preflight()
                a, db = arguments, self._db
                if command == 'status':
                    out = db.status()
                elif command == 'acquire':
                    out = db.acquire(a['owner'], a['role'])
                elif command == 'claim':
                    out = db.claim(a['owner'], a['token'], a['kind'], a['target'], a['payload_hash'])
                elif command == 'begin-write':
                    out = db.begin_write(a['owner'], a['token'], a['action'], a['evidence'])
                elif command in ('submitted', 'unknown', 'cancel'):
                    state = {'submitted': 'submitted_unverified', 'unknown': 'unknown',
                             'cancel': 'cancelled'}[command]
                    out = db.transition(a['owner'], a['token'], a['action'], state, a.get('reason', ''))
                elif command == 'verify':
                    out = db.verify(a['owner'], a['token'], a['action'], a['evidence'])
                elif command == 'release':
                    out = db.release(a['owner'], a['token'])
                else:  # checkpoint-ack is the sole remaining allowlisted command.
                    out = self._checkpoint_module.acknowledge(db, a['record'], a['sha256'])
                self._preflight()
                return CommandResult(True, 0, self._ledger_module.canonical({'ok': True, **out}) + '\n')
            except (GateBlocked, self._ledger_module.Blocked, OSError, sqlite3.Error,
                    ValueError, TypeError, KeyError, IndexError, zipfile.BadZipFile) as error:
                return self._error(error, arguments.get('token'))
            except Exception:
                return self._error('Unexpected in-process ledger failure; no automatic retry')

    def close(self):
        with self._lock:
            _require(threading.get_ident() == self._thread,
                     'Close the staging ledger adapter on its creating thread')
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self):
        _require(not self._closed, 'Staging ledger adapter is closed')
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
