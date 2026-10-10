"""Staging-only cooperative file RPC for the frozen BrowserAdapter protocol.

No browser, network, shell, ledger, credential, or production-activation code.
A ticket digest must be conveyed by trusted orchestration, not learned from an
untrusted directory scan. Native identity/tool provenance cannot be attested here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from typing import Callable, Iterable

from dispatch_gate import (CommandResult, GateBlocked, KINDS, ROLES, action_id,
                           canonical, completed_json, parse_json, payload_hash)

from integration_paths import INTEGRATION_ROOT
SCHEMA = 'staging-native-tool-request-v1'
RESPONSE_SCHEMA = 'staging-native-tool-response-v1'
OPERATIONS = frozenset(('observe', 'preflight', 'mutate', 'readback'))
HASH = re.compile(r'[a-f0-9]{64}\Z')
ID = re.compile(r'[a-f0-9]{32}\Z')
MAX_BYTES = 1_000_000
BINDING_KEYS = {'role', 'worker_id', 'browser_id', 'tab_id', 'account'}
ACTION_KEYS = {'kind', 'target', 'payload', 'authorization_id', 'payload_hash', 'action_id'}
SECRET_KEYS = {'token', 'claim_token', 'ledger_token', 'auth_token', 'authorization',
               'access_token', 'refresh_token', 'api_key', 'password', 'secret',
               'cookie', 'cookies', 'credentials', 'headers'}
REQUEST_KEYS = {'schema', 'request_id', 'operation', 'binding', 'action', 'payload_hash',
                'authorization_reference', 'intent_id', 'slot_start', 'slot_deadline',
                'created_at', 'response_deadline', 'readback_of', 'transport_mode'}
RESPONSE_KEYS = {'schema', 'request_id', 'request_digest', 'operation', 'binding',
                 'payload_hash', 'authorization_reference', 'intent_id', 'slot_start',
                 'slot_deadline', 'claimed_at', 'dispatched_at', 'completed_at', 'result'}


class BridgeBlocked(GateBlocked):
    """Uncertain, expired, corrupt, denied, or replayed bridge operation."""


def _need(value, reason):
    if not value:
        raise BridgeBlocked(reason)


def _digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _copy(value):
    return parse_json(canonical(value))


def _text(value, label, maximum=2048):
    _need(type(value) is str and 0 < len(value) <= maximum and value == value.strip()
          and not any(ord(c) < 32 for c in value), f'Invalid {label}')
    return value


def _no_credentials(value):
    """Reject credential-bearing schemas, not a claim of content-based DLP."""
    if type(value) is dict:
        _need(all(type(key) is str and key.lower().replace('-', '_') not in SECRET_KEYS
                  for key in value), 'Credential fields are forbidden in bridge files')
        for item in value.values():
            _no_credentials(item)
    elif type(value) is list:
        for item in value:
            _no_credentials(item)


@dataclass(frozen=True)
class BindingPin:
    role: str
    worker_id: str
    browser_id: str
    tab_id: str
    account: str

    def __post_init__(self):
        _need(self.role in ROLES, 'Unknown role')
        for name in ('worker_id', 'browser_id', 'tab_id'):
            _text(getattr(self, name), name)
        _need(self.browser_id.casefold() not in {'cdp', 'iab', 'extension', 'mcpapps'},
              'Browser selection aliases are not canonical instance identities')
        _need(type(self.account) is str and re.fullmatch(r'[a-z0-9_.]{1,64}', self.account),
              'Canonical account required')

    @classmethod
    def from_dict(cls, value):
        _need(type(value) is dict and set(value) == BINDING_KEYS, 'Exact binding required')
        return cls(**value)

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class SlotContext:
    binding: BindingPin
    slot_start: int
    slot_deadline: int
    authorization_reference: str

    def __post_init__(self):
        _need(type(self.binding) is BindingPin, 'Pinned binding required')
        _need(type(self.slot_start) is int and type(self.slot_deadline) is int
              and 0 <= self.slot_start < self.slot_deadline, 'Exact slot bounds required')
        _text(self.authorization_reference, 'public authorization reference')


@dataclass(frozen=True)
class RequestTicket:
    request_id: str
    request_digest: str

    def __post_init__(self):
        _need(type(self.request_id) is str and ID.fullmatch(self.request_id), 'Invalid request ID')
        _need(type(self.request_digest) is str and HASH.fullmatch(self.request_digest),
              'Invalid pinned request digest')


@dataclass(frozen=True)
class ClaimedRequest:
    ticket: RequestTicket
    worker_binding: BindingPin
    claimed_at: int


@dataclass(frozen=True)
class DispatchSpec:
    """Read-only serialized snapshot. No credentials or executable method names."""
    ticket: RequestTicket
    request_json: str = field(repr=False)
    dispatched_at: int

    def request(self):
        return _copy(parse_json(self.request_json))


class SyntheticTestCapability:
    """Explicit synthetic-test switch; NOT permission for any real tool call."""
    __slots__ = ()

    @classmethod
    def for_tests_only(cls):
        return cls()


class FileToolBridge:
    """No retries, takeover, deletion, or repair. Close/reopen preserves markers.

    Cooperating callers must retain trusted tickets and fixed role identities.
    Atomic files and flock protect concurrency/crashes, not a malicious same-UID
    actor capable of replacing the process, directory, files, or trusted tickets.
    """
    def __init__(self, root, *, synthetic_capability=None, clock=None):
        _need(synthetic_capability is None or type(synthetic_capability) is SyntheticTestCapability,
              'Unknown capability')
        _need(clock is None or synthetic_capability is not None,
              'Injected clocks are synthetic-test-only')
        self._synthetic = synthetic_capability is not None
        self._clock = clock or (lambda: int(time.time()))
        self.root = self._validate_root(root)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
        _need(self.root.is_dir() and not self.root.is_symlink(), 'Bridge root is not a directory')
        self._fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(self._fd)
        self._identity = (st.st_dev, st.st_ino)

    @staticmethod
    def _validate_root(root):
        path = Path(root)
        _need(path.is_absolute() and '..' not in path.parts, 'Absolute staging bridge path required')
        _need(path != INTEGRATION_ROOT and path.is_relative_to(INTEGRATION_ROOT),
              'Bridge files must be below the integration staging root')
        _need(path.parent.exists(), 'Explicit staging parent directory must exist')
        for part in (path, *path.parents):
            _need(not part.is_symlink(), 'Symlinked bridge paths are forbidden')
        _need(path.resolve() == path, 'Noncanonical bridge root')
        return path

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _root_check(self):
        _need(self._fd is not None, 'Bridge is closed')
        self._validate_root(self.root)
        st = self.root.stat()
        _need((st.st_dev, st.st_ino) == self._identity, 'Bridge directory was replaced')

    def _now(self):
        value = self._clock()
        _need(type(value) is int and value >= 0, 'Clock must return UTC integer seconds')
        return value

    @staticmethod
    def _name(ticket, suffix):
        _need(type(ticket) is RequestTicket, 'Trusted request ticket required')
        return f'{ticket.request_id}.{suffix}.json'

    def _exists(self, name):
        try:
            os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _read(self, name):
        self._root_check()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._fd)
        try:
            info = os.fstat(fd)
            _need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES,
                  'Missing, special, or oversized bridge file')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                data = source.read(MAX_BYTES + 1)
            _need(len(data) == info.st_size and len(data) <= MAX_BYTES, 'Bridge file changed during read')
            value = parse_json(data.decode('utf-8'))
            _need(type(value) is dict and data == canonical(value).encode(),
                  'Noncanonical or malformed bridge envelope')
            return value
        finally:
            os.close(fd)

    def _create(self, name, value):
        """Publish once: fsynced data, exclusive link, then fsynced directory."""
        self._root_check()
        data = canonical(value).encode()
        _need(0 < len(data) <= MAX_BYTES, 'Oversized bridge envelope')
        temp = f'.pending-{uuid.uuid4().hex}'
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                     0o400, dir_fd=self._fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(data)
                output.flush()
                os.fsync(fd)
            try:
                os.link(temp, name, src_dir_fd=self._fd, dst_dir_fd=self._fd,
                        follow_symlinks=False)
            except FileExistsError:
                raise BridgeBlocked('Durable operation already exists; no replay') from None
            os.fsync(self._fd)
        finally:
            os.close(fd)
            os.unlink(temp, dir_fd=self._fd)
            os.fsync(self._fd)

    @contextmanager
    def _locked(self, ticket):
        self._root_check()
        fd = os.open(self._name(ticket, 'lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                     0o600, dir_fd=self._fd)
        try:
            _need(stat.S_ISREG(os.fstat(fd).st_mode), 'Invalid lock file')
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._root_check()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _action(self, action, binding):
        _need(type(action) is dict and set(action) == ACTION_KEYS, 'Exact action schema required')
        _no_credentials(action)
        _need(action['kind'] in KINDS and type(action['payload']) is dict
              and action['payload'].get('target') == action['target'], 'Invalid target payload')
        _text(action['authorization_id'], 'public action authorization reference')
        _need(action['payload_hash'] == payload_hash(action['payload']), 'Payload hash mismatch')
        _need(action['action_id'] == action_id(binding.account, action['kind'], action['target']),
              'Action identity mismatch')

    def _request(self, ticket):
        request = self._read(self._name(ticket, 'request'))
        _need(set(request) == REQUEST_KEYS and request['schema'] == SCHEMA
              and request['request_id'] == ticket.request_id and _digest(request) == ticket.request_digest,
              'Request schema, identity, or trusted digest mismatch')
        _need(request['operation'] in OPERATIONS, 'Unknown fixed operation')
        binding = BindingPin.from_dict(request['binding'])
        SlotContext(binding, request['slot_start'], request['slot_deadline'],
                    request['authorization_reference'])
        _need(type(request['created_at']) is int and type(request['response_deadline']) is int
              and request['created_at'] < request['response_deadline'], 'Invalid response window')
        _need(request['transport_mode'] in ('read_only', 'synthetic_only'), 'Invalid transport mode')
        if request['operation'] == 'observe':
            _need(request['action'] is None and request['intent_id'] is None
                  and request['readback_of'] is None and request['payload_hash'] == payload_hash({}),
                  'Observe request contains action data')
        else:
            self._action(request['action'], binding)
            _need(request['payload_hash'] == request['action']['payload_hash']
                  and request['authorization_reference'] == request['action']['authorization_id'],
                  'Request action hash or authorization mismatch')
            if request['operation'] == 'preflight':
                _need(request['intent_id'] is None and request['readback_of'] is None,
                      'Preflight cannot carry write intent')
            else:
                _need(type(request['intent_id']) is str and HASH.fullmatch(request['intent_id']),
                      'Exact ledger intent ID required')
            if request['operation'] == 'mutate':
                _need(request['readback_of'] is None and request['transport_mode'] == 'synthetic_only',
                      'Production mutation transport is not shipped')
            if request['operation'] == 'readback':
                self._readback_parent(request)
        _need(request['operation'] == 'mutate' or request['transport_mode'] == 'read_only',
              'Invalid operation transport mode')
        _no_credentials(request)
        return request

    def _readback_parent(self, request):
        parent = request['readback_of']
        _need(type(parent) is dict and set(parent) == {'request_id', 'request_digest'},
              'Readback must link a matching completed mutation')
        ticket = RequestTicket(**parent)
        prior = self._request(ticket)
        _need(prior['operation'] == 'mutate' and all(prior[key] == request[key] for key in
              ('binding', 'action', 'payload_hash', 'authorization_reference', 'intent_id',
               'slot_start', 'slot_deadline')), 'Readback parent mismatch')
        response = self._response(ticket, prior)
        _need(response['result']['stdout']['ok'] is True
              and response['result']['stdout']['outcome'] == 'submitted'
              and self._exists(self._name(ticket, 'accepted')),
              'Readback requires an accepted submitted mutation')
        accepted = self._read(self._name(ticket, 'accepted'))
        _need(set(accepted) == {'request_id', 'request_digest', 'response_digest', 'accepted_at'}
              and accepted['request_id'] == ticket.request_id
              and accepted['request_digest'] == ticket.request_digest
              and accepted['response_digest'] == _digest(response)
              and type(accepted['accepted_at']) is int
              and response['completed_at'] <= accepted['accepted_at'] < prior['response_deadline'],
              'Accepted parent response seal mismatch')

    def submit(self, operation, context, *, action=None, intent_id=None,
               timeout_seconds=30, readback_of=None):
        _need(operation in OPERATIONS and type(context) is SlotContext, 'Fixed operation/context required')
        _need(type(timeout_seconds) is int and 1 <= timeout_seconds <= 300, 'Bounded timeout required')
        _need(operation != 'mutate' or self._synthetic, 'Mutation transport is disabled')
        now = self._now()
        request = {'schema': SCHEMA, 'request_id': uuid.uuid4().hex, 'operation': operation,
                   'binding': context.binding.as_dict(), 'action': _copy(action),
                   'payload_hash': payload_hash({}) if action is None else action.get('payload_hash'),
                   'authorization_reference': context.authorization_reference if action is None
                       else action.get('authorization_id'),
                   'intent_id': intent_id, 'slot_start': context.slot_start,
                   'slot_deadline': context.slot_deadline, 'created_at': now,
                   'response_deadline': now + timeout_seconds,
                   'readback_of': asdict(readback_of) if type(readback_of) is RequestTicket else None,
                   'transport_mode': 'synthetic_only' if operation == 'mutate' else 'read_only'}
        _no_credentials(request)
        if operation != 'observe':
            self._action(request['action'], context.binding)
        _need(context.slot_start <= now and (operation == 'readback' or now < context.slot_deadline),
              'Request is outside the exact slot')
        if operation in ('mutate', 'readback'):
            _need(type(intent_id) is str and HASH.fullmatch(intent_id), 'Exact intent ID required')
        else:
            _need(intent_id is None and readback_of is None, 'Unexpected intent or parent')
        _need(operation != 'observe' or action is None, 'Observe cannot carry an action')
        _need(operation == 'readback' or readback_of is None, 'Unexpected readback parent')
        if operation == 'readback':
            self._readback_parent(request)
        ticket = RequestTicket(request['request_id'], _digest(request))
        if operation == 'mutate':
            # Intent is burned even if publishing the request is interrupted.
            self._create(f'intent-{intent_id}.json', asdict(ticket))
        self._create(self._name(ticket, 'request'), request)
        self._request(ticket)
        return ticket

    def inspect(self, ticket):
        """Return a copy. Inspecting is neither a claim nor dispatch permission."""
        return _copy(self._request(ticket))

    def _open(self, ticket, request, now):
        _need(not self._exists(self._name(ticket, 'abandoned'))
              and not self._exists(self._name(ticket, 'accepted')), 'Request is terminal')
        if not request['created_at'] <= now < request['response_deadline']:
            self._poison(ticket)
            raise BridgeBlocked('Response window expired or clock rolled back')

    def _poison(self, ticket):
        if not self._exists(self._name(ticket, 'abandoned')):
            self._create(self._name(ticket, 'abandoned'),
                         {'request_id': ticket.request_id, 'request_digest': ticket.request_digest,
                          'abandoned_at': self._now(), 'reason': 'uncertain_no_retry'})

    def _window(self, request, now):
        _need(request['slot_start'] <= now, 'Clock is before pinned slot start')
        if request['operation'] == 'readback':
            self._readback_parent(request)
        else:
            _need(now < request['slot_deadline'], 'Pinned slot has expired')

    def claim(self, ticket, worker_binding):
        """Consume durably before any dispatch. A crash is never recoverable here."""
        _need(type(worker_binding) is BindingPin, 'Exact fixed worker binding required')
        with self._locked(ticket):
            request, now = self._request(ticket), self._now()
            self._open(ticket, request, now)
            self._window(request, now)
            _need(worker_binding.as_dict() == request['binding'], 'Worker/binding mismatch')
            _need(request['operation'] != 'mutate' or self._synthetic, 'Mutation transport is disabled')
            self._create(self._name(ticket, 'claimed'),
                         {'request_id': ticket.request_id, 'request_digest': ticket.request_digest,
                          'binding': worker_binding.as_dict(), 'claimed_at': now, 'consumed': True})
            return ClaimedRequest(ticket, worker_binding, now)

    def _claim(self, claim, request):
        _need(type(claim) is ClaimedRequest, 'Exact claim required')
        expected = {'request_id': claim.ticket.request_id, 'request_digest': claim.ticket.request_digest,
                    'binding': claim.worker_binding.as_dict(), 'claimed_at': claim.claimed_at,
                    'consumed': True}
        _need(self._read(self._name(claim.ticket, 'claimed')) == expected
              and expected['binding'] == request['binding'], 'Durable consumed marker mismatch')

    def _observation(self, value, binding, now, not_before):
        _need(type(value) is dict and set(value) == BINDING_KEYS | {'exists', 'logged_in', 'observed_at'},
              'Exact fresh browser observation required')
        _need(all(value[key] == binding[key] for key in BINDING_KEYS)
              and value['exists'] is True and value['logged_in'] is True,
              'Fixed tab/browser/account does not match; never substitute a route')
        _need(type(value['observed_at']) is int and max(not_before, now - 300) <= value['observed_at'] <= now,
              'Observation is stale, predates request, or is future-dated')

    def begin_dispatch(self, claim, observed_binding):
        """Last local gate immediately before the worker's ONE fixed operation.

        The native worker must recheck real clock and binding again if ANY delay
        occurs after this call. A returned spec does not authenticate a tool.
        Synthetic mutation specs MUST NEVER be passed to real tools.
        """
        with self._locked(claim.ticket):
            request, now = self._request(claim.ticket), self._now()
            self._claim(claim, request)
            # Burn this attempt before any timing or identity gate can fail.
            self._create(self._name(claim.ticket, 'attempt'),
                         {'request_id': claim.ticket.request_id, 'request_digest': claim.ticket.request_digest})
            self._open(claim.ticket, request, now)
            _need(claim.claimed_at <= now, 'Clock rolled back after claim')
            self._window(request, now)
            self._observation(observed_binding, request['binding'], now, request['created_at'])
            _need(request['operation'] != 'mutate' or self._synthetic, 'Mutation transport is disabled')
            self._create(self._name(claim.ticket, 'dispatch'),
                         {'request_id': claim.ticket.request_id, 'request_digest': claim.ticket.request_digest,
                          'binding': request['binding'], 'claimed_at': claim.claimed_at,
                          'dispatched_at': now, 'consumed': True})
            return DispatchSpec(claim.ticket, canonical(request), now)

    def _dispatch(self, ticket, request):
        _need(self._read(self._name(ticket, 'attempt')) == asdict(ticket),
              'Durable dispatch-attempt marker mismatch')
        claim = self._read(self._name(ticket, 'claimed'))
        dispatch = self._read(self._name(ticket, 'dispatch'))
        _need(set(dispatch) == {'request_id', 'request_digest', 'binding', 'claimed_at',
                                'dispatched_at', 'consumed'}, 'Malformed dispatch marker')
        _need(set(claim) == {'request_id', 'request_digest', 'binding', 'claimed_at', 'consumed'},
              'Malformed consumed marker')
        _need(all(claim[key] == dispatch[key] for key in claim)
              and dispatch['request_id'] == ticket.request_id
              and dispatch['request_digest'] == ticket.request_digest
              and dispatch['binding'] == request['binding'] and dispatch['consumed'] is True,
              'Dispatch/claim binding mismatch')
        _need(type(dispatch['claimed_at']) is int and type(dispatch['dispatched_at']) is int
              and request['created_at'] <= dispatch['claimed_at'] <= dispatch['dispatched_at']
              < request['response_deadline'], 'Invalid dispatch times')
        self._window(request, dispatch['dispatched_at'])
        return dispatch

    def _result(self, request, result, dispatched_at, now):
        value = completed_json(result)  # Reject running/truncated/nonzero/stderr/duplicate JSON.
        _no_credentials(value)
        if request['operation'] == 'mutate':
            _need(set(value) == {'ok', 'outcome', 'action_id', 'intent_id'}
                  and value['action_id'] == request['action']['action_id']
                  and value['intent_id'] == request['intent_id']
                  and ((value['ok'] is True and value['outcome'] == 'submitted')
                       or (value['ok'] is False and value['outcome'] == 'denied')),
                  'Exact definitive mutation result required')
        else:
            keys = {'ok', 'binding'} if request['operation'] == 'observe' else {'ok', 'binding', 'evidence', 'evidence_path'}
            _need(set(value) == keys and value['ok'] is True, 'Exact successful read result required')
            self._observation(value['binding'], request['binding'], now, dispatched_at)
            if request['operation'] != 'observe':
                evidence = value['evidence']
                _need(type(evidence) is dict and set(evidence) == {'schema', 'account', 'kind', 'target',
                      'payload_hash', 'intent_id', 'outcome', 'observed_at', 'reference', 'proof_file',
                      'proof_sha256', 'receipt_urls'}, 'Exact browser evidence schema required')
                _need(evidence['schema'] == 'browser-action-evidence-v2'
                      and evidence['account'] == request['binding']['account']
                      and evidence['intent_id'] == request['intent_id']
                      and all(evidence[key] == request['action'][key]
                              for key in ('kind', 'target', 'payload_hash')), 'Evidence binding mismatch')
                outcomes = {'absent', 'present'} if request['operation'] == 'preflight' else {'present'}
                _need(evidence['outcome'] in outcomes and type(evidence['observed_at']) is int
                      and max(dispatched_at, now - 300) <= evidence['observed_at'] <= now,
                      'Invalid evidence outcome/time')
                _text(evidence['reference'], 'public evidence reference')
                _need(type(evidence['proof_sha256']) is str and HASH.fullmatch(evidence['proof_sha256'])
                      and type(evidence['receipt_urls']) is list
                      and all(type(url) is str for url in evidence['receipt_urls']), 'Invalid public evidence fields')
                for path in (evidence['proof_file'], value['evidence_path']):
                    _need(type(path) is str and Path(path).is_absolute()
                          and Path(path).resolve().is_relative_to(INTEGRATION_ROOT),
                          'Evidence files must remain in integration staging')
        return value

    def complete(self, claim, result):
        """Publish a single final response; never convert ambiguity into success."""
        with self._locked(claim.ticket):
            request, now = self._request(claim.ticket), self._now()
            self._claim(claim, request)
            dispatch = self._dispatch(claim.ticket, request)
            self._create(self._name(claim.ticket, 'completion_attempt'), asdict(claim.ticket))
            self._open(claim.ticket, request, now)
            _need(dispatch['dispatched_at'] <= now, 'Clock rolled back after dispatch')
            value = self._result(request, result, dispatch['dispatched_at'], now)
            response = {'schema': RESPONSE_SCHEMA, 'request_id': claim.ticket.request_id,
                        'request_digest': claim.ticket.request_digest,
                        **{key: request[key] for key in ('operation', 'binding', 'payload_hash',
                           'authorization_reference', 'intent_id', 'slot_start', 'slot_deadline')},
                        'claimed_at': claim.claimed_at, 'dispatched_at': dispatch['dispatched_at'],
                        'completed_at': now,
                        'result': {'completed': True, 'exit_code': 0, 'stdout': value,
                                   'truncated': False, 'session_id': None, 'stderr': ''}}
            self._create(self._name(claim.ticket, 'response_seal'),
                         {**asdict(claim.ticket), 'response_digest': _digest(response)})
            self._create(self._name(claim.ticket, 'response'), response)

    def _response(self, ticket, request):
        response = self._read(self._name(ticket, 'response'))
        _need(self._read(self._name(ticket, 'completion_attempt')) == asdict(ticket)
              and self._read(self._name(ticket, 'response_seal')) ==
              {**asdict(ticket), 'response_digest': _digest(response)}, 'Response content seal mismatch')
        _need(set(response) == RESPONSE_KEYS and response['schema'] == RESPONSE_SCHEMA
              and response['request_id'] == ticket.request_id
              and response['request_digest'] == ticket.request_digest,
              'Exact response envelope or digest mismatch')
        _need(all(response[key] == request[key] for key in ('operation', 'binding', 'payload_hash',
                  'authorization_reference', 'intent_id', 'slot_start', 'slot_deadline')),
              'Response binding/action/slot mismatch')
        dispatch = self._dispatch(ticket, request)
        _need(response['claimed_at'] == dispatch['claimed_at']
              and response['dispatched_at'] == dispatch['dispatched_at']
              and type(response['completed_at']) is int
              and dispatch['dispatched_at'] <= response['completed_at'] < request['response_deadline'],
              'Response has invalid or late completion time')
        raw = response['result']
        _need(type(raw) is dict and set(raw) == {'completed', 'exit_code', 'stdout', 'truncated',
                                               'session_id', 'stderr'}, 'Exact CommandResult envelope required')
        _need(type(raw['stdout']) is dict, 'Response must contain one complete JSON object')
        result = CommandResult(**{**raw, 'stdout': canonical(raw['stdout'])})
        self._result(request, result, dispatch['dispatched_at'], response['completed_at'])
        return response

    def take_result(self, ticket):
        """Consume a completed response once. None means pending, never success."""
        with self._locked(ticket):
            request, now = self._request(ticket), self._now()
            self._open(ticket, request, now)
            if not self._exists(self._name(ticket, 'response')):
                return None
            response = self._response(ticket, request)
            _need(response['completed_at'] <= now, 'Future completion time')
            self._create(self._name(ticket, 'accepted'),
                         {'request_id': ticket.request_id, 'request_digest': ticket.request_digest,
                          'response_digest': _digest(response), 'accepted_at': now})
            return CommandResult(True, 0, canonical(response['result']['stdout']))

    def abandon(self, ticket):
        """Seal uncertainty after timeout; never release/retry a consumed intent."""
        with self._locked(ticket):
            request = self._request(ticket)
            _need(not self._exists(self._name(ticket, 'accepted')), 'Already accepted')
            if not self._exists(self._name(ticket, 'abandoned')):
                self._create(self._name(ticket, 'abandoned'),
                             {'request_id': ticket.request_id, 'request_digest': ticket.request_digest,
                              'abandoned_at': self._now(), 'reason': 'uncertain_no_retry'})

    def wait_result(self, ticket, *, poll_seconds=0.02):
        _need(type(poll_seconds) in (float, int) and math.isfinite(poll_seconds)
              and 0.001 <= poll_seconds <= 1, 'Invalid bounded polling interval')
        request = self._request(ticket)
        monotonic_deadline = time.monotonic() + max(0, request['response_deadline'] - self._now())
        try:
            while True:
                result = self.take_result(ticket)
                if result is not None:
                    return result
                _need(time.monotonic() < monotonic_deadline, 'Transport timeout; no retry')
                time.sleep(poll_seconds)
        except Exception:
            # A corrupt file cannot safely be repaired. The claim/intent remain.
            try:
                self.abandon(ticket)
            except Exception:
                pass
            raise BridgeBlocked('Bridge output uncertain or unavailable; no retry') from None

    def dispatch_synthetic(self, claim, *, observe_binding: Callable, handler: Callable):
        """Test-only callback helper. There is no real tool handler in this module.

        This is a single callback, NOT arbitrary named-method dispatch. Test
        handlers must contain only synthetic behavior, with no external effects.
        """
        _need(self._synthetic, 'Synthetic helper requires explicit test capability')
        observed = observe_binding()
        spec = self.begin_dispatch(claim, observed)
        # Recheck after every possible pre-handler delay, while consuming once.
        request, now = self._request(claim.ticket), self._now()
        self._open(claim.ticket, request, now)
        self._window(request, now)
        self._observation(observe_binding(), request['binding'], now, request['created_at'])
        # The callback immediately follows the final clock/binding checks.
        now = self._now()
        self._open(claim.ticket, request, now)
        self._window(request, now)
        result = handler(spec)
        self.complete(claim, result)
        return spec


class FileBrowserAdapter:
    """Frozen BrowserAdapter facade; one fixed context per role and scheduled slot.

    A separate orchestrator receives tickets via the optional notification hook,
    then claims and services requests. The hook grants no mutation authority.
    Construct a new adapter for the next slot; contexts never silently rotate.
    """
    def __init__(self, bridge: FileToolBridge, contexts: Iterable[SlotContext], *,
                 timeout_seconds=30, on_submitted=None):
        self.bridge = bridge
        contexts = tuple(contexts)
        _need(contexts and all(type(c) is SlotContext for c in contexts), 'Pinned contexts required')
        _need(len({c.binding.role for c in contexts}) == len(contexts), 'Duplicate role contexts')
        _need(len({c.binding.worker_id for c in contexts}) == len(contexts)
              and len({(c.binding.browser_id, c.binding.tab_id) for c in contexts}) == len(contexts),
              'Roles must have distinct workers and canonical tabs')
        self._contexts = {c.binding.role: c for c in contexts}
        self.timeout_seconds = timeout_seconds
        self._notify = on_submitted
        self._mutations = {}
        self._lock = threading.Lock()

    def _context(self, binding):
        pin = BindingPin.from_dict(binding)
        context = self._contexts.get(pin.role)
        _need(context is not None and context.binding == pin, 'Adapter fixed binding mismatch')
        return context

    def _call(self, operation, binding, action=None, intent_id=None, readback_of=None):
        context = self._context(binding)
        ticket = self.bridge.submit(operation, context, action=action, intent_id=intent_id,
                                    timeout_seconds=self.timeout_seconds, readback_of=readback_of)
        try:
            if self._notify is not None:
                self._notify(ticket)  # Ticket only, no secret or mutable request object.
            result = self.bridge.wait_result(ticket)
            return ticket, result
        except Exception:
            try:
                self.bridge.abandon(ticket)
            except Exception:
                pass
            raise

    def observe(self, binding):
        return self._call('observe', binding)[1]

    def preflight(self, action, binding):
        return self._call('preflight', binding, action)[1]

    def mutate(self, action, binding, intent_id, *, slot_start, slot_deadline):
        context = self._context(binding)
        _need(type(slot_start) is int and type(slot_deadline) is int
              and (slot_start, slot_deadline) == (context.slot_start, context.slot_deadline),
              'Coordinator and adapter slot bounds differ')
        ticket, result = self._call('mutate', binding, action, intent_id)
        value = completed_json(result)
        if value['ok'] is True and value['outcome'] == 'submitted':
            with self._lock:
                self._mutations[intent_id] = ticket
        return result

    def readback(self, action, binding, intent_id):
        with self._lock:
            parent = self._mutations.get(intent_id)
        _need(parent is not None, 'No accepted matching submission for readback')
        return self._call('readback', binding, action, intent_id, parent)[1]
