"""Staging native read handler and inert mutation-operation contracts.

This module has no browser import, executable-script field, network client or
production mutation switch. A trusted native worker can supply a read-only port;
calling a real browser remains subject to that worker's current tool instructions.
Mutation contracts below are synthetic simulations, NEVER real tool permission.
"""
from dataclasses import dataclass
import hashlib
import time

from dispatch_gate import CommandResult, GateBlocked, canonical, payload_hash, require
from tool_bridge import BindingPin, DispatchSpec, FileToolBridge, SyntheticTestCapability
from publisher_safety import validate_payload
from queue_checkpoint import _safe_payload

READ_OPERATIONS = frozenset({'observe', 'preflight', 'readback'})
READ_CAPABILITIES = frozenset({'binding_observation', 'dom_read', 'url_title_read',
                              'screenshot_read', 'permitted_public_navigation', 'reload'})
ROLE_KINDS = {'publisher': {'publish'}, 'spreader': {'repost', 'like', 'reply', 'follow'},
              'commenter': {'reply'}}


def validate_prepared_action(action, binding):
    """Check exportability BEFORE writer acquisition or native preparation."""
    require(action['kind'] in ROLE_KINDS[binding.role], 'Action is outside the role contract')
    require(type(action['payload']) is dict and action['payload'].get('target') == action['target'],
            'Exact outbound target required')
    require(payload_hash(action['payload']) == action['payload_hash'], 'Immutable payload changed')
    _safe_payload(action['kind'], action['payload'])
    if action['kind'] == 'publish':
        validate_payload(action)
    elif action['kind'] == 'reply':
        require(set(action['payload']) == {'target', 'text'} and
                type(action['payload']['text']) is str and bool(action['payload']['text'].strip()),
                'Exact reply text is required before preparation')
    else:
        require(set(action['payload']) == {'target'}, 'Unexpected simple-action payload')


class PreparationAuthorizationGuard:
    """Layer around the exact authorization adapter; adds no grants or quotas."""
    def __init__(self, delegate): self.delegate = delegate
    def authorize_batch(self, job, actions):
        pin = BindingPin(job['role'], job['worker_id'], job['browser_id'], job['tab_id'], job['expected_account'])
        for action in actions: validate_prepared_action(action, pin)
        return self.delegate.authorize_batch(job, actions)
    def authorize(self, job, action):
        pin = BindingPin(job['role'], job['worker_id'], job['browser_id'], job['tab_id'], job['expected_account'])
        validate_prepared_action(action, pin)
        return self.delegate.authorize(job, action)


class NativeReadHandler:
    """Consume existing durable tickets once, using a fixed read-only port.

    Port methods: observe(binding) -> full fresh observed binding dictionary;
    preflight_read(action,binding) -> CommandResult; and
    readback_read(action,binding,intent_id) -> CommandResult. The port MUST derive
    all evidence from actual supported native tools. It must never click controls,
    open action menus, compose, upload, submit, delete or change a profile. It may
    not replace a missing tab, select an alias browser, log in or claim a user tab.
    A capability declaration is a cooperative contract, not code sandboxing.
    """
    def __init__(self, bridge, binding, port, *, clock=None):
        require(type(bridge) is FileToolBridge and type(binding) is BindingPin, 'Exact bridge and worker binding required')
        require(getattr(port, 'capabilities', None) == READ_CAPABILITIES, 'Explicit read-only native port required')
        self.bridge, self.binding, self.port = bridge, binding, port
        self.clock = clock or (lambda: int(time.time()))

    def service(self, ticket):
        request = self.bridge.inspect(ticket)
        require(request['operation'] in READ_OPERATIONS and request['transport_mode'] == 'read_only',
                'Native read handler cannot service any mutation')
        require(request['binding'] == self.binding.as_dict(), 'Native worker binding mismatch')
        if request['action'] is not None: validate_prepared_action(request['action'], self.binding)
        claim = self.bridge.claim(ticket, self.binding)
        try:
            observed = self.port.observe(self.binding.as_dict())
            spec = self.bridge.begin_dispatch(claim, observed)
            request = spec.request()
            # A potentially slow observation is followed by both clock checks.
            observed = self.port.observe(self.binding.as_dict())
            now = self.clock()
            require(type(now) is int and request['created_at'] <= now < request['response_deadline'] and
                    request['slot_start'] <= now and
                    (request['operation'] == 'readback' or now < request['slot_deadline']),
                    'Native read request expired or clock rolled back')
            self.bridge._observation(observed, request['binding'], now, request['created_at'])
            op = request['operation']
            if op == 'observe':
                result = CommandResult(True, 0, canonical({'ok': True, 'binding': observed}))
            elif op == 'preflight':
                result = self.port.preflight_read(request['action'], request['binding'])
            else:
                result = self.port.readback_read(request['action'], request['binding'], request['intent_id'])
            self.bridge.complete(claim, result)
            return spec.ticket
        except Exception:
            self.bridge.abandon(ticket)
            raise


@dataclass(frozen=True)
class StepContract:
    name: str
    effect: str
    expected_sha256: str


class SyntheticMutationContract:
    """Inert state machine for one intent-bound native operation.

    Only a read-only authorization-recheck callback is accepted; no browser action
    is executed. A production
    implementation must be separately reviewed. Its publisher preparation and
    final submission must stay inside the same consumed intent/writer, and the
    whole operation must fit the ledger's one bounded native tool invocation.
    Separate tool submissions require an explicitly revised adapter, not reuse.
    """
    def __init__(self, spec, binding, *, synthetic_capability, clock, authorization_recheck,
                 review_sha256):
        require(type(synthetic_capability) is SyntheticTestCapability and type(spec) is DispatchSpec,
                'Synthetic operation contract only')
        request = spec.request()
        require(hashlib.sha256(canonical(request).encode()).hexdigest() == spec.ticket.request_digest and
                request['request_id'] == spec.ticket.request_id, 'Mutation contract request pin mismatch')
        require(request['operation'] == 'mutate' and request['transport_mode'] == 'synthetic_only' and
                request['binding'] == binding.as_dict(), 'Exact synthetic mutation request required')
        validate_prepared_action(request['action'], binding)
        require(callable(authorization_recheck) and type(review_sha256) is str and
                len(review_sha256) == 64 and all(c in '0123456789abcdef' for c in review_sha256),
                'Pinned exact review and a read-only authorization recheck are required')
        self._request, self.binding, self.clock = request, binding, clock
        self._authorization_recheck, self._review_sha256 = authorization_recheck, review_sha256
        self._index, self._pending, self._halted, self._submitted = 0, None, False, False
        action = request['action']; kind = action['kind']; p = action['payload']
        if kind == 'publish':
            # UI composition/upload are changing operations, not read preflight.
            entries = [('compose_four_parts', 'draft_change', payload_hash({'root':p['root'],'replies':p['replies']})),
                       ('attach_original_image', 'media_upload', p['image_sha256']),
                       ('inspect_complete_composer', 'read', action['payload_hash']),
                       ('submit_bundle_once', 'public_submission', action['payload_hash'])]
        elif kind == 'repost':
            entries = [('open_exact_repost_control', 'potential_public_change', action['payload_hash']),
                       ('inspect_repost_menu', 'read', action['payload_hash']),
                       ('submit_repost_once', 'public_submission', action['payload_hash'])]
        elif kind == 'reply':
            entries = [('compose_exact_reply', 'draft_change', action['payload_hash']),
                       ('inspect_exact_reply', 'read', action['payload_hash']),
                       ('submit_reply_once', 'public_submission', action['payload_hash'])]
        else:
            entries = [('activate_exact_'+kind+'_once', 'public_submission', action['payload_hash'])]
        self.steps = tuple(StepContract(*entry) for entry in entries)

    @property
    def submitted(self): return self._submitted
    @property
    def halted(self): return self._halted

    def next_step(self, observed_binding):
        # Consume/fail closed before returning any changing instruction.
        if self._halted or self._pending is not None or self._index >= len(self.steps):
            self._halted = True
            raise GateBlocked('No repeat, pending, halted or completed operation step')
        now = self.clock(); req = self._request
        try:
            require(type(now) is int and req['created_at'] <= now < req['response_deadline'] and
                    req['slot_start'] <= now < req['slot_deadline'], 'Mutation step expired or clock rolled back')
            require(type(observed_binding) is dict and set(observed_binding) == set(req['binding']) |
                    {'exists','logged_in','observed_at'} and
                    all(observed_binding.get(k) == v for k,v in req['binding'].items()) and
                    observed_binding['exists'] is True and observed_binding['logged_in'] is True and
                    type(observed_binding['observed_at']) is int and
                    max(req['created_at'], now-30) <= observed_binding['observed_at'] <= now,
                    'Actual fresh fixed binding required at every operation boundary')
            check = self._authorization_recheck()
            now = self.clock()
            action = req['action']
            require(type(check) is dict and check.get('schema') == 'consumed-authorization-recheck-v1' and
                    check.get('binding') == req['binding'] and
                    check.get('slot') == {'scheduled_at':req['slot_start'],'next_same_role_at':req['slot_deadline']} and
                    check.get('review_sha256') == self._review_sha256 and
                    all(check.get(k) == action[k] for k in ('authorization_id','action_id','kind','target','payload_hash')) and
                    type(check.get('checked_at')) is int and type(check.get('expires_at')) is int and
                    check['checked_at'] <= now < check['expires_at'] and now-check['checked_at'] <= 5 and
                    req['created_at'] <= now < req['response_deadline'] and req['slot_start'] <= now < req['slot_deadline'],
                    'Exact consumed-action approval expired, changed or was not rechecked')
            self._pending = self.steps[self._index]
            return self._pending
        except Exception:
            self._halted = True
            raise

    def record_synthetic_result(self, name, *, state, observed_sha256):
        """State is a test observation, never evidence of real browser success."""
        require(not self._halted and self._pending is not None, 'No pending operation step')
        step = self._pending
        try:
            require(name == step.name and observed_sha256 == step.expected_sha256, 'Step or immutable content mismatch')
            expected = 'clear_new_repost' if name == 'inspect_repost_menu' else \
                       'bundle_ready' if name == 'inspect_complete_composer' else \
                       'reply_ready' if name == 'inspect_exact_reply' else \
                       'submitted' if step.effect == 'public_submission' else \
                       'menu_opened_no_state_change' if name == 'open_exact_repost_control' else 'prepared'
            require(state == expected, 'Denied, already/delete/undo, ambiguous or unexpected outcome: no further step')
            if step.effect == 'public_submission': self._submitted = True
            self._index += 1
            self._pending = None
        except Exception:
            self._halted = True
            raise


def staged_coordinator(queue, identity, *, clock, ledger, browser, authorization, **kwargs):
    """Combined entrypoint: goal controller plus export/publisher semantic guards."""
    from goal_coordinator import GoalCoordinator
    from publisher_safety import PublisherBrowserGuard, PublisherAuthorizationGuard
    return GoalCoordinator(queue, identity, clock=clock, ledger=ledger,
        browser=PublisherBrowserGuard(browser,clock=clock),
        authorization=PublisherAuthorizationGuard(PreparationAuthorizationGuard(authorization)), **kwargs)
