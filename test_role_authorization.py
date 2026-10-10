"""Public-safe synthetic records ONLY. Fixture fabrication is not an approval service."""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from integration_paths import SOURCE_ROOT as STAGING, INTEGRATION_ROOT
from dispatch_gate import GateBlocked, action_id, canonical, payload_hash, successful
from role_authorization import (BASE_FACT, CONDITIONS, EVIDENCE_SCHEMA, OBJECTIVES,
    ROLE_OFFSET, SCHEMA, ExactRoleAuthorization, ReviewContext, StagingReplayStore, TrustedReviewPin)


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return canonical(value).encode('utf-8')


class SyntheticFixture:
    """Makes test-only reviewed decisions; never suitable as a runtime producer."""
    def __init__(self, role='spreader', kinds=None, already_newly_verified=None):
        if kinds is None:
            kinds = {'spreader': ['repost'] * 5, 'commenter': ['reply'], 'publisher': ['publish']}[role]
        self.role = role
        self.prior = (None if role == "commenter" else 0) if already_newly_verified is None else already_newly_verified
        self.objective = None if role == "commenter" else {"kind": "repost" if role == "spreader" else "publish",
            "newly_verified_goal": OBJECTIVES[role]["target"], "already_newly_verified": self.prior}
        self.start = 3600 * 100 + ROLE_OFFSET[role]
        self.now = self.start + 20
        self.policy_reference = 'synthetic-public-policy-v1'
        self.binding = {'role': role, 'worker_id': 'synthetic-worker-' + role,
            'browser_id': 'synthetic-canonical-browser', 'tab_id': 'synthetic-tab-' + role,
            'account': 'synthetic_account'}
        self.slot = {'scheduled_at': self.start, 'next_same_role_at': self.start + 3600}
        self.actions, raw_actions = [], []
        for index, kind in enumerate(kinds):
            target = (f'https://blog.example/{index + 101}' if kind == 'publish' else
                f'https://www.threads.com/@synthetic_person{index}' + ('' if kind == 'follow' else f'/post/Synthetic{index}'))
            payload = {'target': target}
            if kind in {'reply', 'self_reply'}: payload['text'] = 'Synthetic reply only.'
            if kind == 'publish':
                payload.update(article_id=index + 101, blog_url=target, root='Synthetic root.',
                    replies=['Synthetic first continuation ' + target, 'Synthetic second.', 'Synthetic third.'],
                    root_image_path=str(INTEGRATION_ROOT/'synthetic-original.png'),
                    root_image_url='https://example.com/synthetic-original.png', image_sha256='a' * 64,
                    preview_reply_index=1)
            raw = {'kind': kind, 'target': target, 'payload': payload, 'authorization_id': f'synthetic-approval-{index}'}
            item = dict(raw, payload_hash=payload_hash(payload), action_id=action_id(self.binding['account'], kind, target))
            raw_actions.append(raw); self.actions.append(item)
        self.body = {'actions': raw_actions}
        self.job = dict(job_id='synthetic-job-' + role, generation=1, **self.slot,
            **{k: v for k, v in self.binding.items() if k != 'account'},
            expected_account=self.binding['account'], payload_json=canonical(self.body), payload_hash=payload_hash(self.body),
            state='ready', created_at=self.start, unrelated_status='coordinator metadata can change')
        self.context = ReviewContext(**self.binding, job_id=self.job['job_id'], generation=1, **self.slot,
            batch_payload_hash=self.job['payload_hash'], actions_hash=digest(encoded(self.actions)),
            already_newly_verified=self.prior)
        self.sources = {}
        for category in ['policy', 'approval', 'usage']:
            self.add_source('synthetic-' + category, category, facts=[BASE_FACT[category]])
        decisions = []
        counts = {}
        for i, action in enumerate(self.actions):
            # Unknown role/kind fixture combinations are made deliberately invalid.
            facts = sorted(CONDITIONS.get((role, action['kind']), {'role_policy_satisfied'}))
            ref = f'synthetic-observation-{i}'
            self.add_source(ref, 'observation', facts=facts, action=action)
            decisions.append({k: action[k] for k in ['authorization_id', 'action_id', 'kind', 'target', 'payload_hash']} |
                {'decision': 'allow', 'reviewed_at': self.now, 'conditions': [
                    {'condition': fact, 'source_reference': ref} for fact in facts]})
            counts[action['kind']] = counts.get(action['kind'], 0) + 1
        self.record = {'schema': SCHEMA, 'decision_id': 'synthetic-reviewed-batch-' + role,
            'producer_reference': 'synthetic-authenticated-parent', 'issued_at': self.now, 'expires_at': self.now + 120,
            'policy': {'reference': self.policy_reference, 'sha256': digest(self.sources['synthetic-policy']),
                       'source_reference': 'synthetic-policy'}, 'binding': self.binding.copy(), 'slot': self.slot.copy(),
            'job': {'job_id': self.job['job_id'], 'generation': 1, 'batch_payload_hash': self.job['payload_hash'],
                    'actions_hash': self.context.actions_hash}, 'role_objective': copy.deepcopy(OBJECTIVES[role]),
            'run_progress': copy.deepcopy(self.objective),
            'standing_quota': {'status': 'not_asserted', 'source_reference': 'synthetic-policy'},
            'batch_grant': {'scope': 'exact_reviewed_batch', 'allowed_kinds': sorted(counts),
                'per_kind_limits': counts, 'max_actions': len(self.actions),
                'approval_source': 'synthetic-approval', 'usage_source': 'synthetic-usage'},
            'decisions': decisions, 'sources': []}
        self.current_policy = (self.policy_reference, self.record['policy']['sha256'])
        self.replay = StagingReplayStore()
        self.repin()

    def add_source(self, ref, category, *, facts, action=None):
        self.sources[ref] = encoded({'schema': EVIDENCE_SCHEMA, 'reference': ref,
            'origin_reference': 'synthetic-origin-' + ref, 'category': category,
            'recorded_at': self.now, 'policy_reference': self.policy_reference,
            'binding': self.binding.copy(), 'slot': self.slot.copy(),
            'action_id': None if action is None else action['action_id'],
            'payload_hash': None if action is None else action['payload_hash'],
            'run_progress': copy.deepcopy(self.objective) if category == 'usage' else None, 'facts': facts})

    def repin(self):
        # Tests explicitly represent a separately supplied trusted pin. This is
        # NOT a runtime helper; a proposal cannot approve or authenticate itself.
        self.record['sources'] = [{'reference': k, 'sha256': digest(v)} for k, v in self.sources.items()]
        self.raw = encoded(self.record)
        self.pin = TrustedReviewPin(digest(self.raw), 'synthetic-authenticated-parent',
            self.policy_reference, digest(self.sources['synthetic-policy']), self.context)

    def source_change(self, reference, update):
        doc = json.loads(self.sources[reference]); update(doc)
        self.sources[reference] = encoded(doc)
        self.repin()

    def adapter(self, **kwargs):
        options = dict(pin=self.pin, source_bytes=self.sources, current_policy=lambda: self.current_policy,
                       clock=lambda: self.now, replay_store=self.replay)
        options.update(kwargs)
        return ExactRoleAuthorization(self.raw, **options)


class RoleAuthorizationTests(unittest.TestCase):
    def test_all_roles_exact_protocol(self):
        for role in ['publisher', 'spreader', 'commenter']:
            with self.subTest(role=role):
                f = SyntheticFixture(role); a = f.adapter()
                batch = successful(a.authorize_batch(f.job, f.actions))
                self.assertEqual(batch['policy_reference'], f.policy_reference)
                self.assertEqual(batch['batch_payload_hash'], f.job['payload_hash'])
                self.assertEqual(batch['max_actions'], len(f.actions))
                self.assertEqual(batch['quota_scope'], 'exact_reviewed_batch')
                self.assertIs(batch['standing_quota_asserted'], False)
                for action in f.actions:
                    decision = successful(a.authorize(f.job, action))
                    for key in ['authorization_id', 'kind', 'target', 'payload_hash']:
                        self.assertEqual(decision[key], action[key])

    def test_conditional_spreader_actions_are_individually_reviewed(self):
        f = SyntheticFixture(kinds=['repost', 'like', 'reply', 'follow'])
        a = f.adapter(); a.authorize_batch(f.job, f.actions)
        for action in f.actions: a.authorize(f.job, action)

    def test_goal_and_exact_prior_verified_count_are_exposed(self):
        for role, count in [('spreader', 3), ('publisher', 0), ('commenter', None)]:
            f = SyntheticFixture(role, already_newly_verified=count)
            batch = successful(f.adapter().authorize_batch(f.job, f.actions))
            self.assertEqual(batch['objective'], f.objective)

    def test_more_reviewed_candidates_do_not_raise_goal(self):
        f = SyntheticFixture(kinds=['repost'] * 8)
        batch = successful(f.adapter().authorize_batch(f.job, f.actions))
        self.assertEqual(batch['max_actions'], 8)
        self.assertEqual(batch['per_kind_limits'], {'repost': 8})
        self.assertEqual(batch['objective'], {'kind': 'repost', 'newly_verified_goal': 5, 'already_newly_verified': 0})
        # Goal-aware coordinator must skip remaining candidates once verified=5.
        # The unchanged base coordinator does not implement this stopping rule.

    def test_prior_verified_history_cannot_be_invented(self):
        f = SyntheticFixture(already_newly_verified=3)
        f.record['run_progress']['already_newly_verified'] = 0; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()
        f = SyntheticFixture(already_newly_verified=3)
        f.source_change('synthetic-usage', lambda d: d['run_progress'].update(already_newly_verified=0))
        with self.assertRaises(GateBlocked): f.adapter()

    def test_negative_unbounded_or_boolean_history_rejected(self):
        for count in [-1, 6, True, 'unlimited']:
            f = SyntheticFixture()
            with self.assertRaises(GateBlocked):
                f.adapter(pin=replace(f.pin, context=replace(f.context, already_newly_verified=count)))

    def test_core_batch_validation_accepts_exact_response(self):
        from coordinator import SerialCoordinator
        from dispatch_gate import DispatchGate, LedgerIdentity
        f = SyntheticFixture(); coordinator = SerialCoordinator.__new__(SerialCoordinator)
        coordinator.authorization = f.adapter()
        coordinator.gate = DispatchGate(LedgerIdentity('synthetic_account', '1' * 32), lambda: f.now)
        result = coordinator._authorize_batch(f.job, f.actions)
        self.assertEqual(result['per_kind_limits'], {'repost': 5})

    def test_core_action_validation_accepts_exact_response(self):
        from coordinator import SerialCoordinator
        from dispatch_gate import DispatchGate, LedgerIdentity
        from types import SimpleNamespace
        f = SyntheticFixture(); coordinator = SerialCoordinator.__new__(SerialCoordinator)
        coordinator.authorization = f.adapter()
        coordinator.gate = DispatchGate(LedgerIdentity('synthetic_account', '1' * 32), lambda: f.now)
        policy = coordinator._authorize_batch(f.job, f.actions)
        coordinator._authorize(SimpleNamespace(job=f.job, policy=policy), f.actions[0])

    def test_wrong_independent_binding_each_dimension(self):
        for key, value in [('role', 'commenter'), ('worker_id', 'other-worker'), ('browser_id', 'other-browser'),
            ('tab_id', 'other-tab'), ('account', 'other_account'), ('job_id', 'other-job'), ('generation', 2),
            ('scheduled_at', 1), ('next_same_role_at', 999999), ('batch_payload_hash', 'c' * 64), ('actions_hash', 'd' * 64)]:
            with self.subTest(key=key):
                f = SyntheticFixture(); pin = replace(f.pin, context=replace(f.context, **{key: value}))
                with self.assertRaises(GateBlocked): f.adapter(pin=pin)

    def test_wrong_job_binding_each_dimension(self):
        for key, value in [('role', 'commenter'), ('worker_id', 'other-worker'), ('browser_id', 'other-browser'),
            ('tab_id', 'other-tab'), ('expected_account', 'other_account'), ('job_id', 'other-job'),
            ('generation', 2), ('scheduled_at', 1), ('next_same_role_at', 999999), ('payload_hash', 'c' * 64)]:
            with self.subTest(key=key):
                f = SyntheticFixture(); a = f.adapter(); job = dict(f.job, **{key: value})
                with self.assertRaises(GateBlocked): a.authorize_batch(job, f.actions)

    def test_lifecycle_metadata_is_not_a_new_manifest(self):
        f = SyntheticFixture(); a = f.adapter(); a.authorize_batch(f.job, f.actions)
        job = dict(f.job, state='dispatching', unrelated_status='changed')
        a.authorize(job, f.actions[0])

    def test_record_tamper_without_new_trusted_digest(self):
        f = SyntheticFixture(); record = copy.deepcopy(f.record); record['binding']['tab_id'] = 'evil-tab'
        f.raw = encoded(record)
        with self.assertRaises(GateBlocked): f.adapter()

    def test_missing_trusted_pin(self):
        f = SyntheticFixture()
        with self.assertRaises(GateBlocked): f.adapter(pin=None)

    def test_digest_from_file_cannot_change_independent_context(self):
        f = SyntheticFixture(); f.record['binding']['tab_id'] = 'evil-tab'; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_wrong_producer_pin(self):
        f = SyntheticFixture()
        with self.assertRaises(GateBlocked): f.adapter(pin=replace(f.pin, producer_reference='unknown-producer'))

    def test_wrong_policy_reference_or_digest(self):
        for pair in [('new-policy', 'a' * 64), ('synthetic-public-policy-v1', 'b' * 64)]:
            f = SyntheticFixture(); f.current_policy = pair
            with self.assertRaises(GateBlocked): f.adapter()

    def test_policy_change_between_batch_and_action(self):
        f = SyntheticFixture(); a = f.adapter(); a.authorize_batch(f.job, f.actions)
        f.current_policy = ('revised-public-policy', 'd' * 64)
        with self.assertRaises(GateBlocked): a.authorize(f.job, f.actions[0])

    def test_policy_unavailable(self):
        f = SyntheticFixture()
        def missing(): raise RuntimeError('Synthetic unavailable source')
        with self.assertRaises(GateBlocked): f.adapter(current_policy=missing)

    def test_review_stale_future_expired_and_slot_rollback(self):
        for now in ['before_issue', 'expiry', 'future_slot', 'previous_slot']:
            f = SyntheticFixture()
            f.now = {'before_issue': f.now - 1, 'expiry': f.record['expires_at'],
                     'future_slot': f.start + 3600, 'previous_slot': f.start - 1}[now]
            with self.subTest(now=now), self.assertRaises(GateBlocked): f.adapter()

    def test_expiry_rechecked_per_action(self):
        f = SyntheticFixture(); a = f.adapter(); a.authorize_batch(f.job, f.actions)
        f.now = f.record['expires_at']
        with self.assertRaises(GateBlocked): a.authorize(f.job, f.actions[0])

    def test_missed_slot_cannot_be_caught_up_even_with_new_review_time(self):
        f = SyntheticFixture(); f.now += 3600
        f.record['issued_at'] = f.now; f.record['expires_at'] = f.now + 120; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_freshness_cannot_be_relaxed(self):
        for freshness in [0, -1, 301, True, None]:
            f = SyntheticFixture()
            with self.subTest(freshness=freshness), self.assertRaises(GateBlocked): f.adapter(freshness=freshness)

    def test_missing_or_tampered_source(self):
        for variant in ['missing', 'changed', 'extra']:
            f = SyntheticFixture(); sources = dict(f.sources)
            if variant == 'missing': sources.pop('synthetic-approval')
            elif variant == 'changed': sources['synthetic-usage'] += b' '
            else: sources['synthetic-extra'] = sources['synthetic-usage']
            with self.subTest(variant=variant), self.assertRaises(GateBlocked): f.adapter(source_bytes=sources)

    def test_source_binding_slot_and_policy_mismatch(self):
        for update in [lambda d: d['binding'].update(tab_id='other-tab'),
                       lambda d: d['slot'].update(scheduled_at=d['slot']['scheduled_at'] - 3600),
                       lambda d: d.update(policy_reference='other-policy'),
                       lambda d: d.update(action_id='f' * 64),
                       lambda d: d.update(payload_hash='f' * 64)]:
            f = SyntheticFixture(); f.source_change('synthetic-observation-0', update)
            with self.assertRaises(GateBlocked): f.adapter()

    def test_missing_conditional_fact(self):
        for role, kind, missing in [('spreader', 'follow', 'follow_condition_satisfied'),
                ('spreader', 'like', 'like_condition_satisfied'),
                ('spreader', 'repost', 'repost_not_already_present'),
                ('commenter', 'reply', 'existing_conversation_verified'),
                ('publisher', 'publish', 'original_image_reviewed')]:
            f = SyntheticFixture(role, [kind]); f.record['decisions'][0]['conditions'] = [
                c for c in f.record['decisions'][0]['conditions'] if c['condition'] != missing]
            f.repin()
            with self.subTest(role=role, kind=kind), self.assertRaises(GateBlocked): f.adapter()

    def test_condition_reference_without_attested_fact(self):
        f = SyntheticFixture(kinds=['follow'])
        f.source_change('synthetic-observation-0', lambda d: d.update(facts=['role_policy_satisfied']))
        with self.assertRaises(GateBlocked): f.adapter()

    def test_condition_source_wrong_category(self):
        f = SyntheticFixture(); f.record['decisions'][0]['conditions'][0]['source_reference'] = 'synthetic-approval'
        f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_stale_conditional_observation_even_when_review_fresh(self):
        f = SyntheticFixture(); f.now = f.start + 600
        f.record['issued_at'] = f.now; f.record['expires_at'] = f.now + 120
        for d in f.record['decisions']: d['reviewed_at'] = f.now
        # Refresh usage and all but one observation, preserving a stale observation.
        for ref in list(f.sources):
            if ref != 'synthetic-observation-0':
                doc = json.loads(f.sources[ref]); doc['recorded_at'] = f.now; f.sources[ref] = encoded(doc)
        f.record['policy']['sha256'] = digest(f.sources['synthetic-policy'])
        f.current_policy = (f.policy_reference, f.record['policy']['sha256']); f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_role_prohibitions(self):
        for role, kind in [('commenter', 'like'), ('commenter', 'repost'), ('commenter', 'follow'),
                ('commenter', 'publish'), ('publisher', 'reply'), ('spreader', 'publish'),
                ('spreader', 'self_reply')]:
            f = SyntheticFixture(role, [kind])
            with self.subTest(role=role, kind=kind), self.assertRaises(GateBlocked): f.adapter()

    def test_unknown_standing_quota_is_not_inferred_from_batch(self):
        f = SyntheticFixture(); f.record['standing_quota'] = {'repost': 5}; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_goal_is_verified_reposts_not_candidates(self):
        f = SyntheticFixture(); f.record['role_objective'] = {'metric': 'repost_candidates', 'target': 5}; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_unbounded_or_spare_batch_quota_rejected(self):
        for key, value in [('max_actions', None), ('max_actions', -1), ('max_actions', True),
                ('max_actions', 1000000), ('max_actions', 6), ('scope', 'standing_role_quota'),
                ('per_kind_limits', {'repost': 6}), ('per_kind_limits', {'repost': True}),
                ('per_kind_limits', {'repost': None}), ('per_kind_limits', {'repost': 'unlimited'})]:
            f = SyntheticFixture(); f.record['batch_grant'][key] = value; f.repin()
            with self.subTest(key=key, value=value), self.assertRaises(GateBlocked): f.adapter()

    def test_denied_action_cannot_produce_allow(self):
        f = SyntheticFixture(); f.record['decisions'][0]['decision'] = 'deny'; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_empty_or_duplicate_decisions_rejected(self):
        for modify in [lambda r: r.update(decisions=[]),
                       lambda r: r['decisions'].__setitem__(1, copy.deepcopy(r['decisions'][0]))]:
            f = SyntheticFixture(); modify(f.record); f.repin()
            with self.assertRaises(GateBlocked): f.adapter()

    def test_action_and_batch_replay_rejected(self):
        f = SyntheticFixture(); a = f.adapter(); a.authorize_batch(f.job, f.actions)
        with self.assertRaises(GateBlocked): a.authorize_batch(f.job, f.actions)
        a.authorize(f.job, f.actions[0])
        with self.assertRaises(GateBlocked): a.authorize(f.job, f.actions[0])
        with self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, f.actions)

    def test_another_review_cannot_reopen_same_scheduled_run(self):
        f = SyntheticFixture(); f.adapter().authorize_batch(f.job, f.actions)
        f.record['decision_id'] = 'synthetic-second-review'; f.repin()
        with self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, f.actions)

    def test_action_without_batch_rejected(self):
        f = SyntheticFixture()
        with self.assertRaises(GateBlocked): f.adapter().authorize(f.job, f.actions[0])

    def test_concurrent_replays_allow_only_one_response(self):
        f = SyntheticFixture(); adapters = [f.adapter(), f.adapter()]; results = []
        def run(adapter):
            try: adapter.authorize_batch(f.job, f.actions); results.append('allowed')
            except GateBlocked: results.append('blocked')
        threads = [threading.Thread(target=run, args=(a,)) for a in adapters]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertCountEqual(results, ['allowed', 'blocked'])

    def test_wrong_action_payload_target_kind_and_authorization_reference(self):
        changes = [('target', 'https://www.threads.com/@synthetic_other/post/Wrong'),
            ('kind', 'like'), ('payload_hash', 'f' * 64), ('action_id', 'f' * 64),
            ('authorization_id', 'unreviewed-approval'), ('payload', {'target': 'https://example.com'})]
        for key, value in changes:
            f = SyntheticFixture(); a = f.adapter(); a.authorize_batch(f.job, f.actions)
            bad = dict(f.actions[0], **{key: value})
            with self.subTest(key=key), self.assertRaises(GateBlocked): a.authorize(f.job, bad)

    def test_action_list_reorder_or_insertion(self):
        for modify in [lambda a: list(reversed(a)), lambda a: a + [a[0]], lambda a: a[1:]]:
            f = SyntheticFixture()
            with self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, modify(f.actions))

    def test_mutating_callers_sources_does_not_change_adapter(self):
        f = SyntheticFixture(); a = f.adapter(); f.sources.clear()
        a.authorize_batch(f.job, f.actions)

    def test_payload_json_tampering_rejected_even_if_action_argument_unchanged(self):
        f = SyntheticFixture(); a = f.adapter(); body = json.loads(f.job['payload_json'])
        body['actions'][0]['payload']['extra'] = 'Synthetic changed bytes'
        job = dict(f.job, payload_json=canonical(body))
        with self.assertRaises(GateBlocked): a.authorize_batch(job, f.actions)

    def test_publisher_bundle_cannot_omit_continuations_or_image(self):
        for field in ['replies', 'image_sha256', 'root_image_path', 'preview_reply_index']:
            f = SyntheticFixture('publisher')
            # A changed proposal is not covered by the independently pinned review.
            f.actions[0]['payload'].pop(field)
            with self.subTest(field=field), self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, f.actions)

    def test_extra_fields_executable_instructions_and_credentials_rejected(self):
        for key in ['handler', 'code', 'password', 'access_token']:
            f = SyntheticFixture(); f.record[key] = 'synthetic-forbidden-value'; f.repin()
            with self.subTest(key=key), self.assertRaises(GateBlocked): f.adapter()

    def test_proposal_cannot_smuggle_executable_payload_fields(self):
        f = SyntheticFixture()
        body = json.loads(f.job['payload_json'])
        body['actions'][0]['payload']['handler'] = 'synthetic-forbidden-handler'
        f.job['payload_json'] = canonical(body)
        with self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, f.actions)

    def test_independently_specified_schedule_regression(self):
        expected = {'spreader': 0, 'publisher': 20 * 60, 'commenter': 40 * 60}
        self.assertEqual(ROLE_OFFSET, expected)
        for role, offset in expected.items():
            f = SyntheticFixture(role)
            self.assertEqual(f.context.scheduled_at % 3600, offset)
            for wrong in {0, 1200, 2400} - {offset}:
                context = replace(f.context, scheduled_at=360000 + wrong, next_same_role_at=363600 + wrong)
                with self.subTest(role=role, offset=wrong), self.assertRaises(GateBlocked): context.validate()

    def test_current_slot_schedule_has_no_cross_role_anchor(self):
        for role in ['publisher', 'spreader', 'commenter']:
            f = SyntheticFixture(role)
            wrong_start = f.start + 1200
            context = replace(f.context, scheduled_at=wrong_start, next_same_role_at=wrong_start + 3600)
            with self.subTest(role=role), self.assertRaises(GateBlocked):
                f.adapter(pin=replace(f.pin, context=context))

    def test_no_credential_source_field_or_secret_body(self):
        for update in [lambda d: d.update(password='synthetic-value'),
                       lambda d: d.update(origin_reference='Bearer synthetic-token')]:
            f = SyntheticFixture(); f.source_change('synthetic-observation-0', update)
            with self.assertRaises(GateBlocked): f.adapter()

    def test_nonfinite_duplicate_json_and_boolean_identity_rejected(self):
        f = SyntheticFixture(); f.raw = f.raw[:-1] + b',"schema":"duplicate"}'
        f.pin = replace(f.pin, review_sha256=digest(f.raw))
        with self.assertRaises(GateBlocked): f.adapter()
        f = SyntheticFixture(); f.raw = f.raw.replace(b'"max_actions":5', b'"max_actions":NaN')
        f.pin = replace(f.pin, review_sha256=digest(f.raw))
        with self.assertRaises(GateBlocked): f.adapter()
        f = SyntheticFixture(); f.record['job']['generation'] = True; f.repin()
        with self.assertRaises(GateBlocked): f.adapter()

    def test_consumed_action_recheck_exact_public_shape(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        result = a.recheck_consumed_action(f.job, f.actions[0])
        expected = {'schema', 'binding', 'slot', 'job_id', 'generation', 'batch_payload_hash',
            'actions_hash', 'authorization_id', 'action_id', 'kind', 'target', 'payload_hash',
            'policy_reference', 'policy_sha256', 'review_sha256', 'decision_id', 'checked_at',
            'review_expires_at', 'expires_at'}
        self.assertEqual(set(result), expected)
        self.assertEqual(result['schema'], 'consumed-authorization-recheck-v1')
        self.assertEqual(result['binding'], f.binding)
        self.assertEqual(result['slot'], f.slot)
        self.assertEqual(result['review_sha256'], f.pin.review_sha256)
        self.assertEqual(result['policy_sha256'], f.pin.policy_sha256)
        self.assertEqual(result['checked_at'], f.now)
        self.assertEqual(result['expires_at'], f.record['expires_at'])
        self.assertNotIn('authorized', result)
        self.assertNotIn('permit', result)
        self.assertNotIn('may_dispatch', result)

    def test_recheck_after_preflight_delay_rejects_revoked_policy(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        f.now += 20; f.current_policy = ('synthetic-revoked-policy', 'f' * 64)
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[0])

    def test_recheck_after_preflight_delay_rejects_expired_review(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        f.now = f.record['expires_at']
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[0])

    def test_recheck_rejects_unconsumed_batch_and_action(self):
        f = SyntheticFixture(); a = f.adapter()
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[0])
        a.authorize_batch(f.job, f.actions)
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[0])
        a.authorize(f.job, f.actions[0])
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[1])

    def test_repeated_rechecks_do_not_consume_or_mint_permission(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        first = a.recheck_consumed_action(f.job, f.actions[0])
        for _ in range(5): self.assertEqual(a.recheck_consumed_action(f.job, f.actions[0]), first)
        # No fresh grant for the consumed action or batch is created.
        with self.assertRaises(GateBlocked): a.authorize(f.job, f.actions[0])
        with self.assertRaises(GateBlocked): a.authorize_batch(f.job, f.actions)
        # Rechecking does not spend an unrelated action's independently reviewed grant.
        a.authorize(f.job, f.actions[1])
        with self.assertRaises(GateBlocked): a.authorize(f.job, f.actions[1])

    def test_recheck_exact_action_and_identity_remain_bound(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        for job in [dict(f.job, tab_id='other-tab'), dict(f.job, next_same_role_at=f.start + 7200),
                    dict(f.job, payload_hash='f' * 64)]:
            with self.assertRaises(GateBlocked): a.recheck_consumed_action(job, f.actions[0])
        for action in [dict(f.actions[0], kind='like'), dict(f.actions[0], payload_hash='f' * 64),
                       dict(f.actions[0], authorization_id='other-grant')]:
            with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, action)

    def test_mutating_recheck_snapshot_does_not_change_grant(self):
        f = SyntheticFixture(); a = f.adapter()
        a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        result = a.recheck_consumed_action(f.job, f.actions[0])
        result['binding']['tab_id'] = 'other-tab'; result['slot']['next_same_role_at'] += 1000
        result['expires_at'] += 1000
        fresh = a.recheck_consumed_action(f.job, f.actions[0])
        self.assertEqual(fresh['binding'], f.binding)
        self.assertEqual(fresh['slot'], f.slot)
        self.assertEqual(fresh['expires_at'], f.record['expires_at'])

    def test_recheck_effective_expiry_covers_older_conditional_evidence(self):
        f = SyntheticFixture()
        # Review occurs late enough that one still-fresh observation will expire
        # before the review's own deadline. Every datum remains in the same slot.
        f.now = f.start + 290
        f.record['issued_at'] = f.now; f.record['expires_at'] = f.now + 120
        for d in f.record['decisions']: d['reviewed_at'] = f.now
        for ref in list(f.sources):
            if ref != 'synthetic-observation-0':
                doc = json.loads(f.sources[ref]); doc['recorded_at'] = f.now; f.sources[ref] = encoded(doc)
        f.record['policy']['sha256'] = digest(f.sources['synthetic-policy'])
        f.current_policy = (f.policy_reference, f.record['policy']['sha256']); f.repin()
        a = f.adapter(); a.authorize_batch(f.job, f.actions); a.authorize(f.job, f.actions[0])
        result = a.recheck_consumed_action(f.job, f.actions[0])
        self.assertEqual(result['expires_at'], f.start + 20 + 300 + 1)
        self.assertLess(result['expires_at'], result['review_expires_at'])
        f.now = result['expires_at']
        with self.assertRaises(GateBlocked): a.recheck_consumed_action(f.job, f.actions[0])

    @staticmethod
    def _prepare_timed_operation(operation, *, policy_effect=None):
        f = SyntheticFixture(); armed = [False]
        def policy():
            if armed[0] and policy_effect is not None: policy_effect(f)
            return f.current_policy
        a = f.adapter(current_policy=policy)
        if operation != 'batch': a.authorize_batch(f.job, f.actions)
        if operation == 'recheck': a.authorize(f.job, f.actions[0])
        calls = {'batch': lambda: a.authorize_batch(f.job, f.actions),
                 'action': lambda: a.authorize(f.job, f.actions[0]),
                 'recheck': lambda: a.recheck_consumed_action(f.job, f.actions[0])}
        return f, a, armed, calls[operation]

    def _assert_callback_expiry(self, operation):
        f, a, armed, call = self._prepare_timed_operation(operation,
            policy_effect=lambda fixture: setattr(fixture, 'now', fixture.now + 2))
        f.now = f.record['expires_at'] - 1; armed[0] = True
        with self.assertRaises(GateBlocked): call()
        self.assertGreaterEqual(f.now, f.record['expires_at'])
        if operation == 'batch': self.assertFalse(a._batch_used)
        elif operation == 'action': self.assertNotIn(f.actions[0]['authorization_id'], a._used_actions)

    def test_batch_callback_cannot_return_success_after_expiry(self):
        self._assert_callback_expiry('batch')

    def test_action_callback_cannot_return_success_after_expiry(self):
        self._assert_callback_expiry('action')

    def test_recheck_callback_cannot_return_stale_snapshot_after_expiry(self):
        self._assert_callback_expiry('recheck')

    def test_callback_clock_rollback_inside_valid_slot_blocks_all_operations(self):
        for operation in ['batch', 'action', 'recheck']:
            f, a, armed, call = self._prepare_timed_operation(operation,
                policy_effect=lambda fixture: setattr(fixture, 'now', fixture.now - 1))
            f.now += 10; armed[0] = True
            with self.subTest(operation=operation), self.assertRaises(GateBlocked): call()
            self.assertGreater(f.now, f.record['issued_at'])

    def test_constructor_policy_delay_cannot_accept_expired_review(self):
        f = SyntheticFixture(); f.now = f.record['expires_at'] - 1
        def slow_policy():
            f.now += 2
            return f.current_policy
        with self.assertRaises(GateBlocked): f.adapter(current_policy=slow_policy)

    def test_slow_manifest_validation_blocks_before_consume_or_recheck_return(self):
        for operation in ['batch', 'action', 'recheck']:
            f, a, armed, call = self._prepare_timed_operation(operation)
            original = a._job_actions
            def delayed(*args, **kwargs):
                result = original(*args, **kwargs)
                f.now += 2
                return result
            f.now = f.record['expires_at'] - 1
            with patch.object(a, '_job_actions', delayed):
                with self.subTest(operation=operation), self.assertRaises(GateBlocked): call()
            if operation == 'batch': self.assertFalse(a._batch_used)
            elif operation == 'action': self.assertNotIn(f.actions[0]['authorization_id'], a._used_actions)

    def test_slow_response_serialization_blocks_before_consumption(self):
        import role_authorization as module
        for operation in ['batch', 'action']:
            f, a, armed, call = self._prepare_timed_operation(operation)
            original = module.canonical
            def slow_success(value):
                result = original(value)
                if type(value) is dict and value.get('ok') is True and value.get('authorized') is True:
                    f.now += 2
                return result
            f.now = f.record['expires_at'] - 1
            with patch.object(module, 'canonical', slow_success):
                with self.subTest(operation=operation), self.assertRaises(GateBlocked): call()
            if operation == 'batch': self.assertFalse(a._batch_used)
            else: self.assertNotIn(f.actions[0]['authorization_id'], a._used_actions)

    def test_replay_store_delay_fails_closed_and_preserves_consumed_batch(self):
        f, a, armed, call = self._prepare_timed_operation('batch')
        original = f.replay.consume_batch
        def delayed(*args):
            original(*args)
            f.now += 2
        f.now = f.record['expires_at'] - 1
        with patch.object(f.replay, 'consume_batch', delayed):
            with self.assertRaises(GateBlocked): call()
        self.assertTrue(a._batch_used)
        # Even a new review ID/digest cannot reopen the already consumed run.
        f.now -= 2
        with self.assertRaises(GateBlocked): call()
        f.record['decision_id'] = 'synthetic-new-review-after-lost-result'; f.repin()
        with self.assertRaises(GateBlocked): f.adapter().authorize_batch(f.job, f.actions)

    def test_action_consumption_delay_fails_closed_and_keeps_consumed_mark(self):
        f, a, armed, call = self._prepare_timed_operation('action')
        class DelayedSet(set):
            def add(self, item):
                super().add(item)
                f.now += 2
        a._used_actions = DelayedSet(a._used_actions)
        f.now = f.record['expires_at'] - 1
        with self.assertRaises(GateBlocked): call()
        self.assertIn(f.actions[0]['authorization_id'], a._used_actions)
        f.now -= 2
        with self.assertRaises(GateBlocked): call()

    def test_final_clock_boundary_after_runtime_check_blocks_all_returns(self):
        for operation in ['batch', 'action', 'recheck']:
            f, a, armed, call = self._prepare_timed_operation(operation)
            original = a._runtime_check; checks = [0]
            def delayed_second_check():
                now = original(); checks[0] += 1
                if checks[0] == 2: f.now += 2
                return now
            f.now = f.record['expires_at'] - 1
            with patch.object(a, '_runtime_check', delayed_second_check):
                with self.subTest(operation=operation), self.assertRaises(GateBlocked): call()

    def test_recheck_timestamp_is_sampled_after_successful_callback_delay(self):
        f, a, armed, call = self._prepare_timed_operation('recheck',
            policy_effect=lambda fixture: setattr(fixture, 'now', fixture.now + 2))
        original_expiry = f.record['expires_at']; armed[0] = True
        before = f.now; result = call()
        self.assertGreater(f.now, before)
        self.assertEqual(result['checked_at'], f.now)
        self.assertEqual(result['review_expires_at'], original_expiry)
        self.assertEqual(result['expires_at'], original_expiry)

    def test_elapsed_validation_rechecks_current_policy_before_return(self):
        for operation in ['batch', 'action', 'recheck']:
            f, a, armed, call = self._prepare_timed_operation(operation)
            original = a._job_actions
            def revoked(*args, **kwargs):
                result = original(*args, **kwargs)
                f.current_policy = ('synthetic-policy-revoked-during-validation', 'd' * 64)
                return result
            with patch.object(a, '_job_actions', revoked):
                with self.subTest(operation=operation), self.assertRaises(GateBlocked): call()

    def test_clock_rollback_between_calls_cannot_revive_review(self):
        f, a, armed, call = self._prepare_timed_operation('recheck')
        f.now += 10; call(); f.now -= 1
        with self.assertRaises(GateBlocked): call()
        f.now = f.record['expires_at']
        with self.assertRaises(GateBlocked): call()
        f.now -= 1
        with self.assertRaises(GateBlocked): call()


if __name__ == '__main__': unittest.main()
