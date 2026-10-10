"""Real frozen queue/gates with synthetic adapters; no production operations."""
import copy
from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
from integration_paths import SOURCE_ROOT as CORE
import queue_core
from coordinator import SerialCoordinator
from dispatch_gate import GateBlocked, LedgerIdentity, action_id, canonical, payload_hash
from queue_core import Binding, QueueCore, Schedule, initialize_staging, ConflictError
import test_coordinator as core_tests
from test_coordinator import FakeAuthorization, FakeBrowser, FakeLedger
from goal_coordinator import (CandidatePlan, FROZEN_COORDINATOR_SHA256, GoalCoordinator,
                              NativeRepostPlanner, validated_objective)


def raw(n, kind='repost', *, target=None):
    target = target or (f'https://blog.example/{n+1}' if kind == 'publish' else
        f'https://threads.com/@synthetic_person/post/Candidate{n}')
    p = {'target': target}
    if kind == 'reply': p['text'] = f'Synthetic reviewed reply {n}'
    return {'kind': kind, 'target': target, 'payload': p, 'authorization_id': f'synthetic-{kind}-{n}'}


class GoalAuthorization(FakeAuthorization):
    def __init__(self, *, baseline=0):
        self.baseline = baseline
        self.calls = []
        self.batch_changes = None
        self.changes = None

    def authorize_batch(self, job, actions):
        role = job['role']
        obj = None if role == 'commenter' else {
            'kind': 'repost' if role == 'spreader' else 'publish',
            'newly_verified_goal': 5 if role == 'spreader' else 1,
            'already_newly_verified': self.baseline}
        kinds = {'spreader': ['repost', 'like', 'reply', 'follow'],
                 'publisher': ['publish'], 'commenter': ['reply']}[role]
        changes = self.batch_changes
        self.batch_changes = {'objective': obj, 'allowed_kinds': kinds,
            'max_actions': 100, 'per_kind_limits': {k: 100 for k in kinds}, **(changes or {})}
        result = super().authorize_batch(job, actions)
        self.batch_changes = changes
        return result

    def authorize(self, job, action):
        self.calls.append(action['action_id'])
        return super().authorize(job, action)


class Harness:
    def __init__(self, root, *, baseline=0, cls=GoalCoordinator, now=100, account='example.bot', plan=None):
        self.root = Path(root); self.now = now; self.clock = lambda: self.now
        self.ledger = FakeLedger(self.clock)
        self.ledger.identity = LedgerIdentity(account, 'a' * 32)
        self.browser = FakeBrowser(root, self.clock)
        self.authorization = GoalAuthorization(baseline=baseline)
        self.bindings = {r: Binding('worker-' + r, 'synthetic-cloud', 'tab-' + r, account)
                         for r in ('publisher', 'spreader', 'commenter')}
        self.identity = initialize_staging(self.root/'queue.sqlite', self.bindings,
            {r: Schedule(0, 1000) for r in self.bindings}, ledger_db_id=self.ledger.identity.db_id)
        self.queue = QueueCore(self.root/'queue.sqlite', self.identity)
        kwargs = {'plan': plan} if cls is GoalCoordinator else {}
        self.coordinator = cls(self.queue, self.ledger.identity, clock=self.clock,
            ledger=self.ledger, browser=self.browser, authorization=self.authorization, **kwargs)

    def prepare(self, actions, role='spreader'):
        b = self.bindings[role]
        self.evidence = self.queue.record_observation(role, worker_id=b.worker_id, browser_id=b.browser_id,
            tab_id=b.tab_id, observed_account=b.expected_account, tab_exists=True,
            observed_at=self.now, now=self.now)
        start = self.now // 1000 * 1000
        self.job = self.queue.enqueue(role, start, start+1000, evidence_id=self.evidence, now=self.now)
        self.queue.mark_ready(self.job['job_id'], {'actions': actions}, evidence_id=self.evidence, now=self.now)
        self.job = self.queue.inspect_job(self.job['job_id'])
        return self.job

    def progress(self):
        return self.queue.list_action_progress(self.coordinator._run.claim)

    def seed_duplicate(self, action, state='verified'):
        key = action_id(self.ledger.identity.account, action['kind'], action['target'])
        self.ledger.actions[key] = {'id': key, 'account': self.ledger.identity.account,
            'kind': action['kind'], 'target_url': action['target'], 'payload_hash': payload_hash(action['payload']),
            'state': state, 'intent_id': 'e'*64 if state == 'verified' else None}

    def pair(self):
        # Reuse frozen synthetic checkpoint fixture, with this harness's exact state.
        return core_tests.CoordinatorTests.pair(self)


class GoalCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='goal-tests-', dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.staging_patch = patch.object(queue_core, 'STAGING_ROOT', self.root)
        self.staging_patch.start(); self.addCleanup(self.staging_patch.stop)
        self.count = 0

    def h(self, **kwargs):
        self.count += 1; root = self.root/str(self.count); root.mkdir()
        return Harness(root, **kwargs)

    def safe_boundary(self, h):
        self.assertEqual(h.ledger.calls.count('acquire'), 1)
        self.assertEqual(h.ledger.calls.count('release'), 1)
        self.assertTrue(h.ledger.pending)
        self.assertEqual(h.queue.inspect_job(h.job['job_id'])['state'], 'checkpoint_wait')
        self.assertEqual(h.coordinator.run_once().state, 'needs_checkpoint')
        self.assertEqual(h.ledger.calls.count('acquire'), 1)

    def test_five_new_cancels_unstarted_reserves_before_authorization_and_claim(self):
        h = self.h(); actions = [raw(i) for i in range(8)]; h.prepare(actions)
        result = h.coordinator.run_once()
        self.assertEqual(result.state, 'needs_checkpoint')
        self.assertEqual(len(h.browser.mutations), 5)
        self.assertEqual(len(h.authorization.calls), 5)
        self.assertEqual(h.ledger.calls.count('claim'), 5)
        cancelled = [r for r in h.progress() if r['state'] == 'cancelled']
        self.assertEqual(len(cancelled), 3)
        self.assertTrue(all(json.loads(r['result_json']) == {'reason': 'goal_reached'} for r in cancelled))
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_total, 5)
        self.assertTrue(h.coordinator.last_goal_report.goal_reached)
        self.assertEqual(len(h.progress()), 8)
        self.safe_boundary(h)

    def test_ledger_duplicate_and_existing_repost_use_next_pre_reviewed_reserves(self):
        h = self.h(); actions = [raw(i) for i in range(8)]; h.prepare(actions)
        h.seed_duplicate(actions[0])
        base = h.browser.preflight
        def preflight(action, binding):
            h.browser.preflight_outcome = 'present' if action['target'] == actions[1]['target'] else 'absent'
            return base(action, binding)
        h.browser.preflight = preflight
        self.assertEqual(h.coordinator.run_once().state, 'needs_checkpoint')
        report = h.coordinator.last_goal_report
        self.assertEqual((report.newly_verified_this_batch, report.duplicate_candidates,
                          report.already_present_candidates, report.cancelled_candidates), (5, 1, 1, 1))
        self.assertEqual(len(h.browser.mutations), 5)
        self.assertEqual(h.ledger.calls.count('claim'), 7)
        self.safe_boundary(h)

    def test_existing_ledger_verified_never_counts_as_current_run_success(self):
        h = self.h(); actions = [raw(i) for i in range(5)]; h.prepare(actions)
        for a in actions: h.seed_duplicate(a)
        result = h.coordinator.run_once()
        self.assertEqual(result.state, 'needs_checkpoint')
        self.assertEqual(len(h.browser.mutations), 0)
        self.assertEqual(h.coordinator.last_goal_report.goal_shortfall, 5)
        self.assertIn('goal shortfall 5', result.reason)
        self.safe_boundary(h)

    def test_exact_independent_baseline_counts_only_remaining_new_actions(self):
        h = self.h(baseline=3); h.prepare([raw(i) for i in range(7)])
        h.coordinator.run_once()
        r = h.coordinator.last_goal_report
        self.assertEqual((r.already_newly_verified, r.newly_verified_this_batch, r.newly_verified_total), (3, 2, 5))
        self.assertEqual(len(h.browser.mutations), 2)
        self.safe_boundary(h)

    def test_goal_already_reached_cancels_all_reposts(self):
        h = self.h(baseline=5); h.prepare([raw(0), raw(1)])
        h.coordinator.run_once()
        self.assertEqual(h.browser.mutation_records, [])
        self.assertEqual(h.ledger.calls.count('claim'), 0)
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_this_batch, 0)
        self.safe_boundary(h)

    def test_non_repost_actions_do_not_count_toward_goal(self):
        p=NativeRepostPlanner('example.bot',0,1000,reserve_target=2)
        for i in range(7):
            p.review(raw(i),review_reference=f'r-{i}',qualified=True,
                     related_actions=[raw(30,'like'),raw(31,'reply')] if i==0 else [])
        plan=p.freeze();h=self.h(plan=plan);h.prepare(plan.prepared_payload()['actions'])
        h.coordinator.run_once()
        self.assertEqual(len(h.browser.mutations), 7)
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_total, 5)
        self.safe_boundary(h)

    def test_reserve_group_reply_and_like_cancel_before_authorize_or_claim(self):
        p=NativeRepostPlanner('example.bot',0,1000,reserve_target=1)
        for i in range(6):
            p.review(raw(i),review_reference=f'r-{i}',qualified=True,
                     related_actions=[raw(i,'reply'),raw(i,'like')])
        plan=p.freeze();h=self.h(plan=plan);h.prepare(plan.prepared_payload()['actions'])
        h.coordinator.run_once()
        self.assertEqual(len(h.browser.mutations),15)
        self.assertEqual(len(h.authorization.calls),15)
        self.assertEqual(h.ledger.calls.count('claim'),15)
        byid={r['action_id']:r for r in h.progress()}
        for kind in ('reply','like'):
            key=action_id(h.ledger.identity.account,kind,raw(5,kind)['target'])
            self.assertEqual(byid[key]['state'],'cancelled')
            self.assertEqual(json.loads(byid[key]['result_json'])['reason'],'goal_reached_group')
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_total,5)
        self.safe_boundary(h)

    def test_ungrouped_spreader_conditionals_fail_before_batch_review_or_acquire(self):
        h=self.h();h.prepare([raw(0),raw(1,'reply')])
        self.assertEqual(h.coordinator.run_once().state,'blocked')
        self.assertNotIn('acquire',h.ledger.calls)
        self.assertEqual(h.browser.mutations,[])

    def test_shortfall_remains_explicit_even_after_checkpoint_done(self):
        h = self.h(); h.prepare([raw(1), raw(2)])
        first = h.coordinator.run_once()
        self.assertIn('goal shortfall 3', first.reason)
        done = h.coordinator.complete_checkpoint(**h.pair())
        self.assertEqual(done.state, 'done')
        self.assertIn('goal shortfall 3', done.reason)
        self.assertFalse(h.coordinator.last_goal_report.goal_reached)
        self.assertEqual(h.coordinator.last_goal_report.coordination_state, 'done')

    def test_goal_validation_rejects_missing_arbitrary_boolean_negative_or_oversized(self):
        bad = [None, {}, {'kind':'like','newly_verified_goal':5,'already_newly_verified':0},
            {'kind':'repost','newly_verified_goal':4,'already_newly_verified':0},
            {'kind':'repost','newly_verified_goal':5,'already_newly_verified':True},
            {'kind':'repost','newly_verified_goal':5,'already_newly_verified':-1},
            {'kind':'repost','newly_verified_goal':5,'already_newly_verified':6},
            {'kind':'repost','newly_verified_goal':5,'already_newly_verified':0,'extra':True}]
        for obj in bad:
            with self.subTest(objective=obj):
                h = self.h(); h.prepare([raw(1)])
                h.authorization.batch_changes = {'objective':obj}
                self.assertEqual(h.coordinator.run_once().state, 'blocked')
                self.assertNotIn('acquire', h.ledger.calls)
        with self.assertRaises(GateBlocked): validated_objective({}, 'spreader')
        with self.assertRaises(GateBlocked): validated_objective({}, 'publisher')

    def test_publisher_goal_is_one_and_commenter_has_no_numeric_goal(self):
        h = self.h(); h.prepare([raw(1,'publish'),raw(2,'publish')], 'publisher')
        h.coordinator.run_once()
        self.assertEqual(len(h.browser.mutations), 1)
        self.assertEqual(h.coordinator.last_goal_report.goal, 1)
        other = self.h(); other.prepare([raw(1,'reply'),raw(2,'reply')], 'commenter')
        other.coordinator.run_once()
        self.assertEqual(len(other.browser.mutations), 2)
        self.assertIsNone(other.coordinator.last_goal_report)

    def test_deadline_after_mutation_still_reads_back_then_cancels_rest(self):
        h = self.h(); h.prepare([raw(i) for i in range(7)])
        h.browser.after_mutate = lambda: setattr(h, 'now', 1000)
        self.assertEqual(h.coordinator.run_once().state, 'needs_checkpoint')
        self.assertEqual(len(h.browser.mutations), 1)
        self.assertEqual(h.browser.calls.count('readback'), 1)
        self.assertEqual(h.coordinator.last_goal_report.goal_shortfall, 4)
        self.assertEqual(len(h.progress()), 7)
        self.safe_boundary(h)

    def test_expiry_between_preflight_and_intent_cancels_reservation(self):
        h = self.h(now=990); h.prepare([raw(i) for i in range(7)])
        h.browser.after_preflight = lambda: setattr(h, 'now', 1000)
        self.assertEqual(h.coordinator.run_once().state, 'needs_checkpoint')
        self.assertEqual(h.ledger.calls.count('cancel'), 1)
        self.assertNotIn('begin-write', h.ledger.calls)
        self.assertEqual(h.coordinator.last_goal_report.goal_shortfall, 5)
        self.safe_boundary(h)

    def test_reviewer_denial_holds_writer_and_never_uses_reserve(self):
        h = self.h(); h.prepare([raw(i) for i in range(7)]); h.browser.outcome = 'denied'
        self.assertEqual(h.coordinator.run_once().state, 'blocked')
        self.assertEqual(len(h.browser.mutations), 1)
        self.assertEqual(h.ledger.calls.count('acquire'), 1)
        self.assertNotIn('release', h.ledger.calls)
        self.assertEqual(h.progress()[0]['state'], 'denied_unresolved')
        self.assertEqual(h.coordinator.last_goal_report.goal_shortfall, 5)
        h.coordinator.run_once(); self.assertEqual(len(h.browser.mutations), 1)

    def test_stop_mid_batch_blocks_without_release_or_more_mutation(self):
        h = self.h(); h.prepare([raw(i) for i in range(7)])
        base = h.browser.readback
        def readback(*args):
            result = base(*args); h.ledger.stops.append({'reason':'synthetic STOP'}); return result
        h.browser.readback = readback
        self.assertEqual(h.coordinator.run_once().state, 'blocked')
        self.assertEqual(len(h.browser.mutations), 1)
        self.assertEqual(h.ledger.calls.count('acquire'), 1)
        self.assertNotIn('release', h.ledger.calls)
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_this_batch, 1)

    def test_bad_readback_cannot_increment_goal(self):
        h = self.h(); h.prepare([raw(i) for i in range(7)])
        h.browser.readback_changes = {'intent_id':'f'*64}
        self.assertEqual(h.coordinator.run_once().state, 'blocked')
        self.assertEqual(h.coordinator.last_goal_report.newly_verified_this_batch, 0)
        self.assertNotIn('release',h.ledger.calls)

    def test_checkpoint_pending_prevents_new_batch_acquisition(self):
        h = self.h(); h.prepare([raw(i) for i in range(7)]); h.coordinator.run_once()
        other = GoalCoordinator(h.queue,h.ledger.identity,clock=h.clock,ledger=h.ledger,
            browser=h.browser,authorization=h.authorization)
        self.assertEqual(other.run_once().state,'wait')
        self.assertEqual(h.ledger.calls.count('acquire'),1)

    def test_no_post_freeze_or_same_slot_supplementation(self):
        h = self.h(); h.prepare([raw(1)])
        same = h.queue.enqueue('spreader',0,1000,evidence_id=h.evidence,now=h.now)
        self.assertEqual(same['job_id'],h.job['job_id'])
        with self.assertRaises(ConflictError):
            h.queue.mark_ready(h.job['job_id'],{'actions':[raw(1),raw(2)]},evidence_id=h.evidence,now=h.now)

    def test_plan_binds_exact_payload_slot_and_authorized_baseline(self):
        planner=NativeRepostPlanner('example.bot',0,1000,reserve_target=1)
        for i in range(6): planner.review(raw(i),review_reference=f'review-{i}',qualified=True)
        plan=planner.freeze(); h=self.h(plan=plan); h.prepare(plan.prepared_payload()['actions'])
        self.assertEqual(h.coordinator.run_once().state,'needs_checkpoint')
        self.assertEqual(h.coordinator.last_goal_report.plan_id,plan.plan_id)
        wrong=self.h(plan=plan); wrong.prepare([raw(i+20) for i in range(6)])
        self.assertEqual(wrong.coordinator.run_once().state,'blocked')
        self.assertNotIn('acquire',wrong.ledger.calls)

    def test_frozen_source_pin_matches(self):
        self.assertEqual(hashlib.sha256((CORE/'coordinator.py').read_bytes()).hexdigest(),FROZEN_COORDINATOR_SHA256)

    def test_differential_unchanged_flows_equal_frozen_core(self):
        for scenario in ('normal','duplicate','present','denial','expiry','stop','readback_mismatch'):
            outputs=[]
            for cls in (SerialCoordinator,GoalCoordinator):
                h=self.h(cls=cls); actions=[raw(i) for i in range(5)];h.prepare(actions)
                if scenario=='duplicate':h.seed_duplicate(actions[0])
                elif scenario=='present':h.browser.preflight_outcome='present'
                elif scenario=='denial':h.browser.outcome='denied'
                elif scenario=='expiry':h.browser.after_mutate=lambda h=h:setattr(h,'now',1000)
                elif scenario=='stop':h.ledger.stops=[{'reason':'synthetic STOP'}]
                elif scenario=='readback_mismatch':h.browser.readback_changes={'intent_id':'f'*64}
                r=h.coordinator.run_once()
                progress=[] if h.coordinator._run is None else sorted(
                    (p['action_id'],p['state'],p['result_json']) for p in h.progress())
                outputs.append((r.state,h.ledger.calls,h.browser.calls,h.browser.mutations,progress,
                                h.ledger.writer,h.ledger.pending,h.ledger.seq))
            with self.subTest(scenario=scenario):self.assertEqual(outputs[0],outputs[1])

    def test_exact_role_authorization_integrates_with_reserve_stop(self):
        from test_role_authorization import SyntheticFixture
        f=SyntheticFixture(kinds=['repost']*8)
        h=self.h(now=f.now,account=f.binding['account'])
        # The test independently pins actual queue identity, exact hourly slot,
        # manifest and source bytes in a synthetic reviewed authorization.
        self.assertEqual(f.slot['scheduled_at'] % 3600,0)
        root=h.root/'exact';root.mkdir()
        bindings={r:Binding('exact-'+r,'exact-browser','exact-tab-'+r,f.binding['account']) for r in h.bindings}
        identity=initialize_staging(root/'q.sqlite',bindings,
            {r:Schedule(f.start,3600) for r in bindings},ledger_db_id=h.ledger.identity.db_id)
        q=QueueCore(root/'q.sqlite',identity);b=bindings['spreader']
        ev=q.record_observation('spreader',worker_id=b.worker_id,browser_id=b.browser_id,tab_id=b.tab_id,
            observed_account=b.expected_account,tab_exists=True,observed_at=f.now,now=f.now)
        j=q.enqueue('spreader',f.start,f.start+3600,evidence_id=ev,now=f.now)
        j=q.mark_ready(j['job_id'],f.body,evidence_id=ev,now=f.now)
        f.binding={'role':'spreader','worker_id':b.worker_id,'browser_id':b.browser_id,'tab_id':b.tab_id,'account':b.expected_account}
        f.context=replace(f.context,**f.binding,job_id=j['job_id'],generation=j['generation'])
        f.record['binding']=f.binding.copy();f.record['job']['job_id']=j['job_id']
        for ref,data in list(f.sources.items()):
            doc=json.loads(data);doc['binding']=f.binding.copy();f.sources[ref]=canonical(doc).encode()
        f.record['policy']['sha256']=hashlib.sha256(f.sources['synthetic-policy']).hexdigest()
        f.current_policy=(f.policy_reference,f.record['policy']['sha256']);f.repin()
        c=GoalCoordinator(q,h.ledger.identity,clock=lambda:f.now,ledger=h.ledger,browser=h.browser,authorization=f.adapter())
        self.assertEqual(c.run_once().state,'needs_checkpoint')
        self.assertEqual(len(h.browser.mutations),5)
        self.assertEqual(c.last_goal_report.cancelled_candidates,3)


class PlannerTests(unittest.TestCase):
    def planner(self,**kwargs):return NativeRepostPlanner('synthetic_account',0,3600,**kwargs)

    def test_keeps_reviewing_past_unqualified_existing_and_duplicates(self):
        p=self.planner(reserve_target=2)
        p.review(raw(0),review_reference='r-0',qualified=False)
        p.review(raw(1),review_reference='r-1',qualified=True,already_present=True)
        p.review(raw(2),review_reference='r-2',qualified=True,ledger_duplicate=True)
        for i in range(3,10):p.review(raw(i),review_reference=f'r-{i}',qualified=True)
        self.assertFalse(p.needs_more_reviews)
        plan=p.freeze();self.assertEqual(plan.selected_reposts,7);self.assertEqual(plan.reserve_count,2)
        self.assertEqual(plan.summary()['reviewed_candidates'],10)
        self.assertEqual(len(plan.prepared_payload()['actions']),7)

    def test_insufficient_supply_reports_exact_shortfall_and_requires_explicit_partial(self):
        p=self.planner();p.review(raw(1),review_reference='r-1',qualified=True)
        with self.assertRaises(GateBlocked):p.freeze()
        plan=p.freeze(source_exhausted=True)
        self.assertEqual(plan.goal_shortfall,4)
        self.assertEqual(plan.summary()['status'],'insufficient_reviewed_supply')
        with self.assertRaises(GateBlocked):plan.prepared_payload()
        self.assertEqual(len(plan.prepared_payload(allow_shortfall=True)['actions']),1)

    def test_unique_reply_per_canonical_target_across_groups_and_aliases(self):
        p=self.planner(reserve_target=0)
        reply=raw(99,'reply');alias=raw(100,'reply',target=reply['target'].replace('threads.com','www.threads.net')+'/')
        p.review(raw(1),review_reference='r-1',qualified=True,related_actions=[reply])
        p.review(raw(2),review_reference='r-2',qualified=True,related_actions=[alias])
        for i in range(3,6):p.review(raw(i),review_reference=f'r-{i}',qualified=True)
        plan=p.freeze();actions=plan.prepared_payload()['actions']
        self.assertEqual(sum(a['kind']=='reply' for a in actions),1)
        self.assertEqual(len(json.loads(plan.groups_json)),5)
        self.assertEqual(json.loads(plan.observations_json)[1]['skipped_related'][0]['reason'],'duplicate_canonical_action')

    def test_duplicate_candidate_does_not_readd_its_conditional_reply(self):
        p=self.planner(reserve_target=0)
        p.review(raw(1),review_reference='r-1',qualified=True,related_actions=[raw(1,'reply')])
        self.assertFalse(p.review(raw(1),review_reference='r-2',qualified=True,related_actions=[raw(2,'reply')]))
        plan=p.freeze(source_exhausted=True)
        self.assertEqual(plan.selected_reposts,1)
        self.assertEqual(len(plan.prepared_payload(allow_shortfall=True)['actions']),2)

    def test_plan_is_detached_immutable_and_tamper_evident(self):
        p=self.planner(reserve_target=0);a=raw(1)
        p.review(a,review_reference='r-1',qualified=True);a['target']='https://invalid.example/'
        plan=p.freeze(source_exhausted=True)
        copy_payload=plan.prepared_payload(allow_shortfall=True);copy_payload['actions'].clear()
        self.assertEqual(plan.selected_reposts,1)
        with self.assertRaises(GateBlocked):replace(plan,already_newly_verified=4).validate()
        with self.assertRaises(GateBlocked):p.review(raw(2),review_reference='r-2',qualified=True)

    def test_action_limit_does_not_become_goal_or_permission(self):
        p=self.planner(reserve_target=95)
        for i in range(100):p.review(raw(i),review_reference=f'r-{i}',qualified=True)
        plan=p.freeze()
        self.assertEqual(plan.required_new,5);self.assertEqual(plan.selected_reposts,100)
        self.assertFalse(p.needs_more_reviews)

    def test_zero_remaining_goal_requires_no_extra_candidate_reviews(self):
        p=self.planner(already_newly_verified=5)
        self.assertFalse(p.needs_more_reviews)
        self.assertEqual(p.freeze().selected_reposts,0)


if __name__=='__main__':unittest.main()
