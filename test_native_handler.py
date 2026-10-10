import copy
import tempfile
import unittest
from pathlib import Path

from dispatch_gate import GateBlocked, action_id, payload_hash, successful
from native_handler import (NativeReadHandler, READ_CAPABILITIES, SyntheticMutationContract,
                            validate_prepared_action)
from tool_bridge import FileToolBridge, BindingPin, SlotContext, SyntheticTestCapability, INTEGRATION_ROOT
import test_publisher_safety as publisher_tests


class NativeHandlerTests(unittest.TestCase):
    def setUp(self):
        INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT);self.addCleanup(self.tmp.cleanup)
        self.now=1000;self.cap=SyntheticTestCapability.for_tests_only()
        self.bridge=FileToolBridge(Path(self.tmp.name)/'bridge',synthetic_capability=self.cap,clock=lambda:self.now)
        self.addCleanup(self.bridge.close)
        self.pin=BindingPin('spreader','worker-spreader','browser-1','tab-1','synthetic_account')
        self.context=SlotContext(self.pin,900,1500,'synthetic-policy')
        self.action={'kind':'repost','target':'https://threads.com/@synthetic_other/post/abc',
                     'authorization_id':'synthetic-policy'}
        self.action['payload']={'target':self.action['target']}
        self.action['payload_hash']=payload_hash(self.action['payload'])
        self.action['action_id']=action_id(self.pin.account,'repost',self.action['target'])

    def observation(self,pin=None):
        return {**(pin or self.pin).as_dict(),'exists':True,'logged_in':True,'observed_at':self.now}

    def spec(self,action=None,pin=None):
        pin=pin or self.pin;action=action or self.action
        ctx=SlotContext(pin,900,1500,'synthetic-policy')
        t=self.bridge.submit('mutate',ctx,action=action,intent_id='a'*64)
        c=self.bridge.claim(t,pin)
        return self.bridge.begin_dispatch(c,self.observation(pin))

    def check(self,action=None,pin=None):
        action=action or self.action;pin=pin or self.pin
        return {'schema':'consumed-authorization-recheck-v1','binding':pin.as_dict(),
                'slot':{'scheduled_at':900,'next_same_role_at':1500},'review_sha256':'f'*64,
                **{k:action[k] for k in ('authorization_id','action_id','kind','target','payload_hash')},
                'checked_at':self.now,'expires_at':1500}

    def contract(self):
        return SyntheticMutationContract(self.spec(),self.pin,synthetic_capability=self.cap,clock=lambda:self.now,
            authorization_recheck=lambda:self.check(),review_sha256='f'*64)

    def test_read_handler_services_observe_once(self):
        outer=self
        class Port:
            capabilities=READ_CAPABILITIES
            def observe(self,binding):return outer.observation()
        t=self.bridge.submit('observe',self.context)
        handler=NativeReadHandler(self.bridge,self.pin,Port(),clock=lambda:self.now)
        handler.service(t)
        self.assertEqual(successful(self.bridge.take_result(t))['binding'],self.observation())
        with self.assertRaises(GateBlocked):handler.service(t)

    def test_read_handler_refuses_mutation_before_claim(self):
        class Port:capabilities=READ_CAPABILITIES
        t=self.bridge.submit('mutate',self.context,action=self.action,intent_id='b'*64)
        with self.assertRaises(GateBlocked):NativeReadHandler(self.bridge,self.pin,Port()).service(t)
        self.assertFalse((self.bridge.root/(t.request_id+'.claimed.json')).exists())

    def test_port_with_click_capability_rejects(self):
        class Port:capabilities=READ_CAPABILITIES|{'click'}
        with self.assertRaises(GateBlocked):NativeReadHandler(self.bridge,self.pin,Port())

    def test_clock_rollback_after_fresh_observation_abandons_before_read(self):
        outer=self
        class Port:
            capabilities=READ_CAPABILITIES
            count=0
            def observe(self,binding):
                self.count+=1
                if self.count==2:outer.now=899
                return outer.observation()
            def preflight_read(self,*args):raise AssertionError('Must not execute')
        t=self.bridge.submit('preflight',self.context,action=self.action)
        with self.assertRaises(GateBlocked):NativeReadHandler(self.bridge,self.pin,Port(),clock=lambda:self.now).service(t)
        self.assertTrue((self.bridge.root/(t.request_id+'.abandoned.json')).exists())

    def test_repost_menu_requires_clear_new_observation(self):
        c=self.contract()
        step=c.next_step(self.observation());self.assertEqual(step.effect,'potential_public_change')
        c.record_synthetic_result(step.name,state='menu_opened_no_state_change',observed_sha256=step.expected_sha256)
        step=c.next_step(self.observation());self.assertEqual(step.name,'inspect_repost_menu')
        c.record_synthetic_result(step.name,state='clear_new_repost',observed_sha256=step.expected_sha256)
        step=c.next_step(self.observation());c.record_synthetic_result(step.name,state='submitted',observed_sha256=step.expected_sha256)
        self.assertTrue(c.submitted)
        with self.assertRaises(GateBlocked):c.next_step(self.observation())

    def test_unexpected_menu_state_stops_all_further_steps(self):
        c=self.contract();step=c.next_step(self.observation())
        with self.assertRaises(GateBlocked):c.record_synthetic_result(step.name,state='already_reposted',observed_sha256=step.expected_sha256)
        self.assertTrue(c.halted);self.assertFalse(c.submitted)
        with self.assertRaises(GateBlocked):c.next_step(self.observation())

    def test_pending_step_cannot_be_issued_twice(self):
        c=self.contract();c.next_step(self.observation())
        with self.assertRaises(GateBlocked):c.next_step(self.observation())

    def test_each_step_rechecks_expiry_and_binding(self):
        c=self.contract();self.now=1500
        with self.assertRaises(GateBlocked):c.next_step(self.observation())

    def test_revocation_between_steps_stops_before_next_preparation(self):
        c=self.contract();step=c.next_step(self.observation())
        c.record_synthetic_result(step.name,state='menu_opened_no_state_change',observed_sha256=step.expected_sha256)
        def revoked():raise GateBlocked('Synthetic policy revoked')
        c._authorization_recheck=revoked
        with self.assertRaises(GateBlocked):c.next_step(self.observation())
        self.assertTrue(c.halted);self.assertFalse(c.submitted)

    def test_recheck_wrong_payload_or_expiry_halts(self):
        c=self.contract()
        c._authorization_recheck=lambda:{**self.check(),'payload_hash':'0'*64}
        with self.assertRaises(GateBlocked):c.next_step(self.observation())
        self.assertTrue(c.halted)

    def test_real_exact_authorizer_recheck_contract_revocation(self):
        from test_role_authorization import SyntheticFixture
        f=SyntheticFixture();self.now=f.now
        auth=f.adapter()
        successful(auth.authorize_batch(f.job,f.actions));successful(auth.authorize(f.job,f.actions[0]))
        pin=BindingPin.from_dict(f.binding);ctx=SlotContext(pin,f.start,f.start+3600,f.actions[0]['authorization_id'])
        ticket=self.bridge.submit('mutate',ctx,action=f.actions[0],intent_id='d'*64)
        claim=self.bridge.claim(ticket,pin);spec=self.bridge.begin_dispatch(claim,self.observation(pin))
        c=SyntheticMutationContract(spec,pin,synthetic_capability=self.cap,clock=lambda:self.now,
            authorization_recheck=lambda:auth.recheck_consumed_action(f.job,f.actions[0]),
            review_sha256=f.pin.review_sha256)
        step=c.next_step(self.observation(pin))
        c.record_synthetic_result(step.name,state='menu_opened_no_state_change',observed_sha256=step.expected_sha256)
        f.current_policy=('synthetic-revoked','e'*64)
        with self.assertRaises(GateBlocked):c.next_step(self.observation(pin))
        self.assertFalse(c.submitted)

    def test_payload_export_rules_apply_before_ui_preparation(self):
        bad=copy.deepcopy(self.action);bad['payload']['extra']='not allowed'
        bad['payload_hash']=payload_hash(bad['payload'])
        with self.assertRaises(ValueError):validate_prepared_action(bad,self.pin)

    def test_publisher_preparation_is_inside_intent_contract(self):
        f=publisher_tests.PublisherTests();f.setUp();self.addCleanup(f.doCleanups)
        pin=BindingPin.from_dict(f.binding)
        c=SyntheticMutationContract(self.spec(f.action,pin),pin,synthetic_capability=self.cap,clock=lambda:self.now,
            authorization_recheck=lambda:self.check(f.action,pin),review_sha256='f'*64)
        self.assertEqual([s.effect for s in c.steps],['draft_change','media_upload','read','public_submission'])
        for expected in ('prepared','prepared','bundle_ready','submitted'):
            step=c.next_step(self.observation(pin));c.record_synthetic_result(step.name,state=expected,observed_sha256=step.expected_sha256)
        self.assertTrue(c.submitted)

    def test_publisher_missing_image_rejects_before_any_step(self):
        f=publisher_tests.PublisherTests();f.setUp();self.addCleanup(f.doCleanups);f.image.unlink()
        pin=BindingPin.from_dict(f.binding)
        with self.assertRaises((GateBlocked,FileNotFoundError)):
            SyntheticMutationContract(self.spec(f.action,pin),pin,synthetic_capability=self.cap,clock=lambda:self.now,
            authorization_recheck=lambda:self.check(f.action,pin),review_sha256='f'*64)


class CombinedEntrypointTests(unittest.TestCase):
    def run_fixture(self, *, invalid=False):
        import test_goal_coordinator as goal_tests
        import queue_core
        from unittest.mock import patch
        from native_handler import staged_coordinator
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as root:
            with patch.object(queue_core,'STAGING_ROOT',Path(root)):
                h=goal_tests.Harness(root)
                actions=[goal_tests.raw(i) for i in range(8)]
                if invalid:actions[0]['payload']['unreviewed']='extra'
                h.prepare(actions)
                c=staged_coordinator(h.queue,h.ledger.identity,clock=h.clock,ledger=h.ledger,
                                    browser=h.browser,authorization=h.authorization)
                result=c.run_once()
                if invalid:
                    self.assertEqual(result.state,'blocked')
                    self.assertNotIn('acquire',h.ledger.calls)
                    self.assertEqual(len(h.browser.mutations),0)
                else:
                    self.assertEqual(result.state,'needs_checkpoint')
                    self.assertEqual(len(h.browser.mutations),5)
                    self.assertEqual(c.last_goal_report.newly_verified_total,5)
                    self.assertEqual(h.ledger.calls.count('acquire'),1)
                    self.assertEqual(h.ledger.calls.count('release'),1)

    def test_combined_goal_and_payload_guards_complete_one_writer(self):self.run_fixture()
    def test_combined_export_guard_rejects_before_writer(self):self.run_fixture(invalid=True)

if __name__=='__main__':unittest.main()
