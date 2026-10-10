"""Independent copied-code probes; only synthetic adapters/queue databases."""
import hashlib
import json
from dataclasses import asdict,replace
from pathlib import Path
from unittest import mock
import unittest
import queue_core
from test_coordinator import CoordinatorTests as _CoordinatorFixture

class ReviewExtraTests(unittest.TestCase):
    def test_changed_companion_library_id_rejected_cross_run(self):
        self.prepare('publisher');self.prepare('spreader')
        self.assertEqual(self.coordinator.run_once().state,'needs_checkpoint')
        self.assertEqual(self.coordinator.complete_checkpoint(**self.pair()).state,'done')
        self.assertEqual(self.coordinator.run_once().state,'needs_checkpoint')
        args=self.pair();e=replace(args['expected_pair'],queue_library_file_id='replacement-queue-library',queue_library_version='v9',queue_previous_version='unrelated-version')
        args['expected_pair']=e;args['pair_manifest']['expected']=asdict(e)
        args['pair_manifest']['queue_receipt'].update(library_file_id=e.queue_library_file_id,library_version=e.queue_library_version,previous_version=e.queue_previous_version)
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state,'needs_checkpoint')
        self.assertEqual(self.ledger.calls.count('checkpoint-ack'),1)

    def test_denial_ledger_only_closure_does_not_release_queue(self):
        job=self.prepare();self.browser.outcome='denied'
        self.assertEqual(self.coordinator.run_once().state,'blocked')
        # Simulates independently approved ledger bookkeeping only, not an actual adapter.
        for a in self.ledger.actions.values():a['state']='cancelled'
        self.ledger.writer=None;self.ledger.stops=[];self.ledger.pending=False;self.ledger.seq+=1
        self.assertEqual(self.coordinator.run_once().state,'blocked')
        self.assertEqual(self.make_coordinator().run_once().state,'blocked')
        self.assertEqual(self.queue.inspect_job(job)['state'],'blocked')
        self.assertIsNotNone(self.queue.snapshot()['dispatcher']['job_id'])

    def test_clock_rollback_after_final_queue_validation_blocks_future_slot(self):
        self.now=1100;b=self.bindings['publisher']
        evidence=self.queue.record_observation('publisher',worker_id=b.worker_id,browser_id=b.browser_id,tab_id=b.tab_id,observed_account=b.expected_account,tab_exists=True,observed_at=self.now,now=self.now)
        job=self.queue.enqueue('publisher',1000,2000,evidence_id=evidence,now=self.now)
        target='https://blog.example/123'
        self.queue.mark_ready(job['job_id'],{'actions':[{'kind':'publish','target':target,'payload':{'target':target,'text':'Synthetic'},'authorization_id':'synthetic'}]},evidence_id=evidence,now=self.now)
        original=self.queue.validate_action_start
        def roll_back(*args,**kwargs):
            result=original(*args,**kwargs)
            if any(a['state']=='intent' for a in self.ledger.actions.values()):self.now=999
            return result
        with mock.patch.object(self.queue,'validate_action_start',side_effect=roll_back):
            result=self.coordinator.run_once()
        self.assertEqual(len(self.browser.mutations),0)
        self.assertEqual(result.state,'blocked')
        self.assertLess(self.now,1000)

    def test_nonzero_reviewer_denial_stays_unknown_not_verified(self):
        from dispatch_gate import CommandResult
        job=self.prepare()
        def denied(action,binding,intent,**slot):
            return CommandResult(True,2,'',stderr='Permission reviewer denied before dispatch')
        with mock.patch.object(self.browser,'mutate',side_effect=denied):
            self.assertEqual(self.coordinator.run_once().state,'blocked')
        self.assertTrue(self.ledger.stops);self.assertEqual(next(iter(self.ledger.actions.values()))['state'],'unknown')
        self.assertEqual(self.queue.inspect_job(job)['state'],'blocked')


for name in ('setUp', 'tearDown', 'make_coordinator', 'prepare', 'pair'):
    setattr(ReviewExtraTests, name, getattr(_CoordinatorFixture, name))
del _CoordinatorFixture

if __name__=='__main__':unittest.main(verbosity=2)
