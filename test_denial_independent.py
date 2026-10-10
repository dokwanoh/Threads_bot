"""Independent denial-extension tests. Fresh synthetic Fixture databases only.
No production database, token, browser, STOP, or authorization is used.
"""
import json
import sqlite3
import threading
import unittest
from unittest import mock
import zipfile

import ledger as m
import checkpoint as cp
import denial_extension as de
from test_independent import Fixture, ROOT, ACCOUNT, TARGET, PAYLOAD


class IndependentDenialTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.auth = self.f.active()
        self.kind = 'reply'
        self.key = None
        self.intent = None
        self.denial_hash = None
        self.source_hash = None
        self.approval_hash = None
        self.approval_body_hash = None

    def tearDown(self): self.f.close()

    def blocked(self, fn, *args, **kwargs):
        with self.assertRaises((m.Blocked, sqlite3.Error, OSError, ValueError, KeyError)):
            fn(*args, **kwargs)

    def prepare(self, kind='reply', unknown=True, submitted=False):
        self.kind = kind
        self.key = self.f.claim(self.auth, kind, TARGET)['action_id']
        self.intent = self.f.l.begin_write(self.auth['owner'], self.auth['token'], self.key,
            self.f.evidence(self.key, 'absent', kind=kind))['intent_id']
        if submitted:
            self.f.l.transition(self.auth['owner'], self.auth['token'], self.key, 'submitted_unverified')
        if unknown:
            self.f.l.transition(self.auth['owner'], self.auth['token'], self.key, 'unknown', 'Synthetic reviewer denial; no browser was used')

    def evidence(self, source_updates=None, outer_updates=None):
        common = dict(account=ACCOUNT, db_id=self.f.l.get('db_id'), action_id=self.key,
            kind=self.kind, target=TARGET, payload_hash=PAYLOAD, intent_id=self.intent,
            intent_at=self.f.l.row(self.key)['intent_at'], owner=self.auth['owner'])
        request = 'SYNTHETIC TOOL REQUEST ONLY: reply to '+TARGET
        result = 'This action was rejected due to unacceptable risk. Do not bypass this rejection'
        s = dict(schema='retained-preexecution-denial-context-v1', **common,
            tool_name='synthetic.tool', request_text=request, result_text=result,
            result_is_error=True, denied_at=self.f.now, tool_call_id=None,
            missing_call_id_reason='Synthetic fixture has no actual call ID',
            original_context_reference='synthetic:test-context', execution_stage='before_tool_execution',
            submission_not_sent=True, no_subsequent_browser_call=True,
            request_sha256=m.digest(request), result_sha256=m.digest(result))
        if source_updates: s.update(source_updates)
        source, sh = self.f.record(s, 'synthetic-context')
        self.source_hash = sh
        o = dict(schema='operator-attested-tool-denial-v1', **common,
            source_file=str(source), source_sha256=sh, attested_at=self.f.now,
            provenance='operator_attested_original_tool_context')
        if outer_updates: o.update(outer_updates)
        p, h = self.f.record(o, 'synthetic-denial')
        self.denial_hash = h
        return p, h

    def record(self, **kwargs):
        p, h = self.evidence(**kwargs)
        return de.record_denied(self.f.l, self.auth['owner'], self.auth['token'], self.key, p, h)

    def approval(self, updates=None, body=None):
        body = body or 'SYNTHETIC approval for exact no-execution recording, STOP closure, run release and checkpoint gate; no browser dispatch or retry.'
        proof = self.f.root / 'synthetic-approval.txt'
        proof.write_text(body)
        ph = m.digest(proof.read_bytes()); self.approval_body_hash = ph
        a = dict(schema='operator-approved-denial-finalization-v1', account=ACCOUNT,
            db_id=self.f.l.get('db_id'), action_id=self.key, intent_id=self.intent,
            intent_at=self.f.l.row(self.key)['intent_at'], owner=self.auth['owner'], source_sha256=self.f.l.row(self.key)['proof_hash'], proof_file=str(proof),
            proof_sha256=ph, approval_reference='synthetic:user-approval',
            decision='record_no_execution_release_run_and_require_checkpoint',
            follow_retry_authorized=False, other_new_dispatch_authorized=False, reviewed_at=self.f.now)
        if updates: a.update(updates)
        p,h = self.f.record(a, 'synthetic-approval-envelope'); self.approval_hash=h
        return p,h

    def finalize(self, **kwargs):
        p,h=self.approval(**kwargs)
        return de.finalize_denied_run(self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)

    def snapshot(self):
        return {table:[tuple(r) for r in self.f.l.db.execute('SELECT * FROM '+table)]
            for table in ('meta','writer','runs','actions','blobs','stops','audit')}

    def package(self):
        path=self.f.root/'synthetic-checkpoint.zip'
        result=cp.package(self.f.path,path,source_dir=ROOT,account=ACCOUNT)
        return path,result

    def checkpoint_ack(self, path, package):
        p,h=self.f.record(dict(schema='library-checkpoint-roundtrip-v1',account=ACCOUNT,
            db_id=package['db_id'],baseline_hash=package['baseline_hash'],
            checkpoint_seq=package['checkpoint_seq'],checkpoint_hash=package['checkpoint_hash'],
            library_file_id='synthetic-runtime-library-id',library_version='v1',previous_version='',
            archive_sha256=m.digest(path.read_bytes()),downloaded_archive=str(path),
            transport_reference='Synthetic fixture: no Library upload occurred',verified_at=self.f.now))
        return cp.acknowledge(self.f.l,p,h)

    def test_unknown_happy_path_retains_stop_writer_and_intent(self):
        self.prepare(); original=dict(self.f.l.row(self.key)); out=self.record()
        self.assertFalse(out['may_dispatch']);self.assertTrue(out['stop_retained'])
        row=self.f.l.row(self.key)
        for k in ('id','session','intent_id','intent_at','payload_hash'):self.assertEqual(row[k],original[k])
        self.assertEqual(row['state'],'cancelled');self.assertIsNotNone(self.f.l.status()['writer'])
        self.blocked(self.f.l.release,self.auth['owner'],self.auth['token'])

    def test_intent_path_creates_stop(self):
        self.prepare(unknown=False);self.record();self.assertEqual(len(self.f.l.status()['stops']),1)

    def test_exact_kind_required_despite_shared_action_key(self):
        self.prepare(kind='self_reply')
        self.blocked(self.record,source_updates={'kind':'reply'},outer_updates={'kind':'reply'})

    def test_attestation_must_not_predate_denial(self):
        self.prepare();self.blocked(self.record,outer_updates={'attested_at':self.f.now-1})

    def test_approval_must_not_predate_denial(self):
        self.prepare();self.record();self.blocked(self.finalize,updates={'reviewed_at':self.f.now-1})

    def test_submitted_then_unknown_is_ineligible(self):
        self.prepare(submitted=True);before=self.snapshot();self.blocked(self.record);self.assertEqual(before,self.snapshot())

    def test_generic_error_is_not_denial(self):
        self.prepare();result='Synthetic timeout; execution unknown'
        self.blocked(self.record,source_updates={'result_text':result,'result_sha256':m.digest(result)})

    def test_subsequent_call_is_ineligible(self):
        self.prepare();self.blocked(self.record,source_updates={'no_subsequent_browser_call':False})

    def test_hash_mismatch_rejected(self):
        self.prepare();self.blocked(self.record,source_updates={'request_sha256':'0'*64})

    def test_unknown_missing_stop_rejected(self):
        self.prepare();self.f.l.db.execute('DELETE FROM stops');self.blocked(self.record)

    def test_other_stop_not_replaced(self):
        self.prepare();self.f.l.db.execute("UPDATE stops SET action_id='synthetic-other'")
        self.blocked(self.record);self.assertEqual(self.f.l.status()['stops'][0]['action_id'],'synthetic-other')

    def test_mismatched_bindings_leave_state_unchanged(self):
        self.prepare();before=self.snapshot()
        cases=({'account':'other_account'}, {'db_id':'wrong-db'}, {'action_id':'0'*64},
            {'owner':'other-owner'}, {'payload_hash':'0'*64}, {'intent_id':'0'*64},
            {'target':'https://threads.net/@someone/post/Different'})
        for changes in cases:
            with self.subTest(changes=changes):
                self.blocked(self.record,source_updates=changes);self.assertEqual(before,self.snapshot())

    def test_record_audit_failure_rolls_back_everything(self):
        self.prepare();before=self.snapshot()
        with mock.patch.object(self.f.l,'event',side_effect=sqlite3.OperationalError('synthetic audit failure')):
            self.blocked(self.record)
        self.assertEqual(before,self.snapshot())

    def test_finalize_second_audit_failure_rolls_back_everything(self):
        self.prepare();self.record();before=self.snapshot();original=self.f.l.event;calls=[]
        def fail_second(*args,**kwargs):
            calls.append(args[0])
            if len(calls)==2:raise sqlite3.OperationalError('synthetic second audit failure')
            return original(*args,**kwargs)
        with mock.patch.object(self.f.l,'event',side_effect=fail_second):self.blocked(self.finalize)
        self.assertEqual(len(calls),2);self.assertEqual(before,self.snapshot())

    def test_finalization_atomic_release_and_checkpoint_gate(self):
        self.prepare();self.record();out=self.finalize();s=self.f.l.status()
        self.assertTrue(out['released']);self.assertFalse(out['may_dispatch'])
        self.assertFalse(s['stops']);self.assertIsNone(s['writer']);self.assertTrue(s['checkpoint_pending'])
        self.assertEqual(s['checkpoint_seq'],1);self.blocked(self.f.l.acquire,'new:synthetic','publisher')

    def test_finalization_rejects_generic_cancelled(self):
        self.prepare();self.f.l.db.execute("UPDATE actions SET state='cancelled' WHERE id=?",(self.key,))
        self.denial_hash=self.f.l.row(self.key)['proof_hash'];self.blocked(self.finalize)

    def test_finalization_rejects_retry_or_other_dispatch_approval(self):
        self.prepare();self.record()
        self.blocked(self.finalize,updates={'follow_retry_authorized':True})
        self.blocked(self.finalize,updates={'other_new_dispatch_authorized':True})

    def test_finalization_rejects_unrelated_denial_approval(self):
        self.prepare();self.record();self.blocked(self.finalize,updates={'source_sha256':'0'*64})

    def test_other_reservation_prevents_release(self):
        other=self.f.claim(self.auth,'like',TARGET)['action_id'];self.prepare();self.record()
        self.blocked(self.finalize);self.assertEqual(self.f.l.row(other)['state'],'reserved')

    def test_replay_does_not_release_twice(self):
        self.prepare();self.record();self.blocked(self.record);self.finalize();self.blocked(self.finalize)
        self.assertEqual(self.f.l.get('checkpoint_seq'),'1')

    def test_evidence_closure_contains_context_and_approval(self):
        self.prepare();self.record();self.finalize();_,manifest,_=cp.check_snapshot(self.f.l.db)
        required={self.denial_hash,self.source_hash,self.approval_hash,self.approval_body_hash}
        self.assertTrue(required<=set(manifest['evidence_hashes']))

    def test_checkpoint_requires_denial_extension_member(self):
        self.prepare();self.record();self.finalize();path,pkg=self.package()
        with zipfile.ZipFile(path) as z:members={n:z.read(n) for n in z.namelist()}
        del members['denial_extension.py'];pm=json.loads(members['PACKAGE_MANIFEST.json']);del pm['members']['denial_extension.py']
        members['PACKAGE_MANIFEST.json']=m.canonical(pm).encode()
        with zipfile.ZipFile(path,'w') as z:
            for n,b in members.items():z.writestr(n,b)
        self.blocked(self.checkpoint_ack,path,pkg)

    def test_checkpoint_roundtrip_preserves_duplicate_blocker(self):
        self.prepare();self.record();self.finalize();path,pkg=self.package();self.checkpoint_ack(path,pkg)
        auth=self.f.l.acquire('synthetic:new-owner','publisher')
        out=self.f.l.claim(auth['owner'],auth['token'],'self_reply',TARGET.replace('www.threads.com','threads.net'),m.digest('different'))
        self.assertTrue(out['duplicate']);self.assertFalse(out['payload_matches']);self.assertFalse(out['may_dispatch'])

    def lose_commit_response(self, fn):
        real=self.f.l.db
        class LostResponse:
            def __getattr__(self,k):return getattr(real,k)
            def execute(self,sql,*args):
                result=real.execute(sql,*args)
                if sql=='COMMIT':raise sqlite3.OperationalError('synthetic lost commit response')
                return result
        self.f.l.db=LostResponse()
        try:self.blocked(fn)
        finally:self.f.l.db=real

    def test_lost_record_response_retains_terminal_stop(self):
        self.prepare();self.lose_commit_response(self.record)
        self.assertEqual(self.f.l.row(self.key)['state'],'cancelled')
        self.assertTrue(self.f.l.status()['stops']);self.assertIsNotNone(self.f.l.status()['writer'])
        self.blocked(self.record);self.blocked(self.f.l.release,self.auth['owner'],self.auth['token'])

    def test_lost_finalize_response_retains_checkpoint_gate(self):
        self.prepare();self.record();self.lose_commit_response(self.finalize)
        status=self.f.l.status()
        self.assertIsNone(status['writer']);self.assertFalse(status['stops'])
        self.assertTrue(status['checkpoint_pending']);self.assertEqual(status['checkpoint_seq'],1)
        self.blocked(self.finalize);self.blocked(self.f.l.acquire,'synthetic:new','publisher')

    def race(self, callback):
        barrier=threading.Barrier(2);results=[];lock=threading.Lock()
        def worker():
            ledger=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
            try:
                barrier.wait(timeout=10)
                try:out=callback(ledger)
                except (m.Blocked,sqlite3.Error) as error:out=error
                with lock:results.append(out)
            finally:ledger.close()
        threads=[threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(results),2)
        self.assertEqual(sum(isinstance(result,dict) for result in results),1)

    def test_concurrent_record_has_one_winner(self):
        self.prepare();p,h=self.evidence()
        self.race(lambda ledger:de.record_denied(ledger,self.auth['owner'],self.auth['token'],self.key,p,h))
        self.assertEqual(self.f.l.db.execute("SELECT COUNT(*) FROM audit WHERE event='denied_before_dispatch_recorded'").fetchone()[0],1)
        self.assertTrue(self.f.l.status()['stops'])

    def test_concurrent_finalization_has_one_winner(self):
        self.prepare();self.record();p,h=self.approval()
        self.race(lambda ledger:de.finalize_denied_run(ledger,self.auth['owner'],self.auth['token'],self.key,p,h))
        self.assertEqual(self.f.l.get('checkpoint_seq'),'1');self.assertEqual(self.f.l.get('checkpoint_pending'),'1')

    def test_approval_body_not_authenticated_documents_external_trust_boundary(self):
        # This is an intentional characterization test, not proof of valid approval.
        # A caller can assert a positive decision while supplying contradictory bytes.
        self.prepare();self.record()
        out=self.finalize(body='SYNTHETIC NEGATIVE USER ANSWER: Do not clear STOP or release this run.')
        self.assertTrue(out['released'])


if __name__=='__main__':unittest.main(verbosity=2)
