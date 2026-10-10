"""Independent checkpoint regressions; all DBs and archives are disposable."""
import io
import json
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest import mock
import zipfile
import ledger as m
import checkpoint as cp
from test_independent import Fixture, ROOT, ACCOUNT, TARGET

class IndependentCheckpointTests(unittest.TestCase):
    def setUp(self):self.f=Fixture();self.auth=self.f.active()
    def tearDown(self):self.f.close()
    def blocked(self,fn,*args,**kwargs):
        with self.assertRaises((m.Blocked,sqlite3.Error,OSError,ValueError)):
            fn(*args,**kwargs)
    def release(self):return self.f.l.release(self.auth['owner'],self.auth['token'])
    def package(self):
        self.f.n+=1
        path=self.f.root/f'checkpoint-{self.f.n}.zip'
        result=cp.package(self.f.path,path,source_dir=ROOT,account=ACCOUNT)
        return path,result
    def receipt(self,path,package,**updates):
        value=dict(schema='library-checkpoint-roundtrip-v1',account=ACCOUNT,
            db_id=package['db_id'],baseline_hash=package['baseline_hash'],
            checkpoint_seq=package['checkpoint_seq'],checkpoint_hash=package['checkpoint_hash'],
            library_file_id='synthetic-runtime-library-id',library_version='v1',previous_version='',
            archive_sha256=m.digest(path.read_bytes()),downloaded_archive=str(path),
            transport_reference='Synthetic local fixture, no actual Library activity',verified_at=self.f.now)
        value.update(updates);return self.f.record(value,'checkpoint-receipt')
    def ack(self,path,package,**updates):
        p,h=self.receipt(path,package,**updates);return cp.acknowledge(self.f.l,p,h)
    def pending(self):
        self.release();return self.package()
    def next_run(self,owner='test:next'):
        self.auth=self.f.l.acquire(owner,'publisher');return self.auth
    def tamper_db(self,path,mutate):
        with zipfile.ZipFile(path) as z:members={n:z.read(n) for n in z.namelist()}
        dbpath=self.f.root/f'tamper-{self.f.n}.sqlite';dbpath.write_bytes(members['runtime.sqlite'])
        db=sqlite3.connect(dbpath)
        try:mutate(db);db.commit()
        finally:db.close()
        members['runtime.sqlite']=dbpath.read_bytes()
        pm=json.loads(members['PACKAGE_MANIFEST.json']);pm['members']['runtime.sqlite']=m.digest(members['runtime.sqlite'])
        members['PACKAGE_MANIFEST.json']=m.canonical(pm).encode()
        with zipfile.ZipFile(path,'w') as z:
            for n,b in members.items():z.writestr(n,b)
    def test_release_sets_gate_and_sequence_atomically(self):
        out=self.release();self.assertTrue(out['checkpoint_pending']);self.assertEqual(out['checkpoint_seq'],1)
        self.assertIsNone(self.f.l.status()['writer']);self.blocked(self.f.l.acquire,'new:owner','publisher')
        self.blocked(self.f.l.release,self.auth['owner'],self.auth['token'])
    def test_release_failure_restores_writer_and_no_gate(self):
        with mock.patch.object(self.f.l,'event',side_effect=sqlite3.OperationalError('simulated full storage')):
            self.blocked(self.release)
        status=self.f.l.status();self.assertFalse(status['checkpoint_pending']);self.assertEqual(status['checkpoint_seq'],0)
        self.assertEqual(status['writer']['owner'],self.auth['owner'])
    def test_checkpoint_and_ack_allow_exact_next_run(self):
        path,pkg=self.pending();self.assertTrue(self.f.l.status()['checkpoint_pending'])
        out=self.ack(path,pkg);self.assertFalse(out['checkpoint_pending']);self.assertFalse(out['may_dispatch'])
        self.next_run();self.assertEqual(self.f.l.get('checkpoint_seq'),'1')
    def test_wrong_archive_hash_keeps_pending(self):
        path,pkg=self.pending();p,h=self.receipt(path,pkg);path.write_bytes(path.read_bytes()+b'changed')
        self.blocked(cp.acknowledge,self.f.l,p,h);self.assertEqual(self.f.l.get('checkpoint_pending'),'1')
    def test_wrong_receipt_database_id_rejected(self):
        path,pkg=self.pending();self.blocked(self.ack,path,pkg,db_id='different-db')
    def test_wrong_receipt_sequence_rejected(self):
        path,pkg=self.pending();self.blocked(self.ack,path,pkg,checkpoint_seq=2)
    def test_stale_receipt_rejected(self):
        path,pkg=self.pending();self.blocked(self.ack,path,pkg,verified_at=self.f.now-3601)
    def test_wrong_receipt_account_rejected(self):
        path,pkg=self.pending();self.blocked(self.ack,path,pkg,account='wrong-account')
    def test_baseline_library_file_cannot_be_runtime_file(self):
        path,pkg=self.pending();self.blocked(self.ack,path,pkg,library_file_id=self.f.l.get('baseline_library_id'))
    def test_version_chain_stays_pinned_across_runs(self):
        path,pkg=self.pending();self.ack(path,pkg);self.next_run();path2,pkg2=self.pending()
        self.assertEqual(pkg2['checkpoint_seq'],2)
        self.blocked(self.ack,path2,pkg2,library_file_id='different-runtime-id',library_version='v2',previous_version='v1')
        self.blocked(self.ack,path2,pkg2,library_version='v2',previous_version='wrong')
        self.blocked(self.ack,path2,pkg2,library_version='v1',previous_version='v1')
        self.ack(path2,pkg2,library_version='v2',previous_version='v1')
        self.assertEqual(self.f.l.get('checkpoint_library_version'),'v2')
    def test_old_checkpoint_cannot_ack_later_sequence(self):
        path,pkg=self.pending();self.ack(path,pkg);self.next_run();self.release()
        self.blocked(self.ack,path,pkg);self.assertEqual(self.f.l.get('checkpoint_pending'),'1')
    def test_duplicate_ack_cannot_be_replayed(self):
        path,pkg=self.pending();self.ack(path,pkg);self.blocked(self.ack,path,pkg)
    def test_packager_rejects_active_writer(self):self.blocked(self.package)
    def test_packager_rejects_reserved_work(self):
        self.f.claim(self.auth);self.blocked(self.release);self.blocked(self.package)
    def test_packager_rejects_unknown_outcome(self):
        key=self.f.claim(self.auth)['action_id'];p=self.f.evidence(key,'absent')
        self.f.l.begin_write(self.auth['owner'],self.auth['token'],key,p)
        self.f.l.transition(self.auth['owner'],self.auth['token'],key,'unknown','Synthetic uncertain browser outcome')
        self.blocked(self.release);self.blocked(self.package)
    def test_snapshot_tampered_action_rejected(self):
        path,pkg=self.pending();self.tamper_db(path,lambda db:db.execute("UPDATE actions SET target_url='https://threads.com/@fake/post/Fake'"))
        self.blocked(self.ack,path,pkg)
    def test_snapshot_tampered_library_pin_rejected(self):
        path,pkg=self.pending();self.tamper_db(path,lambda db:db.execute("UPDATE meta SET value='wrong-library' WHERE key='checkpoint_library_id'"))
        self.blocked(self.ack,path,pkg)
    def test_snapshot_tampered_previous_version_rejected(self):
        path,pkg=self.pending();self.tamper_db(path,lambda db:db.execute("UPDATE meta SET value='wrong-version' WHERE key='checkpoint_library_version'"))
        self.blocked(self.ack,path,pkg)
    def test_snapshot_tampered_baseline_library_rejected(self):
        path,pkg=self.pending();self.tamper_db(path,lambda db:db.execute("UPDATE meta SET value='wrong-baseline-id' WHERE key='baseline_library_id'"))
        self.blocked(self.ack,path,pkg)
    def test_live_state_change_after_package_rejected(self):
        path,pkg=self.pending()
        self.f.l.db.execute("UPDATE actions SET target_url='https://threads.com/@fake/post/Fake'")
        self.blocked(self.ack,path,pkg);self.assertEqual(self.f.l.get('checkpoint_pending'),'1')
    def test_token_values_and_deleted_hashes_absent_from_package(self):
        token=self.auth['token'];token_hash=m.digest(token);path,pkg=self.pending()
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                data=z.read(name);self.assertNotIn(token.encode(),data);self.assertNotIn(token_hash.encode(),data)
    def test_ack_storage_failure_keeps_gate_and_pin_unchanged(self):
        path,pkg=self.pending();p,h=self.receipt(path,pkg)
        with mock.patch.object(self.f.l,'event',side_effect=sqlite3.OperationalError('simulated storage failure')):
            self.blocked(cp.acknowledge,self.f.l,p,h)
        self.assertEqual(self.f.l.get('checkpoint_pending'),'1');self.assertEqual(self.f.l.get('checkpoint_library_id'),'')
    def test_checkpoint_read_uses_exact_hashed_archive_bytes(self):
        path,pkg=self.pending();p,h=self.receipt(path,pkg);original=cp.file_bytes
        def swap_after_read(value,*args,**kwargs):
            result=original(value,*args,**kwargs)
            if Path(value)==path:path.write_bytes(b'Changed after read')
            return result
        with mock.patch.object(cp,'file_bytes',side_effect=swap_after_read):
            self.assertFalse(cp.acknowledge(self.f.l,p,h)['checkpoint_pending'])
    def test_completed_action_evidence_is_bound_in_checkpoint(self):
        key=self.f.claim(self.auth)['action_id'];preflight=self.f.evidence(key,'absent')
        intent=self.f.l.begin_write(self.auth['owner'],self.auth['token'],key,preflight)
        self.f.l.transition(self.auth['owner'],self.auth['token'],key,'submitted_unverified')
        readback=self.f.evidence(key,'present',intent['intent_id'],receipts=['https://threads.com/@'+ACCOUNT+'/post/SyntheticVerifiedReceipt'])
        self.f.l.verify(self.auth['owner'],self.auth['token'],key,readback)
        proof_hash=self.f.l.row(key)['proof_hash'];path,pkg=self.pending()
        with zipfile.ZipFile(path) as z:
            manifest=json.loads(z.read('RUNTIME_MANIFEST.json'))
            self.assertIn(proof_hash,manifest['evidence_hashes'])
            self.assertIn('evidence/'+proof_hash+'.bin',z.namelist())
            self.assertTrue(any(a['id']==key and a['state']=='verified' for a in manifest['actions']))
            self.assertTrue(any(e['event']=='single_write_intent_committed' for e in manifest['audit']))
        self.ack(path,pkg);self.next_run()
        result=self.f.claim(self.auth);self.assertTrue(result['duplicate']);self.assertFalse(result['may_dispatch'])
    def test_lost_release_response_durably_blocks_new_writer(self):
        real=self.f.l.db
        class LostResponse:
            def __getattr__(self,k):return getattr(real,k)
            def execute(self,sql,*args):
                result=real.execute(sql,*args)
                if sql=='COMMIT':raise sqlite3.OperationalError('Synthetic lost release response')
                return result
        self.f.l.db=LostResponse()
        self.blocked(self.release);self.f.l.db=real
        self.assertEqual(self.f.l.get('checkpoint_pending'),'1')
        self.assertIsNone(self.f.l.status()['writer'])
        self.blocked(self.f.l.acquire,'lost-response:new','publisher')
    def test_checkpoint_restore_remains_pending(self):
        path,pkg=self.pending()
        with zipfile.ZipFile(path) as z:data=z.read('runtime.sqlite')
        db=sqlite3.connect(':memory:')
        try:
            db.deserialize(data);v,_,_=cp.check_snapshot(db);self.assertEqual(v['checkpoint_pending'],'1')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM writer').fetchone()[0],0)
        finally:db.close()
    def test_release_vs_acquire_race_never_grants_new_writer(self):
        barrier=threading.Barrier(2);results=[];lock=threading.Lock()
        def worker(which):
            l=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
            try:
                barrier.wait(timeout=10)
                try:r=l.release(self.auth['owner'],self.auth['token']) if which==0 else l.acquire('racing:newowner','publisher')
                except (m.Blocked,sqlite3.Error) as e:r=e
                with lock:results.append((which,r))
            finally:l.close()
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(len(results),2)
        self.assertTrue(all(not isinstance(r,dict) for i,r in results if i==1))
        self.assertTrue(self.f.l.status()['checkpoint_pending'])

if __name__=='__main__':unittest.main(verbosity=2)
