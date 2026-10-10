"""Adversarial tests against disposable, synthetic recovery databases only."""
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock
import zipfile

import ledger as m

ROOT = Path(__file__).resolve().parent
ACCOUNT = m.ACCOUNT
NOW = int(time.time())
TARGET = 'https://www.threads.com/@public_person/post/TestTargetA'
OTHER = 'https://www.threads.net/@someone/post/TestTargetB'
PAYLOAD = m.digest('synthetic public payload')


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='independent-ledger-test-')
        self.root = Path(self.temp.name)
        self.path = self.root / 'recovery.sqlite'
        self.now = NOW
        m.Ledger.init_recovery(self.path, ACCOUNT)
        self.l = m.Ledger(self.path, ACCOUNT, clock=lambda: self.now)
        self.n = 0

    def close(self):
        try: self.l.close()
        except sqlite3.Error: pass
        self.temp.cleanup()

    def record(self, value, prefix='record'):
        self.n += 1
        p = self.root / f'{prefix}{self.n}.json'
        p.write_text(m.canonical(value), encoding='utf-8')
        return p, m.digest(p.read_bytes())

    def import_one(self, classification='current_observed', kind='like', target=OTHER):
        proof = self.root / 'public-proof.txt'
        proof.write_text('Synthetic public observation for isolated tests.')
        p, h = self.record(dict(schema='public-action-observation-v1', account=ACCOUNT,
            kind=kind, target=target, classification=classification, observed_at=self.now,
            reference='Synthetic independent test fixture', source_file=str(proof),
            source_sha256=m.digest(proof.read_bytes()), payload=None, receipt_urls=[]))
        return self.l.import_observation(p, h)

    def seal(self):
        self.import_one()
        p, h = self.record(dict(schema='recovery-review-v1', account=ACCOUNT,
            manifest_sha256=m.digest(m.canonical(self.l.manifest())),
            review_reference='Synthetic independent review', known_gaps=['Synthetic fixture only'],
            fresh_duplicate_checks_required=True, reviewed_at=self.now))
        return self.l.seal(p, h)

    def make_archive(self, mutate=None, extra=None):
        snapshot = self.root / f'snapshot{self.n}.sqlite'
        out = sqlite3.connect(snapshot)
        self.l.db.backup(out)
        out.execute('PRAGMA journal_mode=DELETE')
        if mutate:
            mutate(out)
            out.commit()
        out.close()
        members = {'reconstructed.sqlite': snapshot.read_bytes(),
                   'ledger.py': (ROOT / 'ledger.py').read_bytes(),
                   'denial_extension.py': (ROOT / 'denial_extension.py').read_bytes(),
                   'settings.py': (ROOT / 'settings.py').read_bytes(),
                   'RECOVERY.md': b'Synthetic isolated backup fixture. Never use operationally.'}
        if extra: members.update(extra)
        manifest = dict(schema='threads-ledger-backup-v1', account=ACCOUNT,
            db_id=self.l.get('db_id'), baseline_hash=self.l.get('baseline_hash'),
            members={k:m.digest(v) for k,v in members.items()})
        path = self.root / f'archive{self.n}.zip'
        with zipfile.ZipFile(path, 'w') as z:
            for k,v in members.items(): z.writestr(k, v)
            z.writestr('PACKAGE_MANIFEST.json', m.canonical(manifest))
        return path

    def receipt(self, archive):
        return self.record(dict(schema='library-roundtrip-verification-v1', account=ACCOUNT,
            db_id=self.l.get('db_id'), baseline_hash=self.l.get('baseline_hash'),
            library_file_id='synthetic-library-test-id', library_version='synthetic-version',
            archive_sha256=m.digest(archive.read_bytes()), downloaded_archive=str(archive),
            transport_reference='Synthetic disposable fixture; no actual Library upload',
            verified_at=self.now))

    def active(self):
        self.seal()
        p,h = self.receipt(self.make_archive())
        self.l.activate(p,h)
        return self.l.acquire('test:owner', 'publisher')

    def claim(self, auth, kind='reply', target=TARGET):
        return self.l.claim(auth['owner'], auth['token'], kind, target, PAYLOAD)

    def evidence(self, action, outcome, intent=None, observed_at=None, target=TARGET,
                 kind='reply', receipts=None):
        proof = self.root / 'browser-proof.txt'
        proof.write_text('Synthetic public browser evidence for isolated tests.')
        return self.record(dict(schema='browser-action-evidence-v2', account=ACCOUNT,
            kind=kind, target=target, payload_hash=PAYLOAD, intent_id=intent, outcome=outcome,
            observed_at=self.now if observed_at is None else observed_at,
            reference='Synthetic independent browser observation', proof_file=str(proof),
            proof_sha256=m.digest(proof.read_bytes()), receipt_urls=receipts or []))[0]


class IndependentLedgerTests(unittest.TestCase):
    def setUp(self): self.f=Fixture()
    def tearDown(self): self.f.close()
    def blocked(self, fn, *args, **kwargs):
        with self.assertRaises((m.Blocked, sqlite3.Error, OSError, ValueError)):
            fn(*args, **kwargs)
    def auth(self): return self.f.active()
    def reserve(self):
        a=self.auth(); r=self.f.claim(a); return a,r['action_id']
    def begin(self,a,key):
        return self.f.l.begin_write(a['owner'],a['token'],key,self.f.evidence(key,'absent'))

    def test_missing_database_not_created(self):
        p=self.f.root/'missing.sqlite';self.blocked(m.Ledger,p,ACCOUNT);self.assertFalse(p.exists())
    def test_wrong_database(self):
        p=self.f.root/'wrong.sqlite';sqlite3.connect(p).close();self.blocked(m.Ledger,p,ACCOUNT)
    def test_schema_guard_removal_rejected(self):
        self.f.l.db.execute('DROP TRIGGER audit_no_update');self.blocked(m.Ledger,self.f.path,ACCOUNT)
    def test_wrong_account(self): self.blocked(m.Ledger,self.f.path,'different_account')
    def test_inactive_gate(self):
        self.blocked(self.f.l.acquire,'test:owner','publisher')
        self.f.seal();self.blocked(self.f.l.acquire,'test:owner','publisher')
        self.assertEqual(self.f.l.status()['phase'],'sealed')
    def test_empty_recovery_not_sealable(self):
        p,h=self.f.record(dict(schema='recovery-review-v1',account=ACCOUNT,
            manifest_sha256=m.digest(m.canonical(self.f.l.manifest())),review_reference='Synthetic',
            known_gaps=[],fresh_duplicate_checks_required=True,reviewed_at=NOW))
        self.blocked(self.f.l.seal,p,h)
    def test_archive_bad_hash_fails_gate(self):
        self.f.seal();archive=self.f.make_archive();p,h=self.f.receipt(archive)
        archive.write_bytes(archive.read_bytes()+b'changed')
        self.blocked(self.f.l.activate,p,h);self.assertEqual(self.f.l.get('phase'),'sealed')
    def test_tampered_snapshot_content_fails_gate(self):
        self.f.seal()
        archive=self.f.make_archive(lambda db:db.execute("UPDATE actions SET target_url='https://www.threads.com/@fake/post/Fake'"))
        p,h=self.f.receipt(archive);self.blocked(self.f.l.activate,p,h)
    def test_tampered_snapshot_account_fails_gate(self):
        self.f.seal();archive=self.f.make_archive(lambda db:db.execute("UPDATE meta SET value='wrong' WHERE key='account'"))
        p,h=self.f.receipt(archive);self.blocked(self.f.l.activate,p,h)
    def test_archive_writer_credentials_rejected(self):
        self.f.seal()
        def mutate(db):db.execute('INSERT INTO writer VALUES(?,?,?,?,?,?)',(ACCOUNT,'session','owner','publisher','f'*64,NOW))
        p,h=self.f.receipt(self.f.make_archive(mutate));self.blocked(self.f.l.activate,p,h)
    def test_duplicate_reply_self_reply_share_domain(self):
        a,key=self.reserve();out=self.f.claim(a,'self_reply',TARGET.replace('www.threads.com','threads.net'))
        self.assertEqual(key,out['action_id']);self.assertTrue(out['duplicate']);self.assertFalse(out['may_dispatch'])
    def test_wrong_payload_never_dispatches_duplicate(self):
        a,key=self.reserve()
        out=self.f.l.claim(a['owner'],a['token'],'reply',TARGET,m.digest('different'))
        self.assertFalse(out['payload_matches']);self.assertFalse(out['may_dispatch'])
    def test_single_use_intent(self):
        a,key=self.reserve();result=self.begin(a,key);self.assertTrue(result['may_dispatch'])
        self.blocked(self.begin,a,key);self.assertEqual(self.f.l.row(key)['state'],'intent')
    def test_unknown_blocks_every_new_write_and_release(self):
        a,key=self.reserve();intent=self.begin(a,key)
        self.f.l.transition(a['owner'],a['token'],key,'unknown','Browser outcome unavailable')
        self.blocked(self.f.claim,a,'like',TARGET)
        self.blocked(self.f.l.release,a['owner'],a['token'])
        self.blocked(self.f.l.acquire,'test:other','commenter')
        evidence=self.f.evidence(key,'present',intent['intent_id'],receipts=['https://threads.net/@'+ACCOUNT+'/post/OwnReceiptA'])
        self.f.l.verify(a['owner'],a['token'],key,evidence)
        self.blocked(self.f.claim,a,'like',TARGET)
        self.f.l.acknowledge_reconciliation(a['owner'],a['token'],key)
        self.assertFalse(self.f.claim(a,'like',TARGET)['may_dispatch'])
    def test_lost_token_never_takeover_even_after_year(self):
        a=self.auth();self.f.now+=365*86400
        self.blocked(self.f.l.acquire,'test:newowner','reconciler')
        self.blocked(self.f.l.release,a['owner'],'0'*64)
        self.assertEqual(self.f.l.status()['writer']['owner'],a['owner'])
    def test_duplicate_run_owner_rejected(self):
        a=self.auth();self.f.l.release(a['owner'],a['token'])
        self.blocked(self.f.l.acquire,a['owner'],'publisher')
    def test_crash_after_intent_prevents_retry(self):
        a,key=self.reserve();self.begin(a,key);self.f.l.close()
        self.f.l=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
        self.blocked(self.begin,a,key);self.blocked(self.f.l.acquire,'crash:newowner','publisher')
        self.assertEqual(self.f.l.row(key)['state'],'intent')
    def test_stale_absence_evidence_rejected(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent',observed_at=self.f.now-301)
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
        self.assertEqual(self.f.l.row(key)['state'],'reserved')
    def test_storage_failure_rolls_back_intent(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent');before=self.f.l.status()['audit_events']
        with mock.patch.object(self.f.l,'event',side_effect=sqlite3.OperationalError('simulated disk full')):
            self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
        self.assertEqual(self.f.l.row(key)['state'],'reserved')
        self.assertEqual(self.f.l.status()['audit_events'],before)
    def test_query_only_storage_never_returns_dispatch(self):
        a,key=self.reserve();self.f.l.db.execute('PRAGMA query_only=ON')
        self.blocked(self.begin,a,key);self.assertEqual(self.f.l.row(key)['state'],'reserved')
    def test_lost_commit_response_leaves_nonretryable_intent(self):
        a,key=self.reserve();real=self.f.l.db
        class LostResponse:
            def __getattr__(self,k):return getattr(real,k)
            def execute(self,sql,*args):
                result=real.execute(sql,*args)
                if sql=='COMMIT':raise sqlite3.OperationalError('simulated lost commit response')
                return result
        self.f.l.db=LostResponse()
        self.blocked(self.begin,a,key);self.f.l.db=real
        self.assertEqual(self.f.l.row(key)['state'],'intent');self.blocked(self.begin,a,key)
    def test_evidence_intent_race_cannot_verify_old_evidence(self):
        a,key=self.reserve();p=self.f.evidence(key,'present',receipts=['https://threads.net/@'+ACCOUNT+'/post/OwnReceiptA'])
        original=self.f.l.observation
        def racing(path,row,outcome):
            result=original(path,row,outcome)
            self.begin(a,key)
            return result
        with mock.patch.object(self.f.l,'observation',side_effect=racing):
            # Use a separate ledger for the racing intent to avoid wrapper recursion.
            def race(path,row,outcome):
                result=original(path,row,outcome)
                other=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
                try:other.begin_write(a['owner'],a['token'],key,self.f.evidence(key,'absent'))
                finally:other.close()
                return result
            with mock.patch.object(self.f.l,'observation',side_effect=race):
                self.blocked(self.f.l.verify,a['owner'],a['token'],key,p)
        self.assertEqual(self.f.l.row(key)['state'],'intent')
    def test_preflight_race_with_readback_cannot_dispatch(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent');original=self.f.l.observation
        def race(path,row,outcome):
            result=original(path,row,outcome)
            other=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
            try:other.verify(a['owner'],a['token'],key,self.f.evidence(key,'present',receipts=['https://threads.net/@'+ACCOUNT+'/post/OwnReceiptA']))
            finally:other.close()
            return result
        with mock.patch.object(self.f.l,'observation',side_effect=race):
            self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
        self.assertEqual(self.f.l.row(key)['state'],'already_present')
    def race_calls(self, callback):
        barrier=threading.Barrier(2);results=[];lock=threading.Lock()
        def worker(i):
            ledger=m.Ledger(self.f.path,ACCOUNT,clock=lambda:self.f.now)
            try:
                barrier.wait(timeout=10)
                try:out=callback(ledger,i)
                except (m.Blocked,sqlite3.Error) as e:out=e
                with lock:results.append(out)
            finally:ledger.close()
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(len(results),2)
        return results
    def test_atomic_writer_race_has_one_winner(self):
        self.f.seal();p,h=self.f.receipt(self.f.make_archive());self.f.l.activate(p,h)
        results=self.race_calls(lambda l,i:l.acquire('race:'+str(i),'publisher'))
        self.assertEqual(sum(isinstance(r,dict) for r in results),1)
        self.assertEqual(self.f.l.db.execute('SELECT COUNT(*) FROM writer').fetchone()[0],1)
    def test_atomic_reply_claim_race_reserves_once(self):
        a=self.auth()
        results=self.race_calls(lambda l,i:l.claim(a['owner'],a['token'],'reply' if i else 'self_reply',TARGET,PAYLOAD))
        self.assertEqual(sum(isinstance(r,dict) and not r['duplicate'] for r in results),1)
    def test_atomic_intent_race_dispatches_once(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        results=self.race_calls(lambda l,i:l.begin_write(a['owner'],a['token'],key,p))
        self.assertEqual(sum(isinstance(r,dict) and r['may_dispatch'] for r in results),1)
    def test_changed_open_schema_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.l.db.execute('DROP TRIGGER audit_no_update')
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_changed_open_account_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.l.db.execute("UPDATE meta SET value='changed-account' WHERE key='account'")
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_changed_open_database_id_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.l.db.execute("UPDATE meta SET value='changed-db-identity' WHERE key='db_id'")
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_deleted_open_wal_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        Path(str(self.f.path)+'-wal').unlink()
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_deleted_open_shared_memory_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        Path(str(self.f.path)+'-shm').unlink()
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_sqlite_capacity_failure_rolls_back_intent(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        data=json.loads(p.read_text());proof=Path(data['proof_file'])
        proof.write_bytes(b'Synthetic public proof. '*50000)
        data['proof_sha256']=m.digest(proof.read_bytes());p.write_text(m.canonical(data))
        pages=self.f.l.db.execute('PRAGMA page_count').fetchone()[0]
        self.f.l.db.execute('PRAGMA max_page_count='+str(pages))
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
        self.assertEqual(self.f.l.row(key)['state'],'reserved')
    def test_audit_and_evidence_guards_are_immutable(self):
        self.f.import_one()
        self.blocked(self.f.l.db.execute,"UPDATE audit SET event='changed'")
        self.blocked(self.f.l.db.execute,'DELETE FROM audit')
        self.blocked(self.f.l.db.execute,"UPDATE blobs SET bytes=x'00'")
        self.blocked(self.f.l.db.execute,'DELETE FROM blobs')
    def test_deleted_open_database_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.path.unlink()
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_renamed_open_database_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.path.rename(self.f.root/'renamed.sqlite')
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_replaced_open_database_never_dispatches(self):
        a,key=self.reserve();p=self.f.evidence(key,'absent')
        self.f.path.rename(self.f.root/'renamed.sqlite')
        sqlite3.connect(self.f.path).close()
        self.blocked(self.f.l.begin_write,a['owner'],a['token'],key,p)
    def test_archive_parse_uses_exact_previously_hashed_bytes(self):
        self.f.seal();archive=self.f.make_archive();p,h=self.f.receipt(archive)
        original=m.file_bytes;original_hash=m.digest(archive.read_bytes())
        def swap_after_read(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if Path(path)==archive:archive.write_bytes(b'Replacement must not be inspected')
            return result
        with mock.patch.object(m,'file_bytes',side_effect=swap_after_read):
            result=self.f.l.activate(p,h)
        self.assertEqual(result['backup_sha256'],original_hash)
    def test_backup_changed_receipt_binding_rejected(self):
        self.f.seal()
        def mutate(db):
            action=db.execute('SELECT id FROM actions LIMIT 1').fetchone()[0]
            db.execute('INSERT INTO receipts VALUES(?,?,?)',('threads:post:UnexpectedReceipt',action,'a'*64))
        p,h=self.f.receipt(self.f.make_archive(mutate));self.blocked(self.f.l.activate,p,h)
    def package_source(self):
        source=self.f.root/'package-source';source.mkdir()
        for name in ('ledger.py','denial_extension.py','package_recovery.py','checkpoint.py','settings.py','test_independent.py'):
            (source/name).write_bytes((ROOT/name).read_bytes())
        (source/'RECOVERY.md').write_text('Synthetic recovery documentation.')
        (source/'FAIL_FAST.md').write_text('Synthetic fail-closed documentation.')
        (source/'CHECKPOINT.md').write_text('Synthetic checkpoint documentation.')
        self.secret_marker='synthetic-excluded-secret-'+os.urandom(16).hex()
        (source/'.env').write_text(self.secret_marker)
        self.token_marker='synthetic-excluded-token-'+os.urandom(16).hex()
        (source/'owner_token.txt').write_text(self.token_marker)
        return source
    def test_package_preserves_db_evidence_without_unallowlisted_files(self):
        import package_recovery
        self.f.seal();source=self.package_source();out=self.f.root/'backup.zip'
        result=package_recovery.package(self.f.path,out,source_dir=source,account=ACCOUNT)
        self.assertFalse(result['activated']);self.assertFalse(result['uploaded'])
        with zipfile.ZipFile(out) as z:
            names=z.namelist();self.assertIn('test_independent.py',names)
            self.assertTrue(any(n.startswith('evidence/') for n in names))
            self.assertNotIn('.env',names);self.assertNotIn('owner_token.txt',names)
            for name in names:
                self.assertNotIn(self.secret_marker.encode(),z.read(name))
                self.assertNotIn(self.token_marker.encode(),z.read(name))
            db=sqlite3.connect(':memory:')
            try:
                db.deserialize(z.read('reconstructed.sqlite'))
                self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'memory')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM writer').fetchone()[0],0)
                self.assertEqual(dict(db.execute('SELECT key,value FROM meta'))['phase'],'sealed')
            finally:db.close()
        p,h=self.f.receipt(out);self.assertEqual(self.f.l.activate(p,h)['phase'],'active')
    def test_package_rejects_unsealed_database(self):
        import package_recovery
        self.blocked(package_recovery.package,self.f.path,self.f.root/'backup.zip',source_dir=self.package_source(),account=ACCOUNT)
    def test_package_rejects_active_database(self):
        import package_recovery
        self.auth()
        self.blocked(package_recovery.package,self.f.path,self.f.root/'backup.zip',source_dir=self.package_source(),account=ACCOUNT)
    def test_symlink_alias_cannot_bypass_forbidden_runtime(self):
        original=self.f.root/'simulated-original-runtime';original.mkdir()
        alias=self.f.root/'runtime-alias';alias.symlink_to(original,target_is_directory=True)
        with mock.patch.object(m,'OLD_RUNTIME',original):
            self.blocked(m.Ledger.init_recovery,alias/'forbidden.sqlite',ACCOUNT)
        self.assertFalse((original/'forbidden.sqlite').exists())

if __name__=='__main__': unittest.main(verbosity=2)
