"""Real CLI subprocesses against synthetic local DB only; no browser/network."""
import json
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
import zipfile
import test_publisher_preparation as fixtures
m,cp,prep=fixtures.m,fixtures.cp,fixtures.prep
ROOT=Path(__file__).resolve().parent

class PreparationCliTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Fixture(create=False);self.addCleanup(self.f.close)

    def cli(self,command,*args,expected=0,source=None,db=None):
        f=self.f
        argv=['ledger.py',command,'--db',str(db or f.path),'--account',f.l.account,*args]
        code='import sys,ledger;ledger.time.time=lambda:'+str(f.time)+';sys.argv='+repr(argv)+';sys.exit(ledger.main())'
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=source or ROOT,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
        value=json.loads(result.stdout if expected==0 else result.stderr)
        self.assertIs(value['ok'],expected==0)
        self.assertNotIn(f.token,result.stdout+result.stderr)
        return value

    def auth(self):return ['--owner',self.f.owner,'--token',self.f.token,'--action',self.f.action]

    def test_all_steps_seal_final_and_real_restored_archive_ack(self):
        f=self.f
        value=self.cli('create-publisher-preparation',*self.auth(),'--payload-file',str(f.payload_path),'--payload-file-sha256',f.payload_hash,'--browser-session','browser-instance:synthetic','--tab-id','synthetic-tab')
        f.created=value
        self.assertFalse(value['may_dispatch'])
        self.cli('begin-write',*self.auth(),'--evidence',str(f.evidence()),expected=2)
        for index,step in enumerate(prep.STEP_IDS):
            begin=self.cli('begin-publisher-step',*self.auth(),'--step-id',step)
            self.assertTrue(begin['may_prepare']);self.assertFalse(begin['may_dispatch'])
            self.cli('begin-publisher-step',*self.auth(),'--step-id',step,expected=2)
            record=f.complete_record(begin['permit']);path,h=f.save(record)
            done=self.cli('complete-publisher-step',*self.auth(),'--record',str(path),'--sha256',h)
            self.assertFalse(done['social_success'])
            self.cli('complete-publisher-step',*self.auth(),'--record',str(path),'--sha256',h,expected=2)
        path,h=f.save(f.seal_record())
        self.cli('seal-publisher-preparation',*self.auth(),'--record',str(path),'--sha256',h)
        self.cli('seal-publisher-preparation',*self.auth(),'--record',str(path),'--sha256',h,expected=2)
        final=self.cli('begin-write',*self.auth(),'--evidence',str(f.evidence()))
        self.assertTrue(final['may_dispatch']);self.assertEqual(final['preparation_binding']['operation'],'final_publish_only')
        self.cli('begin-write',*self.auth(),'--evidence',str(f.evidence()),expected=2)
        self.cli('submitted',*self.auth())
        self.cli('verify',*self.auth(),'--evidence',str(f.evidence('present')))
        self.cli('release','--owner',f.owner,'--token',f.token)
        archive=f.root/'synthetic-checkpoint.zip';pack=cp.package(f.path,archive,source_dir=ROOT)
        with tempfile.TemporaryDirectory(prefix='synthetic-prep-restore-') as td:
            restored=Path(td)
            with zipfile.ZipFile(archive) as z:
                self.assertIn('publisher_preparation.py',z.namelist());self.assertIn('PREPARATION.md',z.namelist());self.assertIn('settings.py',z.namelist())
                z.extractall(restored)
            # Restore a disposable operational copy using its required WAL mode.
            restore_db=sqlite3.connect(restored/'runtime.sqlite')
            restore_db.execute('PRAGMA journal_mode=WAL');restore_db.close()
            for path in f.root.glob('*.json'):path.unlink()
            f.image.unlink()
            self.assertFalse(f.payload_path.exists())
            status=self.cli('status',source=restored,db=restored/'runtime.sqlite')
            self.assertTrue(status['checkpoint_pending']);self.assertTrue(status['publisher_preparations'][0]['sealed'])
            self.assertEqual(status['actions'][0]['state'],'verified')
            receipt={'schema':'library-checkpoint-roundtrip-v1','account':f.l.account,'db_id':f.l.get('db_id'),'baseline_hash':f.l.get('baseline_hash'),'checkpoint_seq':pack['checkpoint_seq'],'checkpoint_hash':pack['checkpoint_hash'],'library_file_id':'synthetic-runtime-library','library_version':'1','previous_version':'','archive_sha256':pack['archive_sha256'],'downloaded_archive':str(archive),'transport_reference':'Synthetic local copy only; no external Library transport','verified_at':f.time}
            rp=restored/'synthetic-receipt.json';rp.write_text(m.canonical(receipt))
            ack=self.cli('checkpoint-ack','--record',str(rp),'--sha256',m.digest(rp.read_bytes()),source=restored,db=restored/'runtime.sqlite')
            self.assertFalse(ack['checkpoint_pending'])
            next_owner=self.cli('acquire','--owner','synthetic-next','--role','commenter',source=restored,db=restored/'runtime.sqlite')
            self.assertTrue(next_owner['ok'])

    def test_uncertain_step_cli_stops_without_receipts(self):
        f=self.f
        self.cli('create-publisher-preparation',*self.auth(),'--payload-file',str(f.payload_path),'--payload-file-sha256',f.payload_hash,'--browser-session','browser-instance:synthetic','--tab-id','synthetic-tab')
        begin=self.cli('begin-publisher-step',*self.auth(),'--step-id',prep.STEP_IDS[0])
        self.cli('unknown-publisher-step',*self.auth(),'--nonce',begin['permit']['nonce'],'--reason','Synthetic terminal result uncertain')
        status=self.cli('status');self.assertEqual(status['actions'][0]['state'],'unknown');self.assertEqual(status['receipts'] if 'receipts' in status else f.l.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],0)
        self.cli('release','--owner',f.owner,'--token',f.token,expected=2)

if __name__=='__main__':unittest.main()
