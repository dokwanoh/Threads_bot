"""Real subprocess CLI regressions; credentials and DBs are synthetic/disposable."""
import json
import subprocess
import sys
import unittest
import ledger as m
from test_independent import ROOT,ACCOUNT
from test_denial_independent import IndependentDenialTests

class DenialCliTests(unittest.TestCase):
    def cli(self,command,record,sha,expect=2,module=False,db=None):
        cmd=[sys.executable,'-B']+(['-m','ledger'] if module else [str(ROOT/'ledger.py')])
        cmd += [command,'--db',str(db or self.f.path),'--account',ACCOUNT,'--record',str(record),'--sha256',sha]
        if command in ('record-denied-before-dispatch','finalize-denied-run'):
            cmd += ['--owner',self.auth['owner'],'--token',self.auth['token'],'--action',self.key]
        result=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=15)
        # Do not print command arguments or synthetic ownership token.
        self.assertEqual(result.returncode,expect,result.stdout+result.stderr)
        self.assertNotIn('Traceback',result.stdout+result.stderr)
        output=result.stdout if expect==0 else result.stderr
        self.assertEqual(result.stderr if expect==0 else result.stdout,'')
        self.assertEqual(len(output.strip().splitlines()),1)
        value=json.loads(output);self.assertEqual(value['ok'],expect==0);self.assertFalse(value['may_dispatch'])
        if expect!=0:self.assertFalse(value['automatic_retry'])
        return value

    def test_invalid_provenance_has_json_exit2_no_traceback(self):
        self.prepare();p,h=self.evidence(outer_updates={'provenance':'unreviewed'});before=self.snapshot()
        self.cli('record-denied-before-dispatch',p,h);self.assertEqual(before,self.snapshot())

    def test_bad_evidence_hash_has_json_exit2(self):
        self.prepare();p,h=self.evidence();before=self.snapshot()
        self.cli('record-denied-before-dispatch',p,'0'*64);self.assertEqual(before,self.snapshot())

    def test_wrong_kind_in_transaction_has_json_exit2(self):
        self.prepare();p,h=self.evidence(source_updates={'kind':'self_reply'});before=self.snapshot()
        self.cli('record-denied-before-dispatch',p,h);self.assertEqual(before,self.snapshot())

    def test_valid_denial_cli_retains_stop_and_owner(self):
        self.prepare();p,h=self.evidence();out=self.cli('record-denied-before-dispatch',p,h,expect=0)
        self.assertEqual(out['state'],'cancelled');self.assertTrue(out['stop_retained'])
        self.assertIsNotNone(self.f.l.status()['writer']);self.assertEqual(len(self.f.l.status()['stops']),1)

    def test_finalizer_invalid_scope_has_json_exit2(self):
        self.prepare();self.record();p,h=self.approval(updates={'other_new_dispatch_authorized':True});before=self.snapshot()
        self.cli('finalize-denied-run',p,h);self.assertEqual(before,self.snapshot())

    def test_finalizer_wrong_denial_has_json_exit2(self):
        self.prepare();self.record();p,h=self.approval(updates={'source_sha256':'0'*64});before=self.snapshot()
        self.cli('finalize-denied-run',p,h);self.assertEqual(before,self.snapshot())

    def test_valid_finalizer_cli_sets_checkpoint_gate(self):
        self.prepare();self.record();p,h=self.approval();out=self.cli('finalize-denied-run',p,h,expect=0)
        self.assertTrue(out['checkpoint_pending']);self.assertIsNone(self.f.l.status()['writer'])
        self.assertEqual(self.f.l.status()['stops'],[])

    def test_checkpoint_helper_error_has_json_exit2(self):
        p,h=self.f.record({'schema':'invalid'});before=self.snapshot()
        self.cli('checkpoint-ack',p,h);self.assertEqual(before,self.snapshot())

    def test_checkpoint_helper_success_via_cli(self):
        self.prepare();self.record();self.finalize();path,pkg=self.package()
        p,h=self.f.record(dict(schema='library-checkpoint-roundtrip-v1',account=ACCOUNT,
            db_id=pkg['db_id'],baseline_hash=pkg['baseline_hash'],checkpoint_seq=pkg['checkpoint_seq'],checkpoint_hash=pkg['checkpoint_hash'],
            library_file_id='synthetic-runtime-library-id',library_version='v1',previous_version='',archive_sha256=m.digest(path.read_bytes()),
            downloaded_archive=str(path),transport_reference='SYNTHETIC TEST ONLY. No Library upload.',verified_at=self.f.now))
        out=self.cli('checkpoint-ack',p,h,expect=0);self.assertFalse(out['checkpoint_pending'])

    def test_python_m_ledger_keeps_same_exception_identity(self):
        self.prepare();p,h=self.evidence(outer_updates={'provenance':'unreviewed'})
        self.cli('record-denied-before-dispatch',p,h,module=True)

    def test_missing_db_is_structured_and_not_created(self):
        p,h=self.f.record({'schema':'invalid'});missing=self.f.root/'missing.sqlite'
        self.cli('checkpoint-ack',p,h,db=missing);self.assertFalse(missing.exists())

for name in ('setUp','tearDown','blocked','prepare','evidence','record','approval','finalize','snapshot','package'):
    setattr(DenialCliTests,name,getattr(IndependentDenialTests,name))
del IndependentDenialTests
if __name__=='__main__':unittest.main(verbosity=2)
