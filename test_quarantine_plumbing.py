"""Synthetic CLI, checkpoint ACK, and archive dependency checks only."""
import json
import os
import shutil
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile

import test_quarantine_extension as fixtures
m,cp,ui=fixtures.m,fixtures.cp,fixtures.ui
ROOT=Path(__file__).resolve().parent


class PlumbingTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Fixture();self.addCleanup(self.f.close)

    def cli(self,*,missing=False,bad_sha=False):
        f=self.f
        pin=f.root/'independent-pin.json';pin.write_text(m.canonical(f.pin_dict))
        args=['ledger.py','finalize-uncertain-quarantine','--db',str(f.path),'--account',f.l.account,
              '--owner',f.owner,'--token',f.token,'--action',f.action,'--incident',str(f.ip),
              '--incident-sha256',f.ih,'--approval',str(f.ap),'--approval-sha256',f.ah]
        if not missing:args+=['--trusted-review',str(pin),'--trusted-review-sha256','0'*64 if bad_sha else m.digest(pin.read_bytes())]
        code='import sys,ledger;ledger.time.time=lambda:'+str(f.time)+';sys.argv='+repr(args)+';sys.exit(ledger.main())'
        return subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,text=True,timeout=20)

    def test_cli_exact_independent_gate_and_replay(self):
        f=self.f;before=f.snapshot()
        for kwargs in [{'missing':True},{'bad_sha':True}]:
            result=self.cli(**kwargs);self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertEqual(f.snapshot(),before)
        result=self.cli();self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertTrue(value['ok']);self.assertFalse(value['may_dispatch'])
        self.assertEqual(value['checkpoint_seq'],1);self.assertEqual(f.l.row(f.action)['state'],'cancelled')
        self.assertNotIn(f.token,result.stdout+result.stderr)
        after=f.snapshot();self.assertEqual(self.cli().returncode,2);self.assertEqual(after,f.snapshot())

    def checkpoint(self):
        f=self.f;f.finalize();archive=f.root/'checkpoint.zip'
        result=cp.package(f.path,archive,source_dir=ROOT,account=f.l.account)
        receipt={'schema':'library-checkpoint-roundtrip-v1','account':f.l.account,'db_id':f.l.get('db_id'),
            'baseline_hash':f.l.get('baseline_hash'),'checkpoint_seq':result['checkpoint_seq'],
            'checkpoint_hash':result['checkpoint_hash'],'library_file_id':'synthetic-runtime-library',
            'library_version':'synthetic-version-1','previous_version':'','archive_sha256':result['archive_sha256'],
            'downloaded_archive':str(archive),'transport_reference':'LOCAL SYNTHETIC ONLY, no actual Library transfer',
            'verified_at':f.time}
        path=f.root/'ack.json';path.write_text(m.canonical(receipt))
        return archive,receipt,path

    def test_actual_ack_then_next_run_still_blocks_exact_cancelled_key(self):
        archive,receipt,path=self.checkpoint();f=self.f
        with zipfile.ZipFile(archive) as z:
            self.assertIn('quarantine_extension.py',z.namelist())
            self.assertEqual(z.read('quarantine_extension.py'),(ROOT/'quarantine_extension.py').read_bytes())
        ack=cp.acknowledge(f.l,path,m.digest(path.read_bytes()))
        self.assertFalse(ack['checkpoint_pending']);self.assertFalse(ack['may_dispatch'])
        auth=f.l.acquire('synthetic-next-run','spreader')
        for url in [fixtures.TARGET,'https://threads.net/@another/post/SyntheticUncertainQuarantine/']:
            for kind in ['repost','like','reply','self_reply']:
                before=f.snapshot()
                with self.assertRaises(m.Blocked):f.l.claim(auth['owner'],auth['token'],kind,url,fixtures.PAYLOAD)
                self.assertEqual(before,f.snapshot())
        value=f.l.claim(auth['owner'],auth['token'],'like','https://threads.com/@unrelated/post/OtherAllowedSynthetic',fixtures.PAYLOAD)
        self.assertEqual(value['state'],'reserved')
        status=f.l.status();self.assertEqual(len(status['quarantines']),1)
        terminal=next(a for a in status['actions'] if a['id']==f.action)
        self.assertEqual(terminal['external_outcome'],'unknown');self.assertEqual(terminal['termination'],'operator_accepted_uncertainty')
        self.assertEqual(terminal['new_verified_count'],0);self.assertIs(terminal['retry_allowed'],False)

    def test_extracted_archive_alone_acks_then_blocks_sixteen_aliases(self):
        archive,receipt,_=self.checkpoint();f=self.f
        with tempfile.TemporaryDirectory(prefix='synthetic-extracted-checkpoint-') as tmp:
            restored=Path(tmp)
            with zipfile.ZipFile(archive) as z:z.extractall(restored)
            copied=restored/'checkpoint.zip';shutil.copyfile(archive,copied)
            receipt['downloaded_archive']=str(copied)
            ack=restored/'ack.json';ack.write_text(m.canonical(receipt))
            account,now,action=f.l.account,f.time,f.action
            f.l.close();shutil.rmtree(f.root)
            self.assertFalse(f.root.exists())
            script=r"""
import contextlib,io,json,os,sqlite3,sys
from pathlib import Path
sys.path.insert(0,os.getcwd())
import ledger as m,checkpoint as cp,quarantine_extension as ui,settings
for module in (m,cp,ui,settings):
    assert Path(module.__file__).resolve().parent==Path.cwd()
account,now,action=sys.argv[1:];now=int(now)
m.time.time=lambda:now
path=Path('runtime.sqlite');ack=Path('ack.json')
# Archive snapshots are DELETE-mode; only the disposable restored working copy is opened in WAL.
restored_db=sqlite3.connect(path)
assert restored_db.execute('PRAGMA journal_mode=WAL').fetchone()[0]=='wal'
restored_db.close()
sys.argv=['ledger.py','checkpoint-ack','--db',str(path),'--account',account,
          '--record',str(ack),'--sha256',m.digest(ack.read_bytes())]
output=io.StringIO()
with contextlib.redirect_stdout(output):code=m.main()
assert code==0,output.getvalue()
result=json.loads(output.getvalue());assert result['ok'] and not result['checkpoint_pending']
assert result['may_dispatch'] is False
l=m.Ledger(path,account,clock=lambda:now)
try:
    auth=l.acquire('synthetic-restored-writer','spreader');blocked=0
    for domain in ('threads.com','www.threads.com','threads.net','www.threads.net'):
        for kind in ('repost','like','reply','self_reply'):
            before='\n'.join(l.db.iterdump())
            try:l.claim(auth['owner'],auth['token'],kind,
                        'https://'+domain+'/@different_handle/post/SyntheticUncertainQuarantine/',
                        m.digest('synthetic restored payload'))
            except m.Blocked:blocked+=1
            else:raise AssertionError('Quarantined alias escaped')
            assert before=='\n'.join(l.db.iterdump())
    status=l.status();row=next(a for a in status['actions'] if a['id']==action)
    assert row['external_outcome']=='unknown' and row['new_verified_count']==0
    assert row['retry_allowed'] is False and row['quarantined'] is True
    assert len(status['quarantines'])==1
    other=l.claim(auth['owner'],auth['token'],'like',
                  'https://threads.com/@unrelated/post/SyntheticRestoredOther',m.digest('other'))
    assert other['state']=='reserved'
    print(json.dumps({'blocked_aliases':blocked,'unrelated_state':other['state']}))
finally:l.close()
"""
            env={k:v for k,v in os.environ.items() if not k.startswith(('PYTHON','THREADS_BOT_'))}
            result=subprocess.run([sys.executable,'-I','-B','-c',script,account,str(now),action],
                                  cwd=restored,env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout),{'blocked_aliases':16,'unrelated_state':'reserved'})

    def test_archive_missing_helper_rejected_even_with_rehashed_manifest(self):
        archive,receipt,path=self.checkpoint();f=self.f
        with zipfile.ZipFile(archive) as z:members={n:z.read(n) for n in z.namelist()}
        del members['quarantine_extension.py']
        manifest=json.loads(members['PACKAGE_MANIFEST.json']);del manifest['members']['quarantine_extension.py']
        members['PACKAGE_MANIFEST.json']=m.canonical(manifest).encode()
        modified=f.root/'missing-helper.zip'
        with zipfile.ZipFile(modified,'w') as z:
            for name,data in members.items():z.writestr(name,data)
        receipt.update(downloaded_archive=str(modified),archive_sha256=m.digest(modified.read_bytes()))
        path.write_text(m.canonical(receipt));before=f.snapshot()
        with self.assertRaises(m.Blocked):cp.acknowledge(f.l,path,m.digest(path.read_bytes()))
        self.assertEqual(before,f.snapshot());self.assertEqual(f.l.get('checkpoint_pending'),'1')

if __name__=='__main__':unittest.main()
