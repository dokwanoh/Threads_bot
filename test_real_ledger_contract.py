"""Independent integration with copied real ledger code + synthetic browser only."""
import sys
from pathlib import Path
import tempfile, unittest
import queue_core
from queue_core import Binding,Schedule,QueueCore,initialize_staging
from coordinator import SerialCoordinator
from dispatch_gate import LedgerIdentity,CommandResult,canonical
from test_coordinator import FakeBrowser,FakeAuthorization
from test_independent import Fixture
import ledger

class SyntheticRealLedgerAdapter:
    def __init__(self,db):
        self.db=db;self.identity=LedgerIdentity(db.account,db.get('db_id'));self.calls=[];self.lose_begin=False
    def execute(self,command,**a):
        self.calls.append(command)
        try:
            if command=='status':out=self.db.status()
            elif command=='acquire':out=self.db.acquire(a['owner'],a['role'])
            elif command=='claim':out=self.db.claim(a['owner'],a['token'],a['kind'],a['target'],a['payload_hash'])
            elif command=='begin-write':
                out=self.db.begin_write(a['owner'],a['token'],a['action'],a['evidence'])
                if self.lose_begin:return CommandResult(False,None,'',session_id='synthetic-lost')
            elif command in ('submitted','unknown','cancel'):
                out=self.db.transition(a['owner'],a['token'],a['action'],{'submitted':'submitted_unverified','unknown':'unknown','cancel':'cancelled'}[command],a.get('reason',''))
            elif command=='verify':out=self.db.verify(a['owner'],a['token'],a['action'],a['evidence'])
            elif command=='release':out=self.db.release(a['owner'],a['token'])
            else:raise AssertionError(command)
            return CommandResult(True,0,canonical({'ok':True,**out}))
        except ledger.Blocked as e:return CommandResult(True,2,'',stderr=canonical({'ok':False,'may_dispatch':False,'error':str(e)}))

class RealLedgerContractTests(unittest.TestCase):
    def setUp(self):
        queue_core.STAGING_ROOT.mkdir(parents=True, exist_ok=True)
        self.f=Fixture();self.f.seal();p,h=self.f.receipt(self.f.make_archive());self.f.l.activate(p,h)
        self.now=self.f.now;self.f.l.clock=lambda:self.now
        self.temp=tempfile.TemporaryDirectory(dir=queue_core.STAGING_ROOT);self.root=Path(self.temp.name)
        self.la=SyntheticRealLedgerAdapter(self.f.l);self.browser=FakeBrowser(self.root,lambda:self.now)
        self.bindings={r:Binding('synthetic-'+r,'synthetic-cloud','tab-'+r,self.la.identity.account) for r in ('publisher','spreader','commenter')}
        self.identity=initialize_staging(self.root/'queue.sqlite',self.bindings,{r:Schedule(self.now-100,1000) for r in self.bindings},ledger_db_id=self.la.identity.db_id)
        self.q=QueueCore(self.root/'queue.sqlite',self.identity)
        self.c=SerialCoordinator(self.q,self.la.identity,clock=lambda:self.now,ledger=self.la,browser=self.browser,authorization=FakeAuthorization())
    def tearDown(self):self.temp.cleanup();self.f.close()
    def prepare(self):
        b=self.bindings['spreader'];e=self.q.record_observation('spreader',worker_id=b.worker_id,browser_id=b.browser_id,tab_id=b.tab_id,observed_account=b.expected_account,tab_exists=True,observed_at=self.now,now=self.now)
        job=self.q.enqueue('spreader',self.now-100,self.now+900,evidence_id=e,now=self.now)
        acts=[]
        for i in range(2):
            t=f'https://threads.com/@someone/post/IndependentContract{i}'
            acts.append({'kind':'like','target':t,'payload':{'target':t},'authorization_id':'synthetic-like'})
        self.q.mark_ready(job['job_id'],{'actions':acts},evidence_id=e,now=self.now)
        return job['job_id']
    def test_real_ledger_batch_contract_to_checkpoint_boundary(self):
        j=self.prepare();out=self.c.run_once();self.assertEqual(out.state,'needs_checkpoint')
        s=self.f.l.status();self.assertTrue(s['checkpoint_pending']);self.assertIsNone(s['writer']);self.assertFalse(s['stops'])
        self.assertEqual(len([a for a in s['actions'] if a['state']=='verified']),2)
        self.assertEqual(len(self.browser.mutations),2);self.assertEqual(self.la.calls.count('acquire'),1);self.assertEqual(self.la.calls.count('release'),1)
        self.assertEqual(self.q.inspect_job(j)['state'],'checkpoint_wait')
    def test_real_ledger_denial_retains_unknown_stop_and_writer(self):
        j=self.prepare();self.browser.outcome='denied';self.assertEqual(self.c.run_once().state,'blocked')
        s=self.f.l.status();self.assertEqual(len(s['stops']),1);self.assertIsNotNone(s['writer']);self.assertFalse(s['checkpoint_pending'])
        self.assertEqual(len([a for a in s['actions'] if a['state']=='unknown']),1)
        self.assertEqual(self.q.inspect_job(j)['state'],'blocked');self.assertEqual(len(self.browser.mutations),1)
    def test_real_ledger_lost_begin_response_never_dispatches(self):
        j=self.prepare();self.la.lose_begin=True;self.assertEqual(self.c.run_once().state,'blocked')
        self.assertFalse(self.browser.mutations);self.assertEqual(len([a for a in self.f.l.status()['actions'] if a['state']=='intent']),1)
        self.assertEqual(self.q.inspect_job(j)['state'],'blocked')

if __name__=='__main__':unittest.main(verbosity=2)
