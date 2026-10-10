from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest

from dispatch_gate import GateBlocked, successful, action_id, payload_hash
from native_read_cli import read_step
from tool_bridge import BindingPin, FileToolBridge, INTEGRATION_ROOT, SlotContext, SyntheticTestCapability


class ReadCliTests(unittest.TestCase):
    def setUp(self):
        INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT);self.addCleanup(self.tmp.cleanup)
        self.bridge=FileToolBridge(Path(self.tmp.name)/'bridge',synthetic_capability=SyntheticTestCapability.for_tests_only(),clock=lambda:1000)
        self.addCleanup(self.bridge.close)
        self.pin=BindingPin('spreader','worker','browser-1','tab-1','synthetic_account')
        self.ctx=SlotContext(self.pin,900,1200,'synthetic-reference')
        self.obs={**self.pin.as_dict(),'exists':True,'logged_in':True,'observed_at':1000}

    def test_separate_steps_roundtrip_without_browser(self):
        t=self.bridge.submit('observe',self.ctx)
        self.assertEqual(read_step(self.bridge,'inspect',t,self.pin)['operation'],'observe')
        claim=read_step(self.bridge,'claim',t,self.pin)
        begin=read_step(self.bridge,'begin',t,self.pin,claimed_at=claim['claimed_at'],data=self.obs)
        self.assertEqual(begin['request']['binding'],self.pin.as_dict())
        result={'completed':True,'exit_code':0,'stdout':{'ok':True,'binding':self.obs},
                'truncated':False,'session_id':None,'stderr':''}
        read_step(self.bridge,'complete',t,self.pin,claimed_at=claim['claimed_at'],data=result)
        self.assertEqual(successful(self.bridge.take_result(t))['binding'],self.obs)

    def test_mutation_refused_even_with_synthetic_bridge(self):
        target='https://threads.com/@synthetic_other/post/abc';payload={'target':target}
        action={'kind':'repost','target':target,'payload':payload,'payload_hash':payload_hash(payload),
                'authorization_id':'synthetic-reference','action_id':action_id(self.pin.account,'repost',target)}
        ticket=self.bridge.submit('mutate',self.ctx,action=action,intent_id='a'*64)
        for op in ('inspect','claim','begin','complete'):
            with self.subTest(op=op),self.assertRaises(GateBlocked):read_step(self.bridge,op,ticket,self.pin)

    def test_claim_replay_wrong_binding_and_incomplete_response_refuse(self):
        t=self.bridge.submit('observe',self.ctx)
        wrong=BindingPin('spreader','other','browser-1','tab-1','synthetic_account')
        with self.assertRaises(GateBlocked):read_step(self.bridge,'claim',t,wrong)
        c=read_step(self.bridge,'claim',t,self.pin)
        with self.assertRaises(GateBlocked):read_step(self.bridge,'claim',t,self.pin)
        read_step(self.bridge,'begin',t,self.pin,claimed_at=c['claimed_at'],data=self.obs)
        with self.assertRaises(GateBlocked):read_step(self.bridge,'complete',t,self.pin,claimed_at=c['claimed_at'],data={'ok':True})

if __name__=='__main__':unittest.main()
