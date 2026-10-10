"""Synthetic local observation envelopes only. No native browser calls."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import read_trial_driver as driver
from dispatch_gate import GateBlocked
from native_read_cli import read_step
from tool_bridge import BindingPin, FileToolBridge, RequestTicket, INTEGRATION_ROOT


class DriverTests(unittest.TestCase):
    protected=('synthetic-protected-browser','synthetic-protected-tab')

    def setUp(self):
        INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True)

    def pins(self,n):
        return [{'role':role,'worker_id':'synthetic-'+role,'browser_id':'synthetic-browser',
                 'tab_id':'synthetic-tab-'+role,'account':'synthetic_account'}
                for role in ('spreader','publisher','commenter')[:n]]

    def exercise(self,n):
        with tempfile.TemporaryDirectory(prefix='synthetic-read-trial-',dir=INTEGRATION_ROOT) as tmp:
            value=driver.publish(tmp,self.pins(n),'synthetic-read-reference',duration=30,protected=self.protected)
            with FileToolBridge(value['bridge_root']) as bridge:
                for item in value['tickets']:
                    pin=BindingPin.from_dict(item['binding']);ticket=RequestTicket(item['request_id'],item['request_digest'])
                    claim=read_step(bridge,'claim',ticket,pin)
                    observed={**pin.as_dict(),'exists':True,'logged_in':True,'observed_at':int(time.time())}
                    read_step(bridge,'begin',ticket,pin,claimed_at=claim['claimed_at'],data=observed)
                    # The completion represents a new observation after begin, not the preflight.
                    observed={**pin.as_dict(),'exists':True,'logged_in':True,'observed_at':int(time.time())}
                    result={'completed':True,'exit_code':0,'stdout':{'ok':True,'binding':observed},
                            'truncated':False,'session_id':None,'stderr':''}
                    read_step(bridge,'complete',ticket,pin,claimed_at=claim['claimed_at'],data=result)
            result=driver.consume(value['manifest'],value['manifest_sha256'])
            self.assertEqual(len(result['results']),n)
            self.assertTrue(Path(result['result_file']).is_file())
            with self.assertRaises(GateBlocked):driver.consume(value['manifest'],value['manifest_sha256'])

    def test_one_role_roundtrip(self):self.exercise(1)
    def test_three_roles_roundtrip(self):self.exercise(3)

    def test_protected_composer_rejects_before_ticket_creation(self):
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
            bindings=self.pins(1);bindings[0].update(browser_id=self.protected[0],tab_id=self.protected[1])
            with self.assertRaises(GateBlocked):driver.publish(tmp,bindings,'synthetic-read-reference',protected=self.protected)
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_duplicate_worker_and_wrong_manifest_hash_reject(self):
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
            pins=self.pins(3);pins[1]['worker_id']=pins[0]['worker_id']
            with self.assertRaises(GateBlocked):driver.publish(tmp,pins,'synthetic-read-reference',protected=self.protected)
            value=driver.publish(tmp,self.pins(1),'synthetic-read-reference',protected=self.protected)
            with self.assertRaises(GateBlocked):driver.consume(value['manifest'],'0'*64)

    def test_protection_is_required_before_any_ticket_creation(self):
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
            with self.assertRaises(TypeError):
                driver.publish(tmp,self.pins(1),'synthetic-read-reference')
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_invalid_protection_fails_before_any_ticket_creation(self):
        for protected in (None, (), ('', 'tab'), ('browser', ''), ('browser', ' tab'),
                          ('browser', 'tab\n'), ('browser', 'tab\x00'), ['browser', 'tab']):
            with self.subTest(protected=protected), tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
                with self.assertRaises(GateBlocked):
                    driver.publish(tmp,self.pins(1),'synthetic-read-reference',protected=protected)
                self.assertFalse(list(Path(tmp).iterdir()))

    def test_cli_requires_explicit_protection_before_reading_bindings(self):
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
            result=subprocess.run([sys.executable,'-B',str(Path(driver.__file__)),
                'publish','--root',tmp,'--bindings-file',str(Path(tmp)/'missing.json'),
                '--reference','synthetic-read-reference'],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn('--protected-browser-id',result.stderr)
            self.assertIn('--protected-tab-id',result.stderr)
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_protected_browser_alias_rejects_before_ticket_creation(self):
        for alias in ('cdp','iab','extension','mcpapps','IAB','CDP'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
                with self.assertRaises(GateBlocked):
                    driver.publish(tmp,self.pins(1),'synthetic-read-reference',
                                   protected=(alias,'synthetic-protected-tab'))
                self.assertFalse(list(Path(tmp).iterdir()))

    def test_clock_boundary_requires_separate_post_begin_observation(self):
        for fresh in (False,True):
            with self.subTest(fresh=fresh), tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
                clock=[1_800_000_000]
                with patch('time.time',side_effect=lambda:clock[0]):
                    value=driver.publish(tmp,self.pins(1),'synthetic-read-reference',
                                         duration=30,protected=self.protected)
                    item=value['tickets'][0]
                    pin=BindingPin.from_dict(item['binding'])
                    ticket=RequestTicket(item['request_id'],item['request_digest'])
                    with FileToolBridge(value['bridge_root']) as bridge:
                        claim=read_step(bridge,'claim',ticket,pin)
                        preflight={**pin.as_dict(),'exists':True,'logged_in':True,'observed_at':clock[0]}
                        clock[0]+=1
                        begun=read_step(bridge,'begin',ticket,pin,
                                        claimed_at=claim['claimed_at'],data=preflight)
                        self.assertLess(preflight['observed_at'],begun['dispatched_at'])
                        clock[0]+=1
                        observed={**preflight,'observed_at':clock[0]} if fresh else preflight
                        envelope={'completed':True,'exit_code':0,'stdout':{'ok':True,'binding':observed},
                                  'truncated':False,'session_id':None,'stderr':''}
                        if fresh:
                            read_step(bridge,'complete',ticket,pin,
                                      claimed_at=claim['claimed_at'],data=envelope)
                        else:
                            with self.assertRaises(GateBlocked):
                                read_step(bridge,'complete',ticket,pin,
                                          claimed_at=claim['claimed_at'],data=envelope)
                    if fresh:
                        accepted=driver.consume(value['manifest'],value['manifest_sha256'])
                        self.assertEqual(accepted['results'][0]['binding']['observed_at'],clock[0])
                        self.assertTrue(accepted['no_social_mutation'])

    def test_actual_subprocess_observe_only_roundtrip(self):
        with tempfile.TemporaryDirectory(dir=INTEGRATION_ROOT) as tmp:
            root=Path(tmp);trial=root/'trial';trial.mkdir()
            bindings=root/'bindings.json';bindings.write_text(json.dumps(self.pins(1)))
            def run(script,*args):
                result=subprocess.run([sys.executable,'-B',str(Path(driver.__file__).parent/script),
                    *map(str,args)],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr+result.stdout)
                self.assertEqual(result.stderr,'')
                value=json.loads(result.stdout);self.assertTrue(value['ok']);return value
            value=run('read_trial_driver.py','publish','--root',trial,'--bindings-file',bindings,
                '--reference','synthetic-read-reference','--duration','30',
                '--protected-browser-id',self.protected[0],'--protected-tab-id',self.protected[1])
            item=value['tickets'][0]
            args=['--root',value['bridge_root'],'--request-id',item['request_id'],
                  '--request-digest',item['request_digest'],'--binding-file',item['binding_file']]
            run('native_read_cli.py','inspect',*args)
            claim=run('native_read_cli.py','claim',*args)['result']
            observed={**item['binding'],'exists':True,'logged_in':True,'observed_at':int(time.time())}
            observation=root/'observation.json';observation.write_text(json.dumps(observed))
            run('native_read_cli.py','begin',*args,'--claimed-at',claim['claimed_at'],
                '--data-file',observation)
            # A subprocess may cross a second boundary during begin. Completion must
            # use a separately collected post-begin synthetic observation.
            observed={**item['binding'],'exists':True,'logged_in':True,'observed_at':int(time.time())}
            envelope=root/'completion.json';envelope.write_text(json.dumps({
                'completed':True,'exit_code':0,'stdout':{'ok':True,'binding':observed},
                'truncated':False,'session_id':None,'stderr':''}))
            run('native_read_cli.py','complete',*args,'--claimed-at',claim['claimed_at'],
                '--data-file',envelope)
            accepted=run('read_trial_driver.py','consume','--manifest',value['manifest'],
                         '--sha256',value['manifest_sha256'])
            self.assertTrue(accepted['no_social_mutation'])
            self.assertEqual(len(accepted['results']),1)

if __name__=='__main__':unittest.main()
