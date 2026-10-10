import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile
import json
import base64

from dispatch_gate import GateBlocked, action_id, canonical, payload_hash, successful
from test_coordinator import FakeAuthorization, FakeBrowser
import publisher_safety as p


class PublisherTests(unittest.TestCase):
    def setUp(self):
        p.STAGING_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=p.STAGING_ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = 'https://blog.example/1234'
        self.image = self.root/'original.png'
        self.image.write_bytes(b'\x89PNG\r\n\x1a\nsynthetic image fixture only')
        self.payload = {'target': self.target, 'article_id': 1234, 'blog_url': self.target,
            'root': '합성 본문', 'replies': ['첫 댓글 '+self.target, '두번째 합성 댓글', '세번째 합성 댓글'],
            'root_image_path': str(self.image), 'root_image_url': 'https://example.com/original.png',
            'image_sha256': hashlib.sha256(self.image.read_bytes()).hexdigest(), 'preview_reply_index': 1}
        self.action = {'kind': 'publish', 'target': self.target, 'payload': self.payload,
            'payload_hash': payload_hash(self.payload), 'authorization_id': 'synthetic-policy',
            'action_id': action_id('synthetic_account', 'publish', self.target)}
        self.binding = {'role': 'publisher', 'worker_id': 'synthetic-publisher',
            'browser_id': 'synthetic-instance', 'tab_id': 'synthetic-tab', 'account': 'synthetic_account'}
        self.intent = 'a'*64
        self.urls = [f'https://threads.com/@synthetic_account/post/part{i}' for i in range(4)]
        self.source = self.root/'actual-observation-synthetic.txt'
        self.source.write_text('\n'.join([*self.urls, self.payload['root'], *self.payload['replies'], '합성 미리보기 제목']))
        self.proof = {'schema': 'publisher-bundle-readback-v1', 'account': self.binding['account'],
            'target': self.target, 'payload_hash': self.action['payload_hash'], 'intent_id': self.intent,
            'observed_at': 1000, 'parts': [{'url': self.urls[i], 'parent_url': None if i==0 else self.urls[i-1],
                'account': self.binding['account'], 'text': text, 'observation_reference': 'synthetic-observation'}
                for i,text in enumerate([self.payload['root'], *self.payload['replies']])],
            'image': {'part_url': self.urls[0], 'source_sha256': self.payload['image_sha256'],
                'visible': True, 'visual_match': True, 'observation_reference': 'synthetic-observation'},
            'preview': {'part_url': self.urls[1], 'href': self.target, 'card_text': '합성 미리보기 제목',
                'observation_reference': 'synthetic-observation'},
            'reloaded': True, 'reload_reference': 'synthetic-observation',
            'source_records': [{'reference': 'synthetic-observation', 'path': str(self.source),
                'sha256': hashlib.sha256(self.source.read_bytes()).hexdigest()}]}

    def value(self, proof=None, receipts=None):
        path=self.root/'bundle-proof.json';path.write_text(canonical(p.make_self_contained_proof(proof or self.proof,self.action)))
        return {'evidence': {'outcome': 'present', 'receipt_urls': self.urls if receipts is None else receipts,
            'proof_file': str(path), 'proof_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}

    def check(self, proof=None, receipts=None):
        return p.validate_present_bundle(self.value(proof, receipts),self.action,self.binding,self.intent,now=1001)

    def test_full_synthetic_bundle_contract_passes(self):
        p.validate_payload(self.action)
        self.assertEqual(len(self.check()['parts']),4)

    def test_target_only_publish_payload_rejected(self):
        bad=copy.deepcopy(self.action);bad['payload']={'target':self.target}
        with self.assertRaises(GateBlocked):p.validate_payload(bad)

    def test_every_required_payload_field_and_image_hash_is_checked(self):
        for key in p.PAYLOAD_KEYS:
            bad=copy.deepcopy(self.action);del bad['payload'][key]
            with self.subTest(key=key),self.assertRaises(GateBlocked):p.validate_payload(bad)
        self.image.write_bytes(b'changed after approval')
        with self.assertRaises(GateBlocked):p.validate_payload(self.action)

    def test_one_root_receipt_never_verifies_bundle(self):
        with self.assertRaises(GateBlocked):self.check(receipts=self.urls[:1])

    def test_duplicate_unowned_and_reordered_receipts_reject(self):
        for urls in ([self.urls[0]]*4, [self.urls[0].replace('@synthetic_account','@other'),*self.urls[1:]], list(reversed(self.urls))):
            with self.assertRaises(GateBlocked):self.check(receipts=urls)

    def test_part_text_owner_parent_and_count_mismatch_reject(self):
        for key,value in (('text','different'),('account','other'),('parent_url',self.urls[0]),('url',self.urls[0])):
            proof=copy.deepcopy(self.proof);proof['parts'][2][key]=value
            with self.subTest(key=key),self.assertRaises(GateBlocked):self.check(proof)
        proof=copy.deepcopy(self.proof);proof['parts'].pop()
        with self.assertRaises(GateBlocked):self.check(proof)

    def test_image_preview_and_reload_are_required(self):
        changes=[('image','visible',False),('image','visual_match',False),('image','source_sha256','0'*64),
            ('preview','href','https://blog.example/999'),('preview','part_url',self.urls[2]),
            ('preview','card_text','not in real source')]
        for obj,key,value in changes:
            proof=copy.deepcopy(self.proof);proof[obj][key]=value
            with self.subTest(key=key),self.assertRaises(GateBlocked):self.check(proof)
        proof=copy.deepcopy(self.proof);proof['reloaded']=False
        with self.assertRaises(GateBlocked):self.check(proof)

    def test_reference_requires_actual_matching_observation_bytes(self):
        proof=copy.deepcopy(self.proof);proof['parts'][0]['observation_reference']='invented'
        with self.assertRaises(GateBlocked):self.check(proof)
        self.source.write_text('source changed')
        with self.assertRaises(GateBlocked):self.check()

    def test_stale_wrong_intent_and_wrong_hash_reject(self):
        for key,value in (('observed_at',700),('intent_id','b'*64),('payload_hash','b'*64)):
            proof=copy.deepcopy(self.proof);proof[key]=value
            with self.subTest(key=key),self.assertRaises(GateBlocked):self.check(proof)

    def test_retained_proof_survives_original_source_deletion(self):
        proof=p.make_self_contained_proof(self.proof,self.action)
        self.source.unlink();self.image.unlink()
        result=p.validate_retained_bundle(proof,self.action,self.binding,self.intent,receipts=self.urls,now=1001)
        self.assertEqual(len(result['parts']),4)

    def test_v1_external_path_proof_cannot_verify(self):
        with self.assertRaises(GateBlocked):
            p.validate_retained_bundle(self.proof,self.action,self.binding,self.intent,receipts=self.urls,now=1001)

    def test_oversized_original_rejects_during_preparation(self):
        self.image.write_bytes(b'\x89PNG\r\n\x1a\n'+b'x'*p.MAX_ORIGINAL_IMAGE_BYTES)
        self.action['payload']['image_sha256']=hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.action['payload_hash']=payload_hash(self.action['payload'])
        with self.assertRaises(GateBlocked):p.validate_payload(self.action)

    def test_retained_image_and_source_bytes_tamper_reject(self):
        proof=p.make_self_contained_proof(self.proof,self.action)
        for entry in (proof['original_image'],proof['source_records'][0]['embedded']):
            saved=entry['base64'];entry['base64']='aW52YWxpZA=='
            with self.assertRaises(GateBlocked):
                p.validate_retained_bundle(proof,self.action,self.binding,self.intent,receipts=self.urls,now=1001)
            entry['base64']=saved

    def test_receipt_domain_aliases_of_same_post_reject(self):
        urls=[self.urls[0],self.urls[0]+'/',self.urls[0].replace('threads.com','www.threads.com'),
              self.urls[0].replace('threads.com','threads.net')]
        with self.assertRaises(GateBlocked):self.check(receipts=urls)


class CoordinatorPublisherTests(unittest.TestCase):
    def setUp(self):
        p.STAGING_ROOT.mkdir(parents=True, exist_ok=True)
        from test_ledger_adapter_v2 import CoordinatorAdapterTests
        self.fixture=CoordinatorAdapterTests(methodName='test_exact_frozen_coordinator_reaches_real_checkpoint_boundary')
        self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        self.f=self.fixture
        self.c=p.guarded_coordinator(self.f.q,self.f.a.identity,clock=lambda:self.f.f.now,
            ledger=self.f.a,browser=self.f.browser,authorization=FakeAuthorization())

    def prepare(self, payload):
        b=self.f.bindings['publisher'];q=self.f.q;now=self.f.f.now
        e=q.record_observation('publisher',worker_id=b.worker_id,browser_id=b.browser_id,tab_id=b.tab_id,
            observed_account=b.expected_account,tab_exists=True,observed_at=now,now=now)
        j=q.enqueue('publisher',now-100,now+900,evidence_id=e,now=now)
        q.mark_ready(j['job_id'],{'actions':[{'kind':'publish','target':'https://blog.example/1234',
            'payload':payload,'authorization_id':'synthetic'}]},evidence_id=e,now=now)
        return j['job_id']

    def test_target_only_payload_blocks_before_writer_acquire(self):
        self.prepare({'target':'https://blog.example/1234'})
        self.assertEqual(self.c.run_once().state,'blocked')
        self.assertIsNone(successful(self.f.a.execute('status'))['writer'])
        self.assertFalse(self.f.browser.calls)

    def test_full_payload_with_root_only_readback_never_becomes_verified(self):
        helper=PublisherTests(methodName='test_full_synthetic_bundle_contract_passes');helper.setUp()
        self.addCleanup(helper.doCleanups)
        self.prepare(helper.payload)
        self.assertEqual(self.c.run_once().state,'blocked')
        status=successful(self.f.a.execute('status'))
        publish=[a for a in status['actions'] if a['kind']=='publish']
        self.assertEqual(len(publish),1)
        self.assertEqual(publish[0]['state'],'submitted_unverified')
        self.assertEqual(len(self.f.browser.mutations),1)
        self.assertIsNotNone(status['writer'])

    def test_real_ledger_checkpoint_retains_sources_and_image_without_runtime_files(self):
        from test_coordinator import reply
        import ledger_adapter_v2
        f=self.f
        helper=PublisherTests();helper.setUp();self.addCleanup(helper.doCleanups)
        # Ledger adapter accepts evidence paths only inside its synthetic fixture.
        image=f.f.root/'original.png';image.write_bytes(helper.image.read_bytes())
        payload=copy.deepcopy(helper.payload);payload['root_image_path']=str(image)
        self.prepare(payload)
        class BundleBrowser(FakeBrowser):
            def readback(self,action,binding,intent_id):
                value=successful(super().readback(action,binding,intent_id))
                urls=[f'https://threads.com/@{binding["account"]}/post/Retained{i}' for i in range(4)]
                source=self.folder/'bundle-observation.txt'
                source.write_text('RETAINED_SYNTHETIC_OBSERVATION\n'+'\n'.join(urls+[payload['root']]+payload['replies']+['Retained card']))
                proof=copy.deepcopy(helper.proof)
                proof.update(account=binding['account'],payload_hash=action['payload_hash'],intent_id=intent_id,observed_at=self.clock())
                for i,part in enumerate(proof['parts']):
                    part.update(url=urls[i],account=binding['account'],parent_url=None if i==0 else urls[i-1])
                proof['image'].update(part_url=urls[0])
                proof['preview'].update(part_url=urls[1],card_text='Retained card')
                proof['source_records'][0].update(path=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest())
                sealed=p.make_self_contained_proof(proof,action)
                path=Path(value['evidence']['proof_file']);path.write_text(canonical(sealed))
                value['evidence'].update(proof_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),receipt_urls=urls)
                Path(value['evidence_path']).write_text(canonical(value['evidence']))
                self.saved=(action,binding,intent_id,urls,self.clock(),str(source),str(path))
                return reply(value)
        browser=BundleBrowser(f.f.root,lambda:f.f.now)
        coordinator=p.guarded_coordinator(f.q,f.a.identity,clock=lambda:f.f.now,
            ledger=f.a,browser=browser,authorization=FakeAuthorization())
        self.assertEqual(coordinator.run_once().state,'needs_checkpoint')
        action,binding,intent,urls,at,source,proofpath=browser.saved
        archive=f.f.root/'retained-publisher.zip'
        f.f.cp.package(f.f.path,archive,source_dir=ledger_adapter_v2.FIXTURE_SOURCE_ROOT,account=f.a.identity.account)
        Path(source).unlink();image.unlink();Path(proofpath).unlink()
        with zipfile.ZipFile(archive) as z:
            sealed=None
            for name in z.namelist():
                if not name.startswith('evidence/'):continue
                try:record=json.loads(z.read(name))
                except (ValueError,UnicodeDecodeError):continue
                if type(record) is dict and record.get('schema')=='publisher-bundle-readback-v2':sealed=record
            self.assertIsNotNone(sealed)
            self.assertIn(b'RETAINED_SYNTHETIC_OBSERVATION',base64.b64decode(sealed['source_records'][0]['embedded']['base64']))
            self.assertEqual(hashlib.sha256(base64.b64decode(sealed['original_image']['base64'])).hexdigest(),payload['image_sha256'])
            p.validate_retained_bundle(sealed,action,binding,intent,receipts=urls,now=at)

if __name__=='__main__':unittest.main()
