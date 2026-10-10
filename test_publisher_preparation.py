"""Synthetic-only draft permit tests. No live DB, browser, credentials or network."""
import base64
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import ledger as m
import publisher_preparation as prep
import checkpoint as cp
import denial_extension as de
from settings import BLOG_HOST

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a0N8AAAAASUVORK5CYII=')


def source(data, media_type='text/plain'):
    data = data.encode() if isinstance(data, str) else data
    return {'media_type': media_type, 'sha256': m.digest(data), 'size': len(data),
            'data_base64': base64.b64encode(data).decode()}


class Fixture:
    """Reusable synthetic full-archive/CLI fixture for integration tests."""
    def __init__(self, create=True):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-publisher-')
        self.root = Path(self.tmp.name); self.path = self.root / 'synthetic.sqlite'
        self.time = 1_800_000_000; self.serial = 0
        m.Ledger.init_recovery(self.path)
        self.l = m.Ledger(self.path, clock=lambda: self.time)
        with self.l.tx():
            review = self.l.blob(b'Synthetic review, not a live recovery')
            for key, value in {'phase': 'active', 'backup_hash': m.digest('synthetic backup'),
                'baseline_hash': m.digest('synthetic baseline'), 'review_hash': review,
                'baseline_library_id': 'synthetic-baseline-library'}.items(): self.l.put(key, value)
        self.auth = self.l.acquire('synthetic-publisher', 'publisher')
        self.owner, self.token = self.auth['owner'], self.auth['token']
        self.image = self.root / 'synthetic.png'; self.image.write_bytes(PNG)
        self.target = f'https://{BLOG_HOST}/9000001'
        self.payload = {'account': self.l.account, 'kind': 'publish', 'target': self.target,
            'parts': ['Synthetic exact root 🧩', 'Synthetic first reply\n' + self.target,
                      'Synthetic exact second reply', 'Synthetic exact third reply'],
            'image': {'path': str(self.image), 'sha256': m.digest(PNG), 'attach_part_index': 0},
            'preview': {'part_index': 1, 'url': self.target, 'required': True}}
        self.payload_path, self.payload_hash = self.save(self.payload)
        self.action = self.l.claim(self.owner, self.token, 'publish', self.target, self.payload_hash)['action_id']
        self.created = self.register() if create else None

    def close(self):
        self.l.close(); self.tmp.cleanup()

    def save(self, value):
        self.serial += 1; p = self.root / ('synthetic-record-%d.json' % self.serial)
        data = m.canonical(value).encode(); p.write_bytes(data)
        return p, m.digest(data)

    def register(self):
        return prep.create_preparation(self.l, self.owner, self.token, self.action,
            self.payload_path, self.payload_hash, 'browser-instance:synthetic', 'synthetic-tab')

    def begin(self, index):
        return prep.begin_step(self.l, self.owner, self.token, self.action, prep.STEP_IDS[index])['permit']

    def readback(self, index, final=False):
        count = 4 if final else max(1, index)
        read = {'mode': 'read_only', 'observed_at': self.time, 'reference': 'synthetic-read-' + str(self.serial),
            'parts': self.payload['parts'][:count],
            'original_image_sha256': self.payload['image']['sha256'] if final or index >= 1 else None,
            'image_present': bool(final or index >= 1),
            'first_reply_preview': {'part_index': 1, 'url': self.target, 'visible': True} if count >= 2 else None,
            'dom_source': 'dom'}
        if final:
            read.update(screenshot_source='screenshot', visual_review_source='visual',
                visual_inspected_at=self.time, visual_matches_exact_payload=True)
        return read

    def complete_record(self, permit):
        self.time += 1
        index = prep.STEP_IDS.index(permit['step_id'])
        return {'schema': 'publisher-draft-step-completion-v1',
            'binding': copy.deepcopy(permit['binding']), 'manifest_sha256': permit['manifest_sha256'],
            'step_id': permit['step_id'], 'nonce': permit['nonce'], 'operation': copy.deepcopy(permit['operation']),
            'call': {'reference': 'synthetic-call-' + permit['nonce'], 'tool_name': 'mcp__cua_repl__js',
                'started_at': permit['issued_at'], 'completed_at': self.time, 'outcome': 'completed',
                'browser_invocations': 1, 'final_submission': 'not_invoked',
                'request_source': 'request', 'result_source': 'result', 'operator_review_source': 'operator',
                'operator_reviewed_at': self.time, 'operation_matches_permit': True, 'other_mutations': 'none',
                'timestamp_basis': 'observed_outer_bounds',
                'timestamp_provenance': 'Synthetic clock captured immediately before invocation and after terminal result; no native exact timestamps.'},
            'readback': self.readback(index),
            'sources': {'request': source('Synthetic exact bounded request: ' + m.canonical(permit)),
                        'result': source('Synthetic completed one draft call: ' + permit['nonce']),
                        'operator': source('Synthetic reviewed one exact operation, zero final submission or other mutations: ' + permit['nonce']),
                        'dom': source('Synthetic raw DOM readback step ' + str(index))},
            'social_success': False}

    def complete(self, permit, record=None):
        record = record or self.complete_record(permit)
        path, h = self.save(record)
        return prep.complete_step(self.l, self.owner, self.token, self.action, path, h)

    def seal_record(self):
        self.time += 1
        return {'schema': 'publisher-draft-final-inspection-v1',
            'binding': copy.deepcopy(self.created['binding']), 'manifest_sha256': self.created['manifest_sha256'],
            'readback': self.readback(4, True), 'sources': {
                'dom': source('Synthetic fresh complete four-part composer DOM'),
                'screenshot': source(PNG, 'image/png'),
                'visual': source('Synthetic explicit visual comparison with exact four texts, original image and visible numeric first-reply preview')},
            'final_submission': 'not_invoked', 'social_success': False}

    def seal(self, record=None):
        path, h = self.save(record or self.seal_record())
        return prep.seal_preparation(self.l, self.owner, self.token, self.action, path, h)

    def prepare_all(self, seal=True):
        for index in range(5): self.complete(self.begin(index))
        if seal: self.seal()

    def evidence(self, outcome='absent'):
        proof = self.root / ('synthetic-' + outcome + '.txt'); proof.write_text('Synthetic read-only ' + outcome)
        row = self.l.row(self.action)
        value = {'schema': 'browser-action-evidence-v2', 'account': self.l.account, 'kind': 'publish',
            'target': self.target, 'payload_hash': self.payload_hash, 'intent_id': row['intent_id'],
            'outcome': outcome, 'observed_at': self.time, 'reference': 'synthetic-public-read',
            'proof_file': str(proof), 'proof_sha256': m.digest(proof.read_bytes()),
            'receipt_urls': [f'https://www.threads.com/@{self.l.account}/post/SyntheticPublication' + str(i) for i in range(4)] if outcome == 'present' else []}
        return self.save(value)[0]

    def record_denial(self):
        row = self.l.row(self.action)
        common = {key: row[key] for key in ('kind', 'payload_hash', 'intent_id', 'intent_at')}
        common.update(account=self.l.account, db_id=self.l.get('db_id'), action_id=self.action,
                      target=self.target, owner=self.owner)
        request = 'SYNTHETIC exact separate final Publish request'
        result = 'This action was rejected due to unacceptable risk. Do not bypass this rejection'
        context = {'schema': 'retained-preexecution-denial-context-v1', **common,
            'tool_name': 'mcp__cua_repl__js', 'request_text': request, 'result_text': result,
            'result_is_error': True, 'denied_at': self.time, 'tool_call_id': None,
            'missing_call_id_reason': 'Synthetic fixture has no actual browser call',
            'original_context_reference': 'synthetic-final-publish-denial-context',
            'execution_stage': 'before_tool_execution', 'submission_not_sent': True,
            'no_subsequent_browser_call': True, 'request_sha256': m.digest(request),
            'result_sha256': m.digest(result)}
        sp, sh = self.save(context)
        denial = {'schema': 'operator-attested-tool-denial-v1', **common, 'source_file': str(sp),
            'source_sha256': sh, 'attested_at': self.time,
            'provenance': 'operator_attested_original_tool_context'}
        dp, dh = self.save(denial)
        de.record_denied(self.l, self.owner, self.token, self.action, dp, dh)
        return denial, dh, context, sh

    def finalize_denial(self, denial_hash):
        row = self.l.row(self.action)
        body = self.root / 'synthetic-denial-approval.txt'
        body.write_text('SYNTHETIC exact denial bookkeeping closure, release and checkpoint. No retry.')
        approval = {'schema': 'operator-approved-denial-finalization-v1', 'account': self.l.account,
            'db_id': self.l.get('db_id'), 'action_id': self.action, 'intent_id': row['intent_id'],
            'intent_at': row['intent_at'], 'owner': self.owner, 'source_sha256': denial_hash,
            'proof_file': str(body), 'proof_sha256': m.digest(body.read_bytes()),
            'approval_reference': 'synthetic-exact-denial-approval',
            'decision': 'record_no_execution_release_run_and_require_checkpoint',
            'follow_retry_authorized': False, 'other_new_dispatch_authorized': False,
            'reviewed_at': self.time}
        ap, ah = self.save(approval)
        return de.finalize_denied_run(self.l, self.owner, self.token, self.action, ap, ah)


class PreparationTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()
    def tearDown(self): self.f.close()
    def blocked(self, fn, *args):
        with self.assertRaises(m.Blocked): fn(*args)

    def test_reserved_exact_payload_and_schema_unchanged(self):
        f = self.f
        self.assertEqual(m.schema_hash(f.l.db), m.expected_schema_hash())
        self.assertEqual(f.l.row(f.action)['state'], 'reserved')
        state = prep.preparation_records(f.l.db, f.l.account)[0]
        self.assertFalse(state['sealed']); self.assertIsNone(state['pending'])
        self.assertIn(f.payload_hash, prep.preparation_evidence_hashes(f.l.db, f.l.account))
        self.assertIn(m.digest(PNG), prep.preparation_evidence_hashes(f.l.db, f.l.account))

    def test_publish_without_preparation_rejected(self):
        other = Fixture(create=False)
        try: self.blocked(other.l.begin_write, other.owner, other.token, other.action, other.evidence())
        finally: other.close()

    def test_all_five_steps_then_seal_then_separate_publish(self):
        f = self.f; f.prepare_all()
        self.assertEqual(f.l.row(f.action)['state'], 'reserved')
        self.assertEqual(f.l.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 0)
        permit = f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        self.assertTrue(permit['may_dispatch'])
        self.assertEqual(permit['preparation_binding']['binding']['tab_id'], 'synthetic-tab')
        self.assertEqual(f.l.row(f.action)['state'], 'intent')

    def test_lost_permit_response_blocks_all_writes(self):
        f = self.f; f.begin(0)
        self.blocked(f.begin, 0); self.blocked(f.begin, 1)
        self.blocked(f.l.claim, f.owner, f.token, 'like', 'https://www.threads.com/@synthetic/post/Other', m.digest('like'))
        self.blocked(f.l.begin_write, f.owner, f.token, f.action, f.evidence())
        self.blocked(f.l.transition, f.owner, f.token, f.action, 'cancelled')
        self.blocked(f.l.transition, f.owner, f.token, f.action, 'unknown', 'must use exact helper')
        self.blocked(f.l.verify, f.owner, f.token, f.action, f.evidence('present'))
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_readonly_status_does_not_spend_or_repeat_permit(self):
        f = self.f; p = f.begin(0)
        for _ in range(2): self.assertEqual(f.l.status()['publisher_preparations'][0]['pending']['nonce'], p['nonce'])
        self.blocked(f.begin, 0)

    def test_wrong_order_duplicate_registration_and_completion_rejected(self):
        f = self.f; self.blocked(f.register); self.blocked(f.begin, 1)
        permit = f.begin(0); record = f.complete_record(permit); f.complete(permit, record)
        self.blocked(f.complete, permit, record); self.blocked(f.begin, 0)

    def test_unknown_stop_preserves_original_key_and_forbids_restart(self):
        f = self.f; permit = f.begin(0)
        self.blocked(prep.stop_unknown_step, f.l, f.owner, f.token, f.action, '0' * 64, 'wrong nonce')
        prep.stop_unknown_step(f.l, f.owner, f.token, f.action, permit['nonce'], 'Lost terminal result')
        self.assertEqual(f.l.row(f.action)['state'], 'unknown'); self.assertIsNone(f.l.row(f.action)['intent_id'])
        self.assertEqual(f.l.db.execute('SELECT action_id FROM stops').fetchone()[0], f.action)
        self.blocked(f.begin, 0); self.blocked(f.register)
        self.blocked(f.l.verify, f.owner, f.token, f.action, f.evidence('present'))
        self.blocked(f.l.acknowledge_reconciliation, f.owner, f.token, f.action)
        self.blocked(f.l.release, f.owner, f.token)

    def test_no_cancel_or_fake_present_after_completed_preparation(self):
        f = self.f; f.complete(f.begin(0))
        self.blocked(f.l.transition, f.owner, f.token, f.action, 'cancelled')
        self.blocked(f.l.verify, f.owner, f.token, f.action, f.evidence('present'))

    def test_early_seal_and_final_publish_rejected(self):
        f = self.f; self.blocked(f.seal)
        f.prepare_all(seal=False)
        self.blocked(f.l.begin_write, f.owner, f.token, f.action, f.evidence())
        f.seal(); self.blocked(f.seal)

    def test_stale_seal_blocks_publish(self):
        f = self.f; f.prepare_all(); f.time += 301
        self.blocked(f.l.begin_write, f.owner, f.token, f.action, f.evidence())

    def test_expired_step_remains_outstanding(self):
        f = self.f; permit = f.begin(0); f.time += 301
        self.blocked(f.complete, permit)
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_mutated_completion_fields_cannot_consume_step(self):
        f = self.f; permit = f.begin(0); base = f.complete_record(permit)
        mutations = [lambda r: r.update(nonce='0' * 64),
            lambda r: r['binding'].update(tab_id='different-tab'),
            lambda r: r['binding'].update(browser_session='different-browser'),
            lambda r: r['binding'].update(payload_hash='0' * 64),
            lambda r: r['operation'].update(operation='publish'),
            lambda r: r['call'].update(browser_invocations=2),
            lambda r: r['call'].update(final_submission='invoked'),
            lambda r: r['call'].update(other_mutations='hidden request'),
            lambda r: r['call'].update(timestamp_basis='native_exact_unavailable'),
            lambda r: r['call'].update(outcome='unknown'),
            lambda r: r['readback'].update(parts=['Changed root']),
            lambda r: r['readback'].update(mode='changing'),
            lambda r: r.update(social_success=True),
            lambda r: r['sources'].pop('dom')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                record = copy.deepcopy(base); mutate(record); self.blocked(f.complete, permit, record)
                self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])
        f.complete(permit, base)

    def test_mutated_final_inspection_cannot_seal(self):
        f = self.f; f.prepare_all(seal=False); base = f.seal_record()
        mutations = [lambda r: r['binding'].update(tab_id='wrong'),
            lambda r: r['readback']['parts'].__setitem__(3, 'wrong fourth'),
            lambda r: r['readback'].update(original_image_sha256='0' * 64),
            lambda r: r['readback']['first_reply_preview'].update(url=f'https://{BLOG_HOST}/9000002'),
            lambda r: r['readback']['first_reply_preview'].update(visible=False),
            lambda r: r['readback'].update(visual_matches_exact_payload=False),
            lambda r: r['readback'].update(mode='changing'),
            lambda r: r['sources'].update(screenshot=source('not screenshot', 'image/png')),
            lambda r: r.update(final_submission='invoked'),
            lambda r: r.update(social_success=True)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                record = copy.deepcopy(base); mutate(record); self.blocked(f.seal, record)
                self.assertFalse(prep.preparation_records(f.l.db, f.l.account)[0]['sealed'])
        f.seal(base)

    def test_original_paths_not_needed_after_registration(self):
        f = self.f; f.payload_path.unlink(); f.image.unlink()
        f.prepare_all(); closure = prep.preparation_evidence_hashes(f.l.db, f.l.account)
        self.assertIn(m.digest(PNG), closure)
        permit = prep.ensure_publish_prepared(f.l, f.owner, f.action)
        self.assertEqual(permit['binding']['payload_hash'], f.payload_hash)

    def test_upload_permit_uses_retained_hash_contract(self):
        f = self.f; f.complete(f.begin(0)); f.image.write_bytes(b'changed original path')
        value = prep.begin_step(f.l, f.owner, f.token, f.action, prep.STEP_IDS[1])
        self.assertFalse(value['external_publication_allowed'])
        self.assertEqual(value['media_source']['sha256'], m.digest(PNG))
        self.assertTrue(value['media_source']['extract_and_rehash_before_filechooser'])
        self.assertEqual(value['media_source']['attach_part_index'], 0)

    def test_closed_proof_graph_detects_missing_blob(self):
        f = self.f; f.prepare_all()
        dest = sqlite3.connect(':memory:'); dest.row_factory = sqlite3.Row; f.l.db.backup(dest)
        try:
            dest.execute('DROP TRIGGER blobs_no_delete'); dest.execute('DELETE FROM blobs WHERE hash=?', (m.digest(PNG),))
            self.blocked(prep.preparation_records, dest, f.l.account)
        finally: dest.close()

    def test_restored_sqlite_proof_graph_needs_no_original_files(self):
        f = self.f; f.prepare_all(); original = prep.preparation_evidence_hashes(f.l.db, f.l.account)
        dest = sqlite3.connect(':memory:'); dest.row_factory = sqlite3.Row; f.l.db.backup(dest)
        try:
            for path in f.root.glob('*.json'): path.unlink()
            f.image.unlink()
            self.assertEqual(prep.preparation_evidence_hashes(dest, f.l.account), original)
            self.assertTrue(prep.preparation_records(dest, f.l.account)[0]['sealed'])
        finally: dest.close()

    def test_status_never_counts_preparation_as_social_success(self):
        f = self.f; f.prepare_all(); result = f.l.status()
        self.assertFalse(result['may_dispatch'])
        self.assertEqual([a['state'] for a in result['actions']], ['reserved'])
        self.assertEqual(f.l.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 0)

    def test_unrelated_changes_blocked_between_completed_steps(self):
        f = self.f; f.complete(f.begin(0))
        self.blocked(f.l.claim, f.owner, f.token, 'like',
                     'https://www.threads.com/@synthetic/post/Other', m.digest('like'))

    def test_final_binding_clock_rollback_rejected(self):
        f = self.f; f.prepare_all(); b = prep.ensure_publish_prepared(f.l, f.owner, f.action)
        f.time += 2; prep.check_prepared_fresh(f.l, b)
        f.time -= 1
        self.blocked(prep.check_prepared_fresh, f.l, b)

    def test_permit_postcommit_expiry_never_returns_permission(self):
        f = self.f; original = f.l.ensure_storage; calls = 0
        def storage():
            nonlocal calls
            calls += 1
            original()
            if calls == 3: f.time += 301
        with patch.object(f.l, 'ensure_storage', storage): self.blocked(f.begin, 0)
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_completion_late_clock_rollback_rejected(self):
        f = self.f; permit = f.begin(0); record = f.complete_record(permit)
        # Remain inside freshness window while making clock go backwards during
        # proof persistence. The failed transaction must leave pending intact.
        f.time += 2; original = f.l.blob; calls = 0
        def blob(data):
            nonlocal calls
            calls += 1
            if calls == 1: f.time -= 1
            return original(data)
        with patch.object(f.l, 'blob', blob): self.blocked(f.complete, permit, record)
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_prepared_publish_cannot_verify_only_root_receipt(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        path = f.evidence('present'); value = json.loads(path.read_text())
        value['receipt_urls'] = value['receipt_urls'][:1]; path, _ = f.save(value)
        self.blocked(f.l.verify, f.owner, f.token, f.action, path)
        self.assertEqual(f.l.row(f.action)['state'], 'intent')

    def test_actual_denial_api_status_finalize_checkpoint_restore(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        _, dh, _, sh = f.record_denial()
        status = f.l.status()
        self.assertEqual(status['actions'][0]['state'], 'cancelled')
        self.assertEqual(status['publisher_preparations'][0]['termination_class'], 'denied_before_dispatch')
        self.assertEqual(status['publisher_preparations'][0]['new_verified_count'], 0)
        self.assertTrue(status['stops']); self.assertIsNotNone(status['writer'])
        self.blocked(f.begin, 0); self.blocked(f.l.transition, f.owner, f.token, f.action, 'cancelled')
        f.finalize_denial(dh)
        f.time += 4000  # Historical proof closure must never acquire a freshness expiry.
        self.assertEqual(f.l.status()['actions'][0]['state'], 'cancelled')
        _, manifest, _ = cp.check_snapshot(f.l.db)
        self.assertIn(dh, manifest['evidence_hashes']); self.assertIn(sh, manifest['evidence_hashes'])
        archive = f.root / 'synthetic-denied-checkpoint.zip'
        cp.package(f.path, archive, source_dir=ROOT)
        with zipfile.ZipFile(archive) as z:
            restored = sqlite3.connect(':memory:'); restored.row_factory = sqlite3.Row
            try:
                restored.deserialize(z.read('runtime.sqlite'))
                for path in f.root.glob('*.json'): path.unlink()
                f.image.unlink()
                for path in f.root.glob('*.txt'): path.unlink()
                _, restored_manifest, _ = cp.check_snapshot(restored)
                self.assertEqual(restored_manifest, manifest)
                self.assertEqual(prep.preparation_records(restored, f.l.account)[0]['termination_class'], 'denied_before_dispatch')
            finally: restored.close()

    def test_cancelled_without_denial_is_not_a_compatibility_bypass(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        clone = sqlite3.connect(':memory:'); clone.row_factory = sqlite3.Row; f.l.db.backup(clone)
        try:
            clone.execute("UPDATE actions SET state='cancelled' WHERE id=?", (f.action,))
            self.blocked(prep.preparation_records, clone, f.l.account)
        finally: clone.close()

    def test_denial_missing_corrupt_proofs_and_malformed_metadata_rejected(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        _, dh, _, sh = f.record_denial()
        mutations = [
            lambda db: db.execute('DELETE FROM blobs WHERE hash=?', (dh,)),
            lambda db: db.execute('DELETE FROM blobs WHERE hash=?', (sh,)),
            lambda db: db.execute("UPDATE blobs SET bytes=x'00' WHERE hash=?", (sh,)),
            lambda db: db.execute("UPDATE audit SET details=json_set(details,'$.resolution','unknown') WHERE event='denied_before_dispatch_recorded'"),
            lambda db: db.execute("UPDATE audit SET details=json_set(details,'$.retry_allowed',json('true')) WHERE event='denied_before_dispatch_recorded'"),
            lambda db: db.execute("UPDATE audit SET owner='different-owner' WHERE event='denied_before_dispatch_recorded'"),
            lambda db: db.execute("UPDATE audit SET details=json_set(details,'$.source_hash',?) WHERE event='denied_before_dispatch_recorded'", ('0' * 64,)),
            lambda db: db.execute('INSERT INTO receipts VALUES(?,?,?)', ('threads:post:Fake', f.action, dh)),
            lambda db: db.execute("INSERT INTO audit(at,account,owner,event,action_id,details) VALUES(?,?,?,?,?,?)", (f.time, f.l.account, f.owner, 'submitted_unverified', f.action, '{}')),
            lambda db: db.execute('DELETE FROM stops')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                clone = sqlite3.connect(':memory:'); clone.row_factory = sqlite3.Row; f.l.db.backup(clone)
                try:
                    for trigger in ('blobs_no_delete', 'blobs_no_update', 'audit_no_update'): clone.execute('DROP TRIGGER ' + trigger)
                    mutation(clone)
                    self.blocked(prep.preparation_records, clone, f.l.account)
                finally: clone.close()

    def test_normal_second_boundary_registration_succeeds(self):
        other = Fixture(create=False)
        try:
            original = other.l.blob; advanced = False
            def blob(data):
                nonlocal advanced
                if not advanced: other.time += 1; advanced = True
                return original(data)
            with patch.object(other.l, 'blob', blob): other.created = other.register()
            self.assertEqual(other.l.row(other.action)['state'], 'reserved')
            self.assertEqual(len(prep.preparation_records(other.l.db, other.l.account)), 1)
        finally: other.close()

    def test_normal_second_boundary_step_permit_succeeds(self):
        f = self.f; original = f.l.blob
        def blob(data): f.time += 1; return original(data)
        with patch.object(f.l, 'blob', blob): permit = f.begin(0)
        self.assertEqual(permit['expires_at'], permit['issued_at'] + 300)
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_normal_second_boundary_unknown_stop_succeeds(self):
        f = self.f; permit = f.begin(0); original = f.l.blob
        def blob(data): f.time += 1; return original(data)
        with patch.object(f.l, 'blob', blob):
            prep.stop_unknown_step(f.l, f.owner, f.token, f.action, permit['nonce'], 'Synthetic lost result')
        self.assertEqual(f.l.row(f.action)['state'], 'unknown')
        self.assertEqual(f.l.db.execute('SELECT action_id FROM stops').fetchone()[0], f.action)

    def test_normal_second_boundary_denial_finalization_succeeds(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        _, dh, _, _ = f.record_denial(); original = f.l.event
        def event(name, *args, **kwargs):
            f.time += 1
            return original(name, *args, **kwargs)
        with patch.object(f.l, 'event', event): f.finalize_denial(dh)
        self.assertEqual(f.l.status()['actions'][0]['state'], 'cancelled')
        cp.check_snapshot(f.l.db)

    def test_registration_step_unknown_actual_clock_rollback_rejected(self):
        other = Fixture(create=False)
        try:
            original = other.l.blob
            def blob(data): other.time -= 1; return original(data)
            with patch.object(other.l, 'blob', blob): self.blocked(other.register)
            self.assertEqual(prep.preparation_records(other.l.db, other.l.account), [])
        finally: other.close()
        f = self.f; original = f.l.blob
        def rollback(data): f.time -= 1; return original(data)
        with patch.object(f.l, 'blob', rollback): self.blocked(f.begin, 0)
        f.time += 1; permit = f.begin(0)
        with patch.object(f.l, 'blob', rollback):
            self.blocked(prep.stop_unknown_step, f.l, f.owner, f.token, f.action, permit['nonce'], 'Synthetic unknown')
        self.assertEqual(f.l.row(f.action)['state'], 'reserved')
        self.assertIsNotNone(prep.preparation_records(f.l.db, f.l.account)[0]['pending'])

    def test_explicit_final_publish_deadline_is_exclusive(self):
        f = self.f; f.prepare_all(); binding = prep.ensure_publish_prepared(f.l, f.owner, f.action)
        self.assertEqual(binding['expires_at'], binding['prepared_read_at'] + 300)
        f.time = binding['expires_at']
        self.blocked(prep.check_prepared_fresh, f.l, binding)

    def test_full_publish_verified_release_checkpoint_closure(self):
        f = self.f; f.prepare_all(); f.l.begin_write(f.owner, f.token, f.action, f.evidence())
        f.l.transition(f.owner, f.token, f.action, 'submitted_unverified')
        f.l.verify(f.owner, f.token, f.action, f.evidence('present')); f.l.release(f.owner, f.token)
        _, manifest, _ = cp.check_snapshot(f.l.db)
        self.assertTrue(set(prep.preparation_evidence_hashes(f.l.db, f.l.account)) <= set(manifest['evidence_hashes']))


if __name__ == '__main__': unittest.main()
