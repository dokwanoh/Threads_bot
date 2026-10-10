"""Synthetic staging fixtures only. No browser, live database, or real approval."""
import base64
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import ledger as m
import checkpoint as cp
import quarantine_extension as ui

TARGET = 'https://www.threads.com/@synthetic_actor/post/SyntheticUncertainQuarantine'
PAYLOAD = m.digest('synthetic repost payload')


def source(data, media_type='text/plain'):
    data = data.encode() if isinstance(data, str) else data
    return {'media_type': media_type, 'sha256': m.digest(data), 'size': len(data),
            'data_base64': base64.b64encode(data).decode()}


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-uncertain-quarantine-')
        self.root = Path(self.tmp.name)
        self.path = self.root / 'synthetic.sqlite'
        self.time = 1_800_000_000
        self.base = self.time
        self.target = TARGET
        m.Ledger.init_recovery(self.path)
        self.l = m.Ledger(self.path, clock=lambda: self.time)
        # Explicit synthetic fixture activation, never a production recovery shortcut.
        with self.l.tx():
            review = self.l.blob(b'Synthetic baseline review only')
            for key, val in {'phase': 'active', 'backup_hash': m.digest('synthetic backup'),
                             'review_hash': review, 'baseline_hash': m.digest('synthetic baseline'),
                             'baseline_library_id': 'synthetic-baseline-library-id'}.items():
                self.l.put(key, val)
        self.auth = self.l.acquire('synthetic-ui-run', 'spreader')
        self.owner, self.token = self.auth['owner'], self.auth['token']
        self.action = self.l.claim(self.owner, self.token, 'repost', self.target, PAYLOAD)['action_id']
        p = self.root / 'preflight.txt'
        p.write_text('Synthetic read-only original absence')
        evidence = {'schema': 'browser-action-evidence-v2', 'account': self.l.account, 'kind': 'repost',
                    'target': self.target, 'payload_hash': PAYLOAD, 'intent_id': None, 'outcome': 'absent',
                    'observed_at': self.time, 'reference': 'synthetic-original-preflight',
                    'proof_file': str(p), 'proof_sha256': m.digest(p.read_bytes()), 'receipt_urls': []}
        self.preflight = self.root / 'preflight.json'
        self.preflight.write_text(m.canonical(evidence))
        self.intent = self.l.begin_write(self.owner, self.token, self.action, self.preflight)['intent_id']
        self.time += 3
        self.l.transition(self.owner, self.token, self.action, 'unknown', 'Synthetic menu loading UI-abort')
        self.original_intent = dict(self.l.row(self.action))
        self.make_evidence()

    def make_evidence(self):
        b = {'account': self.l.account, 'db_id': self.l.get('db_id'), 'action_id': self.action,
             'kind': 'repost', 'target': self.target, 'payload_hash': PAYLOAD, 'intent_id': self.intent,
             'intent_at': self.base, 'owner': self.owner, 'session': self.auth['session'],
             'run_started_at': self.base,
             'stop': dict(self.l.db.execute('SELECT * FROM stops').fetchone()),
             'expected_checkpoint_seq': 0, 'browser_session': 'browser-instance:1', 'tab_id': 'synthetic-tab'}
        sources = {'request': source('Synthetic original tool code: open once, read menu, raise Unexpected repost menu; no repost selected, otherwise final branch.'),
                   'result': source('Script completed; error: Unexpected repost menu; no repost selected'),
                   'operator': source('Synthetic original operator: authentic completed single call and exact guard before final submission, no pending call or later mutation; external outcome remains unknown and whole-post quarantine approval is separately reviewed.'),
                   'current_operator': source('Synthetic current operator: original call terminal, outstanding calls zero, no subsequent changing call. Original synthetic-tab was absent from listTabs after cleanup, without an observed explicit close call; actual current read-only replacement is synthetic-replacement-tab in the same observed CUA browser-instance:1, same account and ledger session. Native start/end timestamps are unavailable; retained reminder boundaries are conservative request lower/completion upper bounds.'),
                   'target': source('Synthetic refreshed target DOM: aggregate count only; personal repost state unknown.'),
                   'profile': source('Synthetic virtualized profile feed: target unseen, feed not exhausted, outcome unknown.')}
        failed = {'incident_protocol': 'legacy_current_ui_single_call_v1', 'completed_call_count': 1, 'tool_name': 'mcp__cua_repl__js', 'original_context_reference': 'synthetic-tool-context',
                  'tool_call_id': None, 'missing_call_id_reason': 'Synthetic original transport did not expose an ID',
                  'request_source': 'request', 'result_source': 'result', 'request_started_at': self.base + 1,
                  'completed_at': self.base + 2, 'timestamp_basis': 'observed_outer_bounds',
                  'timestamp_provenance': 'Synthetic reminder immediately before request is the lower bound; reminder following terminal result is the upper bound; exact native timestamps are unavailable.',
                  'completion': 'completed_error',
                  'execution_stage': 'after_menu_open_before_final_submit', 'final_submission': 'not_invoked',
                  'subsequent_mutations': 'none', 'outstanding_call': 'none'}
        observations = []
        for index, (signal, sid) in enumerate((('refreshed_target_state', 'target'), ('limited_account_repost_state', 'profile'))):
            observations.append({'signal': signal, 'classification': 'unknown', 'coverage': 'partial', 'limitations': 'Virtualized/incomplete or aggregate-only readback cannot establish absence.',
                                 **{key: b[key] for key in ('account', 'target', 'browser_session')},
                                 'tab_id': 'synthetic-replacement-tab',
                                 'mode': 'read_only', 'observed_at': self.base + 10 + index,
                                 'refreshed_at': self.base + 10 + index, 'reference': 'synthetic-read-' + sid,
                                 'source_ids': [sid]})
        self.incident = {'schema': 'legacy-current-ui-uncertainty-incident-v2', 'binding': b, 'source_sha256': '',
                         'bundle': {'schema': 'retained-uncertain-quarantine-sources-v2', 'disposition': dict(ui.DISPOSITION), 'failed_call': failed,
                                    'reconciliation': {'schema': 'replacement-tab-readback-provenance-v1',
                                        'original_browser_session': b['browser_session'], 'original_tab_id': b['tab_id'],
                                        'browser_session': b['browser_session'], 'tab_id': 'synthetic-replacement-tab',
                                        'browser_identity_basis': 'observed_cua_browser_instance_not_native_session',
                                        'account': b['account'], 'ledger_session': b['session'], 'target': b['target'],
                                        'classification': 'original_tab_unavailable_replacement_read_only',
                                        'original_tab_state': 'not_listed_after_cleanup',
                                        'original_tab_unavailable_reason': 'Synthetic listTabs after cleanup did not return the original tab; no explicit close call was observed.',
                                        'replacement_tab_state': 'current',
                                        'mode': 'read_only', 'operator_source': 'current_operator'},
                                    'observations': observations, 'operator_review': {
                                        'reviewer': 'synthetic-parent-reviewer', 'reference': 'synthetic-independent-review-context',
                                        'reviewed_at': self.base + 12, 'source': 'operator', 'classification': ui.CLASSIFICATION,
                                        'trace_classification': 'authentic_completed_single_call_exact_guard_before_final_submission_no_pending_or_later_mutations'}, 'sources': sources}}
        aps = {'question': source('Synthetic exact pending question: accept unknown outcome, permanently quarantine the entire canonical post across all post write kinds, and release the account after verified checkpoint for other targets, without retry?'),
               'answer': source('Synthetic owner affirmative answer to that exact question: yes.'),
               'context': source('Synthetic authenticated conversation context links the exact question, owner answer and incident.')}
        self.approval = {'schema': 'uncertain-quarantine-approval-v1', 'binding': dict(b), 'source_sha256': '', 'proof_sha256': '',
                         'bundle': {'schema': 'retained-uncertain-quarantine-approval-v1',
                                    'pending_question_reference': 'synthetic-pending-question',
                                    'affirmative_answer_reference': 'synthetic-owner-answer', 'question_source': 'question',
                                    'answer_source': 'answer', 'context_source': 'context', 'question_at': self.base + 13,
                                    'answer_at': self.base + 14, 'decision': ui.DECISION,
                                    'accepted_external_outcome': 'unknown', 'quarantine_scope': ui.QUARANTINE_SCOPE,
                                    'resume_scope': ui.RESUME_SCOPE, 'new_verified_count': 0, 'retry_authorized': False,
                                    'new_social_dispatch_authorized': False, 'reviewed_at': self.base + 15, 'sources': aps}}
        self.time = self.base + 16
        self.write()

    def write(self, repin=True):
        self.incident['source_sha256'] = m.digest(m.canonical(self.incident['bundle']))
        self.ip = self.root / 'incident.json'
        self.ip.write_text(m.canonical(self.incident))
        self.ih = m.digest(self.ip.read_bytes())
        self.approval['source_sha256'] = self.ih
        self.approval['proof_sha256'] = m.digest(m.canonical(self.approval['bundle']))
        self.ap = self.root / 'approval.json'
        self.ap.write_text(m.canonical(self.approval))
        self.ah = m.digest(self.ap.read_bytes())
        if repin:
            ib, ab = self.incident['bundle'], self.approval['bundle']
            s, aps = ib['sources'], ab['sources']
            self.pin_dict = {'schema': 'trusted-uncertain-quarantine-review-pin-v1', 'incident_sha256': self.ih,
                             'approval_sha256': self.ah, 'pending_question_reference': 'synthetic-pending-question',
                             'pending_question_sha256': aps['question']['sha256'],
                             'affirmative_answer_reference': 'synthetic-owner-answer',
                             'affirmative_answer_sha256': aps['answer']['sha256'], 'approval_context_sha256': aps['context']['sha256'],
                             'failed_request_sha256': s['request']['sha256'], 'failed_result_sha256': s['result']['sha256'],
                             'failed_context_reference': 'synthetic-tool-context', 'operator_attestation_sha256': s['operator']['sha256'],
                             'reconciliation_provenance_sha256': s['current_operator']['sha256'],
                             'reconciliation_source_sha256': [s['target']['sha256'], s['profile']['sha256']],
                             'reviewer': 'synthetic-parent-reviewer', 'review_context_reference': 'synthetic-independent-review-context',
                             'reviewed_at': self.base + 15, 'classification': ui.CLASSIFICATION}
            self.pin = ui.TrustedReviewPin.from_dict(self.pin_dict)

    def finalize(self, **kwargs):
        return ui.finalize_uncertain_quarantine(self.l, self.owner, self.token, self.action,
                                                   self.ip, self.ih, self.ap, self.ah,
                                                   trusted_review=kwargs.get('trusted_review', self.pin))

    def snapshot(self):
        return '\n'.join(self.l.db.iterdump())

    def close(self):
        self.l.close()
        self.tmp.cleanup()


class UncertainQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def tearDown(self):
        self.f.close()

    def blocked(self, callback=None, errors=(m.Blocked,)):
        before = self.f.snapshot()
        with self.assertRaises(errors):
            (callback or self.f.finalize)()
        self.assertEqual(before, self.f.snapshot())

    def test_happy_path_atomic_and_preserves_original_intent(self):
        f = self.f
        old_events = list(f.l.db.execute('SELECT seq,event,details FROM audit'))
        old_blobs = set(r[0] for r in f.l.db.execute('SELECT hash FROM blobs'))
        result = f.finalize()
        self.assertEqual(result['termination_class'], ui.SUBTYPE)
        self.assertEqual(result['external_outcome'], 'unknown')
        self.assertEqual(result['termination'], 'operator_accepted_uncertainty')
        self.assertEqual(result['new_verified_count'], 0)
        self.assertFalse(result['retry_allowed'])
        self.assertFalse(result['may_dispatch'])
        self.assertEqual(result['newly_verified_actions'], 0)
        row = dict(f.l.row(f.action))
        for key in ('id', 'intent_id', 'intent_at', 'session', 'target_key', 'target_url', 'payload_hash', 'created_at'):
            self.assertEqual(row[key], f.original_intent[key])
        self.assertEqual(row['state'], 'cancelled')
        self.assertFalse(f.l.db.execute('SELECT 1 FROM stops').fetchone())
        self.assertFalse(f.l.db.execute('SELECT 1 FROM writer').fetchone())
        self.assertEqual(f.l.get('checkpoint_pending'), '1')
        self.assertEqual(f.l.get('checkpoint_seq'), '1')
        self.assertEqual([tuple(r) for r in f.l.db.execute('SELECT seq,event,details FROM audit LIMIT ?', (len(old_events),))], [tuple(r) for r in old_events])
        self.assertTrue(old_blobs <= set(r[0] for r in f.l.db.execute('SELECT hash FROM blobs')))
        self.assertEqual(f.l.db.execute('SELECT state FROM runs').fetchone()[0], 'released')

    def test_independent_pin_mandatory(self):
        for value in (None, True, self.f.pin_dict, {'approved': True}):
            with self.subTest(value=type(value).__name__):
                self.blocked(lambda: self.f.finalize(trusted_review=value))

    def test_separate_pin_loader_requires_exact_schema_and_hash(self):
        p = self.f.root / 'independent-pin.json'
        p.write_text(m.canonical(self.f.pin_dict))
        self.assertEqual(ui.load_trusted_review(p, m.digest(p.read_bytes())), self.f.pin)
        with self.assertRaises(m.Blocked):
            ui.load_trusted_review(p, '0' * 64)
        invalid = dict(self.f.pin_dict, approved=True)
        with self.assertRaises(m.Blocked):
            ui.TrustedReviewPin.from_dict(invalid)

    def test_incident_change_after_parent_review(self):
        self.f.incident['bundle']['sources']['result'] = source('Changed error: Unexpected repost menu; no repost selected')
        self.f.write(repin=False)
        self.blocked()

    def test_wrong_exact_binding(self):
        changes = {'account': 'other.account', 'db_id': 'another-db', 'action_id': 'a' * 64, 'kind': 'like',
                   'target': 'https://www.threads.net/@alias/post/SyntheticUncertainQuarantine', 'payload_hash': 'b' * 64,
                   'intent_id': 'c' * 64, 'intent_at': self.f.base - 1, 'owner': 'other-owner',
                   'session': 'other-session', 'run_started_at': self.f.base - 1, 'expected_checkpoint_seq': 1}
        for key, val in changes.items():
            with self.subTest(field=key):
                original = self.f.incident['binding'][key]
                self.f.incident['binding'][key] = val
                self.f.approval['binding'][key] = val
                self.f.write()
                self.blocked()
                self.f.incident['binding'][key] = original
                self.f.approval['binding'][key] = original
        self.f.write()

    def test_wrong_stop_identity(self):
        self.f.incident['binding']['stop'] = {**self.f.incident['binding']['stop'], 'reason': 'Other stop'}
        self.f.approval['binding'] = dict(self.f.incident['binding'])
        self.f.write()
        self.blocked()

    def test_wrong_writer_token(self):
        self.f.token = '0' * 64
        self.blocked()

    def test_missing_or_unrelated_approval(self):
        for key, val in (('pending_question_reference', 'github-upload-question'),
                         ('affirmative_answer_reference', 'github-upload-yes'),
                         ('decision', 'denied'), ('retry_authorized', True),
                         ('new_social_dispatch_authorized', True)):
            with self.subTest(field=key):
                before = self.f.approval['bundle'][key]
                self.f.approval['bundle'][key] = val
                self.f.write()
                self.blocked()
                self.f.approval['bundle'][key] = before
        self.f.write()
        self.f.ap.unlink()
        self.blocked(errors=(OSError,))

    def test_unrelated_approval_context_bytes(self):
        self.f.approval['bundle']['sources']['context'] = source('Unrelated GitHub upload approval context')
        self.f.write(repin=False)
        self.blocked()

    def test_incomplete_or_mutating_tool_state(self):
        changes = {'completion': 'running', 'execution_stage': 'before_tool_execution',
                   'final_submission': 'invoked', 'subsequent_mutations': 'one', 'outstanding_call': 'pending'}
        for key, val in changes.items():
            with self.subTest(field=key):
                before = self.f.incident['bundle']['failed_call'][key]
                self.f.incident['bundle']['failed_call'][key] = val
                self.f.write()
                self.blocked()
                self.f.incident['bundle']['failed_call'][key] = before

    def test_missing_operator_attestation_raw(self):
        self.f.incident['bundle']['sources']['operator'] = source('')
        self.f.write()
        self.blocked()

    def test_wrong_error_is_not_ui_abort(self):
        self.f.incident['bundle']['sources']['result'] = source('This action was rejected due to unacceptable risk.')
        self.f.write()
        self.blocked()

    def test_limited_readback_must_stay_unknown_and_partial(self):
        changes = [('classification', 'absent'), ('coverage', 'authoritative_exact_target'), ('mode', 'clicked_menu'),
                   ('account', 'other.account'), ('target', 'https://www.threads.com/@other/post/Other'),
                   ('browser_session', 'other-browser'), ('tab_id', 'other-tab'), ('source_ids', [])]
        for key, val in changes:
            with self.subTest(field=key):
                before = self.f.incident['bundle']['observations'][1][key]
                self.f.incident['bundle']['observations'][1][key] = val
                self.f.write()
                self.blocked()
                self.f.incident['bundle']['observations'][1][key] = before

    def test_repeated_signal_or_bytes_not_independent(self):
        self.f.incident['bundle']['observations'][1]['signal'] = 'refreshed_target_state'
        self.f.write()
        self.blocked()

    def test_corrupt_embedded_source(self):
        self.f.incident['bundle']['sources']['target']['data_base64'] = base64.b64encode(b'Changed raw content').decode()
        self.f.write()
        self.blocked()

    def test_extra_zero_count_assertion_rejected(self):
        self.f.incident['bundle']['newly_verified_actions'] = 0
        self.f.write()
        self.blocked()

    def test_ever_submitted_or_present_history_rejected(self):
        for event, details in (('submitted_unverified', {}), ('browser_readback_attested', {'state': 'verified'})):
            with self.subTest(event=event):
                # Each appended contradiction stays in history, as it should.
                self.f.l.event(event, self.f.owner, self.f.action, **details)
                self.blocked()

    def test_second_intent_or_later_attempt_rejected(self):
        self.f.l.event('single_write_intent_committed', self.f.owner, self.f.action, intent_id=self.f.intent)
        self.blocked()

    def test_other_reserved_action_blocks(self):
        l = self.f.l
        key = m.action_key(l.account, 'like', 'https://www.threads.com/@other/post/OtherPending')
        l.db.execute("INSERT INTO actions(id,account,kind,target_key,target_url,payload_hash,state,session,created_at,updated_at) VALUES(?,?,?,?,?,?,'reserved',?,?,?)",
                     (key, l.account, 'like', 'threads:post:OtherPending', 'https://www.threads.com/@other/post/OtherPending', PAYLOAD,
                      self.f.auth['session'], self.f.time, self.f.time))
        self.blocked()

    def test_run_verified_count_is_derived(self):
        self.f.l.event('browser_readback_attested', self.f.owner, 'other-action', state='verified')
        self.blocked()

    def test_stale_read_or_review(self):
        self.f.time += 301
        self.blocked()

    def test_failure_itself_can_be_historical(self):
        f = self.f
        for ob in f.incident['bundle']['observations']:
            ob['observed_at'] += 86400
            ob['refreshed_at'] += 86400
        f.incident['bundle']['operator_review']['reviewed_at'] += 86400
        for key in ('question_at', 'answer_at', 'reviewed_at'):
            f.approval['bundle'][key] += 86400
        f.time += 86400
        f.write()
        f.pin_dict['reviewed_at'] += 86400
        f.pin = ui.TrustedReviewPin.from_dict(f.pin_dict)
        self.assertEqual(f.finalize()['state'], 'cancelled')

    def test_expiry_during_audit_rolls_back_everything(self):
        original = self.f.l.event
        def expire(*args, **kwargs):
            original(*args, **kwargs)
            self.f.time += 301
        with patch.object(self.f.l, 'event', side_effect=expire):
            self.blocked()

    def test_clock_rollback_during_audit_rolls_back(self):
        original = self.f.l.event
        def rollback(*args, **kwargs):
            original(*args, **kwargs)
            self.f.time -= 1
        with patch.object(self.f.l, 'event', side_effect=rollback):
            self.blocked()

    def test_expiry_during_final_storage_check_rolls_back(self):
        original = self.f.l.ensure_storage
        calls = [0]
        def expire():
            original()
            calls[0] += 1
            if calls[0] == 2:
                self.f.time += 301
        with patch.object(self.f.l, 'ensure_storage', side_effect=expire):
            self.blocked()

    def test_expiry_before_lock_acquisition_recheck(self):
        original = self.f.l.ensure_storage
        def expire():
            original()
            self.f.time += 301
        with patch.object(self.f.l, 'ensure_storage', side_effect=expire):
            self.blocked()

    def test_actual_lock_wait_expiry_rolls_back(self):
        locker = sqlite3.connect(self.f.path, isolation_level=None, check_same_thread=False)
        locker.execute('BEGIN IMMEDIATE')
        def release_lock():
            self.f.time += 301
            locker.execute('ROLLBACK')
        timer = threading.Timer(0.15, release_lock)
        before = self.f.snapshot()
        timer.start()
        try:
            with self.assertRaises(m.Blocked):
                self.f.finalize()
        finally:
            timer.join()
            locker.close()
        self.assertEqual(before, self.f.snapshot())

    def crash_at_commit(self, mode):
        f = self.f
        pin = f.root / 'synthetic-independent-pin.json'
        pin.write_text(m.canonical(f.pin_dict))
        script = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import ledger as m
import quarantine_extension as ui
source, db, owner, token, action, incident, ih, approval, ah, pin, ph, now, mode = sys.argv[1:]
l = m.Ledger(db, clock=lambda: int(now))
class CrashConnection:
    def __init__(self, db): self.db = db
    def __getattr__(self, name): return getattr(self.db, name)
    def execute(self, sql, *args):
        if sql == 'COMMIT' and mode == 'before': os._exit(61)
        result = self.db.execute(sql, *args)
        if sql == 'COMMIT' and mode == 'after': os._exit(62)
        return result
l.db = CrashConnection(l.db)
ui.finalize_uncertain_quarantine(l, owner, token, action, incident, ih, approval, ah,
                                    trusted_review=ui.load_trusted_review(pin, ph))
os._exit(63)
'''
        return subprocess.run([sys.executable, '-B', '-c', script, str(ROOT), str(f.path), f.owner, f.token,
                               f.action, str(f.ip), f.ih, str(f.ap), f.ah, str(pin), m.digest(pin.read_bytes()),
                               str(f.time), mode], capture_output=True, text=True, timeout=10)

    def test_process_death_before_commit_preserves_stop_and_writer(self):
        before = self.f.snapshot()
        result = self.crash_at_commit('before')
        self.assertEqual(result.returncode, 61, result.stderr)
        self.assertEqual(before, self.f.snapshot())
        self.assertEqual(self.f.l.row(self.f.action)['state'], 'unknown')

    def test_process_death_after_commit_leaves_checkpoint_pending(self):
        result = self.crash_at_commit('after')
        self.assertEqual(result.returncode, 62, result.stderr)
        self.assertEqual(self.f.l.row(self.f.action)['state'], 'cancelled')
        self.assertFalse(self.f.l.db.execute('SELECT 1 FROM writer').fetchone())
        self.assertFalse(self.f.l.db.execute('SELECT 1 FROM stops').fetchone())
        self.assertEqual(self.f.l.get('checkpoint_pending'), '1')
        self.assertEqual(self.f.l.get('checkpoint_seq'), '1')
        self.blocked()

    def test_forced_audit_failure_rolls_back(self):
        original = self.f.l.event
        def fail(*args, **kwargs):
            original(*args, **kwargs)
            if args[0] == 'writer_released':
                raise RuntimeError('Synthetic pre-commit failure')
        with patch.object(self.f.l, 'event', side_effect=fail):
            self.blocked(errors=(RuntimeError,))

    def test_forced_blob_failure_rolls_back(self):
        original = self.f.l.blob
        def fail(data):
            original(data)
            raise RuntimeError('Synthetic storage failure')
        with patch.object(self.f.l, 'blob', side_effect=fail):
            self.blocked(errors=(RuntimeError,))

    def test_replay_rejected_without_second_sequence(self):
        self.f.finalize()
        self.blocked()
        self.assertEqual(self.f.l.get('checkpoint_seq'), '1')

    def test_checkpoint_gate_blocks_acquire_and_claim(self):
        self.f.finalize()
        self.blocked(lambda: self.f.l.acquire('next-synthetic-run', 'spreader'))
        self.blocked(lambda: self.f.l.claim(self.f.owner, self.f.token, 'repost', TARGET, PAYLOAD))

    def test_retained_graph_and_restore_after_source_deletion(self):
        f = self.f
        f.finalize()
        manifest = cp.runtime_manifest(f.l.db)
        self.assertIn(f.ih, manifest['evidence_hashes'])
        self.assertIn(f.ah, manifest['evidence_hashes'])
        self.assertIn(f.incident['source_sha256'], manifest['evidence_hashes'])
        self.assertIn(f.approval['proof_sha256'], manifest['evidence_hashes'])
        out = f.root / 'synthetic-checkpoint.zip'
        cp.package(f.path, out, source_dir=ROOT)
        for path in list(f.root.iterdir()):
            if path.suffix in ('.json', '.txt'):
                path.unlink()
        with zipfile.ZipFile(out) as archive:
            self.assertIn('quarantine_extension.py', archive.namelist())
            restore_path = f.root / 'restored.sqlite'
            restore_path.write_bytes(archive.read('runtime.sqlite'))
            db = sqlite3.connect(restore_path)
            db.row_factory = sqlite3.Row
            _, saved_manifest, _ = cp.check_snapshot(db)
            self.assertEqual(saved_manifest, manifest)
            for h in manifest['evidence_hashes']:
                data = bytes(db.execute('SELECT bytes FROM blobs WHERE hash=?', (h,)).fetchone()[0])
                self.assertEqual(m.digest(data), h)
                self.assertEqual(archive.read('evidence/' + h + '.bin'), data)
            saved = json.loads(bytes(db.execute('SELECT bytes FROM blobs WHERE hash=?', (f.ih,)).fetchone()[0]))
            self.assertEqual(ui.source_bytes(saved['bundle']['sources'])['target'], ui.source_bytes(f.incident['bundle']['sources'])['target'])
            self.assertEqual(m.schema_hash(db), m.expected_schema_hash())
            # Restore normal WAL requirement. Checkpoint ACK is separately tested by parent.
            db.execute('PRAGMA journal_mode=WAL')
            db.close()
        restored = m.Ledger(restore_path, clock=lambda: f.time)
        try:
            with self.assertRaises(m.Blocked):
                restored.acquire('restore-pending-run', 'spreader')
            # Synthetic ACK-gate clearance solely to isolate dedupe behavior.
            restored.put('checkpoint_pending', '0')
            auth = restored.acquire('restore-new-run', 'spreader')
            for alias in (TARGET, 'https://threads.net/@different_handle/post/SyntheticUncertainQuarantine/'):
                for kind in ui.POST_KINDS:
                    with self.assertRaises(m.Blocked):
                        restored.claim(auth['owner'], auth['token'], kind, alias, PAYLOAD)
            self.assertEqual(len(ui.quarantine_records(restored.db, restored.account)), 1)
            other = 'https://threads.net/@synthetic_actor/post/OtherAllowedPost'
            self.assertEqual(restored.claim(auth['owner'], auth['token'], 'like', other, PAYLOAD)['state'], 'reserved')
        finally:
            restored.close()


    def test_native_v4_or_multicall_future_incidents_rejected(self):
        for field, value in [('incident_protocol', 'native_v4'), ('completed_call_count', 2), ('completed_call_count', True)]:
            old = self.f.incident['bundle']['failed_call'][field]
            self.f.incident['bundle']['failed_call'][field] = value
            self.f.write()
            self.blocked()
            self.f.incident['bundle']['failed_call'][field] = old

    def test_older_no_execution_role_github_and_generic_approval_do_not_qualify(self):
        for decision in ('record_no_execution_release_run_and_require_checkpoint',
                         'approve_spreader_role', 'approve_github_upload', 'continue'):
            self.f.approval['bundle']['decision'] = decision
            self.f.write()
            self.blocked()

    def test_immutable_proof_disposition_must_remain_unknown(self):
        for field, value in [('external_outcome', 'absent'), ('termination', 'not_executed'),
                             ('new_verified_count', 1), ('retry_allowed', True)]:
            old = self.f.incident['bundle']['disposition'][field]
            self.f.incident['bundle']['disposition'][field] = value
            self.f.write()
            self.blocked()
            self.f.incident['bundle']['disposition'][field] = old

    def test_whole_post_scope_and_no_implicit_resume_authority(self):
        for field, value in [('accepted_external_outcome', 'absent'), ('quarantine_scope', 'repost_only'),
                             ('resume_scope', 'retry_same_target'), ('new_verified_count', True)]:
            old = self.f.approval['bundle'][field]
            self.f.approval['bundle'][field] = value
            self.f.write()
            self.blocked()
            self.f.approval['bundle'][field] = old

    def test_cross_kind_domain_and_handle_aliases_with_profile_scope_preserved(self):
        f = self.f
        f.finalize()
        for domain in ('threads.com', 'www.threads.com', 'threads.net', 'www.threads.net'):
            for kind in ui.POST_KINDS:
                with self.subTest(domain=domain, kind=kind):
                    self.blocked(lambda: ui.ensure_not_quarantined(f.l, kind, 'https://' + domain + '/@another_handle/post/SyntheticUncertainQuarantine/'))
        ui.ensure_not_quarantined(f.l, 'follow', 'https://threads.net/@synthetic_actor')
        ui.ensure_not_quarantined(f.l, 'reply', 'https://threads.net/@synthetic_actor/post/UnrelatedPost')

    def test_mutable_row_cannot_hide_immutable_quarantine(self):
        f = self.f
        f.finalize()
        for column, value in [('proof_hash', None), ('state', 'verified'), ('intent_id', None),
                              ('target_key', 'threads:post:Different')]:
            old = f.l.row(f.action)[column]
            f.l.db.execute('UPDATE actions SET ' + column + '=? WHERE id=?', (value, f.action))
            with self.assertRaises(m.Blocked):
                ui.quarantine_records(f.l.db, f.l.account)
            f.l.db.execute('UPDATE actions SET ' + column + '=? WHERE id=?', (old, f.action))

    def test_missing_subtype_or_quarantine_audit_fails_closed(self):
        f = self.f
        f.finalize()
        trigger = f.l.db.execute("SELECT sql FROM sqlite_master WHERE name='audit_no_delete'").fetchone()[0]
        f.l.db.execute('DROP TRIGGER audit_no_delete')
        f.l.db.execute("DELETE FROM audit WHERE action_id=? AND event IN (?,?,?)", (f.action, 'target_quarantined_unresolved', ui.SUBTYPE, 'uncertain_quarantine_explicitly_approved'))
        f.l.db.execute(trigger)
        self.blocked(lambda: f.l.status())
        self.blocked(lambda: cp.runtime_manifest(f.l.db))

    def test_missing_proof_source_graph_fails_closed(self):
        f = self.f
        f.finalize()
        trigger = f.l.db.execute("SELECT sql FROM sqlite_master WHERE name='blobs_no_delete'").fetchone()[0]
        f.l.db.execute('DROP TRIGGER blobs_no_delete')
        f.l.db.execute('DELETE FROM blobs WHERE hash=?', (f.approval['proof_sha256'],))
        f.l.db.execute(trigger)
        self.blocked(lambda: f.l.status())
        self.blocked(lambda: cp.runtime_manifest(f.l.db))

    def test_quarantine_is_inserted_before_stop_and_writer_release(self):
        f = self.f
        original = f.l.event
        observed = []
        def inspect(event, *args, **kwargs):
            result = original(event, *args, **kwargs)
            if event == 'target_quarantined_unresolved':
                observed.append(event)
                self.assertIsNotNone(f.l.db.execute('SELECT 1 FROM writer').fetchone())
                self.assertIsNotNone(f.l.db.execute('SELECT 1 FROM stops').fetchone())
                self.assertEqual(f.l.row(f.action)['state'], 'unknown')
            return result
        with patch.object(f.l, 'event', side_effect=inspect):
            f.finalize()
        self.assertEqual(observed, ['target_quarantined_unresolved'])

    def test_existing_denial_via_normal_api_survives_ack_and_later_quarantine(self):
        import denial_extension as de
        f = self.f
        def save(name, value):
            p = f.root / name
            p.write_text(m.canonical(value))
            return p, m.digest(p.read_bytes())
        def ack(name):
            archive = f.root / (name + '.zip')
            out = cp.package(f.path, archive, source_dir=ROOT)
            receipt = {'schema': 'library-checkpoint-roundtrip-v1', 'account': f.l.account,
                       'db_id': f.l.get('db_id'), 'baseline_hash': f.l.get('baseline_hash'),
                       'checkpoint_seq': out['checkpoint_seq'], 'checkpoint_hash': out['checkpoint_hash'],
                       'library_file_id': 'synthetic-runtime-denial-compat',
                       'library_version': name, 'previous_version': f.l.get('checkpoint_library_version'),
                       'archive_sha256': out['archive_sha256'], 'downloaded_archive': str(archive),
                       'transport_reference': 'LOCAL SYNTHETIC ONLY; no Library transfer', 'verified_at': f.time}
            rp, rh = save(name + '-ack.json', receipt)
            return cp.acknowledge(f.l, rp, rh)
        common = {'account': f.l.account, 'db_id': f.l.get('db_id'), 'action_id': f.action,
                  'kind': 'repost', 'target': f.target, 'payload_hash': PAYLOAD, 'intent_id': f.intent,
                  'intent_at': f.base, 'owner': f.owner}
        request = 'Synthetic denied tool request only'
        result = 'This action was rejected due to unacceptable risk. Do not bypass this rejection'
        source_record = {'schema': 'retained-preexecution-denial-context-v1', **common,
                         'tool_name': 'synthetic.tool', 'request_text': request, 'result_text': result,
                         'result_is_error': True, 'denied_at': f.time, 'tool_call_id': None,
                         'missing_call_id_reason': 'Synthetic test has no actual call',
                         'original_context_reference': 'synthetic-denial-context', 'execution_stage': 'before_tool_execution',
                         'submission_not_sent': True, 'no_subsequent_browser_call': True,
                         'request_sha256': m.digest(request), 'result_sha256': m.digest(result)}
        sp, sh = save('denial-source.json', source_record)
        outer = {'schema': 'operator-attested-tool-denial-v1', **common, 'source_file': str(sp),
                 'source_sha256': sh, 'attested_at': f.time, 'provenance': 'operator_attested_original_tool_context'}
        dp, dh = save('denial.json', outer)
        de.record_denied(f.l, f.owner, f.token, f.action, dp, dh)
        self.assertEqual(ui.quarantine_records(f.l.db, f.l.account), [])
        self.assertEqual(f.l.status()['actions'][0]['state'], 'cancelled')
        body = f.root / 'denial-approval.txt'
        body.write_text('SYNTHETIC exact denial bookkeeping closure only; no retry.')
        approval = {'schema': 'operator-approved-denial-finalization-v1', 'account': f.l.account,
                    'db_id': f.l.get('db_id'), 'action_id': f.action, 'intent_id': f.intent, 'intent_at': f.base,
                    'owner': f.owner, 'source_sha256': dh, 'proof_file': str(body), 'proof_sha256': m.digest(body.read_bytes()),
                    'approval_reference': 'synthetic-denial-approval', 'decision': 'record_no_execution_release_run_and_require_checkpoint',
                    'follow_retry_authorized': False, 'other_new_dispatch_authorized': False, 'reviewed_at': f.time}
        ap, ah = save('denial-approval.json', approval)
        de.finalize_denied_run(f.l, f.owner, f.token, f.action, ap, ah)
        self.assertFalse(ack('denial-v1')['checkpoint_pending'])
        original_denial = f.action
        f.time += 5
        f.base = f.time
        f.target = 'https://threads.com/@synthetic_actor/post/OtherLegacyUncertainPost'
        f.auth = f.l.acquire('synthetic-after-denial', 'spreader')
        f.owner, f.token = f.auth['owner'], f.auth['token']
        f.action = f.l.claim(f.owner, f.token, 'repost', f.target, PAYLOAD)['action_id']
        pf = json.loads(f.preflight.read_text())
        pf.update(target=f.target, observed_at=f.time)
        f.preflight.write_text(m.canonical(pf))
        f.intent = f.l.begin_write(f.owner, f.token, f.action, f.preflight)['intent_id']
        f.time += 3
        f.l.transition(f.owner, f.token, f.action, 'unknown', 'Synthetic later legacy UI guard')
        f.original_intent = dict(f.l.row(f.action))
        f.make_evidence()
        f.incident['binding']['expected_checkpoint_seq'] = 1
        f.approval['binding'] = dict(f.incident['binding'])
        f.write()
        self.assertEqual(f.finalize()['checkpoint_seq'], 2)
        self.assertEqual(len(f.l.status()['quarantines']), 1)
        self.assertEqual(f.l.row(original_denial)['state'], 'cancelled')
        self.assertFalse(ack('quarantine-v2')['checkpoint_pending'])
        auth = f.l.acquire('synthetic-after-two-checkpoints', 'spreader')
        self.assertEqual(f.l.claim(auth['owner'], auth['token'], 'like',
                                  'https://threads.net/@another/post/AllowedAfterDenialAndQuarantine', PAYLOAD)['state'], 'reserved')



    def test_replacement_provenance_rejects_identity_scope_and_tab_mismatches(self):
        changes = [('original_browser_session', 'browser-instance:2'), ('original_tab_id', 'wrong-old-tab'),
                   ('browser_session', 'browser-instance:2'), ('browser_identity_basis', 'native_session_id'),
                   ('account', 'other.account'), ('ledger_session', 'other-ledger-session'),
                   ('target', 'https://threads.com/@synthetic_actor/post/OtherPost'),
                   ('classification', 'original_tab_explicitly_closed'), ('original_tab_state', 'closed'),
                   ('replacement_tab_state', 'unverified'), ('mode', 'write'), ('operator_source', 'operator'),
                   ('original_tab_unavailable_reason', '')]
        for field, value in changes:
            with self.subTest(field=field):
                old = self.f.incident['bundle']['reconciliation'][field]
                self.f.incident['bundle']['reconciliation'][field] = value
                self.f.write()
                self.blocked()
                self.f.incident['bundle']['reconciliation'][field] = old

    def test_both_readbacks_must_use_exact_replacement_not_original_tab(self):
        for index in (0, 1):
            ob = self.f.incident['bundle']['observations'][index]
            for field, value in [('tab_id', 'synthetic-tab'), ('tab_id', 'different-current-tab'),
                                 ('browser_session', 'browser-instance:2'), ('account', 'other.account'),
                                 ('target', 'https://threads.com/@another/post/WrongTarget')]:
                old = ob[field]
                ob[field] = value
                self.f.write()
                self.blocked()
                ob[field] = old

    def test_original_tab_cannot_be_relabelled_as_replacement(self):
        f = self.f
        f.incident['binding']['tab_id'] = 'synthetic-replacement-tab'
        f.approval['binding']['tab_id'] = 'synthetic-replacement-tab'
        f.incident['bundle']['reconciliation']['original_tab_id'] = 'synthetic-replacement-tab'
        f.write()
        self.blocked()

    def test_same_tab_v2_path_is_not_silently_accepted_as_replacement_v3(self):
        f = self.f
        f.incident['bundle']['reconciliation']['tab_id'] = 'synthetic-tab'
        for ob in f.incident['bundle']['observations']:
            ob['tab_id'] = 'synthetic-tab'
        f.write()
        self.blocked()

    def test_missing_replacement_provenance_or_distinct_attestation_rejected(self):
        f = self.f
        provenance = f.incident['bundle'].pop('reconciliation')
        f.write()
        self.blocked()
        f.incident['bundle']['reconciliation'] = provenance
        f.incident['bundle']['sources']['current_operator'] = source('')
        f.write()
        self.blocked()

    def test_current_operator_provenance_cannot_change_after_independent_review(self):
        self.f.incident['bundle']['sources']['current_operator'] = source('Different current provenance, unreviewed.')
        self.f.write(repin=False)
        self.blocked()

    def test_observed_outer_timestamp_basis_and_provenance_are_required(self):
        failed = self.f.incident['bundle']['failed_call']
        for field, value in [('timestamp_basis', 'exact_native_timestamps'), ('timestamp_provenance', ''),
                             ('request_started_at', self.f.base - 1), ('completed_at', self.f.base),
                             ('completed_at', self.f.base + 4)]:
            with self.subTest(field=field, value=value):
                old = failed[field]
                failed[field] = value
                self.f.write()
                self.blocked()
                failed[field] = old

    def test_original_and_current_operator_bytes_retained_separately_unknown(self):
        f = self.f
        original = ui.source_bytes(f.incident['bundle']['sources'])['operator']
        current = ui.source_bytes(f.incident['bundle']['sources'])['current_operator']
        self.assertNotEqual(original, current)
        f.finalize()
        saved = json.loads(bytes(f.l.db.execute('SELECT bytes FROM blobs WHERE hash=?', (f.ih,)).fetchone()[0]))
        sources = ui.source_bytes(saved['bundle']['sources'])
        self.assertEqual(sources['operator'], original)
        self.assertEqual(sources['current_operator'], current)
        self.assertEqual(saved['binding']['tab_id'], 'synthetic-tab')
        self.assertEqual(saved['bundle']['reconciliation']['tab_id'], 'synthetic-replacement-tab')
        self.assertEqual(saved['bundle']['disposition'], ui.DISPOSITION)
        self.assertTrue(all(ob['classification'] == 'unknown' and ob['coverage'] == 'partial' for ob in saved['bundle']['observations']))
        self.assertEqual(f.l.status()['quarantines'][0]['external_outcome'], 'unknown')


if __name__ == '__main__':
    unittest.main(verbosity=2)
