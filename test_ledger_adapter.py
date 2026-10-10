"""Disposable synthetic DBs only; no operational DB, browser, network or Library."""
import contextlib
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zipfile

from dispatch_gate import DispatchGate, GateBlocked, LedgerIdentity, successful
from coordinator import SerialCoordinator
import queue_core
from queue_core import Binding, QueueCore, Schedule, initialize_staging
from test_coordinator import FakeAuthorization, FakeBrowser
import ledger_adapter as adapter_module
from ledger_adapter import FIXTURE_DATA_ROOT, FIXTURE_SOURCE_ROOT, StagingLedgerAdapter


ACCOUNT = 'example.bot'
NOW = 1_791_634_000
TARGET = 'https://threads.com/@synthetic_person/post/AdapterSyntheticA'
BASELINE_TARGET = 'https://threads.com/@synthetic_person/post/AdapterBaseline'


class SyntheticFixture:
    def __init__(self, active=True):
        FIXTURE_DATA_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='adapter-test-', dir=FIXTURE_DATA_ROOT)
        self.root = Path(self.temp.name)
        self.path = self.root / 'synthetic.sqlite'
        self.now = NOW
        self.m, self.cp = adapter_module._load_pinned_sources()
        self.m.Ledger.init_recovery(self.path, ACCOUNT)
        self.l = self.m.Ledger(self.path, ACCOUNT, clock=lambda: self.now)
        self.identity = LedgerIdentity(ACCOUNT, self.l.get('db_id'))
        self.n = 0
        if active:
            self.activate_explicit_synthetic_fixture()

    def record(self, value):
        self.n += 1
        path = self.root / f'record-{self.n}.json'
        path.write_text(self.m.canonical(value))
        return path, self.m.digest(path.read_bytes())

    def proof(self):
        path = self.root / 'proof.txt'
        path.write_text('DISPOSABLE SYNTHETIC TEST EVIDENCE. No browser or real social action.')
        return path

    def activate_explicit_synthetic_fixture(self):
        proof = self.proof()
        path, sha = self.record(dict(schema='public-action-observation-v1', account=ACCOUNT,
            kind='like', target=BASELINE_TARGET, classification='current_observed',
            observed_at=self.now, reference='Synthetic fixture only', source_file=str(proof),
            source_sha256=self.m.digest(proof.read_bytes()), payload=None, receipt_urls=[]))
        self.l.import_observation(path, sha)
        path, sha = self.record(dict(schema='recovery-review-v1', account=ACCOUNT,
            manifest_sha256=self.m.digest(self.m.canonical(self.l.manifest())),
            review_reference='Disposable synthetic review', known_gaps=['Synthetic only'],
            fresh_duplicate_checks_required=True, reviewed_at=self.now))
        self.l.seal(path, sha)
        snapshot = self.root / 'baseline.sqlite'
        db = sqlite3.connect(snapshot)
        self.l.db.backup(db)
        db.execute('PRAGMA journal_mode=DELETE')
        db.close()
        members = {'reconstructed.sqlite': snapshot.read_bytes(),
                   'ledger.py': (FIXTURE_SOURCE_ROOT / 'ledger.py').read_bytes(),
                   'denial_extension.py': (FIXTURE_SOURCE_ROOT / 'denial_extension.py').read_bytes(),
                   'settings.py': (FIXTURE_SOURCE_ROOT / 'settings.py').read_bytes(),
                   'RECOVERY.md': b'Disposable synthetic recovery fixture. Never use operationally.'}
        manifest = dict(schema='threads-ledger-backup-v1', account=ACCOUNT,
            db_id=self.identity.db_id, baseline_hash=self.l.get('baseline_hash'),
            members={k: self.m.digest(v) for k, v in members.items()})
        archive = self.root / 'baseline.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for key, value in members.items():
                z.writestr(key, value)
            z.writestr('PACKAGE_MANIFEST.json', self.m.canonical(manifest))
        path, sha = self.record(dict(schema='library-roundtrip-verification-v1', account=ACCOUNT,
            db_id=self.identity.db_id, baseline_hash=self.l.get('baseline_hash'),
            library_file_id='synthetic-baseline-only', library_version='synthetic-baseline-v1',
            archive_sha256=self.m.digest(archive.read_bytes()), downloaded_archive=str(archive),
            transport_reference='LOCAL SYNTHETIC FIXTURE; no actual Library upload',
            verified_at=self.now))
        self.l.activate(path, sha)

    def evidence(self, target, payload_hash, outcome, intent_id=None):
        proof = self.proof()
        return self.record(dict(schema='browser-action-evidence-v2', account=ACCOUNT,
            kind='like', target=target, payload_hash=payload_hash, intent_id=intent_id,
            outcome=outcome, observed_at=self.now, reference='Synthetic test readback',
            proof_file=str(proof), proof_sha256=self.m.digest(proof.read_bytes()), receipt_urls=[]))[0]

    def checkpoint(self, **changes):
        self.n += 1
        archive = self.root / f'checkpoint-{self.n}.zip'
        package = self.cp.package(self.path, archive, source_dir=FIXTURE_SOURCE_ROOT, account=ACCOUNT)
        value = dict(schema='library-checkpoint-roundtrip-v1', account=ACCOUNT,
            db_id=self.identity.db_id, baseline_hash=package['baseline_hash'],
            checkpoint_seq=package['checkpoint_seq'], checkpoint_hash=package['checkpoint_hash'],
            library_file_id='synthetic-runtime-only', library_version='synthetic-runtime-v1',
            previous_version='', archive_sha256=package['archive_sha256'],
            downloaded_archive=str(archive), transport_reference='LOCAL SYNTHETIC ROUNDTRIP ONLY',
            verified_at=self.now)
        value.update(changes)
        path, sha = self.record(value)
        return path, sha, archive, package

    def close(self):
        self.l.close()
        self.temp.cleanup()


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.f = SyntheticFixture()
        self.a = StagingLedgerAdapter(self.f.path, self.f.identity, clock=lambda: self.f.now)
        self.gate = DispatchGate(self.f.identity, lambda: self.f.now)

    def tearDown(self):
        self.a.close()
        self.f.close()

    def ok(self, command, **args):
        return successful(self.a.execute(command, **args))

    def fail(self, command, **args):
        out = self.a.execute(command, **args)
        self.assertTrue(out.completed)
        self.assertEqual(out.exit_code, 2)
        self.assertEqual(out.stdout, '')
        self.assertFalse(out.truncated)
        self.assertIsNone(out.session_id)
        error = json.loads(out.stderr)
        self.assertEqual(set(error), {'ok', 'may_dispatch', 'automatic_retry', 'error'})
        self.assertIs(error['ok'], False)
        self.assertIs(error['may_dispatch'], False)
        self.assertIs(error['automatic_retry'], False)
        return error

    def acquire(self, owner='synthetic.spreader.1'):
        raw = self.a.execute('acquire', owner=owner, role='spreader')
        return self.gate.acquired(raw, owner)

    def reserve(self, target=TARGET):
        auth = self.acquire()
        ph = self.f.m.digest(self.f.m.canonical({'target': target}))
        claim = self.ok('claim', owner=auth['owner'], token=auth['token'],
                        kind='like', target=target, payload_hash=ph)
        return auth, claim['action_id'], ph

    def begin(self):
        auth, action, ph = self.reserve()
        evidence = self.f.evidence(TARGET, ph, 'absent')
        intent = self.ok('begin-write', owner=auth['owner'], token=auth['token'],
                         action=action, evidence=evidence)
        return auth, action, ph, intent

    def test_status_matches_actual_cli_shape(self):
        out = self.a.execute('status')
        self.assertEqual(json.loads(out.stdout), {'ok': True, **self.f.l.status()})
        self.assertTrue(out.stdout.endswith('\n'))
        self.assertEqual(out.stderr, '')
        self.gate.status(out)

    def test_one_use_full_action_release_and_checkpoint_ack(self):
        auth, action, ph, intent = self.begin()
        self.assertEqual(set(intent), {'ok', 'action_id', 'intent_id', 'state', 'may_dispatch',
            'exactly_one_browser_call', 'lost_response_means_do_not_dispatch'})
        self.ok('submitted', owner=auth['owner'], token=auth['token'], action=action)
        path = self.f.evidence(TARGET, ph, 'present', intent['intent_id'])
        verified = self.ok('verify', owner=auth['owner'], token=auth['token'], action=action, evidence=path)
        self.assertEqual(verified['state'], 'verified')
        self.assertFalse(verified['stop_cleared'])
        released = self.gate.release(self.a.execute('release', owner=auth['owner'], token=auth['token']))
        self.assertEqual(released['checkpoint_seq'], 1)
        self.fail('acquire', owner='synthetic.next', role='spreader')
        path, sha, archive, package = self.f.checkpoint()
        ack = self.ok('checkpoint-ack', record=path, sha256=sha)
        self.assertEqual(ack, {'ok': True, 'checkpoint_pending': False, 'checkpoint_seq': 1,
            'checkpoint_hash': package['checkpoint_hash'], 'archive_sha256': package['archive_sha256'],
            'may_dispatch': False})
        self.assertEqual(self.ok('status')['checkpoint_library_version'], 'synthetic-runtime-v1')
        self.acquire('synthetic.spreader.2')

    def test_unknown_retains_stop_and_writer_even_after_verified(self):
        auth, action, ph, intent = self.begin()
        self.ok('unknown', owner=auth['owner'], token=auth['token'], action=action,
                reason='Synthetic outcome unavailable')
        self.fail('release', owner=auth['owner'], token=auth['token'])
        path = self.f.evidence(TARGET, ph, 'present', intent['intent_id'])
        self.ok('verify', owner=auth['owner'], token=auth['token'], action=action, evidence=path)
        self.assertEqual(len(self.ok('status')['stops']), 1)
        self.fail('acknowledge-reconciliation', owner=auth['owner'], token=auth['token'], action=action)
        self.fail('release', owner=auth['owner'], token=auth['token'])
        self.assertIsNotNone(self.ok('status')['writer'])

    def test_cancel_reservation_and_already_present_mapping(self):
        auth, action, ph = self.reserve()
        self.assertEqual(self.ok('cancel', owner=auth['owner'], token=auth['token'], action=action)['state'], 'cancelled')
        target = TARGET + 'Other'
        claim = self.ok('claim', owner=auth['owner'], token=auth['token'], kind='like', target=target, payload_hash=ph)
        path = self.f.evidence(target, ph, 'present')
        self.assertEqual(self.ok('verify', owner=auth['owner'], token=auth['token'],
                                action=claim['action_id'], evidence=path)['state'], 'already_present')
        self.ok('release', owner=auth['owner'], token=auth['token'])

    def test_duplicate_claim_preserves_sparse_real_shape(self):
        auth, action, ph = self.reserve()
        claim = self.ok('claim', owner=auth['owner'], token=auth['token'], kind='like', target=TARGET, payload_hash=ph)
        self.assertEqual(claim, {'ok': True, 'action_id': action, 'state': 'reserved',
            'duplicate': True, 'payload_matches': True, 'may_dispatch': False})

    def test_errors_match_real_cli_keys_and_message(self):
        auth = self.acquire()
        with self.assertRaises(self.f.m.Blocked) as actual:
            self.f.l.release(auth['owner'], '0' * 64)
        error = self.fail('release', owner=auth['owner'], token='0' * 64)
        self.assertEqual(error['error'], str(actual.exception))

    def test_no_stream_output_logging_subprocess_or_raw_token_persistence(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('No subprocess allowed')):
            auth = self.acquire()
            self.ok('status')
            self.fail('release', owner=auth['owner'], token='0' * 64)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn(auth['token'], repr(self.a))
        self.assertNotIn(auth['token'], repr(self.a.execute('status')))
        dump = '\n'.join(self.f.l.db.iterdump())
        self.assertNotIn(auth['token'], dump)
        self.assertIn(self.f.m.digest(auth['token']), dump)

    def test_unknown_methods_missing_extra_and_wrong_type_arguments_fail(self):
        initial = self.f.l.status()['audit_events']
        for command in ('init-recovery', 'activate', 'seal', 'manifest', 'hash-file',
                        'record-denied-before-dispatch', 'finalize-denied-run',
                        'acknowledge-reconciliation', '__getattribute__', 'close', 'begin_write'):
            self.fail(command)
        self.fail('status', db=str(self.f.path))
        self.fail('acquire', owner='synthetic')
        self.fail('acquire', owner=object(), role='spreader')
        self.fail('acquire', owner='synthetic', role='reconciler')
        self.assertEqual(self.f.l.status()['audit_events'], initial)

    def test_no_implicit_init_or_recovery(self):
        missing = self.f.root / 'missing.sqlite'
        with self.assertRaises((GateBlocked, FileNotFoundError)):
            StagingLedgerAdapter(missing, self.f.identity)
        self.assertFalse(missing.exists())
        other = SyntheticFixture(active=False)
        try:
            with StagingLedgerAdapter(other.path, other.identity, clock=lambda: other.now) as a:
                out = a.execute('acquire', owner='synthetic', role='spreader')
                self.assertEqual(out.exit_code, 2)
                self.assertEqual(successful(a.execute('status'))['phase'], 'recovery')
        finally:
            other.close()

    def test_live_and_external_paths_rejected_before_sqlite_open(self):
        with mock.patch.object(adapter_module.sqlite3, 'connect', side_effect=AssertionError('Must not open')):
            for p in ('/not-approved/live.sqlite', '/tmp/other.sqlite',
                      str(self.f.root / 'live.sqlite')):
                with self.assertRaises(GateBlocked):
                    StagingLedgerAdapter(p, self.f.identity)

    def test_identity_mismatch_rejected_without_mutation(self):
        before = self.f.l.status()['audit_events']
        for identity in (LedgerIdentity(ACCOUNT, '0' * 32), LedgerIdentity('different', self.f.identity.db_id)):
            with self.assertRaises(GateBlocked):
                StagingLedgerAdapter(self.f.path, identity)
        self.assertEqual(self.f.l.status()['audit_events'], before)

    def test_identity_changed_during_use_blocks_before_call(self):
        self.f.l.put('db_id', '0' * 32)
        with mock.patch.object(self.a._db, 'acquire', side_effect=AssertionError('Must not invoke')):
            self.fail('acquire', owner='synthetic', role='spreader')

    def test_replaced_database_inode_blocks_before_call(self):
        saved = self.f.root / 'saved.sqlite'
        self.f.path.rename(saved)
        shutil.copyfile(saved, self.f.path)
        try:
            with mock.patch.object(self.a._db, 'status', side_effect=AssertionError('Must not invoke')):
                self.fail('status')
        finally:
            self.f.path.unlink()
            saved.rename(self.f.path)

    def test_db_symlinks_hardlinks_and_parent_links_rejected(self):
        symlink = self.f.root / 'linked.sqlite'
        symlink.symlink_to(self.f.path)
        with self.assertRaises(GateBlocked):
            StagingLedgerAdapter(symlink, self.f.identity)
        hard = self.f.root / 'hard.sqlite'
        os.link(self.f.path, hard)
        try:
            with self.assertRaises(GateBlocked):
                StagingLedgerAdapter(hard, self.f.identity)
        finally:
            hard.unlink()
        parent = self.f.root / 'parent'
        parent.symlink_to(self.f.root, target_is_directory=True)
        with self.assertRaises(GateBlocked):
            StagingLedgerAdapter(parent / self.f.path.name, self.f.identity)

    def test_sidecar_symlink_blocks_before_execution(self):
        sidecar = Path(str(self.f.path) + '-journal')
        sidecar.symlink_to(self.f.root / 'nonexistent')
        self.fail('status')
        sidecar.unlink()

    def test_source_hash_checked_before_each_command(self):
        copies = self.f.root / 'source-copy'
        copies.mkdir()
        for name in adapter_module.SOURCE_SHA256:
            shutil.copyfile(FIXTURE_SOURCE_ROOT / name, copies / name)
        with mock.patch.object(adapter_module, 'FIXTURE_SOURCE_ROOT', copies):
            for name in adapter_module.SOURCE_SHA256:
                with self.subTest(source=name):
                    original = (copies / name).read_bytes()
                    (copies / name).write_bytes(original + b'\n# changed\n')
                    try:
                        with mock.patch.object(self.a._db, 'status', side_effect=AssertionError('Must not invoke')):
                            self.fail('status')
                    finally:
                        (copies / name).write_bytes(original)

    def test_dispatch_gate_source_pin_rejects_tampering(self):
        copy = self.f.root / 'changed_dispatch_gate.py'
        copy.write_bytes(adapter_module.FROZEN_GATE.read_bytes() + b'\n# changed\n')
        with mock.patch.object(adapter_module, 'FROZEN_GATE', copy), \
             mock.patch.object(adapter_module.dispatch_gate, '__file__', str(copy)), \
             mock.patch.object(self.a._db, 'status', side_effect=AssertionError('Must not invoke')):
            self.fail('status')

    def test_checkpoint_import_does_not_use_ambient_ledger_module(self):
        fake = object()
        with mock.patch.dict(sys.modules, {'ledger': fake}):
            ledger, checkpoint = adapter_module._load_pinned_sources()
            self.assertIs(checkpoint.Ledger, ledger.Ledger)
            self.assertIs(sys.modules['ledger'], fake)

    def test_pinned_sources_do_not_use_ambient_settings_module(self):
        fake = object()
        with mock.patch.dict(sys.modules, {'settings': fake}):
            ledger, checkpoint = adapter_module._load_pinned_sources()
            self.assertEqual(ledger.ACCOUNT, ACCOUNT)
            self.assertEqual(ledger.BLOG_HOST, 'blog.example')
            self.assertEqual(checkpoint.ACCOUNT, ACCOUNT)
            self.assertIs(checkpoint.Ledger, ledger.Ledger)
            self.assertIs(sys.modules['settings'], fake)

    def test_repository_source_and_production_paths_are_not_fixture_data(self):
        from settings import PRODUCTION_ROOT
        with mock.patch.object(adapter_module.sqlite3, 'connect', side_effect=AssertionError('Must not open')):
            for path in (FIXTURE_SOURCE_ROOT / 'repository.sqlite',
                         PRODUCTION_ROOT / 'production.sqlite'):
                with self.subTest(path=path), self.assertRaises(GateBlocked):
                    StagingLedgerAdapter(path, self.f.identity)

    def test_all_public_dependencies_have_literal_source_pins(self):
        import ast
        source = Path(adapter_module.__file__).read_text()
        tree = ast.parse(source)
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'SOURCE_SHA256'
                                  for target in node.targets))
        literal = ast.literal_eval(assignment.value)
        self.assertEqual(set(literal), {'ledger.py', 'checkpoint.py', 'denial_extension.py',
                                      'package_recovery.py', 'settings.py', 'integration_paths.py'})
        self.assertEqual(literal, adapter_module.SOURCE_SHA256)
        for name, digest in literal.items():
            self.assertEqual(self.f.m.digest((FIXTURE_SOURCE_ROOT / name).read_bytes()), digest)

    def test_nested_evidence_path_cannot_read_outside_staging(self):
        auth, action, ph = self.reserve()
        path = self.f.evidence(TARGET, ph, 'absent')
        value = json.loads(path.read_text())
        value['proof_file'] = '/not-approved/DO_NOT_OPEN'
        path.write_text(json.dumps(value))
        error = self.fail('begin-write', owner=auth['owner'], token=auth['token'], action=action, evidence=path)
        self.assertIn('outside', error['error'])
        self.assertEqual(self.ok('status')['actions'][-1]['state'], 'reserved')

    def test_nested_checkpoint_archive_cannot_read_outside_staging(self):
        auth = self.acquire()
        self.ok('release', owner=auth['owner'], token=auth['token'])
        path, sha, _, _ = self.f.checkpoint()
        value = json.loads(path.read_text())
        value['downloaded_archive'] = '/not-approved/DO_NOT_OPEN'
        path, sha = self.f.record(value)
        self.fail('checkpoint-ack', record=path, sha256=sha)
        self.assertTrue(self.ok('status')['checkpoint_pending'])

    def test_checkpoint_hash_wrong_db_version_and_replay_fail(self):
        auth = self.acquire()
        self.ok('release', owner=auth['owner'], token=auth['token'])
        path, sha, archive, _ = self.f.checkpoint()
        self.fail('checkpoint-ack', record=path, sha256='0' * 64)
        original = json.loads(path.read_text())
        for changes in ({'db_id': '0' * 32}, {'checkpoint_seq': 2},
                        {'previous_version': 'wrong-version'}, {'verified_at': self.f.now - 3601},
                        {'archive_sha256': '0' * 64}):
            altered, altered_sha = self.f.record({**original, **changes})
            self.fail('checkpoint-ack', record=altered, sha256=altered_sha)
            self.assertTrue(self.ok('status')['checkpoint_pending'])
        self.ok('checkpoint-ack', record=path, sha256=sha)
        self.fail('checkpoint-ack', record=path, sha256=sha)

    def test_closed_and_cross_thread_adapters_fail_without_work(self):
        results = []
        t = threading.Thread(target=lambda: results.append(self.a.execute('status')))
        t.start()
        t.join()
        self.assertEqual(results[0].exit_code, 2)
        self.a.close()
        self.fail('status')

    def test_unexpected_exception_is_sanitized_and_never_retried(self):
        with mock.patch.object(self.a._db, 'acquire', side_effect=RuntimeError('Do not expose arbitrary details')) as call:
            error = self.fail('acquire', owner='synthetic', role='spreader')
        self.assertEqual(call.call_count, 1)
        self.assertNotIn('arbitrary', error['error'])

    def test_error_text_redacts_current_writer_token(self):
        auth = self.acquire()
        with mock.patch.object(self.a._db, 'release', side_effect=OSError('synthetic ' + auth['token'])):
            result = self.a.execute('release', owner=auth['owner'], token=auth['token'])
        self.assertNotIn(auth['token'], result.stderr)
        self.assertIn('[redacted]', result.stderr)


class CoordinatorAdapterTests(unittest.TestCase):
    """Real frozen coordinator + concrete ledger; browser/policy remain fake."""
    def setUp(self):
        self.f = SyntheticFixture()
        self.a = StagingLedgerAdapter(self.f.path, self.f.identity, clock=lambda: self.f.now)
        self.root_patch = mock.patch.object(queue_core, 'STAGING_ROOT', FIXTURE_DATA_ROOT)
        self.root_patch.start()
        self.bindings = {role: Binding('synthetic-' + role, 'synthetic-cloud', 'tab-' + role, ACCOUNT)
                         for role in ('publisher', 'spreader', 'commenter')}
        self.queue_identity = initialize_staging(self.f.root / 'queue.sqlite', self.bindings,
            {role: Schedule(self.f.now - 100, 1000) for role in self.bindings}, ledger_db_id=self.f.identity.db_id)
        self.q = QueueCore(self.f.root / 'queue.sqlite', self.queue_identity)
        self.browser = FakeBrowser(self.f.root, lambda: self.f.now)
        self.c = SerialCoordinator(self.q, self.a.identity, clock=lambda: self.f.now,
            ledger=self.a, browser=self.browser, authorization=FakeAuthorization())

    def tearDown(self):
        self.root_patch.stop()
        self.a.close()
        self.f.close()

    def prepare(self):
        binding = self.bindings['spreader']
        evidence = self.q.record_observation('spreader', worker_id=binding.worker_id,
            browser_id=binding.browser_id, tab_id=binding.tab_id, observed_account=ACCOUNT,
            tab_exists=True, observed_at=self.f.now, now=self.f.now)
        job = self.q.enqueue('spreader', self.f.now - 100, self.f.now + 900,
                             evidence_id=evidence, now=self.f.now)
        actions = [{'kind': 'like', 'target': TARGET + str(i),
                    'payload': {'target': TARGET + str(i)}, 'authorization_id': 'synthetic-like'}
                   for i in range(2)]
        self.q.mark_ready(job['job_id'], {'actions': actions}, evidence_id=evidence, now=self.f.now)
        return job['job_id']

    def test_exact_frozen_coordinator_reaches_real_checkpoint_boundary(self):
        job = self.prepare()
        with mock.patch.object(self.a, 'execute', wraps=self.a.execute) as calls:
            result = self.c.run_once()
        self.assertEqual(result.state, 'needs_checkpoint')
        commands = [args.args[0] for args in calls.call_args_list]
        self.assertEqual(commands.count('acquire'), 1)
        self.assertEqual(commands.count('release'), 1)
        self.assertEqual(commands.count('begin-write'), 2)
        self.assertEqual(len(self.browser.mutations), 2)
        status = successful(self.a.execute('status'))
        self.assertTrue(status['checkpoint_pending'])
        self.assertIsNone(status['writer'])
        self.assertEqual(sum(a['state'] == 'verified' for a in status['actions']), 2)
        self.assertEqual(self.q.inspect_job(job)['state'], 'checkpoint_wait')

    def test_complete_coordinator_ack_with_real_ledger_and_companion_archives(self):
        from checkpoint_pair import ExpectedPair
        from queue_checkpoint import ExpectedBoundary, build_snapshot, validate_snapshot

        job = self.prepare()
        self.assertEqual(self.c.run_once().state, 'needs_checkpoint')
        run = self.c._run
        receipt_path, receipt_sha, ledger_archive, ledger_package = self.f.checkpoint()
        receipt = json.loads(receipt_path.read_text())
        expected_boundary = ExpectedBoundary(account=ACCOUNT, ledger_db_id=self.f.identity.db_id,
            queue_db_id=self.queue_identity.db_id, registry_generation=run.job['generation'],
            job_id=job, checkpoint_id=run.checkpoint_id, checkpoint_sequence=run.checkpoint_sequence,
            result_digest=run.result_digest)
        package_dir = self.f.root / 'queue-package'
        package_dir.mkdir()
        queue_package = build_snapshot(self.f.root / 'queue.sqlite', self.queue_identity,
                                       expected_boundary, package_dir)
        validate_snapshot(queue_package.archive_path, expected_boundary,
                          expected_archive_sha256=queue_package.archive_sha256)
        expected = ExpectedPair(account=ACCOUNT, ledger_db_id=self.f.identity.db_id,
            queue_db_id=self.queue_identity.db_id, checkpoint_id=run.checkpoint_id,
            checkpoint_sequence=run.checkpoint_sequence, result_digest=run.result_digest,
            registry_revision=run.job['generation'], ledger_checkpoint_hash=ledger_package['checkpoint_hash'],
            ledger_archive_sha256=ledger_package['archive_sha256'],
            queue_archive_sha256=queue_package.archive_sha256,
            ledger_library_file_id=receipt['library_file_id'], ledger_library_version=receipt['library_version'],
            ledger_previous_version=receipt['previous_version'],
            queue_library_file_id='synthetic-queue-only', queue_library_version='synthetic-queue-v1',
            queue_previous_version='', ledger_downloaded_archive=str(ledger_archive),
            queue_downloaded_archive=str(queue_package.archive_path))
        pair = {'schema': 'role-queue-checkpoint-pair-v1', 'expected': asdict(expected),
                'verified_at': self.f.now}
        for kind in ('ledger', 'queue'):
            pair[kind + '_receipt'] = {field: getattr(expected, kind + '_' + field) for field in
                ('archive_sha256', 'downloaded_archive', 'library_file_id', 'library_version', 'previous_version')}
            pair[kind + '_receipt'].update(verified_at=self.f.now,
                transport_reference=receipt['transport_reference'] if kind == 'ledger'
                else 'LOCAL SYNTHETIC QUEUE ROUNDTRIP ONLY')
        result = self.c.complete_checkpoint(receipt_path=str(receipt_path), receipt_sha256=receipt_sha,
                                            pair_manifest=pair, expected_pair=expected)
        self.assertEqual(result.state, 'done')
        self.assertEqual(self.q.inspect_job(job)['state'], 'done')
        self.assertIsNone(self.q.snapshot()['dispatcher']['job_id'])
        self.assertFalse(successful(self.a.execute('status'))['checkpoint_pending'])

    def test_coordinator_definitive_denial_preserves_unknown_stop_and_writer(self):
        job = self.prepare()
        self.browser.outcome = 'denied'
        self.assertEqual(self.c.run_once().state, 'blocked')
        status = successful(self.a.execute('status'))
        self.assertEqual(len(status['stops']), 1)
        self.assertIsNotNone(status['writer'])
        self.assertFalse(status['checkpoint_pending'])
        self.assertEqual(sum(a['state'] == 'unknown' for a in status['actions']), 1)
        self.assertEqual(len(self.browser.mutations), 1)
        self.assertEqual(self.q.inspect_job(job)['state'], 'blocked')

    def test_lost_begin_result_never_calls_fake_browser_mutation(self):
        from dispatch_gate import CommandResult
        job = self.prepare()
        execute = self.a.execute

        def lose_only_begin(command, **args):
            result = execute(command, **args)
            if command == 'begin-write':
                self.assertEqual(result.exit_code, 0)
                return CommandResult(False, None, '', session_id='synthetic-lost-response')
            return result

        with mock.patch.object(self.a, 'execute', side_effect=lose_only_begin):
            self.assertEqual(self.c.run_once().state, 'blocked')
        self.assertFalse(self.browser.mutations)
        status = successful(self.a.execute('status'))
        self.assertEqual(sum(a['state'] == 'intent' for a in status['actions']), 1)
        self.assertIsNotNone(status['writer'])
        self.assertEqual(self.q.inspect_job(job)['state'], 'blocked')


if __name__ == '__main__':
    unittest.main(verbosity=2)
