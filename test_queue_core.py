"""All fixtures are disposable STAGING files. No production/browser/network use."""

from dataclasses import asdict, replace
import hashlib
import json
import multiprocessing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from queue_core import (STAGING_ROOT, Binding, BindingError, BusyError, CheckpointError,
                        ConflictError, DatabaseIdentity, DispatchClaim, QueueCore, QueueError,
                        Schedule, SlotError, StateError, initialize_staging)


def _process_claim(path, identity, evidence, barrier, output, worker):
    try:
        queue = QueueCore(path, identity)
        barrier.wait(timeout=20)
        claim = queue.claim_next(worker, evidence, now=1001)
        output.put(('ok', {'job_id': claim.job_id, 'dispatcher_id': claim.dispatcher_id} if claim else None))
    except Exception as exc:
        output.put(('error', repr(exc)))


class QueueCoreTests(unittest.TestCase):
    def setUp(self):
        STAGING_ROOT.mkdir(exist_ok=True, parents=True)
        self.temp = tempfile.TemporaryDirectory(prefix='queue-test-', dir=STAGING_ROOT)
        self.path = Path(self.temp.name) / 'companion.sqlite3'
        self.bindings = {role: Binding('worker-' + role, 'staging-browser', 'tab-' + role, '@Staging_Account')
                         for role in ('publisher', 'spreader', 'commenter')}
        self.schedules = {role: Schedule(1000, 60) for role in self.bindings}
        self.identity = initialize_staging(self.path, self.bindings, self.schedules, ledger_db_id='staging-ledger-v2')
        self.queue = QueueCore(self.path, self.identity)
        self.evidence = {role: self.observe(role) for role in self.bindings}

    def tearDown(self):
        self.temp.cleanup()

    def observe(self, role, now=1001, **changes):
        b = self.bindings[role]
        params = dict(worker_id=b.worker_id, browser_id=b.browser_id, tab_id=b.tab_id,
                      observed_account=b.expected_account, tab_exists=True, observed_at=now, now=now)
        params.update(changes)
        return self.queue.record_observation(role, **params)

    def enqueue(self, role='publisher', now=1001, scheduled_at=1000, next_at=1060, evidence=None):
        return self.queue.enqueue(role, scheduled_at, next_at, evidence_id=evidence or self.evidence[role], now=now)

    def ready(self, role='publisher', payload=None):
        job = self.enqueue(role)
        return self.queue.mark_ready(job['job_id'], {'actions': []} if payload is None else payload,
                                     evidence_id=self.evidence[role], now=1001)

    def claim(self, action_ids=None):
        claim = self.queue.claim_next('dispatcher-one', self.evidence, now=1001)
        if claim:
            self.queue.register_action_manifest(claim, action_ids or [], now=1001)
        return claim

    def ready_actions(self, action_ids):
        return self.ready(payload={'actions': [{'staging_id': action_id} for action_id in action_ids]})

    def proof(self, **changes):
        result = dict(checkpoint_id='checkpoint-1', result_digest='a' * 64,
                      ledger_db_id='staging-ledger-v2', account='staging_account',
                      checkpoint_sequence=1, checkpoint_hash='b' * 64,
                      library_file_id='library-staging-checkpoint', library_version='version-1',
                      archive_sha256='c' * 64, pair_manifest_sha256='d' * 64,
                      queue_archive_sha256='e' * 64, queue_library_file_id='library-staging-queue',
                      queue_library_version='queue-version-1', queue_previous_version='',
                      pending=False, writer=None, stop=False, unresolved=False)
        result.update(changes)
        return result

    def wait_checkpoint(self, claim):
        self.queue.enter_checkpoint_wait(claim, 'checkpoint-1', 'a' * 64, now=1002)

    def test_explicit_init_and_companion_schema(self):
        snap = self.queue.snapshot()
        self.assertEqual(snap['meta']['schema_version'], 1)
        self.assertEqual(snap['meta']['ledger_db_id'], 'staging-ledger-v2')
        self.assertEqual(len(snap['registry']), 3)
        self.assertIsNone(snap['dispatcher']['job_id'])
        with self.assertRaises(StateError):
            initialize_staging(self.path, self.bindings, self.schedules, ledger_db_id='other')
        with self.assertRaises(StateError):
            QueueCore(Path(self.temp.name) / 'absent.sqlite3', self.identity)
        self.assertFalse((Path(self.temp.name) / 'absent.sqlite3').exists())

    def test_staging_path_is_mandatory(self):
        with self.assertRaises(StateError):
            QueueCore('/tmp/not-the-approved-staging-file.sqlite3', self.identity)

    def test_parallel_roles_prepare_and_queue_is_bounded(self):
        barrier = threading.Barrier(3)
        def prepare(role):
            local = QueueCore(self.path, self.identity)
            barrier.wait(timeout=10)
            job = local.enqueue(role, 1000, 1060, evidence_id=self.evidence[role], now=1001)
            return local.mark_ready(job['job_id'], {'role': role}, evidence_id=self.evidence[role], now=1001)
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = list(pool.map(prepare, self.bindings))
        self.assertEqual({job['state'] for job in jobs}, {'ready'})
        self.assertEqual(len({job['job_id'] for job in jobs}), 3)
        self.assertEqual(len(self.queue.snapshot()['jobs']), 3)

    def test_concurrent_duplicate_enqueue_returns_single_deterministic_job(self):
        def enqueue(_):
            return QueueCore(self.path, self.identity).enqueue('publisher', 1000, 1060,
                       evidence_id=self.evidence['publisher'], now=1001)['job_id']
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(enqueue, range(16)))
        self.assertEqual(len(set(ids)), 1)
        expected = hashlib.sha256(f'{self.identity.db_id}:publisher:1000'.encode()).hexdigest()
        self.assertEqual(ids[0], 'job_' + expected)
        self.assertEqual(len(self.queue.snapshot()['jobs']), 1)

    def test_duplicate_preparation_is_immutable_canonical_json(self):
        job = self.ready(payload={'b': 2, 'a': 1})
        again = self.queue.mark_ready(job['job_id'], {'a': 1, 'b': 2}, evidence_id=self.evidence['publisher'], now=1001)
        self.assertEqual(job['payload_hash'], again['payload_hash'])
        with self.assertRaises(ConflictError):
            self.queue.mark_ready(job['job_id'], {'a': 2}, evidence_id=self.evidence['publisher'], now=1001)
        self.assertEqual(json.loads(self.queue.inspect_job(job['job_id'])['payload_json']), {'a': 1, 'b': 2})
        with sqlite3.connect(self.path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE jobs SET payload_json='{}' WHERE job_id=?", (job['job_id'],))

    def test_no_future_missed_run_or_guessed_boundaries(self):
        for start, end, now in [(1060, 1120, 1001), (940, 1000, 1001),
                                (1000, 1120, 1001), (999, 1059, 1001), (1000, 1060, 1060)]:
            with self.subTest(start=start, end=end, now=now), self.assertRaises(SlotError):
                self.enqueue(scheduled_at=start, next_at=end, now=now)
        self.assertEqual(len(self.queue.snapshot()['jobs']), 0)

    def test_expiry_advances_current_slot_without_catchup(self):
        old = self.ready()
        evidence = self.observe('publisher', now=1060)
        current = self.enqueue(now=1060, scheduled_at=1060, next_at=1120, evidence=evidence)
        self.assertEqual(self.queue.inspect_job(old['job_id'])['state'], 'expired')
        self.assertEqual(current['scheduled_at'], 1060)
        with self.assertRaises(SlotError):
            self.enqueue(now=1060, evidence=evidence)

    def test_deadline_expires_ready_without_starting_action(self):
        job = self.ready()
        self.assertIsNone(self.queue.claim_next('late-dispatcher', self.evidence, now=1060))
        self.assertEqual(self.queue.inspect_job(job['job_id'])['state'], 'expired')

    def test_deadline_during_dispatch_blocks_new_start_but_allows_checkpoint(self):
        self.ready()
        claim = self.claim()
        evidence = self.observe('publisher', now=1060)
        with self.assertRaises(SlotError):
            self.queue.validate_action_start(claim, evidence, now=1060)
        self.queue.enter_checkpoint_wait(claim, 'checkpoint-1', 'a' * 64, now=1061)
        done = self.queue.acknowledge_checkpoint(claim, self.proof(), now=1062)
        self.assertEqual(done['state'], 'done')

    def test_fresh_exact_observation_is_required(self):
        for changes in [dict(tab_exists=False), dict(worker_id='someone-else'),
                        dict(tab_id='another-tab'), dict(browser_id='other-browser'),
                        dict(observed_account='other-account'), dict(observed_at=960), dict(observed_at=1002)]:
            with self.subTest(changes=changes), self.assertRaises(BindingError):
                self.observe('publisher', **changes)
        with self.assertRaises(BindingError):
            self.enqueue(evidence=self.evidence['spreader'])
        with self.assertRaises(BindingError):
            self.enqueue(now=1032)

    def test_dispatch_and_every_action_recheck_observation(self):
        self.ready()
        with self.assertRaises(BindingError):
            self.queue.claim_next('dispatcher', self.evidence, now=1032)
        fresh = self.observe('publisher', now=1032)
        claim = self.queue.claim_next('dispatcher', {'publisher': fresh}, now=1032)
        with self.assertRaises(BindingError):
            self.queue.validate_action_start(claim, self.evidence['publisher'], now=1032)
        self.assertEqual(self.queue.validate_action_start(claim, fresh, now=1032)['state'], 'dispatching')

    def test_registry_rebind_invalidates_all_roles_and_evidence(self):
        job = self.ready('spreader')
        generation = self.queue.rebind('publisher', Binding('new-worker', 'browser', 'new-tab', 'staging_account'),
                                       expected_generation=1, reason='Explicit staging reassignment', now=1002)
        self.assertEqual(generation, 2)
        self.assertEqual(self.queue.inspect_job(job['job_id'])['state'], 'blocked')
        with self.assertRaises(BindingError):
            self.enqueue('spreader', now=1002)
        with self.assertRaises(BindingError):
            self.queue.rebind('publisher', self.bindings['publisher'], expected_generation=1,
                              reason='Stale operator state', now=1002)
        fresh = self.observe('spreader', now=1002)
        with self.assertRaises(BindingError):
            self.queue.mark_ready(job['job_id'], {'text': 'spreader'}, evidence_id=fresh, now=1002)

    def test_duplicate_workers_tabs_and_active_rebinding_are_rejected(self):
        for binding in [replace(self.bindings['publisher'], worker_id=self.bindings['spreader'].worker_id),
                        replace(self.bindings['publisher'], tab_id=self.bindings['spreader'].tab_id)]:
            with self.assertRaises(BindingError):
                self.queue.rebind('publisher', binding, expected_generation=1, reason='Bad map', now=1001)
        self.ready(); self.claim()
        with self.assertRaises(BusyError):
            self.queue.rebind('publisher', self.bindings['publisher'], expected_generation=1, reason='Unsafe rebind', now=1002)

    def test_duplicate_initial_ownership_is_rejected_before_creation(self):
        bindings = dict(self.bindings)
        bindings['spreader'] = self.bindings['publisher']
        path = Path(self.temp.name) / 'invalid.sqlite3'
        with self.assertRaises(BindingError):
            initialize_staging(path, bindings, self.schedules, ledger_db_id='staging-ledger-v2')
        self.assertFalse(path.exists())

    def test_browser_selection_aliases_cannot_hide_physical_ownership(self):
        for alias in ('cdp', 'iab', 'extension', 'mcpapps', 'CDP'):
            with self.subTest(alias=alias), self.assertRaises(BindingError):
                self.queue.rebind('publisher', replace(self.bindings['publisher'], browser_id=alias),
                                  expected_generation=1, reason='Alias must fail closed', now=1001)

    def test_atomic_dispatch_ownership_across_processes(self):
        for role in self.bindings:
            self.ready(role)
        ctx = multiprocessing.get_context('fork')
        barrier, output = ctx.Barrier(6), ctx.Queue()
        processes = [ctx.Process(target=_process_claim,
                     args=(str(self.path), asdict(self.identity), self.evidence, barrier, output, f'dispatcher-{i}')) for i in range(6)]
        for process in processes:
            process.start()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(status == 'ok' for status, _ in results), results)
        winners = [claim for _, claim in results if claim]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(self.queue.snapshot()['dispatcher']['job_id'], winners[0]['job_id'])

    def test_busy_writer_waits_instead_of_skipping_job_or_taking_over(self):
        for role in self.bindings:
            self.ready(role)
        claim = self.claim()
        reopened = QueueCore(self.path, self.identity)
        self.assertIsNone(reopened.claim_next('other-owner', self.evidence, now=1002))
        self.assertIsNone(reopened.claim_next('other-owner', self.evidence, now=100000))
        self.assertEqual(reopened.snapshot()['dispatcher']['claim_token_hash'], hashlib.sha256(claim.claim_token.encode()).hexdigest())
        self.assertEqual(reopened.inspect_job(claim.job_id)['state'], 'dispatching')

    def test_wrong_claim_cannot_start_block_or_release(self):
        self.ready(); claim = self.claim()
        wrong = replace(claim, claim_token='wrong-token')
        for action in [lambda: self.queue.validate_action_start(wrong, self.evidence['publisher'], now=1001),
                       lambda: self.queue.block_claim(wrong, 'Wrong owner', now=1001),
                       lambda: self.queue.enter_checkpoint_wait(wrong, 'checkpoint-1', 'a' * 64, now=1001)]:
            with self.assertRaises(StateError):
                action()
        self.assertEqual(self.queue.snapshot()['dispatcher']['claim_token_hash'], hashlib.sha256(claim.claim_token.encode()).hexdigest())

    def test_checkpoint_wait_retains_writer_until_exact_ack(self):
        self.ready('publisher'); self.ready('spreader')
        claim = self.claim(); self.wait_checkpoint(claim)
        self.assertEqual(self.queue.inspect_job(claim.job_id)['state'], 'checkpoint_wait')
        self.assertIsNone(self.queue.claim_next('other', self.evidence, now=1002))
        with self.assertRaises(StateError):
            self.queue.validate_action_start(claim, self.evidence['publisher'], now=1002)
        with self.assertRaises(ConflictError):
            self.queue.enter_checkpoint_wait(claim, 'checkpoint-other', 'a' * 64, now=1002)
        done = self.queue.acknowledge_checkpoint(claim, self.proof(), now=1003)
        self.assertEqual(done['state'], 'done')
        self.assertIsNone(self.queue.snapshot()['dispatcher']['job_id'])
        next_claim = self.queue.claim_next('other', self.evidence, now=1003)
        self.assertIsNotNone(next_claim)
        self.assertNotEqual(next_claim.job_id, claim.job_id)

    def test_invalid_checkpoint_proofs_never_release(self):
        self.ready(); claim = self.claim(); self.wait_checkpoint(claim)
        cases = [dict(checkpoint_id='wrong'), dict(result_digest='c' * 64), dict(ledger_db_id='wrong'),
                 dict(account='other'), dict(account='@Staging_Account'), dict(checkpoint_sequence=0),
                 dict(checkpoint_hash='invalid'), dict(library_file_id=''), dict(library_version=''),
                 dict(archive_sha256='invalid'), dict(pair_manifest_sha256='invalid'),
                 dict(queue_archive_sha256='invalid'), dict(queue_library_file_id=''), dict(queue_library_version=''),
                 dict(queue_previous_version=None), dict(queue_previous_version='  '),
                 dict(queue_previous_version='queue-version-1'),
                 dict(pending=True), dict(writer='active'), dict(stop=True), dict(unresolved=True),
                 dict(pending=0), dict(stop=0), dict(unresolved=0)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(QueueError):
                self.queue.acknowledge_checkpoint(claim, self.proof(**change), now=1003)
            self.assertEqual(self.queue.snapshot()['dispatcher']['job_id'], claim.job_id)
        with self.assertRaises(CheckpointError):
            self.queue.acknowledge_checkpoint(claim, {'verified': True}, now=1003)

    def test_ack_requires_checkpoint_wait_and_sequence_advances(self):
        self.ready(); claim = self.claim()
        with self.assertRaises(CheckpointError):
            self.queue.acknowledge_checkpoint(claim, self.proof(), now=1002)
        self.wait_checkpoint(claim)
        self.queue.acknowledge_checkpoint(claim, self.proof(), now=1003)
        self.ready('spreader'); second = self.claim()
        self.wait_checkpoint(second)
        with self.assertRaises(CheckpointError):
            self.queue.acknowledge_checkpoint(second, self.proof(), now=1003)
        self.queue.acknowledge_checkpoint(second, self.proof(checkpoint_sequence=2,
            queue_previous_version='queue-version-1', queue_library_version='queue-version-2'), now=1003)

    def test_ack_is_exactly_idempotent_without_releasing_next_owner(self):
        self.ready(); claim = self.claim(); self.wait_checkpoint(claim)
        self.queue.acknowledge_checkpoint(claim, self.proof(), now=1003)
        self.ready('spreader'); second = self.claim()
        self.assertEqual(self.queue.acknowledge_checkpoint(claim, self.proof(), now=1003)['state'], 'done')
        self.assertEqual(self.queue.snapshot()['dispatcher']['job_id'], second.job_id)
        with self.assertRaises(ConflictError):
            self.queue.acknowledge_checkpoint(claim, self.proof(library_version='different'), now=1003)

    def test_uncertain_claim_blocks_globally_including_after_restart(self):
        self.ready(); claim = self.claim()
        self.queue.block_claim(claim, 'Submit result uncertain; read-only reconciliation required', now=1002)
        reopened = QueueCore(self.path, self.identity)
        self.assertIsNone(reopened.claim_next('replacement', self.evidence, now=100000))
        self.assertEqual(reopened.snapshot()['dispatcher']['claim_token_hash'], hashlib.sha256(claim.claim_token.encode()).hexdigest())
        evidence = self.observe('publisher', now=1061)
        with self.assertRaises(BusyError):
            self.enqueue(now=1061, scheduled_at=1060, next_at=1120, evidence=evidence)
        with self.assertRaises(StateError):
            reopened.validate_action_start(claim, self.evidence['publisher'], now=1002)
        # Ordinary checkpoint acknowledgement never bypasses a blocked claim.
        with self.assertRaises(StateError):
            reopened.enter_checkpoint_wait(claim, 'checkpoint-1', 'a' * 64, now=1062)

    def test_absent_corrupt_wrong_identity_and_replaced_database_fail_closed(self):
        with self.assertRaises(StateError):
            QueueCore(self.path, replace(self.identity, db_id='wrong-id'))
        clone = Path(self.temp.name) / 'clone.sqlite3'
        shutil.copy2(self.path, clone)
        clone.replace(self.path)
        with self.assertRaises(StateError):
            self.queue.snapshot()
        with self.assertRaises(StateError):
            QueueCore(self.path, self.identity)
        stat = self.path.stat()
        current = replace(self.identity, device=stat.st_dev, inode=stat.st_ino)
        self.path.write_bytes(b'broken sqlite file')
        with self.assertRaises(StateError):
            QueueCore(self.path, current)
        self.path.unlink()
        with self.assertRaises(StateError):
            QueueCore(self.path, current)
        self.assertFalse(self.path.exists())

    def test_missing_dispatcher_row_and_lost_ownership_fail_closed(self):
        self.ready(); self.claim()
        with sqlite3.connect(self.path) as conn:
            conn.execute('UPDATE dispatcher SET job_id=NULL,dispatcher_id=NULL,claim_token_hash=NULL')
        with self.assertRaises(StateError):
            QueueCore(self.path, self.identity)
        with sqlite3.connect(self.path) as conn:
            conn.execute('DELETE FROM dispatcher')
        with self.assertRaises(StateError):
            self.queue.snapshot()

    def test_json_nonfinite_and_unbounded_payloads_are_rejected(self):
        job = self.enqueue()
        for payload in [dict(value=float('nan')), 'x' * (1024 * 1024 + 1)]:
            with self.assertRaises(QueueError):
                self.queue.mark_ready(job['job_id'], payload, evidence_id=self.evidence['publisher'], now=1001)
        self.assertEqual(self.queue.inspect_job(job['job_id'])['state'], 'preparing')

    def test_action_progress_is_one_way_and_terminal_before_checkpoint(self):
        self.ready_actions(['action-one']); claim = self.claim(['action-one'])
        for state in ('reserved', 'intent', 'submitted'):
            result = {'url': 'https://example.test/staging'} if state == 'submitted' else None
            self.queue.record_action_progress(claim, 'action-one', state, result=result, now=1002)
            with self.assertRaises(CheckpointError):
                self.wait_checkpoint(claim)
        self.queue.record_action_progress(claim, 'action-one', 'verified', result={'readback': 'exact'}, now=1003)
        self.queue.record_action_progress(claim, 'action-one', 'verified', result={'readback': 'exact'}, now=1003)
        with self.assertRaises(ConflictError):
            self.queue.record_action_progress(claim, 'action-one', 'verified', result={'readback': 'different'}, now=1003)
        with self.assertRaises(StateError):
            self.queue.record_action_progress(claim, 'action-one', 'reserved', now=1003)
        self.wait_checkpoint(claim)
        self.queue.acknowledge_checkpoint(claim, self.proof(), now=1004)
        progress = self.queue.list_action_progress(claim)
        self.assertEqual(len(progress), 1)
        self.assertEqual(progress[0]['state'], 'verified')

    def test_progress_single_inflight_action_and_no_writer_token_storage(self):
        self.ready_actions(['one', 'two', 'three']); claim = self.claim(['one', 'two', 'three'])
        for result in [{'writer_token': 'do-not-store'}, {'nested': [{'lease_token': 'do-not-store'}]}]:
            with self.assertRaises(StateError):
                self.queue.record_action_progress(claim, 'one', 'reserved', result=result, now=1002)
        self.queue.record_action_progress(claim, 'one', 'reserved', now=1002)
        with self.assertRaises(BusyError):
            self.queue.record_action_progress(claim, 'two', 'reserved', now=1002)
        self.queue.record_action_progress(claim, 'one', 'already_present', now=1003)
        self.queue.record_action_progress(claim, 'two', 'reserved', now=1003)
        self.queue.record_action_progress(claim, 'two', 'cancelled', now=1003)
        self.queue.record_action_progress(claim, 'three', 'duplicate', now=1003)
        self.wait_checkpoint(claim)

    def test_uncertain_action_never_retries_or_releases_via_checkpoint(self):
        self.ready_actions(['one']); claim = self.claim(['one'])
        self.queue.record_action_progress(claim, 'one', 'uncertain', result={'reason': 'No output'}, now=1002)
        self.assertEqual(self.queue.inspect_job(claim.job_id)['state'], 'blocked')
        with self.assertRaises(StateError):
            self.queue.record_action_progress(claim, 'one', 'verified', now=1003)
        with self.assertRaises(StateError):
            self.wait_checkpoint(claim)
        self.assertIsNone(self.queue.claim_next('another', self.evidence, now=1003))

    def test_action_intent_deadline_and_late_readback(self):
        self.ready_actions(['one', 'two']); claim = self.claim(['one', 'two'])
        self.queue.record_action_progress(claim, 'one', 'reserved', now=1059)
        self.queue.record_action_progress(claim, 'one', 'intent', now=1059)
        self.queue.record_action_progress(claim, 'one', 'submitted', result={'receipt': 'staging'}, now=1060)
        self.queue.record_action_progress(claim, 'one', 'verified', result={'readback': 'staging'}, now=1061)
        with self.assertRaises(SlotError):
            self.queue.record_action_progress(claim, 'two', 'reserved', now=1061)
        self.queue.record_action_progress(claim, 'two', 'cancelled', result={'reason': 'deadline'}, now=1061)
        self.queue.enter_checkpoint_wait(claim, 'checkpoint-1', 'a' * 64, now=1062)

    def test_clock_rollback_cannot_prepare_or_start_future_slot(self):
        job = self.enqueue()
        fresh = self.observe('publisher', now=999)
        with self.assertRaises(SlotError):
            self.queue.mark_ready(job['job_id'], {}, evidence_id=fresh, now=999)
        self.ready()
        with self.assertRaises(SlotError):
            self.queue.claim_next('dispatcher', {'publisher': fresh}, now=999)

    def test_raw_claim_credential_is_never_persisted_or_reported(self):
        self.ready(); claim = self.claim()
        self.assertNotIn(claim.claim_token, repr(claim))
        self.assertNotIn(claim.claim_token, json.dumps(self.queue.snapshot()))
        self.assertNotIn(claim.claim_token, json.dumps(self.queue.inspect_job(claim.job_id)))
        with sqlite3.connect(self.path) as conn:
            dump = '\n'.join(conn.iterdump())
        self.assertNotIn(claim.claim_token, dump)
        token_hash = hashlib.sha256(claim.claim_token.encode()).hexdigest()
        self.assertIn(token_hash, dump)
        forged = replace(claim, claim_token=token_hash)
        with self.assertRaises(StateError):
            self.queue.validate_action_start(forged, self.evidence['publisher'], now=1002)

    def test_removed_guard_index_fails_closed_even_with_valid_sqlite_integrity(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute('DROP INDEX one_dispatch_owner')
            self.assertEqual(conn.execute('PRAGMA quick_check').fetchone()[0], 'ok')
        with self.assertRaises(StateError):
            self.queue.snapshot()

    def test_removed_immutable_trigger_fails_closed_even_with_v1_schema(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute('DROP TRIGGER immutable_payload')
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0], 1)
        with self.assertRaises(StateError):
            QueueCore(self.path, self.identity)

    def test_uncertain_job_cannot_lose_writer_silently(self):
        self.ready(); claim = self.claim()
        self.queue.block_claim(claim, 'Uncertain external result', now=1002)
        with sqlite3.connect(self.path) as conn:
            conn.execute('UPDATE dispatcher SET job_id=NULL,dispatcher_id=NULL,claim_token_hash=NULL')
        with self.assertRaises(StateError):
            self.queue.snapshot()

    def test_blocked_zero_progress_cannot_bypass_through_checkpoint(self):
        self.ready(); claim = self.claim()
        self.queue.block_claim(claim, 'Authorization unresolved before any action', now=1002)
        with self.assertRaises(StateError):
            self.wait_checkpoint(claim)
        with self.assertRaises(CheckpointError):
            self.queue.acknowledge_checkpoint(claim, self.proof(), now=1003)
        self.assertEqual(self.queue.snapshot()['dispatcher']['job_id'], claim.job_id)

    def test_unrecorded_planned_action_prevents_checkpoint(self):
        self.ready_actions(['one', 'two']); claim = self.claim(['one', 'two'])
        self.queue.record_action_progress(claim, 'one', 'duplicate', now=1002)
        with self.assertRaises(CheckpointError):
            self.wait_checkpoint(claim)
        self.queue.record_action_progress(claim, 'two', 'cancelled', now=1002)
        self.wait_checkpoint(claim)

    def test_expected_manifest_is_explicit_complete_and_immutable(self):
        self.ready_actions(['one', 'two'])
        claim = self.queue.claim_next('dispatcher', self.evidence, now=1001)
        with self.assertRaises(CheckpointError):
            self.wait_checkpoint(claim)
        with self.assertRaises(StateError):
            self.queue.record_action_progress(claim, 'one', 'duplicate', now=1001)
        for ids in ([], ['one'], ['one', 'one']):
            with self.assertRaises(StateError):
                self.queue.register_action_manifest(claim, ids, now=1001)
        self.queue.register_action_manifest(claim, ['one', 'two'], now=1001)
        self.queue.register_action_manifest(claim, ['one', 'two'], now=1001)
        with self.assertRaises(ConflictError):
            self.queue.register_action_manifest(claim, ['two', 'one'], now=1001)
        with self.assertRaises(StateError):
            self.queue.record_action_progress(claim, 'not-in-prepared-batch', 'duplicate', now=1001)
        with sqlite3.connect(self.path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE jobs SET action_manifest_json='[]' WHERE job_id=?", (claim.job_id,))

    def test_empty_manifest_requires_actual_empty_prepared_batch(self):
        self.ready(payload={'text': 'Not an explicit empty batch'})
        claim = self.queue.claim_next('dispatcher', self.evidence, now=1001)
        with self.assertRaises(StateError):
            self.queue.register_action_manifest(claim, [], now=1001)

    def test_first_queue_checkpoint_may_use_empty_or_externally_pinned_previous_version(self):
        # Empty previous version is an explicit first-boundary case throughout
        # the ordinary fixtures; an external transport may also pin a baseline.
        self.ready(); claim = self.claim(); self.wait_checkpoint(claim)
        done = self.queue.acknowledge_checkpoint(claim,
            self.proof(queue_previous_version='externally-verified-baseline'), now=1003)
        self.assertEqual(done['state'], 'done')
        self.assertEqual(json.loads(done['checkpoint_proof_json'])['queue_previous_version'],
                         'externally-verified-baseline')

    def test_subsequent_queue_checkpoint_requires_exact_library_version_chain(self):
        self.ready(); first = self.claim(); self.wait_checkpoint(first)
        self.queue.acknowledge_checkpoint(first, self.proof(), now=1003)
        self.ready('spreader'); second = self.claim(); self.wait_checkpoint(second)
        good = self.proof(checkpoint_sequence=2, queue_previous_version='queue-version-1',
                          queue_library_version='queue-version-2')
        mutations = [dict(queue_library_file_id='another-library-identity'),
                     dict(queue_previous_version='unexpected-prior-version'),
                     dict(queue_previous_version=''),
                     dict(queue_library_version='queue-version-1')]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(CheckpointError):
                self.queue.acknowledge_checkpoint(second, dict(good, **mutation), now=1004)
            self.assertEqual(self.queue.snapshot()['dispatcher']['job_id'], second.job_id)
        done = self.queue.acknowledge_checkpoint(second, good, now=1004)
        self.assertEqual(done['state'], 'done')
        self.assertEqual(json.loads(done['checkpoint_proof_json'])['queue_previous_version'], 'queue-version-1')
        self.assertEqual(self.queue.acknowledge_checkpoint(second, good, now=1005)['state'], 'done')
        self.ready('commenter'); third = self.claim(); self.wait_checkpoint(third)
        with self.assertRaises(CheckpointError):
            self.queue.acknowledge_checkpoint(third, self.proof(checkpoint_sequence=3,
                queue_previous_version='queue-version-1', queue_library_version='queue-version-3'), now=1006)
        self.assertEqual(self.queue.acknowledge_checkpoint(third, self.proof(checkpoint_sequence=3,
            queue_previous_version='queue-version-2', queue_library_version='queue-version-3'), now=1006)['state'], 'done')


if __name__ == '__main__':
    unittest.main()
