"""Disposable synthetic fixtures only. No browser, ledger CLI or Library calls."""
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import queue_checkpoint as q


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        q.INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='checkpoint-test-', dir=q.INTEGRATION_ROOT)
        self.root = Path(self.temp.name)
        self.old_root = q.core.STAGING_ROOT
        q.core.STAGING_ROOT = self.root
        self.path = self.root / 'source.sqlite3'
        self.bindings = {role: q.core.Binding('worker-' + role, 'synthetic-browser',
                       'tab-' + role, 'example.bot') for role in q.core.ROLES}
        self.identity = q.core.initialize_staging(self.path, self.bindings,
            {role: q.core.Schedule(1000, 60) for role in q.core.ROLES}, ledger_db_id='a' * 32)
        self.queue = q.core.QueueCore(self.path, self.identity)
        self.evidence = {}
        for role, b in self.bindings.items():
            self.evidence[role] = self.queue.record_observation(role, worker_id=b.worker_id,
                browser_id=b.browser_id, tab_id=b.tab_id, observed_account=b.expected_account,
                tab_exists=True, observed_at=1001, now=1001)
        self.job = self.queue.enqueue('publisher', 1000, 1060,
                                    evidence_id=self.evidence['publisher'], now=1001)
        target = 'https://www.threads.com/@sample/post/abc123'
        self.actions = [{'kind': 'like', 'target': target,
                         'payload': {'target': target}, 'authorization_id': 'synthetic-policy'}]
        self.queue.mark_ready(self.job['job_id'], {'actions': self.actions},
                              evidence_id=self.evidence['publisher'], now=1001)
        self.claim = self.queue.claim_next('synthetic-dispatcher', self.evidence, now=1001)
        self.action_id = q.gate.action_id('example.bot', 'like', target)
        self.queue.register_action_manifest(self.claim, [self.action_id], now=1001)
        self.queue.record_action_progress(self.claim, self.action_id, 'duplicate',
                                         result={'ledger_state': 'verified'}, now=1002)
        self.digest = q._sha(q._canonical(self.queue.list_action_progress(self.claim)))
        self.expected = q.ExpectedBoundary('example.bot', 'a' * 32, self.identity.db_id,
            1, self.claim.job_id, 'a' * 32 + ':1', 1, self.digest)
        self.queue.enter_checkpoint_wait(self.claim, self.expected.checkpoint_id, self.digest, now=1003)

    def tearDown(self):
        q.core.STAGING_ROOT = self.old_root
        self.temp.cleanup()

    def build(self):
        return q.build_snapshot(self.path, self.identity, self.expected, self.root)

    def validate(self, path, expected=None):
        return q.validate_snapshot(path, expected or self.expected,
                                   expected_archive_sha256=q._sha(Path(path).read_bytes()))

    def member_bytes(self, snapshot=None):
        snapshot = snapshot or self.build()
        with zipfile.ZipFile(snapshot.archive_path) as archive:
            return archive.read('manifest.json'), archive.read('queue.sqlite3')

    def write_zip(self, manifest, database, name='changed.zip'):
        path = self.root / name
        path.write_bytes(q._zip_bytes(manifest, database))
        return path

    def mutate_database(self, sql, parameters=(), *, schema_rewrite=False):
        manifest_bytes, database = self.member_bytes()
        dbpath = self.root / 'tamper.sqlite3'
        dbpath.write_bytes(database)
        with sqlite3.connect(dbpath) as conn:
            if schema_rewrite:
                conn.execute('PRAGMA writable_schema=ON')
            conn.execute(sql, parameters)
        database = dbpath.read_bytes()
        manifest = json.loads(manifest_bytes)
        manifest['database_sha256'] = q._sha(database)
        manifest['database_bytes'] = len(database)
        return self.write_zip(q._canonical(manifest), database)

    def test_round_trip_is_semantically_verified_readonly_and_deterministic(self):
        before = self.path.read_bytes(), self.queue.snapshot()
        result = self.build()
        second = self.build()
        self.assertEqual(result.archive_sha256, second.archive_sha256)
        self.assertEqual(result.archive_path, second.archive_path)
        self.assertEqual(before, (self.path.read_bytes(), self.queue.snapshot()))
        self.assertEqual(result, self.validate(result.archive_path))
        manifest = result.manifest()
        self.assertEqual(manifest['semantic']['boundary'], q.asdict(self.expected))
        self.assertEqual(manifest['semantic']['core_schema_sha256'], q.core.EXPECTED_SCHEMA_HASH)
        self.assertEqual(manifest['semantic']['job_coverage'][0]['progress_sha256'], self.digest)
        self.assertNotIn(self.claim.claim_token.encode(), Path(result.archive_path).read_bytes())
        self.assertIn(q._sha(self.claim.claim_token.encode()).encode(), Path(result.archive_path).read_bytes())

    def test_empty_batch_can_checkpoint(self):
        # A separate genuinely empty queue, not an edited frozen preparation.
        empty = self.root / 'empty.sqlite3'
        identity = q.core.initialize_staging(empty, self.bindings,
            {r: q.core.Schedule(1000, 60) for r in q.core.ROLES}, ledger_db_id='a' * 32)
        queue = q.core.QueueCore(empty, identity)
        b = self.bindings['publisher']
        eid = queue.record_observation('publisher', worker_id=b.worker_id, browser_id=b.browser_id,
            tab_id=b.tab_id, observed_account=b.expected_account, tab_exists=True, observed_at=1001, now=1001)
        job = queue.enqueue('publisher', 1000, 1060, evidence_id=eid, now=1001)
        queue.mark_ready(job['job_id'], {'actions': []}, evidence_id=eid, now=1001)
        claim = queue.claim_next('dispatcher-empty', {'publisher': eid}, now=1001)
        queue.register_action_manifest(claim, [], now=1001)
        digest = q._sha(b'[]')
        expected = replace(self.expected, queue_db_id=identity.db_id, job_id=claim.job_id, result_digest=digest)
        queue.enter_checkpoint_wait(claim, expected.checkpoint_id, digest, now=1002)
        self.assertEqual(q.build_snapshot(empty, identity, expected, self.root).expected, expected)

    def test_parallel_unclaimed_preparation_is_preserved(self):
        job = self.queue.enqueue('spreader', 1000, 1060, evidence_id=self.evidence['spreader'], now=1002)
        self.queue.mark_ready(job['job_id'], {'actions': []}, evidence_id=self.evidence['spreader'], now=1002)
        coverage = self.build().manifest()['semantic']['job_coverage']
        self.assertEqual({r['state'] for r in coverage}, {'ready', 'checkpoint_wait'})

    def test_outside_path_missing_and_replaced_source_fail_without_initialization(self):
        for path in (Path('/tmp/not-approved.sqlite3'), self.root / 'missing.sqlite3'):
            with self.subTest(path=path), self.assertRaises(q.SnapshotBlocked):
                q.build_snapshot(path, self.identity, self.expected, self.root)
            self.assertFalse(path.exists())
        replacement = self.root / 'replacement.sqlite3'
        shutil.copyfile(self.path, replacement)
        replacement.replace(self.path)
        with self.assertRaises(q.SnapshotBlocked):
            self.build()

    def test_source_symlink_and_symlink_parent_rejected(self):
        link = self.root / 'link.sqlite3'
        link.symlink_to(self.path)
        with self.assertRaises(q.SnapshotBlocked):
            q.build_snapshot(link, self.identity, self.expected, self.root)
        parent = self.root / 'dirlink'
        parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(q.SnapshotBlocked):
            q.build_snapshot(parent / self.path.name, self.identity, self.expected, self.root)

    def test_live_paths_never_opened(self):
        with mock.patch.object(q.sqlite3, 'connect', side_effect=AssertionError('must not open')):
            for path in ('/not-approved/ledger.sqlite3', '/tmp/queue.sqlite3', '/not-approved/live.sqlite3'):
                with self.subTest(path=path), self.assertRaises(q.SnapshotBlocked):
                    q.build_snapshot(path, self.identity, self.expected, self.root)

    def test_source_root_and_production_root_never_authorize_data_reads(self):
        with mock.patch.object(q.sqlite3, 'connect', side_effect=AssertionError('must not open')):
            for path in (q.SOURCE_ROOT / 'repository.sqlite3',
                         q._settings.PRODUCTION_ROOT / 'production.sqlite3'):
                with self.subTest(path=path), self.assertRaises(q.SnapshotBlocked):
                    q.build_snapshot(path, self.identity, self.expected, self.root)

    def test_each_pinned_source_rejects_tampering_before_execution(self):
        source_copy = self.root / 'source-copy'
        source_copy.mkdir()
        pins = {'settings.py': q.SETTINGS_SOURCE_SHA256,
                'integration_paths.py': q.PATHS_SOURCE_SHA256,
                'queue_core.py': q.CORE_SOURCE_SHA256,
                'dispatch_gate.py': q.GATE_SOURCE_SHA256}
        for name, digest in pins.items():
            with self.subTest(source=name):
                (source_copy / name).write_bytes((q.SOURCE_ROOT / name).read_bytes() + b'\n# changed\n')
                with mock.patch.object(q, 'SOURCE_ROOT', source_copy), \
                     mock.patch('builtins.exec', side_effect=AssertionError('must not execute')), \
                     self.assertRaises(q.SnapshotBlocked):
                    q._frozen_module('_queue_changed_source', name, digest)

    def test_pinned_queue_modules_ignore_ambient_settings(self):
        fake = object()
        with mock.patch.dict(sys.modules, {'settings': fake}):
            core = q._frozen_module('_queue_test_pinned_core', 'queue_core.py',
                                    q.CORE_SOURCE_SHA256, settings=q._settings)
            gate = q._frozen_module('_queue_test_pinned_gate', 'dispatch_gate.py',
                                    q.GATE_SOURCE_SHA256, settings=q._settings)
            self.assertEqual(core.STAGING_ROOT, q._settings.STAGING_ROOT)
            self.assertEqual(gate.BLOG_HOST, q._settings.BLOG_HOST)
            self.assertIs(sys.modules['settings'], fake)

    def test_source_pins_are_explicit_literal_values(self):
        import ast
        tree = ast.parse(Path(q.__file__).read_text())
        wanted = {'SETTINGS_SOURCE_SHA256', 'PATHS_SOURCE_SHA256',
                  'CORE_SOURCE_SHA256', 'GATE_SOURCE_SHA256'}
        literals = {target.id: ast.literal_eval(node.value)
                    for node in tree.body if isinstance(node, ast.Assign)
                    for target in node.targets
                    if isinstance(target, ast.Name) and target.id in wanted}
        self.assertEqual(set(literals), wanted)
        for name, digest in literals.items():
            self.assertEqual(getattr(q, name), digest)
            self.assertRegex(digest, r'^[0-9a-f]{64}$')

    def test_all_independent_boundary_fields_are_pinned(self):
        archive = self.build().archive_path
        changes = {'account': 'wrong', 'ledger_db_id': 'b' * 32,
            'queue_db_id': '00000000-0000-0000-0000-000000000000', 'registry_generation': 2,
            'job_id': 'job_' + 'c' * 64, 'checkpoint_id': 'different', 'checkpoint_sequence': 2,
            'result_digest': 'd' * 64}
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(q.SnapshotBlocked):
                self.validate(archive, replace(self.expected, **{field: value}))

    def test_archive_hash_cannot_be_omitted_or_changed(self):
        archive = self.build().archive_path
        with self.assertRaises(q.SnapshotBlocked):
            q.validate_snapshot(archive, self.expected, expected_archive_sha256='f' * 64)
        with self.assertRaises(TypeError):
            q.validate_snapshot(archive, self.expected)

    def test_result_digest_is_recomputed_not_merely_compared_with_manifest(self):
        archive = self.mutate_database("UPDATE action_progress SET result_json='{}'")
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_payload_hash_and_frozen_trigger_guard_are_required(self):
        archive = self.mutate_database("DELETE FROM sqlite_master WHERE type='trigger' AND name='immutable_payload'",
                                       schema_rewrite=True)
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_payload_tampering_rejected_even_when_trigger_would_be_bypassed(self):
        # Corrupt the saved hash at SQLite page level to leave the schema untouched.
        manifest_bytes, database = self.member_bytes()
        old = self.queue.inspect_job(self.claim.job_id)['payload_hash'].encode()
        self.assertIn(old, database)
        database = database.replace(old, b'f' * 64)
        manifest = json.loads(manifest_bytes)
        manifest['database_sha256'] = q._sha(database)
        archive = self.write_zip(q._canonical(manifest), database)
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_missing_and_unresolved_progress_rejected(self):
        for sql in ('DELETE FROM action_progress', "UPDATE action_progress SET state='uncertain'"):
            with self.subTest(sql=sql):
                archive = self.mutate_database(sql)
                with self.assertRaises(q.SnapshotBlocked):
                    self.validate(archive)
                (self.root / 'tamper.sqlite3').unlink()

    def test_matching_count_but_wrong_action_identity_rejected(self):
        archive = self.mutate_database('UPDATE action_progress SET action_id=?', ('f' * 64,))
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_raw_credential_keys_in_any_json_fail(self):
        for key in ('writer_token', 'ClaimToken', 'access-token', 'api_key', 'password',
                    'authorization', 'refresh_token', 'sessionToken', 'writer_token_hash'):
            with self.subTest(key=key):
                archive = self.mutate_database('UPDATE audit SET detail_json=? WHERE sequence=1',
                                               (json.dumps({key: 'synthetic-secret'}),))
                with self.assertRaises(q.SnapshotBlocked):
                    self.validate(archive)
                (self.root / 'tamper.sqlite3').unlink()

    def test_raw_credential_in_prepared_json_refuses_build(self):
        # Only synthetic DB writes; demonstrate audit is scanned, not only progress.
        with sqlite3.connect(self.path) as conn:
            conn.execute('UPDATE audit SET detail_json=? WHERE sequence=1',
                         (q._canonical({'nested': {'writer_token': 'synthetic-secret'}}).decode(),))
        with self.assertRaises(q.SnapshotBlocked):
            self.build()

    def test_duplicate_json_nonfinite_and_manifest_key_injections_rejected(self):
        manifest, database = self.member_bytes()
        attacks = (manifest[:-1] + b',"format":"role-queue-snapshot-v1"}',
                   manifest[:-1] + b',"x":NaN}', manifest[:-1] + b',"x":1}')
        for attack in attacks:
            with self.subTest(attack=attack[-50:]), self.assertRaises(q.SnapshotBlocked):
                self.validate(self.write_zip(attack, database))

    def test_zip_traversal_duplicate_unexpected_symlink_and_compression_rejected(self):
        manifest, database = self.member_bytes()
        variants = [('manifest.json', '../queue.sqlite3'), ('manifest.json', '/queue.sqlite3'),
                    ('manifest.json', 'manifest.json'), ('manifest.json', 'queue.sqlite3', 'extra'),
                    ('manifest.json', 'queue.sqlite3')]
        for number, names in enumerate(variants):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                for name in names:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = ((stat.S_IFLNK if number == 4 else stat.S_IFREG) | 0o600) << 16
                    archive.writestr(entry, manifest if name == 'manifest.json' else database)
            path = self.root / f'bad-{number}.zip'
            path.write_bytes(stream.getvalue())
            with self.subTest(number=number), self.assertRaises(q.SnapshotBlocked):
                self.validate(path)
        path = self.root / 'deflated.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', manifest)
            archive.writestr('queue.sqlite3', database)
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(path)

    def test_zip_hidden_prefix_suffix_and_corruption_rejected(self):
        source = Path(self.build().archive_path).read_bytes()
        for data in (b'prefix' + source, source + b'suffix', source[:100] + b'x' + source[101:], source[:80]):
            path = self.root / 'badbytes.zip'
            path.write_bytes(data)
            with self.assertRaises(q.SnapshotBlocked):
                self.validate(path)

    def test_size_limits_are_enforced_before_extraction(self):
        snapshot = self.build()
        with mock.patch.object(q, 'MAX_ARCHIVE_BYTES', 100):
            with self.assertRaises(q.SnapshotBlocked):
                self.validate(snapshot.archive_path)
        with mock.patch.object(q, 'MAX_DB_BYTES', 100):
            with self.assertRaises(q.SnapshotBlocked):
                self.validate(snapshot.archive_path)

    def test_corrupt_database_and_schema_version_rejected(self):
        manifest_bytes, database = self.member_bytes()
        bad = b'Not a database' + database[14:]
        manifest = json.loads(manifest_bytes)
        manifest['database_sha256'] = q._sha(bad)
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(self.write_zip(q._canonical(manifest), bad))
        archive = self.mutate_database('PRAGMA user_version=2')
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_claim_retention_and_checkpoint_wait_are_required(self):
        for sql in ("UPDATE jobs SET state='blocked',blocked_reason='synthetic block'",
                    "UPDATE jobs SET state='dispatching'",
                    'UPDATE dispatcher SET job_id=NULL,dispatcher_id=NULL,claim_token_hash=NULL'):
            with self.subTest(sql=sql):
                archive = self.mutate_database(sql)
                with self.assertRaises(q.SnapshotBlocked):
                    self.validate(archive)
                (self.root / 'tamper.sqlite3').unlink()

    def test_wal_consistent_snapshot_and_concurrent_commit_rejection(self):
        with sqlite3.connect(self.path) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('UPDATE meta SET evidence_ttl_seconds=31')
            writer.commit()
            self.build()
            original_zip = q._zip_bytes
            changed = False
            def changing_zip(*args):
                nonlocal changed
                if not changed:
                    changed = True
                    writer.execute('UPDATE meta SET evidence_ttl_seconds=32')
                    writer.commit()
                return original_zip(*args)
            with mock.patch.object(q, '_zip_bytes', side_effect=changing_zip):
                with self.assertRaises(q.SnapshotBlocked):
                    self.build()

    def test_source_replacement_during_build_rejected(self):
        original_zip = q._zip_bytes
        replaced = False
        def replacing_zip(*args):
            nonlocal replaced
            if not replaced:
                replaced = True
                replacement = self.root / 'replacement.sqlite3'
                shutil.copyfile(self.path, replacement)
                replacement.replace(self.path)
            return original_zip(*args)
        with mock.patch.object(q, '_zip_bytes', side_effect=replacing_zip):
            with self.assertRaises(q.SnapshotBlocked):
                self.build()

    def test_hot_journal_not_recovered_or_removed(self):
        journal = Path(str(self.path) + '-journal')
        journal.write_bytes(b'synthetic-journal')
        with self.assertRaises(q.SnapshotBlocked):
            self.build()
        self.assertEqual(journal.read_bytes(), b'synthetic-journal')

    def test_freed_page_secret_bytes_are_not_archived(self):
        secret = 'synthetic-historical-secret-' * 500
        with sqlite3.connect(self.path) as conn:
            conn.execute('PRAGMA secure_delete=OFF')
            conn.execute('INSERT INTO audit(at,event,detail_json) VALUES(1000,\'temporary\',?)',
                         (json.dumps({'writer_token': secret}),))
            conn.commit()
            conn.execute("DELETE FROM audit WHERE event='temporary'")
        self.assertIn(secret[:100].encode(), self.path.read_bytes())
        result = self.build()
        self.assertNotIn(secret[:100].encode(), Path(result.archive_path).read_bytes())

    def test_embedded_json_string_cannot_hide_raw_credential_keys(self):
        archive = self.mutate_database('UPDATE audit SET detail_json=? WHERE sequence=1',
             (json.dumps({'nested': json.dumps({'writer_token': 'synthetic-secret'})}),))
        with self.assertRaises(q.SnapshotBlocked):
            self.validate(archive)

    def test_nested_json_parse_failures_and_encoding_never_fail_open(self):
        forms = [
            '{"writer_token":"synthetic-secret","n":1,"n":2}',
            '{"writer_token":"synthetic-secret","n":NaN}',
            '{"writer_token":"synthetic-secret",',
            json.dumps(json.dumps({'writer_token': 'synthetic-secret'})),
            {'aws_secret_access_key': 'synthetic-secret'},
            {'AWS-Access-Key-ID': 'synthetic-secret'},
            {'clientSecret': 'synthetic-secret'},
        ]
        for value in forms:
            with self.subTest(value=type(value).__name__), self.assertRaises(q.SnapshotBlocked):
                q._no_credentials({'nested': value})

    def test_public_api_unclaimed_preparation_cannot_export_unreviewed_payload(self):
        forms = [
            '{"writer_token":"synthetic-secret","n":1,"n":2}',
            '{"writer_token":"synthetic-secret","n":NaN}',
            json.dumps(json.dumps({'writer_token': 'synthetic-secret'})),
            {'aws_secret_access_key': 'synthetic-secret'},
        ]
        for index, value in enumerate(forms):
            # Separate legitimate queues, no SQL tampering; reproduce parallel
            # role preparation while another role awaits its checkpoint.
            fixture = SnapshotTests(methodName='test_empty_batch_can_checkpoint')
            fixture.setUp()
            try:
                job = fixture.queue.enqueue('spreader', 1000, 1060,
                    evidence_id=fixture.evidence['spreader'], now=1003)
                target = f'https://threads.com/@sample/post/synthetic{index}'
                fixture.queue.mark_ready(job['job_id'], {'actions': [{
                    'kind': 'like', 'target': target, 'authorization_id': 'synthetic',
                    'payload': {'target': target, 'nested': value}}]},
                    evidence_id=fixture.evidence['spreader'], now=1003)
                with self.subTest(index=index), self.assertRaises(q.SnapshotBlocked):
                    fixture.build()
                self.assertFalse(list(fixture.root.glob('queue-checkpoint-*.zip')))
            finally:
                fixture.tearDown()

    def test_safe_schema_rejects_arbitrary_audit_result_and_payload_fields(self):
        for changes in (
            ("UPDATE audit SET detail_json=? WHERE sequence=1", (json.dumps({'free_text': 'synthetic'}),)),
            ("UPDATE audit SET event='unreviewed' WHERE sequence=1", ()),
        ):
            path = self.mutate_database(*changes)
            with self.assertRaises(q.SnapshotBlocked): self.validate(path)
            (self.root / 'tamper.sqlite3').unlink()
        for kind, payload in [('like', {'target': 'x', 'arbitrary': 'x'}),
                              ('publish', {'target': 'x', 'root': {'nested': 'x'}})]:
            with self.assertRaises(q.SnapshotBlocked): q._safe_payload(kind, payload)
        with self.assertRaises(q.SnapshotBlocked): q._safe_result('verified', {'arbitrary': 'x'})

    def test_normal_approved_text_and_hash_fields_remain_supported(self):
        q._safe_payload('reply', {'target': 'https://threads.com/@sample/post/x',
                                 'text': '평범한 한국어 답변과 token이라는 일반 단어'})
        q._no_credentials({'claim_token_hash': 'a' * 64})
        q._no_credentials({'text': json.dumps({'ordinary': 'text'})})
        with self.assertRaises(q.SnapshotBlocked):
            q._no_credentials({'text': '"' + 'malformed quoted structured text'})

    def test_database_tail_and_reserved_header_bytes_rejected(self):
        manifest_bytes, database = self.member_bytes()
        variants = [database + b'{"writer_token":"synthetic-secret"}',
                    database[:72] + b'{"token":"secret"}  ' + database[92:]]
        for bad in variants:
            manifest = json.loads(manifest_bytes)
            manifest['database_sha256'] = q._sha(bad)
            manifest['database_bytes'] = len(bad)
            with self.assertRaises(q.SnapshotBlocked):
                self.validate(self.write_zip(q._canonical(manifest), bad))

    def test_manifest_coverage_and_state_hash_are_recomputed(self):
        manifest_bytes, database = self.member_bytes()
        for key in ('registry_sha256', 'evidence_sha256', 'audit_sha256', 'database_state_sha256',
                    'core_schema_sha256', 'core_source_sha256'):
            manifest = json.loads(manifest_bytes)
            manifest['semantic'][key] = 'f' * 64
            with self.subTest(key=key), self.assertRaises(q.SnapshotBlocked):
                self.validate(self.write_zip(q._canonical(manifest), database))

    def test_no_restore_or_upload_api(self):
        self.assertFalse(any(name in vars(q) for name in ('restore', 'upload', 'acknowledge', 'replay')))


if __name__ == '__main__':
    unittest.main()
