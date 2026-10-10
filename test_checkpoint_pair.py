import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from checkpoint_pair import ExpectedPair, PairBlocked, verify_pair


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.ledger = root / "ledger-downloaded.zip"
        self.queue = root / "queue-downloaded.zip"
        self.ledger.write_bytes(b"synthetic independently validated ledger archive")
        self.queue.write_bytes(b"synthetic independently validated queue snapshot")
        digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        self.expected = ExpectedPair(
            account="example.bot", ledger_db_id="ledger-test", queue_db_id="queue-test",
            checkpoint_id="checkpoint-test-4", checkpoint_sequence=4,
            result_digest="1" * 64, registry_revision=2,
            ledger_checkpoint_hash="2" * 64, ledger_archive_sha256=digest(self.ledger),
            queue_archive_sha256=digest(self.queue),
            ledger_library_file_id="ledger-library-test", ledger_library_version="opaque-v4",
            ledger_previous_version="opaque-v3", queue_library_file_id="queue-library-test",
            queue_library_version="opaque-v1", queue_previous_version="",
            ledger_downloaded_archive=str(self.ledger), queue_downloaded_archive=str(self.queue))
        self.manifest = {
            "schema": "role-queue-checkpoint-pair-v1", "expected": asdict(self.expected),
            "ledger_receipt": self.receipt("ledger", self.ledger),
            "queue_receipt": self.receipt("queue", self.queue), "verified_at": 1000,
        }

    def receipt(self, kind, path):
        return {"archive_sha256": getattr(self.expected, kind + "_archive_sha256"),
                "downloaded_archive": str(path),
                "library_file_id": getattr(self.expected, kind + "_library_file_id"),
                "library_version": getattr(self.expected, kind + "_library_version"),
                "previous_version": getattr(self.expected, kind + "_previous_version"),
                "transport_reference": "actual-tool-result-reference-" + kind,
                "verified_at": 999}

    def verify(self, manifest=None, expected=None, **kwargs):
        return verify_pair(manifest or self.manifest, expected or self.expected, now=kwargs.pop("now", 1001), **kwargs)

    def test_exact_two_artifact_roundtrip_passes(self):
        result = self.verify()
        self.assertEqual(result.expected, self.expected)
        self.assertEqual(len(result.manifest_sha256), 64)
        proof = result.checkpoint_proof_fields()
        self.assertEqual(proof["checkpoint_hash"], "2" * 64)
        self.assertEqual(proof["archive_sha256"], self.expected.ledger_archive_sha256)
        self.assertNotEqual(proof["checkpoint_hash"], proof["archive_sha256"])
        self.assertNotIn("may_dispatch", proof)

    def test_any_pinned_metadata_change_rejects(self):
        changes = {
            "account": "wrong", "ledger_db_id": "wrong", "queue_db_id": "wrong",
            "checkpoint_id": "wrong", "checkpoint_sequence": 5, "result_digest": "0" * 64,
            "registry_revision": 3, "ledger_checkpoint_hash": "0" * 64,
            "ledger_archive_sha256": "0" * 64, "queue_archive_sha256": "0" * 64,
            "ledger_library_file_id": "wrong", "queue_library_file_id": "wrong",
            "ledger_library_version": "wrong", "queue_library_version": "wrong",
            "ledger_previous_version": "wrong", "queue_previous_version": "wrong",
            "ledger_schema_version": 3, "queue_schema_version": 2,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                m = copy.deepcopy(self.manifest)
                m["expected"][key] = value
                with self.assertRaises(PairBlocked): self.verify(m)

    def test_missing_queue_receipt_never_completes(self):
        m = copy.deepcopy(self.manifest)
        del m["queue_receipt"]
        with self.assertRaises(PairBlocked): self.verify(m)

    def test_bool_is_not_integer_metadata(self):
        e = replace(self.expected, checkpoint_sequence=1)
        m = copy.deepcopy(self.manifest)
        m["expected"] = asdict(e)
        m["expected"]["checkpoint_sequence"] = True
        with self.assertRaises(PairBlocked): self.verify(m, e)

    def test_unexpected_fields_and_credentials_rejected(self):
        for target in ("root", "ledger_receipt", "queue_receipt"):
            m = copy.deepcopy(self.manifest)
            (m if target == "root" else m[target])["token"] = "do-not-store"
            with self.subTest(target=target), self.assertRaises(PairBlocked): self.verify(m)

    def test_hash_mismatch_and_missing_file_reject(self):
        self.queue.write_bytes(b"changed")
        with self.assertRaises(PairBlocked): self.verify()
        self.queue.unlink()
        with self.assertRaises(PairBlocked): self.verify()

    def test_receipt_cannot_choose_other_path(self):
        other = self.queue.with_name("same-bytes-other-file.zip")
        other.write_bytes(self.queue.read_bytes())
        m = copy.deepcopy(self.manifest)
        m["queue_receipt"]["downloaded_archive"] = str(other)
        with self.assertRaises(PairBlocked): self.verify(m)

    def test_symlink_download_rejects(self):
        original = self.queue.with_name("queue-original.zip")
        self.queue.rename(original)
        self.queue.symlink_to(original)
        with self.assertRaises(PairBlocked): self.verify()

    def test_stale_future_and_bool_times_reject(self):
        for value in (700, 1002, True, "1000"):
            m = copy.deepcopy(self.manifest)
            m["verified_at"] = value
            with self.subTest(value=value), self.assertRaises(PairBlocked): self.verify(m)
        for value in (700, 1001, False):
            m = copy.deepcopy(self.manifest)
            m["queue_receipt"]["verified_at"] = value
            with self.subTest(receipt=value), self.assertRaises(PairBlocked): self.verify(m)

    def test_shared_library_identity_rejects(self):
        e = replace(self.expected, queue_library_file_id=self.expected.ledger_library_file_id)
        with self.assertRaises(PairBlocked): self.verify(expected=e)

    def test_two_hardlinks_cannot_stand_for_two_artifacts(self):
        self.queue.unlink()
        os.link(self.ledger, self.queue)
        e = replace(self.expected, queue_archive_sha256=self.expected.ledger_archive_sha256)
        m = copy.deepcopy(self.manifest)
        m["expected"] = asdict(e)
        m["queue_receipt"]["archive_sha256"] = e.queue_archive_sha256
        with self.assertRaises(PairBlocked): self.verify(m, e)

    def test_caller_cannot_relax_freshness(self):
        for age in (301, 100000, True, 0):
            with self.subTest(age=age), self.assertRaises(PairBlocked):
                self.verify(max_age=age)

    def test_exact_version_chain_required(self):
        for key in ("library_version", "previous_version", "library_file_id"):
            m = copy.deepcopy(self.manifest)
            m["queue_receipt"][key] = "different"
            with self.subTest(key=key), self.assertRaises(PairBlocked): self.verify(m)

    def test_queue_version_must_advance(self):
        e = replace(self.expected, queue_previous_version=self.expected.queue_library_version)
        m = copy.deepcopy(self.manifest)
        m["expected"] = asdict(e)
        m["queue_receipt"]["previous_version"] = e.queue_previous_version
        with self.assertRaises(PairBlocked): self.verify(m, e)

    def test_no_remote_operation_occurs(self):
        before = [self.ledger.stat().st_mtime_ns, self.queue.stat().st_mtime_ns]
        self.verify()
        self.assertEqual(before, [self.ledger.stat().st_mtime_ns, self.queue.stat().st_mtime_ns])


if __name__ == "__main__":
    unittest.main()
