import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from dispatch_gate import (CommandResult, DispatchGate, GateBlocked, LedgerIdentity,
                           action_id, canonical, completed_json, payload_hash, successful)


def response(value, **kwargs):
    return CommandResult(True, 0, canonical(value), **kwargs)


class DispatchGateTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.identity = LedgerIdentity("example.bot", "a" * 32)
        self.gate = DispatchGate(self.identity, lambda: self.now)

    def status(self, **changes):
        value = {"ok": True, "account": self.identity.account, "db_id": self.identity.db_id,
                 "phase": "active", "backup_hash": "b" * 64, "may_dispatch": False,
                 "checkpoint_pending": False, "checkpoint_seq": 0,
                 "actions": [], "stops": [], "writer": None}
        value.update(changes)
        return value

    def intent(self, **changes):
        value = {"ok": True, "action_id": "a" * 64, "intent_id": "b" * 64,
                 "state": "intent", "may_dispatch": True, "exactly_one_browser_call": True,
                 "lost_response_means_do_not_dispatch": True}
        value.update(changes)
        return value

    def test_requires_final_exit_zero_single_complete_true_json(self):
        bad = [CommandResult(False, None, '{"ok":true}'),
               CommandResult(True, 0, '{"ok":true}', session_id="running"),
               CommandResult(True, 2, '{"ok":true}'),
               CommandResult(True, False, '{"ok":true}'),
               CommandResult(True, 0, '{"ok":true}', truncated=True),
               CommandResult(True, 0, '{"ok":true}', stderr="warning"),
               CommandResult(True, 0, ''), CommandResult(True, 0, '{"ok":'),
               CommandResult(True, 0, '{"ok":true}\n{"ok":true}'),
               CommandResult(True, 0, '{"ok":true,"ok":false}'),
               CommandResult(True, 0, '{"ok":1}'),
               CommandResult(True, 0, '{"ok":true,"n":NaN}'),
               CommandResult(True, 0, '[]')]
        for value in bad:
            with self.subTest(value=repr(value)):
                with self.assertRaises(GateBlocked):
                    successful(value)
        self.assertEqual(successful(response({"ok": True})), {"ok": True})

    def test_wrong_or_missing_status_identity_blocks(self):
        for changes in ({"account": "other"}, {"db_id": "c" * 32},
                        {"writer": {}}, {"checkpoint_pending": 0}, {"actions": None},
                        {"phase": "unknown"}, {"may_dispatch": True}):
            with self.subTest(changes=changes), self.assertRaises(GateBlocked):
                self.gate.status(response(self.status(**changes)))

    def test_preparation_valid_status_ignores_write_busy_gates(self):
        writer = {"account": self.identity.account, "owner": "held", "role": "publisher",
                  "session": "b" * 32, "acquired_at": 1}
        value = self.gate.status(response(self.status(writer=writer, checkpoint_pending=True,
                                                       stops=[{"reason": "unresolved"}])))
        with self.assertRaises(GateBlocked):
            self.gate.write_status(value)

    def test_permit_single_use_even_if_callback_loses_response(self):
        permit = self.gate.intent(response(self.intent()), "a" * 64, 1100, not_before=900)
        calls = []
        def callback():
            calls.append(1)
            raise TimeoutError()
        with self.assertRaises(TimeoutError):
            permit.dispatch(callback)
        with self.assertRaises(GateBlocked):
            permit.dispatch(callback)
        self.assertEqual(calls, [1])
        with self.assertRaises(GateBlocked):
            self.gate.intent(response(self.intent()), "a" * 64, 1100, not_before=900)

    def test_concurrent_permit_consumes_once(self):
        permit = self.gate.intent(response(self.intent()), "a" * 64, 1100, not_before=900)
        calls = []
        def attempt(_):
            try:
                permit.dispatch(lambda: calls.append(1))
                return True
            except GateBlocked:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(20)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(len(calls), 1)

    def test_deadline_expired_consumes_without_dispatch(self):
        permit = self.gate.intent(response(self.intent()), "a" * 64, self.now, not_before=900)
        with self.assertRaises(GateBlocked):
            permit.dispatch(lambda: self.fail("Expired permit dispatched"))
        self.assertTrue(permit.used)

    def test_clock_rollback_after_validation_consumes_without_dispatch(self):
        self.now = 1100
        permit = self.gate.intent(response(self.intent()), "a" * 64, 2000, not_before=1000)
        self.now = 999
        with self.assertRaises(GateBlocked):
            permit.dispatch(lambda: self.fail("Rolled-back future-slot permit dispatched"))
        self.assertTrue(permit.used)
        self.now = 1100
        with self.assertRaises(GateBlocked):
            permit.dispatch(lambda: self.fail("Consumed permit retried after clock recovery"))

    def test_only_exact_one_use_intent_grants_dispatch(self):
        for changes in ({"may_dispatch": False}, {"action_id": "c" * 64},
                        {"intent_id": ""}, {"state": "reserved"},
                        {"exactly_one_browser_call": 1},
                        {"lost_response_means_do_not_dispatch": False}):
            with self.subTest(changes=changes), self.assertRaises(GateBlocked):
                self.gate.intent(response(self.intent(**changes)), "a" * 64, 1100, not_before=900)

    def test_binding_requires_login_presence_role_worker_browser_tab_and_freshness(self):
        expected = {"role": "publisher", "worker_id": "worker-p", "browser_id": "cloud",
                    "tab_id": "tab-p", "account": self.identity.account}
        observed = {**expected, "logged_in": True, "exists": True, "observed_at": self.now}
        self.gate.binding(observed, expected)
        for changes in ({"role": "spreader"}, {"worker_id": "different"},
                        {"browser_id": "local"}, {"tab_id": "different"}, {"account": "other"},
                        {"logged_in": False}, {"exists": False},
                        {"observed_at": 699}, {"observed_at": 1001}):
            with self.subTest(changes=changes), self.assertRaises(GateBlocked):
                self.gate.binding({**observed, **changes}, expected)

    def test_exact_ledger_duplicate_key_and_payload_hash(self):
        a = "https://www.threads.com/@person/post/abc"
        b = "https://threads.net/@other/post/abc/"
        self.assertEqual(action_id(self.identity.account, "reply", a),
                         action_id(self.identity.account, "self_reply", b))
        self.assertNotEqual(action_id(self.identity.account, "reply", a),
                            action_id(self.identity.account, "like", a))
        self.assertEqual(payload_hash({"b": 1, "target": a}),
                         hashlib.sha256(canonical({"target": a, "b": 1}).encode()).hexdigest())

    def test_duplicate_changed_payload_never_grants_intent(self):
        value = self.gate.claim(response({"ok": True, "action_id": "a" * 64,
                  "duplicate": True, "state": "verified", "payload_matches": False,
                  "may_dispatch": False}), "a" * 64)
        self.assertTrue(value["duplicate"])
        self.assertFalse(value["payload_matches"])

    def test_token_stdout_never_appears_in_envelope_repr(self):
        self.assertNotIn("private-writer-token", repr(response({"ok": True, "token": "private-writer-token"})))

    def test_real_symlink_swap_and_file_replacement_snapshots_reject(self):
        # Real filesystem snapshots exercise the very helper used before/after
        # each read; no mocked filesystem calls or timing-dependent race test.
        with tempfile.TemporaryDirectory() as folder:
            path, replacement = Path(folder) / "proof", Path(folder) / "other"
            path.write_bytes(b"proof")
            before = path.lstat()
            self.assertEqual(self.gate._bounded_file(path), b"proof")
            replacement.write_bytes(b"proof")
            os.replace(replacement, path)
            with self.assertRaises(GateBlocked):
                self.gate._unchanged_file(before, path.lstat())
            before = path.lstat()
            replacement.write_bytes(b"other")
            path.unlink()
            path.symlink_to(replacement)
            with self.assertRaises(GateBlocked):
                self.gate._unchanged_file(before, path.lstat())
            with self.assertRaises(GateBlocked):
                self.gate._bounded_file(path)

    def test_real_in_place_file_change_snapshots_reject(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "proof"
            path.write_bytes(b"proof")
            before = path.stat()
            path.write_bytes(b"changed-proof")
            with self.assertRaises(GateBlocked):
                self.gate._unchanged_file(before, path.stat())

    def test_persisted_evidence_is_type_sensitive(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "proof"
            record = Path(folder) / "record.json"
            source.write_bytes(b"actual public proof")
            binding = {"role": "publisher", "worker_id": "worker-p", "browser_id": "cloud",
                       "tab_id": "tab-p", "account": self.identity.account}
            action = {"kind": "publish", "target": "https://blog.example/1", "payload_hash": "a" * 64}
            evidence = {"schema": "browser-action-evidence-v2", "account": self.identity.account,
                        **action, "intent_id": None, "outcome": "absent", "observed_at": self.now,
                        "reference": "browser-proof", "proof_file": str(source),
                        "proof_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "receipt_urls": []}
            # 1000.0 == 1000 in Python, but the persisted JSON types differ.
            record.write_text(canonical({**evidence, "observed_at": float(self.now)}))
            envelope = {"binding": {**binding, "logged_in": True, "exists": True, "observed_at": self.now},
                        "evidence": evidence, "evidence_path": str(record)}
            with self.assertRaises(GateBlocked):
                self.gate.evidence(envelope, action, binding, None, "absent")


if __name__ == "__main__":
    unittest.main()
