"""Real queue/gates with mock transport adapters only; no production operations."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from checkpoint_pair import ExpectedPair
from coordinator import SerialCoordinator
from dispatch_gate import CommandResult, GateBlocked, LedgerIdentity, action_id, canonical
from queue_core import Binding, QueueCore, Schedule, STAGING_ROOT, initialize_staging


def reply(value):
    return CommandResult(True, 0, canonical({"ok": True, **value}))


class FakeLedger:
    """Preserves actual v2 command and response fields, not an alternate ledger."""
    def __init__(self, clock):
        self.clock = clock
        self.identity = LedgerIdentity("example.bot", "a" * 32)
        self.writer = None
        self.actions = {}
        self.stops = []
        self.pending = False
        self.seq = 0
        self.calls = []
        self.override = {}
        self.after = {}
        self.after_hooks = {}
        self.archive = ""
        self.library_id = ""
        self.library_version = ""

    def status(self):
        return {"account": self.identity.account, "db_id": self.identity.db_id,
                "phase": "active", "backup_hash": "f" * 64, "may_dispatch": False,
                "checkpoint_pending": self.pending, "checkpoint_seq": self.seq,
                "checkpoint_archive_hash": self.archive, "checkpoint_library_id": self.library_id,
                "checkpoint_library_version": self.library_version,
                "writer": self.writer, "actions": list(self.actions.values()), "stops": self.stops}

    def execute(self, command, **args):
        self.calls.append(command)  # Deliberately never capture writer credentials.
        if command in self.override:
            return self.override[command]
        result = self._execute(command, args)
        if command in self.after_hooks:
            self.after_hooks[command]()
        return self.after.get(command, result)

    def _execute(self, command, args):
        if command == "status":
            return reply(self.status())
        if command == "acquire":
            assert self.writer is None and not self.pending and not self.stops
            self.writer = {"account": self.identity.account, "owner": args["owner"],
                           "role": args["role"], "session": "c" * 32, "acquired_at": self.clock()}
            return reply({"owner": args["owner"], "token": "private".encode().hex().ljust(64, "d"),
                          "session": self.writer["session"], "may_dispatch": False,
                          "automatic_expiry": False})
        if command == "checkpoint-ack":
            receipt = json.loads(Path(args["record"]).read_text())
            self.pending = False
            self.archive = receipt["archive_sha256"]
            self.library_id = receipt["library_file_id"]
            self.library_version = receipt["library_version"]
            return reply({"checkpoint_pending": False, "checkpoint_seq": self.seq,
                          "checkpoint_hash": receipt["checkpoint_hash"],
                          "archive_sha256": self.archive, "may_dispatch": False})
        assert self.writer is not None and args["owner"] == self.writer["owner"]
        if command == "claim":
            key = action_id(self.identity.account, args["kind"], args["target"])
            if key in self.actions:
                old = self.actions[key]
                return reply({"action_id": key, "state": old["state"], "duplicate": True,
                              "payload_matches": old["payload_hash"] == args["payload_hash"],
                              "may_dispatch": False})
            self.actions[key] = {"id": key, "account": self.identity.account, "kind": args["kind"],
                "target_url": args["target"], "payload_hash": args["payload_hash"],
                "state": "reserved", "intent_id": None}
            return reply({"action_id": key, "state": "reserved", "duplicate": False, "may_dispatch": False})
        if command == "release":
            assert not self.stops and all(a["state"] not in
                ("reserved", "intent", "submitted_unverified", "unknown") for a in self.actions.values())
            self.writer = None
            self.pending = True
            self.seq += 1
            return reply({"released": True, "checkpoint_pending": True,
                          "checkpoint_seq": self.seq, "may_dispatch": False})
        action = self.actions[args["action"]]
        if command == "begin-write":
            assert action["state"] == "reserved"
            action["state"] = "intent"
            action["intent_id"] = hashlib.sha256((action["id"] + "intent").encode()).hexdigest()
            return reply({"action_id": action["id"], "intent_id": action["intent_id"],
                "state": "intent", "may_dispatch": True, "exactly_one_browser_call": True,
                "lost_response_means_do_not_dispatch": True})
        if command == "submitted":
            assert action["state"] == "intent"
            action["state"] = "submitted_unverified"
        elif command == "unknown":
            assert action["state"] in ("intent", "submitted_unverified", "unknown")
            action["state"] = "unknown"
            self.stops.append({"action_id": action["id"], "reason": args["reason"]})
        elif command == "cancel":
            assert action["state"] == "reserved"
            action["state"] = "cancelled"
        elif command == "verify":
            evidence = json.loads(Path(args["evidence"]).read_text())
            assert evidence["intent_id"] == action["intent_id"] and evidence["outcome"] == "present"
            action["state"] = "already_present" if action["state"] == "reserved" else "verified"
        else:
            raise AssertionError(command)
        return reply({"action_id": action["id"], "state": action["state"], "may_dispatch": False})


class FakeAuthorization:
    changes = None
    batch_changes = None

    def authorize_batch(self, job, actions):
        kinds = {"publisher": ["publish", "self_reply"], "spreader": ["like", "repost", "follow"],
                 "commenter": ["reply"]}[job["role"]]
        values = {"authorized": True, "account": job["expected_account"], "role": job["role"],
                  "batch_payload_hash": job["payload_hash"], "policy_reference": "mock-current-user-policy",
                  "allowed_kinds": kinds, "max_actions": 3, "per_kind_limits": {kind: 3 for kind in kinds}}
        values.update(self.batch_changes or {})
        return reply(values)

    def authorize(self, job, action):
        values = {"authorized": True, "role": job["role"], "account": job["expected_account"],
                  "policy_reference": "mock-current-user-policy",
                  **{key: action[key] for key in ("authorization_id", "kind", "target", "payload_hash")}}
        values.update(self.changes or {})
        return reply(values)


class FakeBrowser:
    def __init__(self, folder, clock):
        self.folder = Path(folder)
        self.clock = clock
        self.calls = []
        self.mutations = []
        self.mutation_records = []
        self.active_mutations = 0
        self.peak_mutations = 0
        self.mutation_lock = threading.Lock()
        self.binding_changes = {}
        self.outcome = "submitted"
        self.preflight_outcome = "absent"
        self.after_mutate = None
        self.before_tool_dispatch = None
        self.after_preflight = None
        self.readback_changes = {}

    def observed(self, binding):
        return {**binding, "logged_in": True, "exists": True, "observed_at": self.clock(),
                **self.binding_changes}

    def observe(self, binding):
        self.calls.append("observe")
        return reply({"binding": self.observed(binding)})

    def _proof(self, action, binding, intent_id, outcome):
        number = len(self.calls)
        public_file = self.folder / f"proof-{number}.txt"
        public_file.write_text(f"Mock public evidence {number}")
        evidence = {"schema": "browser-action-evidence-v2", "account": binding["account"],
            "kind": action["kind"], "target": action["target"], "payload_hash": action["payload_hash"],
            "intent_id": intent_id, "outcome": outcome, "observed_at": self.clock(),
            "reference": "mock-observation-" + str(number), "proof_file": str(public_file),
            "proof_sha256": hashlib.sha256(public_file.read_bytes()).hexdigest(),
            "receipt_urls": [] if outcome == "absent" else
            [f'https://threads.com/@example.bot/post/receipt{number}']}
        if intent_id is not None:
            evidence.update(self.readback_changes)
        record = self.folder / f"record-{number}.json"
        record.write_text(canonical(evidence))
        return reply({"binding": self.observed(binding), "evidence": evidence, "evidence_path": str(record)})

    def preflight(self, action, binding):
        self.calls.append("preflight")
        result = self._proof(action, binding, None, self.preflight_outcome)
        if self.after_preflight:
            self.after_preflight()
        return result

    def mutate(self, action, binding, intent_id, *, slot_start, slot_deadline):
        self.calls.append("mutate")
        if self.before_tool_dispatch:
            self.before_tool_dispatch()
        if not (type(slot_start) is int and type(slot_deadline) is int and
                slot_start <= self.clock() < slot_deadline):
            raise GateBlocked("Adapter refused dispatch outside pinned slot boundaries")
        self.mutations.append((action["action_id"], intent_id, binding["tab_id"]))
        self.mutation_records.append((binding["role"], action["kind"], action["target"],
                                      dict(action["payload"]), binding["tab_id"]))
        with self.mutation_lock:
            self.active_mutations += 1
            self.peak_mutations = max(self.peak_mutations, self.active_mutations)
        try:
            if self.after_mutate:
                self.after_mutate()
            if self.outcome == "lost":
                raise TimeoutError("The mutation may have succeeded")
            if self.outcome == "running":
                return CommandResult(False, None, "", session_id="running")
            return reply({"ok": self.outcome != "denied", "outcome": self.outcome,
                          "action_id": action["action_id"], "intent_id": intent_id})
        finally:
            with self.mutation_lock:
                self.active_mutations -= 1

    def readback(self, action, binding, intent_id):
        self.calls.append("readback")
        return self._proof(action, binding, intent_id, "present")


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        STAGING_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="coordinator-test-", dir=STAGING_ROOT)
        self.root = Path(self.temp.name)
        self.now = 100
        self.clock = lambda: self.now
        self.ledger = FakeLedger(self.clock)
        self.browser = FakeBrowser(self.root, self.clock)
        self.authorization = FakeAuthorization()
        self.bindings = {r: Binding("worker-" + r, "cloud", "tab-" + r, "example.bot")
                         for r in ("publisher", "spreader", "commenter")}
        self.identity = initialize_staging(self.root / "queue.sqlite", self.bindings,
            {r: Schedule(0, 1000) for r in self.bindings}, ledger_db_id=self.ledger.identity.db_id)
        self.queue = QueueCore(self.root / "queue.sqlite", self.identity)
        self.coordinator = self.make_coordinator()

    def tearDown(self):
        self.temp.cleanup()

    def make_coordinator(self, **kwargs):
        return SerialCoordinator(self.queue, self.ledger.identity, clock=self.clock,
             ledger=self.ledger, browser=self.browser, authorization=self.authorization, **kwargs)

    def prepare(self, role="publisher", count=1):
        b = self.bindings[role]
        evidence = self.queue.record_observation(role, worker_id=b.worker_id, browser_id=b.browser_id,
            tab_id=b.tab_id, observed_account=b.expected_account, tab_exists=True,
            observed_at=self.now, now=self.now)
        slot = self.now // 1000 * 1000
        job = self.queue.enqueue(role, slot, slot + 1000, evidence_id=evidence, now=self.now)
        actions = []
        for i in range(count):
            kind = {"publisher": "publish", "spreader": "like", "commenter": "reply"}[role]
            target = (f"https://blog.example/{i+1}" if role == "publisher" else
                      f"https://threads.com/@someone/post/target{i+1}")
            actions.append({"kind": kind, "target": target,
                            "payload": {"target": target, "text": f"Message {i}"},
                            "authorization_id": f"authorization-{role}-{i}"})
        self.queue.mark_ready(job["job_id"], {"actions": actions}, evidence_id=evidence, now=self.now)
        return job["job_id"]

    def pair(self, **changes):
        run = self.coordinator._run
        ledger_file, queue_file = self.root / "download-ledger.zip", self.root / "download-queue.zip"
        ledger_file.write_bytes(b"mock ledger archive validated by fake ledger adapter")
        queue_file.write_bytes(b"mock independently pinned queue snapshot")
        expected = ExpectedPair(account=self.ledger.identity.account, ledger_db_id=self.ledger.identity.db_id,
            queue_db_id=self.identity.db_id, checkpoint_id=run.checkpoint_id,
            checkpoint_sequence=run.checkpoint_sequence, result_digest=run.result_digest,
            registry_revision=run.job["generation"], ledger_checkpoint_hash="b" * 64,
            ledger_archive_sha256=hashlib.sha256(ledger_file.read_bytes()).hexdigest(),
            queue_archive_sha256=hashlib.sha256(queue_file.read_bytes()).hexdigest(),
            ledger_library_file_id="library-ledger", ledger_library_version=f"v{run.checkpoint_sequence}",
            ledger_previous_version=self.ledger.library_version,
            queue_library_file_id="library-queue", queue_library_version=f"v{run.checkpoint_sequence}",
            queue_previous_version=f"v{run.checkpoint_sequence-1}" if run.checkpoint_sequence > 1 else "",
            ledger_downloaded_archive=str(ledger_file), queue_downloaded_archive=str(queue_file))
        expected = replace(expected, **changes)
        manifest = {"schema": "role-queue-checkpoint-pair-v1", "expected": asdict(expected),
                    "verified_at": self.now}
        for kind in ("ledger", "queue"):
            manifest[kind + "_receipt"] = {
                key: getattr(expected, kind + "_" + key) for key in
                ("archive_sha256", "downloaded_archive", "library_file_id", "library_version", "previous_version")}
            manifest[kind + "_receipt"].update(transport_reference="mock-transport-" + kind, verified_at=self.now)
        receipt = {"schema": "library-checkpoint-roundtrip-v1", "account": expected.account, "db_id": expected.ledger_db_id,
            "baseline_hash": "f" * 64, "downloaded_archive": expected.ledger_downloaded_archive,
            "transport_reference": "mock-transport-ledger", "verified_at": self.now,
            "checkpoint_seq": expected.checkpoint_sequence, "checkpoint_hash": expected.ledger_checkpoint_hash,
            "archive_sha256": expected.ledger_archive_sha256, "library_file_id": expected.ledger_library_file_id,
            "library_version": expected.ledger_library_version, "previous_version": expected.ledger_previous_version}
        receipt_path = self.root / "receipt.json"
        receipt_path.write_text(canonical(receipt))
        return dict(receipt_path=str(receipt_path), receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                    pair_manifest=manifest, expected_pair=expected)

    def test_single_acquire_whole_batch_then_occupied_until_checkpoint(self):
        job = self.prepare(count=2)
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertEqual(len(self.browser.mutations), 2)
        self.assertEqual(self.ledger.calls.count("acquire"), 1)
        self.assertEqual(self.ledger.calls.count("release"), 1)
        self.assertEqual(self.queue.inspect_job(job)["state"], "checkpoint_wait")
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertEqual(self.make_coordinator().run_once().state, "wait")
        result = self.coordinator.complete_checkpoint(**self.pair())
        self.assertEqual(result.state, "done")
        self.assertEqual(self.queue.inspect_job(job)["state"], "done")
        self.assertIsNone(self.queue.snapshot()["dispatcher"]["job_id"])
        self.assertFalse(self.ledger.pending)

    def test_preparation_valid_during_writer_stop_and_checkpoint(self):
        self.ledger.writer = {"account": self.ledger.identity.account, "owner": "other",
            "role": "commenter", "session": "c" * 32, "acquired_at": 1}
        self.ledger.stops = [{"reason": "unknown"}]
        self.ledger.pending = True
        status = self.coordinator.check_preparation()
        self.assertTrue(status["checkpoint_pending"])
        self.prepare("publisher")
        self.prepare("spreader")
        self.prepare("commenter")
        self.assertEqual(len(self.queue.snapshot()["jobs"]), 3)
        self.assertNotIn("acquire", self.ledger.calls)
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertFalse(self.browser.calls)

    def test_busy_means_wait_without_skipping_ready_slot(self):
        job = self.prepare()
        self.ledger.writer = {"account": self.ledger.identity.account, "owner": "other",
            "role": "commenter", "session": "c" * 32, "acquired_at": 1}
        self.assertEqual(self.coordinator.run_once().state, "wait")
        self.assertEqual(self.queue.inspect_job(job)["state"], "ready")
        self.assertFalse(self.browser.calls)
        self.ledger.writer = None
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")

    def test_missing_malformed_running_and_wrong_identity_never_reach_browser(self):
        self.prepare()
        bad = [CommandResult(False, None, "", session_id="still-running"),
               CommandResult(True, 0, "{bad"), CommandResult(True, 2, '{"ok":true}'),
               reply({**self.ledger.status(), "db_id": "f" * 32})]
        for response in bad:
            self.ledger.override["status"] = response
            self.assertEqual(self.make_coordinator().run_once().state, "blocked")
            self.assertFalse(self.browser.calls)

    def test_wrong_tab_login_and_stale_binding_never_acquire_or_mutate(self):
        self.prepare()
        for changes in ({"tab_id": "other"}, {"account": "other"}, {"logged_in": False},
                        {"exists": False}, {"observed_at": self.now - 31}):
            self.browser.binding_changes = changes
            self.assertEqual(self.make_coordinator().run_once().state, "blocked")
            self.assertNotIn("acquire", self.ledger.calls)
            self.assertFalse(self.browser.mutations)

    def test_wrong_authorization_payload_never_dispatches(self):
        self.prepare()
        self.authorization.changes = {"payload_hash": "b" * 64}
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("claim", self.ledger.calls)

    def test_existing_run_and_kind_quotas_checked_before_writer_acquisition(self):
        self.prepare(count=2)
        for changes in ({"max_actions": 1}, {"max_actions": True},
                        {"allowed_kinds": ["reply"], "per_kind_limits": {"reply": 3}},
                        {"per_kind_limits": {"publish": 1, "self_reply": 3}}):
            self.authorization.batch_changes = changes
            self.assertEqual(self.make_coordinator().run_once().state, "blocked")
            self.assertNotIn("acquire", self.ledger.calls)
            self.assertFalse(self.browser.calls)

    def test_wait_ends_at_same_slot_deadline_without_takeover_or_catchup(self):
        job = self.prepare()
        self.ledger.writer = {"account": self.ledger.identity.account, "owner": "other",
            "role": "commenter", "session": "c" * 32, "acquired_at": 1}
        self.assertEqual(self.coordinator.run_once().state, "wait")
        self.now = 1000
        self.assertEqual(self.coordinator.run_once().state, "idle")
        self.assertEqual(self.queue.inspect_job(job)["state"], "expired")
        self.assertEqual(self.ledger.writer["owner"], "other")
        self.assertFalse(self.browser.calls)

    def test_lost_begin_response_blocks_without_browser_write(self):
        job = self.prepare()
        self.ledger.after["begin-write"] = CommandResult(False, None, "", session_id="lost")
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertFalse(self.browser.mutations)
        self.assertEqual(next(iter(self.ledger.actions.values()))["state"], "intent")
        self.assertEqual(self.queue.inspect_job(job)["state"], "blocked")
        self.assertEqual(self.make_coordinator().run_once().state, "blocked")
        self.assertEqual(self.ledger.calls.count("begin-write"), 1)

    def test_lost_browser_response_records_unknown_stop_and_never_retries(self):
        self.prepare(count=2)
        self.browser.outcome = "lost"
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertEqual(len(self.browser.mutations), 1)
        self.assertTrue(self.ledger.stops)
        self.assertEqual(next(iter(self.ledger.actions.values()))["state"], "unknown")
        self.assertNotIn("readback", self.browser.calls)
        self.assertNotIn("release", self.ledger.calls)
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertEqual(len(self.browser.mutations), 1)

    def test_definitive_denial_is_unresolved_and_cannot_finalize_itself(self):
        job = self.prepare()
        self.browser.outcome = "denied"
        result = self.coordinator.run_once()
        self.assertEqual(result.state, "blocked")
        self.assertIn("separately authorized", result.reason)
        progress = self.queue.list_action_progress(self.coordinator._run.claim)
        self.assertEqual(progress[0]["state"], "denied_unresolved")
        self.assertEqual(self.queue.inspect_job(job)["state"], "blocked")
        self.assertNotIn("release", self.ledger.calls)

    def test_duplicate_changed_payload_is_terminal_without_dispatch(self):
        self.prepare()
        key = action_id(self.ledger.identity.account, "publish", "https://blog.example/1")
        self.ledger.actions[key] = {"id": key, "account": self.ledger.identity.account,
            "kind": "publish", "target_url": "https://blog.example/1", "payload_hash": "b" * 64,
            "state": "verified", "intent_id": None}
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("preflight", self.browser.calls)
        self.assertNotIn("begin-write", self.ledger.calls)

    def test_readback_completes_after_deadline_but_next_action_never_starts(self):
        self.prepare(count=2)
        self.browser.after_mutate = lambda: setattr(self, "now", 1001)
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertEqual(len(self.browser.mutations), 1)
        self.assertEqual(self.browser.calls.count("readback"), 1)
        self.assertEqual(self.ledger.calls.count("claim"), 1)
        states = [r["state"] for r in self.queue.list_action_progress(self.coordinator._run.claim)]
        self.assertEqual(sorted(states), ["cancelled", "verified"])

    def test_deadline_between_preflight_and_intent_cancels_unused_reservation(self):
        self.prepare()
        self.now = 999
        self.browser.after_preflight = lambda: setattr(self, "now", 1000)
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("begin-write", self.ledger.calls)
        self.assertIn("cancel", self.ledger.calls)

    def test_clock_rollback_after_final_queue_validation_never_enters_mutation_callback(self):
        self.now = 1100
        self.prepare()
        armed = [False]
        calls_after_intent = [0]
        def clock():
            if armed[0]:
                calls_after_intent[0] += 1
                # After begin-write: progress timestamp, binding freshness twice,
                # final real QueueCore validation timestamp, then permit clock.
                if calls_after_intent[0] >= 5:
                    self.now = 999
            return self.now
        self.ledger.after_hooks["begin-write"] = lambda: armed.__setitem__(0, True)
        self.coordinator = SerialCoordinator(self.queue, self.ledger.identity, clock=clock,
            ledger=self.ledger, browser=self.browser, authorization=self.authorization)
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertEqual(self.now, 999)
        self.assertGreaterEqual(calls_after_intent[0], 5)
        self.assertNotIn("mutate", self.browser.calls)
        self.assertFalse(self.browser.mutations)
        self.assertTrue(self.ledger.stops)

    def test_delayed_adapter_rechecks_expired_upper_boundary_before_actual_dispatch(self):
        self.now = 1100
        self.prepare()
        self.browser.before_tool_dispatch = lambda: setattr(self, "now", 2000)
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertIn("mutate", self.browser.calls)
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("submitted", self.ledger.calls)
        self.assertTrue(self.ledger.stops)

    def test_delayed_adapter_rechecks_rolled_back_lower_boundary_before_actual_dispatch(self):
        self.now = 1100
        self.prepare()
        self.browser.before_tool_dispatch = lambda: setattr(self, "now", 999)
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertIn("mutate", self.browser.calls)
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("submitted", self.ledger.calls)
        self.assertTrue(self.ledger.stops)

    def test_readback_wrong_intent_blocks_after_exactly_one_mutation(self):
        self.prepare()
        self.browser.readback_changes = {"intent_id": "e" * 64}
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertEqual(len(self.browser.mutations), 1)
        self.assertNotIn("verify", self.ledger.calls)
        self.assertNotIn("release", self.ledger.calls)

    def test_tampered_persisted_preflight_never_reaches_begin_or_mutation(self):
        self.prepare()
        def tamper():
            for record in self.root.glob("record-*.json"):
                record.write_text('{}')
        self.browser.after_preflight = tamper
        self.assertEqual(self.coordinator.run_once().state, "blocked")
        self.assertFalse(self.browser.mutations)
        self.assertNotIn("begin-write", self.ledger.calls)

    def test_atomic_central_dispatch_with_parallel_prepared_roles(self):
        self.prepare("publisher")
        self.prepare("spreader")
        self.prepare("commenter")
        entered, finish = threading.Event(), threading.Event()
        def pause():
            entered.set()
            self.assertTrue(finish.wait(5))
        self.browser.after_mutate = pause
        results = []
        thread = threading.Thread(target=lambda: results.append(self.coordinator.run_once()))
        thread.start()
        self.assertTrue(entered.wait(5))
        other = self.make_coordinator(dispatcher_id="other-coordinator")
        self.assertEqual(other.run_once().state, "wait")
        finish.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].state, "needs_checkpoint")
        self.assertEqual(len(self.browser.mutations), 1)
        self.assertEqual(self.ledger.calls.count("acquire"), 1)
        self.assertEqual(sorted(j["state"] for j in self.queue.snapshot()["jobs"]),
                         ["checkpoint_wait", "ready", "ready"])

    def test_checkpoint_pair_mismatch_keeps_queue_occupied_without_ack(self):
        self.prepare()
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        args = self.pair()
        args["pair_manifest"]["queue_receipt"]["library_version"] = "wrong"
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state, "needs_checkpoint")
        self.assertNotIn("checkpoint-ack", self.ledger.calls)
        self.assertIsNotNone(self.queue.snapshot()["dispatcher"]["job_id"])
        self.assertTrue(self.ledger.pending)

    def test_lost_checkpoint_ack_response_blocks_without_automatic_retry(self):
        self.prepare()
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        args = self.pair()
        self.ledger.after["checkpoint-ack"] = CommandResult(False, None, "", session_id="lost")
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state, "blocked")
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state, "blocked")
        self.assertEqual(self.ledger.calls.count("checkpoint-ack"), 1)
        self.assertIsNotNone(self.queue.snapshot()["dispatcher"]["job_id"])

    def test_boolean_checkpoint_sequence_is_rejected_before_ack(self):
        self.prepare()
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        args = self.pair()
        path = Path(args["receipt_path"])
        data = json.loads(path.read_text())
        data["checkpoint_seq"] = True
        path.write_text(canonical(data))
        args["receipt_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state, "needs_checkpoint")
        self.assertNotIn("checkpoint-ack", self.ledger.calls)

    def test_boolean_ack_sequence_is_rejected_after_single_ack_attempt(self):
        self.prepare()
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        args = self.pair()
        expected = args["expected_pair"]
        self.ledger.after["checkpoint-ack"] = reply({"checkpoint_pending": False,
            "checkpoint_seq": True, "checkpoint_hash": expected.ledger_checkpoint_hash,
            "archive_sha256": expected.ledger_archive_sha256, "may_dispatch": False})
        self.assertEqual(self.coordinator.complete_checkpoint(**args).state, "blocked")
        self.assertEqual(self.ledger.calls.count("checkpoint-ack"), 1)
        self.assertIsNotNone(self.queue.snapshot()["dispatcher"]["job_id"])

    def test_subsequent_companion_identity_and_version_chain_checked_before_ledger_ack(self):
        self.prepare("publisher")
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        self.assertEqual(self.coordinator.complete_checkpoint(**self.pair()).state, "done")
        self.assertEqual(self.ledger.calls.count("checkpoint-ack"), 1)
        self.prepare("spreader")
        self.assertEqual(self.coordinator.run_once().state, "needs_checkpoint")
        changes = ({"queue_library_file_id": "other-library"},
                   {"queue_previous_version": "v999"},
                   {"queue_previous_version": ""},
                   {"queue_library_version": "v1"})
        for change in changes:
            with self.subTest(change=change):
                result = self.coordinator.complete_checkpoint(**self.pair(**change))
                self.assertEqual(result.state, "needs_checkpoint")
                self.assertEqual(self.ledger.calls.count("checkpoint-ack"), 1)
                self.assertTrue(self.ledger.pending)
                self.assertIsNotNone(self.queue.snapshot()["dispatcher"]["job_id"])
        self.assertEqual(self.coordinator.complete_checkpoint(**self.pair()).state, "done")
        self.assertEqual(self.ledger.calls.count("checkpoint-ack"), 2)
        done = [job for job in self.queue.snapshot()["jobs"] if job["state"] == "done"]
        newest = max((json.loads(job["checkpoint_proof_json"]) for job in done),
                     key=lambda proof: proof["checkpoint_sequence"])
        self.assertEqual(newest["queue_previous_version"], "v1")
        self.assertEqual(newest["queue_library_version"], "v2")

    def test_all_three_prepared_roles_complete_serially_with_exact_payload_tab_and_checkpoint(self):
        for role in ("publisher", "spreader", "commenter"):
            self.prepare(role)
        initial = sorted(self.queue.snapshot()["jobs"],
                         key=lambda job: (job["scheduled_at"], job["created_at"], job["role"]))
        expected = []
        for job in initial:
            action = json.loads(job["payload_json"])["actions"][0]
            expected.append((job["role"], action["kind"], action["target"],
                             action["payload"], job["tab_id"]))
        for number, job in enumerate(initial, 1):
            outcome = self.coordinator.run_once()
            self.assertEqual(outcome.state, "needs_checkpoint")
            self.assertEqual(outcome.job_id, job["job_id"])
            self.assertEqual(self.ledger.calls.count("acquire"), number)
            self.assertEqual(self.make_coordinator().run_once().state, "wait")
            self.assertEqual(self.coordinator.complete_checkpoint(**self.pair()).state, "done")
        self.assertEqual(self.browser.mutation_records, expected)
        self.assertEqual(self.browser.peak_mutations, 1)
        self.assertEqual(self.browser.active_mutations, 0)
        self.assertEqual([self.ledger.calls.count(name) for name in
                          ("acquire", "release", "checkpoint-ack")], [3, 3, 3])
        self.assertTrue(all(job["state"] == "done" for job in self.queue.snapshot()["jobs"]))
        self.assertIsNone(self.queue.snapshot()["dispatcher"]["job_id"])
        self.assertFalse(self.ledger.pending)

    def test_safe_default_has_no_enabled_adapter(self):
        self.prepare()
        bare = SerialCoordinator(self.queue, self.ledger.identity, clock=self.clock)
        self.assertEqual(bare.run_once().state, "blocked")
        self.assertFalse(self.browser.calls)


if __name__ == "__main__":
    unittest.main()
