"""Synthetic-only bridge tests. No real browser, network, ledger, or STOP changes."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from dispatch_gate import CommandResult, GateBlocked, action_id, canonical, completed_json, payload_hash
from tool_bridge import (BindingPin, BridgeBlocked, FileBrowserAdapter, FileToolBridge,
                         INTEGRATION_ROOT, RequestTicket, SlotContext, SyntheticTestCapability)


class Clock:
    def __init__(self):
        self.value = 1_000
    def __call__(self):
        return self.value


def command(value):
    return CommandResult(True, 0, canonical(value))


def independent_process_claim(root, ticket, binding):
    try:
        with FileToolBridge(root, synthetic_capability=SyntheticTestCapability.for_tests_only(),
                            clock=lambda: 1000) as bridge:
            bridge.claim(ticket, binding)
            return True
    except BridgeBlocked:
        return False


class BridgeTests(unittest.TestCase):
    def setUp(self):
        INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='bridge-tests-', dir=INTEGRATION_ROOT)
        self.directory = Path(self.temp.name)
        self.clock = Clock()
        self.binding = BindingPin('spreader', 'canonical-worker-1', 'canonical-browser-1', 'tab-1', 'test_account')
        self.context = SlotContext(self.binding, 990, 1_100, 'synthetic-policy-reference')
        self.bridge = FileToolBridge(self.directory / 'rpc',
                     synthetic_capability=SyntheticTestCapability.for_tests_only(), clock=self.clock)
        payload = {'target': 'https://threads.com/@someone/post/abc123'}
        self.action = {'kind': 'like', 'target': payload['target'], 'payload': payload,
                       'authorization_id': 'synthetic-authorized-action', 'payload_hash': payload_hash(payload),
                       'action_id': action_id(self.binding.account, 'like', payload['target'])}
        self.intent_counter = 0

    def tearDown(self):
        self.bridge.close()
        self.temp.cleanup()

    def intent(self):
        self.intent_counter += 1
        return hashlib.sha256(f'test-intent-{self.intent_counter}'.encode()).hexdigest()

    def observation(self, **changes):
        return {**self.binding.as_dict(), 'exists': True, 'logged_in': True,
                'observed_at': self.clock(), **changes}

    def submitted(self, intent, **changes):
        return command({'ok': True, 'outcome': 'submitted', 'action_id': self.action['action_id'],
                        'intent_id': intent, **changes})

    def submit_mutation(self, **changes):
        intent = changes.pop('intent_id', self.intent())
        ticket = self.bridge.submit('mutate', self.context, action=self.action, intent_id=intent, **changes)
        return ticket, intent

    def start(self, ticket):
        claim = self.bridge.claim(ticket, self.binding)
        self.bridge.begin_dispatch(claim, self.observation())
        return claim

    def finish_mutation(self):
        ticket, intent = self.submit_mutation()
        claim = self.start(ticket)
        self.bridge.complete(claim, self.submitted(intent))
        result = self.bridge.take_result(ticket)
        return ticket, intent, result

    def evidence_result(self, request, outcome='present'):
        proof = self.directory / f"proof-{request['request_id']}.txt"
        proof.write_text('synthetic evidence only')
        evidence = {'schema': 'browser-action-evidence-v2', 'account': self.binding.account,
                    **{key: self.action[key] for key in ('kind', 'target', 'payload_hash')},
                    'intent_id': request['intent_id'], 'outcome': outcome, 'observed_at': self.clock(),
                    'reference': 'synthetic-only-reference', 'proof_file': str(proof),
                    'proof_sha256': hashlib.sha256(proof.read_bytes()).hexdigest(), 'receipt_urls': []}
        record = self.directory / f"evidence-{request['request_id']}.json"
        record.write_text(canonical(evidence))
        return command({'ok': True, 'binding': self.observation(), 'evidence': evidence,
                        'evidence_path': str(record)})

    def edit_file(self, ticket, suffix, function):
        path = self.bridge.root / f'{ticket.request_id}.{suffix}.json'
        value = json.loads(path.read_text())
        function(value)
        path.chmod(0o600)
        path.write_text(canonical(value))
        path.chmod(0o400)

    def test_mutation_disabled_by_default_and_no_injected_real_clock(self):
        with FileToolBridge(self.directory / 'default') as bridge:
            with self.assertRaises(BridgeBlocked):
                bridge.submit('mutate', self.context, action=self.action, intent_id=self.intent())
        with self.assertRaises(BridgeBlocked):
            FileToolBridge(self.directory / 'injected', clock=self.clock)

    def test_readonly_bridge_can_claim_no_synthetic_mutations(self):
        ticket, _ = self.submit_mutation()
        with FileToolBridge(self.bridge.root) as bridge:
            with self.assertRaises(BridgeBlocked):
                bridge.claim(ticket, self.binding)

    def test_exact_mutation_result_and_one_use_response(self):
        ticket, intent, result = self.finish_mutation()
        self.assertEqual(completed_json(result)['intent_id'], intent)
        with self.assertRaises(BridgeBlocked):
            self.bridge.take_result(ticket)
        with self.assertRaises(BridgeBlocked):
            self.bridge.claim(ticket, self.binding)

    def test_parallel_claims_dispatch_exactly_once(self):
        ticket, intent = self.submit_mutation()
        barrier = threading.Barrier(12)
        calls = []
        def attempt(_):
            barrier.wait()
            try:
                claim = self.bridge.claim(ticket, self.binding)
                self.bridge.dispatch_synthetic(claim, observe_binding=self.observation,
                    handler=lambda spec: (calls.append(spec.ticket.request_id), self.submitted(intent))[1])
                return True
            except BridgeBlocked:
                return False
        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(attempt, range(12)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(calls, [ticket.request_id])

    def test_parallel_intent_submission_only_one_publishes(self):
        intent = self.intent()
        def submit(_):
            try:
                return self.submit_mutation(intent_id=intent)[0]
            except BridgeBlocked:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(submit, range(8)))
        self.assertEqual(sum(item is not None for item in outcomes), 1)

    def test_wrong_role_worker_browser_tab_account_rejected(self):
        ticket, _ = self.submit_mutation()
        changes = {'role': 'commenter', 'worker_id': 'worker-else', 'browser_id': 'browser-else',
                   'tab_id': 'tab-else', 'account': 'wrong_account'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(BridgeBlocked):
                self.bridge.claim(ticket, replace(self.binding, **{key: value}))
        claim = self.bridge.claim(ticket, self.binding)
        self.assertEqual(claim.worker_binding, self.binding)

    def test_wrong_observation_is_terminal_no_route_repair(self):
        for key, value in {'worker_id': 'wrong', 'browser_id': 'wrong', 'tab_id': 'wrong',
                           'account': 'other_account', 'exists': False, 'logged_in': False}.items():
            ticket, _ = self.submit_mutation()
            claim = self.bridge.claim(ticket, self.binding)
            with self.subTest(key=key), self.assertRaises(BridgeBlocked):
                self.bridge.begin_dispatch(claim, self.observation(**{key: value}))
            with self.assertRaises(BridgeBlocked):
                self.bridge.begin_dispatch(claim, self.observation())

    def test_claim_crash_and_restart_do_not_replay(self):
        ticket, intent = self.submit_mutation()
        self.bridge.claim(ticket, self.binding)
        self.bridge.close()
        self.bridge = FileToolBridge(self.directory / 'rpc',
            synthetic_capability=SyntheticTestCapability.for_tests_only(), clock=self.clock)
        with self.assertRaises(BridgeBlocked):
            self.bridge.claim(ticket, self.binding)
        with self.assertRaises(BridgeBlocked):
            self.submit_mutation(intent_id=intent)
        self.assertIsNone(self.bridge.take_result(ticket))

    def test_dispatch_and_completion_are_one_use(self):
        ticket, intent = self.submit_mutation()
        claim = self.start(ticket)
        with self.assertRaises(BridgeBlocked):
            self.bridge.begin_dispatch(claim, self.observation())
        self.bridge.complete(claim, self.submitted(intent))
        with self.assertRaises(BridgeBlocked):
            self.bridge.complete(claim, self.submitted(intent))

    def test_lost_response_never_replays_and_timeout_stays_terminal(self):
        ticket, intent = self.submit_mutation(timeout_seconds=2)
        claim = self.start(ticket)
        self.assertIsNone(self.bridge.take_result(ticket))
        self.clock.value += 2
        with self.assertRaises(BridgeBlocked):
            self.bridge.take_result(ticket)
        self.clock.value -= 2
        with self.assertRaises(BridgeBlocked):
            self.bridge.complete(claim, self.submitted(intent))
        with self.assertRaises(BridgeBlocked):
            self.submit_mutation(intent_id=intent)

    def test_late_result_is_not_accepted(self):
        ticket, intent = self.submit_mutation(timeout_seconds=2)
        claim = self.start(ticket)
        self.clock.value += 2
        with self.assertRaises(BridgeBlocked):
            self.bridge.complete(claim, self.submitted(intent))
        self.clock.value -= 2
        with self.assertRaises(BridgeBlocked):
            self.bridge.complete(claim, self.submitted(intent))

    def test_completed_but_late_to_collect_is_abandoned(self):
        ticket, intent = self.submit_mutation(timeout_seconds=2)
        claim = self.start(ticket)
        self.bridge.complete(claim, self.submitted(intent))
        self.clock.value += 2
        with self.assertRaises(BridgeBlocked):
            self.bridge.take_result(ticket)

    def test_definitive_denial_preserved_and_cannot_readback_or_retry(self):
        ticket, intent = self.submit_mutation()
        claim = self.start(ticket)
        self.bridge.complete(claim, self.submitted(intent, ok=False, outcome='denied'))
        self.assertEqual(completed_json(self.bridge.take_result(ticket))['outcome'], 'denied')
        with self.assertRaises(BridgeBlocked):
            self.submit_mutation(intent_id=intent)
        with self.assertRaises(BridgeBlocked):
            self.bridge.submit('readback', self.context, action=self.action, intent_id=intent, readback_of=ticket)

    def test_submit_enforces_both_slot_bounds(self):
        for now in (989, 1100, 1101):
            self.clock.value = now
            with self.subTest(now=now), self.assertRaises(BridgeBlocked):
                self.submit_mutation()
        for now in (990, 1099):
            self.clock.value = now
            self.submit_mutation()

    def test_clock_window_rechecked_after_claim(self):
        for now in (989, 1100):
            self.clock.value = 1000
            ticket, _ = self.submit_mutation(timeout_seconds=200)
            claim = self.bridge.claim(ticket, self.binding)
            self.clock.value = now
            with self.subTest(now=now), self.assertRaises(BridgeBlocked):
                self.bridge.begin_dispatch(claim, self.observation())
            self.clock.value = 1000
            with self.assertRaises(BridgeBlocked):
                self.bridge.begin_dispatch(claim, self.observation())

    def test_clock_window_rechecked_immediately_before_synthetic_handler(self):
        for new_time in (989, 1100):
            self.clock.value = 1000
            ticket, intent = self.submit_mutation(timeout_seconds=200)
            claim = self.bridge.claim(ticket, self.binding)
            calls = []
            count = 0
            def delayed_observation():
                nonlocal count
                count += 1
                if count == 2:
                    self.clock.value = new_time
                return self.observation()
            with self.subTest(new_time=new_time), self.assertRaises(BridgeBlocked):
                self.bridge.dispatch_synthetic(claim, observe_binding=delayed_observation,
                    handler=lambda spec: (calls.append(spec), self.submitted(intent))[1])
            self.assertEqual(calls, [])

    def test_request_digest_prevents_file_tamper(self):
        for key, value in {'intent_id': 'a' * 64, 'payload_hash': 'b' * 64,
                           'authorization_reference': 'other-ref', 'slot_start': 991,
                           'slot_deadline': 1200}.items():
            ticket, _ = self.submit_mutation()
            self.edit_file(ticket, 'request', lambda data: data.update({key: value}))
            with self.subTest(key=key), self.assertRaises(BridgeBlocked):
                self.bridge.claim(ticket, self.binding)

    def test_payload_tamper_during_claim_and_dispatch_fails(self):
        ticket, _ = self.submit_mutation()
        claim = self.bridge.claim(ticket, self.binding)
        self.edit_file(ticket, 'request', lambda data: data['action']['payload'].update(text='changed'))
        with self.assertRaises(BridgeBlocked):
            self.bridge.begin_dispatch(claim, self.observation())

    def test_wrong_ticket_id_or_digest(self):
        ticket, _ = self.submit_mutation()
        with self.assertRaises(BridgeBlocked):
            self.bridge.claim(replace(ticket, request_digest='f' * 64), self.binding)
        with self.assertRaises((OSError, BridgeBlocked)):
            self.bridge.claim(replace(ticket, request_id='f' * 32), self.binding)

    def test_mutation_response_wrong_action_intent_outcome_rejected(self):
        for changes in ({'intent_id': 'e' * 64}, {'action_id': 'e' * 64},
                        {'outcome': 'unknown'}, {'outcome': 'denied'}, {'ok': 1}, {'extra': True}):
            ticket, intent = self.submit_mutation()
            claim = self.start(ticket)
            with self.subTest(changes=changes), self.assertRaises(BridgeBlocked):
                self.bridge.complete(claim, self.submitted(intent, **changes))
            with self.assertRaises(BridgeBlocked):
                self.bridge.complete(claim, self.submitted(intent))

    def test_malformed_running_truncated_incomplete_results_consume_completion(self):
        good = command({'ok': True, 'binding': self.observation()})
        values = [replace(good, completed=False), replace(good, session_id='still-running'),
                  replace(good, truncated=True), replace(good, exit_code=None),
                  replace(good, exit_code=True), replace(good, exit_code=1),
                  replace(good, stderr='unexpected'), replace(good, stdout='{"ok":true'),
                  replace(good, stdout='{"ok":true,"ok":true}'),
                  replace(good, stdout='{}\n{}'), replace(good, stdout='[]')]
        for result in values:
            ticket = self.bridge.submit('observe', self.context)
            claim = self.start(ticket)
            with self.subTest(result=result), self.assertRaises(GateBlocked):
                self.bridge.complete(claim, result)
            with self.assertRaises(BridgeBlocked):
                self.bridge.complete(claim, good)

    def test_response_envelope_tamper_rejected(self):
        for key, value in {'request_id': 'f' * 32, 'request_digest': 'f' * 64,
                           'payload_hash': 'f' * 64, 'intent_id': 'f' * 64,
                           'authorization_reference': 'different', 'slot_start': 991,
                           'slot_deadline': 1099, 'completed_at': 1500}.items():
            ticket, intent = self.submit_mutation()
            claim = self.start(ticket)
            self.bridge.complete(claim, self.submitted(intent))
            self.edit_file(ticket, 'response', lambda data: data.update({key: value}))
            with self.subTest(key=key), self.assertRaises(BridgeBlocked):
                self.bridge.take_result(ticket)

    def test_response_content_tamper_rejected_even_same_action(self):
        ticket, intent = self.submit_mutation()
        claim = self.start(ticket)
        self.bridge.complete(claim, self.submitted(intent, ok=False, outcome='denied'))
        self.edit_file(ticket, 'response', lambda data: data['result']['stdout'].update(ok=True, outcome='submitted'))
        with self.assertRaises(BridgeBlocked):
            self.bridge.take_result(ticket)

    def test_completion_requires_dispatch_and_exact_claim(self):
        ticket, intent = self.submit_mutation()
        claim = self.bridge.claim(ticket, self.binding)
        with self.assertRaises((OSError, BridgeBlocked)):
            self.bridge.complete(claim, self.submitted(intent))
        self.bridge.begin_dispatch(claim, self.observation())
        with self.assertRaises(BridgeBlocked):
            self.bridge.complete(replace(claim, worker_binding=replace(self.binding, tab_id='other')),
                                 self.submitted(intent))

    def test_readonly_observe_and_preflight(self):
        for operation in ('observe', 'preflight'):
            ticket = self.bridge.submit(operation, self.context,
                action=self.action if operation == 'preflight' else None)
            claim = self.start(ticket)
            result = command({'ok': True, 'binding': self.observation()}) if operation == 'observe' else \
                self.evidence_result(self.bridge.inspect(ticket), 'absent')
            self.bridge.complete(claim, result)
            self.assertIs(completed_json(self.bridge.take_result(ticket))['ok'], True)

    def test_readback_can_pass_slot_deadline_only_for_accepted_matching_submission(self):
        ticket, intent, _ = self.finish_mutation()
        self.clock.value = 1101
        readback = self.bridge.submit('readback', self.context, action=self.action, intent_id=intent,
                                     readback_of=ticket)
        claim = self.start(readback)
        self.bridge.complete(claim, self.evidence_result(self.bridge.inspect(readback)))
        self.assertEqual(completed_json(self.bridge.take_result(readback))['evidence']['intent_id'], intent)
        with self.assertRaises(BridgeBlocked):
            self.bridge.submit('readback', self.context, action=self.action, intent_id='f' * 64, readback_of=ticket)
        with self.assertRaises(BridgeBlocked):
            self.bridge.submit('readback', self.context, action=self.action, intent_id=intent)

    def test_mutation_started_before_deadline_can_finish_after_slot(self):
        self.clock.value = 1099
        ticket, intent = self.submit_mutation()
        claim = self.start(ticket)
        self.clock.value = 1102
        self.bridge.complete(claim, self.submitted(intent))
        self.assertEqual(completed_json(self.bridge.take_result(ticket))['outcome'], 'submitted')

    def test_parent_accepted_seal_tamper_prevents_readback(self):
        ticket, intent, _ = self.finish_mutation()
        self.edit_file(ticket, 'accepted', lambda data: data.update(response_digest='f' * 64))
        with self.assertRaises(BridgeBlocked):
            self.bridge.submit('readback', self.context, action=self.action, intent_id=intent, readback_of=ticket)

    def test_secrets_rejected_not_written(self):
        for field in ('token', 'ledger_token', 'authorization', 'access-token', 'password'):
            action = json.loads(canonical(self.action))
            action['payload'][field] = 'do-not-log-this-secret'
            action['payload_hash'] = payload_hash(action['payload'])
            with self.subTest(field=field), self.assertRaises(BridgeBlocked):
                self.bridge.submit('mutate', self.context, action=action, intent_id=self.intent())
        self.assertEqual(list(self.bridge.root.glob('*.request.json')), [])

    def test_staging_root_symlink_and_replacement_rejected(self):
        with self.assertRaises(BridgeBlocked):
            FileToolBridge('/tmp/not-allowed-bridge')
        link = self.directory / 'linked'
        link.symlink_to(self.bridge.root, target_is_directory=True)
        with self.assertRaises(BridgeBlocked):
            FileToolBridge(link)
        ticket, _ = self.submit_mutation()
        path = self.bridge.root / f'{ticket.request_id}.request.json'
        path.unlink()
        path.symlink_to(self.directory / 'unknown-file')
        with self.assertRaises((OSError, BridgeBlocked)):
            self.bridge.inspect(ticket)
        original = self.bridge.root
        original.rename(self.directory / 'old-rpc')
        original.mkdir()
        with self.assertRaises(BridgeBlocked):
            self.bridge.inspect(ticket)

    def test_request_snapshot_immutable_after_caller_changes(self):
        ticket, _ = self.submit_mutation()
        self.action['payload']['text'] = 'caller changed mutable input'
        view = self.bridge.inspect(ticket)
        self.assertNotIn('text', view['action']['payload'])
        view['binding']['tab_id'] = 'mutated copy'
        self.assertEqual(self.bridge.inspect(ticket)['binding']['tab_id'], self.binding.tab_id)

    def test_adapter_protocol_all_operations_and_pinned_slots(self):
        served = []
        def service(ticket):
            request = self.bridge.inspect(ticket)
            claim = self.bridge.claim(ticket, self.binding)
            def handler(spec):
                served.append(request['operation'])
                if request['operation'] == 'observe':
                    return command({'ok': True, 'binding': self.observation()})
                if request['operation'] == 'mutate':
                    return self.submitted(request['intent_id'])
                return self.evidence_result(request, 'absent' if request['operation'] == 'preflight' else 'present')
            self.bridge.dispatch_synthetic(claim, observe_binding=self.observation, handler=handler)
        adapter = FileBrowserAdapter(self.bridge, [self.context], on_submitted=service)
        binding = self.binding.as_dict()
        adapter.observe(binding)
        adapter.preflight(self.action, binding)
        intent = self.intent()
        with self.assertRaises(BridgeBlocked):
            adapter.mutate(self.action, binding, intent, slot_start=989, slot_deadline=1100)
        adapter.mutate(self.action, binding, intent, slot_start=990, slot_deadline=1100)
        self.clock.value = 1101
        adapter.readback(self.action, binding, intent)
        self.assertEqual(served, ['observe', 'preflight', 'mutate', 'readback'])
        with self.assertRaises(BridgeBlocked):
            adapter.observe({**binding, 'tab_id': 'replacement'})

    def test_adapter_distinct_role_workers_and_tabs(self):
        second = replace(self.context, binding=replace(self.binding, role='commenter'))
        with self.assertRaises(BridgeBlocked):
            FileBrowserAdapter(self.bridge, [self.context, second])
        second = replace(second, binding=replace(second.binding, worker_id='worker-2', tab_id='tab-2'))
        FileBrowserAdapter(self.bridge, [self.context, second])

    def test_canonical_browser_selection_aliases_rejected(self):
        for alias in ('cdp', 'iab', 'extension', 'mcpapps', 'CDP', 'IAB', 'Extension', 'MCPAPPS'):
            with self.subTest(alias=alias), self.assertRaises(BridgeBlocked):
                replace(self.binding, browser_id=alias)

    def test_independent_processes_claim_exactly_once(self):
        ticket, _ = self.submit_mutation()
        with ProcessPoolExecutor(max_workers=6, mp_context=multiprocessing.get_context('fork')) as pool:
            futures = [pool.submit(independent_process_claim, self.bridge.root, ticket, self.binding)
                       for _ in range(12)]
            self.assertEqual(sum(f.result() for f in futures), 1)

    def test_wait_timeout_has_no_retry_and_seals_request(self):
        ticket = self.bridge.submit('observe', self.context, timeout_seconds=1)
        with self.assertRaises(BridgeBlocked):
            self.bridge.wait_result(ticket)
        with self.assertRaises(BridgeBlocked):
            self.bridge.claim(ticket, self.binding)

    def test_adapter_notify_failure_abandons_without_retry(self):
        tickets = []
        def fail(ticket):
            tickets.append(ticket)
            raise RuntimeError('synthetic lost worker')
        adapter = FileBrowserAdapter(self.bridge, [self.context], on_submitted=fail)
        with self.assertRaises(RuntimeError):
            adapter.observe(self.binding.as_dict())
        self.assertEqual(len(tickets), 1)
        with self.assertRaises(BridgeBlocked):
            self.bridge.claim(tickets[0], self.binding)

    def test_handler_exception_leaves_consumed_dispatch(self):
        ticket, _ = self.submit_mutation()
        claim = self.bridge.claim(ticket, self.binding)
        def fail(spec):
            raise RuntimeError('synthetic lost tool output')
        with self.assertRaises(RuntimeError):
            self.bridge.dispatch_synthetic(claim, observe_binding=self.observation, handler=fail)
        with self.assertRaises(BridgeBlocked):
            self.bridge.dispatch_synthetic(claim, observe_binding=self.observation, handler=fail)
        self.assertIsNone(self.bridge.take_result(ticket))


if __name__ == '__main__':
    unittest.main(verbosity=2)
