"""Offline synthetic timeout fixtures. No live source reads, browser, or real approval."""
import copy
import json
import unittest

import test_quarantine_extension as old
import test_quarantine_plumbing as plumbing

m, ui = old.m, old.ui


def timeout_arguments(binding, deadline):
    code = (ui.WAIT_REQUEST_TEMPLATE.replace('{deadline_ms}', str(deadline * 1000))
            .replace('{deadline}', str(deadline)).replace('{target}', binding['target'])
            .replace('{account}', binding['account']))
    return {'code': code, 'title': 'Repost the verified LangGraph tutorial once', 'timeout_ms': 20000}


def timeout_result(binding):
    return {'isError': True, 'content': [
        {'type': 'text', 'text': ui.WAIT_ERROR_PREFIX + m.canonical(ui.WAIT_DIAGNOSTICS)},
        {'type': 'text', 'text': 'Browser tab: ' + binding['tab_id'] + ', Title: "Synthetic tutorial", URL: "' + binding['target'] + '".\nSynthetic partial target menu only; external outcome unknown.'}]}


class TimeoutFixture(old.Fixture):
    def make_evidence(self):
        super().make_evidence()
        ib, binding = self.incident['bundle'], self.incident['binding']
        ib['failed_call'].update(incident_protocol=ui.WAIT_PROTOCOL, execution_stage=ui.WAIT_STAGE)
        ib['operator_review']['trace_classification'] = ui.WAIT_TRACE
        ib['sources']['request'] = old.source(m.canonical(timeout_arguments(binding, self.base + 200)), 'application/json')
        ib['sources']['result'] = old.source(m.canonical(timeout_result(binding)), 'application/json')
        ib['sources']['operator'] = old.source('SYNTHETIC ONLY: original operator independently reviewed exact complete arguments, terminal waitFor-visible three-match result, and sequential before-final-click trace; final submission not invoked, no outstanding call or later changing call. Native call ID and exact native timestamps unavailable. Retained argument/result serializations are not raw transport bytes. Outcome unknown.')
        ib['sources']['current_operator'] = old.source('SYNTHETIC ONLY: current original tab remains present in the same observed browser instance, account, ledger session and target. Original request terminal; final submission not invoked; no outstanding or subsequent changing calls. Both refreshed observations are read-only and partial/unknown; no replacement tab or tab closure. Outer timestamp bounds only.')
        ib['reconciliation'].update(schema='same-original-tab-readback-provenance-v1',
            tab_id=binding['tab_id'], classification='original_tab_current_same_tab_read_only',
            original_tab_state='current', original_tab_unavailable_reason=None, replacement_tab_state=None)
        for observation in ib['observations']:
            observation['tab_id'] = binding['tab_id']
        self.write()


class LocatorTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.f = TimeoutFixture()
        self.addCleanup(self.f.close)

    blocked = old.UncertainQuarantineTests.blocked
    crash_at_commit = old.UncertainQuarantineTests.crash_at_commit

    # Exercise the exact unchanged atomic/freshness/archive gates with the new fixture.
    test_atomic_unknown_closure = old.UncertainQuarantineTests.test_happy_path_atomic_and_preserves_original_intent
    test_independent_pin_required = old.UncertainQuarantineTests.test_independent_pin_mandatory
    test_exact_stop_required = old.UncertainQuarantineTests.test_wrong_stop_identity
    test_stale_review_or_observation = old.UncertainQuarantineTests.test_stale_read_or_review
    test_partial_unknown_only = old.UncertainQuarantineTests.test_limited_readback_must_stay_unknown_and_partial
    test_no_pending_or_later_mutations = old.UncertainQuarantineTests.test_incomplete_or_mutating_tool_state
    test_failure_can_be_historical = old.UncertainQuarantineTests.test_failure_itself_can_be_historical
    test_lock_wait_expiry = old.UncertainQuarantineTests.test_actual_lock_wait_expiry_rolls_back
    test_final_storage_expiry = old.UncertainQuarantineTests.test_expiry_during_final_storage_check_rolls_back
    test_clock_rollback = old.UncertainQuarantineTests.test_clock_rollback_during_audit_rolls_back
    test_death_before_commit = old.UncertainQuarantineTests.test_process_death_before_commit_preserves_stop_and_writer
    test_death_after_commit = old.UncertainQuarantineTests.test_process_death_after_commit_leaves_checkpoint_pending
    test_no_replay = old.UncertainQuarantineTests.test_replay_rejected_without_second_sequence
    test_archive_source_closure = old.UncertainQuarantineTests.test_retained_graph_and_restore_after_source_deletion
    test_all_post_write_aliases = old.UncertainQuarantineTests.test_cross_kind_domain_and_handle_aliases_with_profile_scope_preserved
    test_old_generic_approval = old.UncertainQuarantineTests.test_older_no_execution_role_github_and_generic_approval_do_not_qualify
    test_unknown_disposition_required = old.UncertainQuarantineTests.test_immutable_proof_disposition_must_remain_unknown
    test_scope_and_checkpoint_resume = old.UncertainQuarantineTests.test_whole_post_scope_and_no_implicit_resume_authority
    test_no_native_v4_or_multicall = old.UncertainQuarantineTests.test_native_v4_or_multicall_future_incidents_rejected
    test_outer_bounds_only = old.UncertainQuarantineTests.test_observed_outer_timestamp_basis_and_provenance_are_required

    def replace_source(self, name, value):
        self.f.incident['bundle']['sources'][name] = old.source(m.canonical(value), 'application/json')
        self.f.write()

    def test_old_guard_replacement_still_succeeds(self):
        f = old.Fixture()
        self.addCleanup(f.close)
        self.assertEqual(f.finalize()['external_outcome'], 'unknown')

    def test_cross_protocol_provenance_rejected(self):
        legacy = old.Fixture()
        self.addCleanup(legacy.close)
        current = self.f.incident['bundle']['reconciliation']
        replacement = legacy.incident['bundle']['reconciliation']
        self.f.incident['bundle']['reconciliation'] = copy.deepcopy(replacement)
        self.f.write()
        self.blocked()
        legacy.incident['bundle']['reconciliation'] = copy.deepcopy(current)
        legacy.write()
        before = legacy.snapshot()
        with self.assertRaises(m.Blocked):
            legacy.finalize()
        self.assertEqual(legacy.snapshot(), before)

    def test_cannot_relabel_timeout_as_old_guard(self):
        ib = self.f.incident['bundle']
        ib['failed_call'].update(incident_protocol='legacy_current_ui_single_call_v1',
                                execution_stage='after_menu_open_before_final_submit')
        ib['operator_review']['trace_classification'] = 'authentic_completed_single_call_exact_guard_before_final_submission_no_pending_or_later_mutations'
        self.f.write()
        self.blocked()

    def test_wrong_stage_or_trace(self):
        for obj, key, values in [
            (self.f.incident['bundle']['failed_call'], 'execution_stage', ['after_menu_open_before_final_submit', 'during_final_click']),
            (self.f.incident['bundle']['operator_review'], 'trace_classification', ['authentic_completed_single_call_exact_guard_before_final_submission_no_pending_or_later_mutations', 'timeout'])]:
            original = obj[key]
            for value in values:
                with self.subTest(value=value):
                    obj[key] = value
                    self.f.write()
                    self.blocked()
            obj[key] = original

    def test_request_must_match_entire_sequential_template(self):
        args = timeout_arguments(self.f.incident['binding'], self.f.base + 200)
        originals = args['code']
        variants = [
            'await choice.click(); ' + originals,
            originals + ' await choice.click();',
            originals.replace('await choice.waitFor(', 'await choice.click('),
            originals.replace('await choice.waitFor(', 'try { await choice.waitFor(') + '} catch(e) {await choice.click();}',
            originals.replace(self.f.target, 'https://threads.com/@wrong/post/Other'),
            originals.replace(str((self.f.base + 200) * 1000), str((self.f.base + 201) * 1000), 1),
            originals.replace("getByText('리포스트',{exact:true})", "getByText('리포스트',{exact:false})"),
            originals.replace('await opener.click(', 'await choice.click(')]
        for code in variants:
            with self.subTest(code=code[:60]):
                self.replace_source('request', {**args, 'code': code})
                self.blocked()

    def test_complete_arguments_required(self):
        args = timeout_arguments(self.f.incident['binding'], self.f.base + 200)
        for mutation in [{'code': args['code']}, {**args, 'timeout_ms': 30000}, {**args, 'title': 'Different request'}, {**args, 'extra': 'unexposed'}]:
            self.replace_source('request', mutation)
            self.blocked()

    def test_generic_click_timeout_and_final_marker_rejected(self):
        result = timeout_result(self.f.incident['binding'])
        for error in ['Error: Timeout', result['content'][0]['text'].replace('locator.waitFor(visible)', 'locator.click()'),
                      result['content'][0]['text'].replace('"waitFor"', '"click"')]:
            changed = copy.deepcopy(result)
            changed['content'][0]['text'] = error
            self.replace_source('result', changed)
            self.blocked()
        changed = copy.deepcopy(result)
        changed['content'][1]['text'] += '\n{"nativeRepostSelectedOnce":true}'
        self.replace_source('result', changed)
        self.blocked()

    def test_result_shape_and_identity(self):
        original = timeout_result(self.f.incident['binding'])
        variants = [dict(original, isError=False), dict(original, content=original['content'][:1]),
                    dict(original, content=original['content'] + [{'type': 'text', 'text': 'Unaccounted output'}])]
        for old_text, new_text in [('Browser tab: synthetic-tab', 'Browser tab: different-tab'), (self.f.target, 'https://threads.com/@wrong/post/Other')]:
            changed = copy.deepcopy(original)
            changed['content'][1]['text'] = changed['content'][1]['text'].replace(old_text, new_text)
            variants.append(changed)
        for variant in variants:
            self.replace_source('result', variant)
            self.blocked()

    def test_exact_diagnostics_required(self):
        for key, value in [('action', 'click'), ('kind', 'timeout'), ('matchCount', 1), ('visibleCount', 3),
                           ('visibleCount', True), ('truncated', True), ('locator', 'internal:role=menuitem'), ('matches', [])]:
            with self.subTest(key=key):
                diagnostics = copy.deepcopy(ui.WAIT_DIAGNOSTICS)
                diagnostics[key] = value
                result = timeout_result(self.f.incident['binding'])
                result['content'][0]['text'] = ui.WAIT_ERROR_PREFIX + m.canonical(diagnostics)
                self.replace_source('result', result)
                self.blocked()
        for key in ui.WAIT_DIAGNOSTICS:
            diagnostics = copy.deepcopy(ui.WAIT_DIAGNOSTICS)
            del diagnostics[key]
            result = timeout_result(self.f.incident['binding'])
            result['content'][0]['text'] = ui.WAIT_ERROR_PREFIX + m.canonical(diagnostics)
            self.replace_source('result', result)
            self.blocked()

    def test_same_original_tab_identity_and_honesty(self):
        provenance = self.f.incident['bundle']['reconciliation']
        for key, value in [('original_browser_session', 'browser-instance:2'), ('browser_session', 'browser-instance:2'),
                           ('original_tab_id', 'different-tab'), ('tab_id', 'different-tab'), ('account', 'different.account'),
                           ('ledger_session', 'different-session'), ('target', 'https://threads.com/@wrong/post/Other'),
                           ('original_tab_state', 'not_listed_after_cleanup'), ('original_tab_unavailable_reason', 'closed'),
                           ('replacement_tab_state', 'current'), ('mode', 'mutating')]:
            with self.subTest(key=key):
                original = provenance[key]
                provenance[key] = value
                self.f.write()
                self.blocked()
                provenance[key] = original

    def test_old_target_approval_and_unreviewed_relabel_rejected(self):
        original = copy.deepcopy(self.f.approval)
        self.f.approval['binding']['target'] = 'https://threads.com/@old_target/post/OldQuarantine'
        self.f.write()
        self.blocked()
        self.f.approval = original
        self.f.write()
        self.f.approval['bundle']['sources']['question'] = old.source('Synthetic old target approval question')
        self.f.write(repin=False)
        self.blocked()

    def test_stale_approval_and_success_claim_rejected(self):
        self.f.approval['bundle']['reviewed_at'] = self.f.base - 1000
        self.f.write()
        self.blocked()
        self.f.approval['bundle']['reviewed_at'] = self.f.base + 15
        self.f.incident['bundle']['disposition']['external_outcome'] = 'verified'
        self.f.write()
        self.blocked()


class LocatorTimeoutPlumbingTests(plumbing.PlumbingTests):
    def setUp(self):
        self.f = TimeoutFixture()
        self.addCleanup(self.f.close)


if __name__ == '__main__':
    unittest.main()
