"""Staging-only legacy UI uncertainty closure. Never assert absence, dispatch, or retry.

Integrity is not authentication. The separately supplied TrustedReviewPin is an
operator-attestation boundary: its provider MUST review authentic tool and user
conversation sources. No JSON field, hash, or copied prose proves that review.
"""
import base64
from dataclasses import dataclass, fields
import json
import re

from ledger import HASH, action_key, target_key, canonical, digest, exact, file_bytes, must, text

MAX_SOURCE_BYTES = 2_000_000
MAX_TOTAL_SOURCE_BYTES = 4_000_000
FRESH_SECONDS = 300
CLASSIFICATION = 'independently_reviewed_legacy_ui_uncertainty_quarantine'
SUBTYPE = 'operator_closed_uncertain_target_quarantined_v1'
POST_KINDS = ('repost', 'like', 'reply', 'self_reply')
DISPOSITION = {'external_outcome': 'unknown', 'termination': 'operator_accepted_uncertainty',
               'new_verified_count': 0, 'retry_allowed': False}
QUARANTINE_SCOPE = 'entire_canonical_post_all_post_write_kinds'
RESUME_SCOPE = 'other_posts_after_verified_checkpoint'
TERMINATION = 'operator_accepted_uncertainty'
DECISION = 'accept_unknown_quarantine_post_release_writer_require_checkpoint_no_retry'
BINDING_FIELDS = ('account', 'db_id', 'action_id', 'kind', 'target', 'payload_hash',
                  'intent_id', 'intent_at', 'owner', 'session', 'run_started_at',
                  'stop', 'expected_checkpoint_seq', 'browser_session', 'tab_id')


@dataclass(frozen=True)
class TrustedReviewPin:
    schema: str
    incident_sha256: str
    approval_sha256: str
    pending_question_reference: str
    pending_question_sha256: str
    affirmative_answer_reference: str
    affirmative_answer_sha256: str
    approval_context_sha256: str
    failed_request_sha256: str
    failed_result_sha256: str
    failed_context_reference: str
    operator_attestation_sha256: str
    reconciliation_provenance_sha256: str
    reconciliation_source_sha256: tuple
    reviewer: str
    review_context_reference: str
    reviewed_at: int
    classification: str

    @classmethod
    def from_dict(cls, value):
        """Parse independently provided operator pins; does NOT authenticate them."""
        exact(value, tuple(f.name for f in fields(cls)))
        must(value['schema'] == 'trusted-uncertain-quarantine-review-pin-v1', 'Wrong trusted review pin schema')
        must(value['classification'] == CLASSIFICATION, 'Explicit independent uncertainty-acceptance classification required')
        for name in ('incident_sha256', 'approval_sha256', 'pending_question_sha256',
                     'affirmative_answer_sha256', 'approval_context_sha256',
                     'failed_request_sha256', 'failed_result_sha256', 'operator_attestation_sha256', 'reconciliation_provenance_sha256'):
            hash_value(value[name], name)
        for name in ('pending_question_reference', 'affirmative_answer_reference',
                     'failed_context_reference', 'reviewer', 'review_context_reference'):
            text(value[name], name)
        must(value['pending_question_reference'] != value['affirmative_answer_reference'],
             'Question and answer must be distinct authentic messages')
        hashes = value['reconciliation_source_sha256']
        must(type(hashes) in (list, tuple) and 2 <= len(hashes) <= 8,
             'Multiple independently reviewed limited observation sources required')
        for h in hashes:
            hash_value(h, 'reconciliation source')
        must(len(set(hashes)) == len(hashes), 'Duplicate reconciliation source')
        integer(value['reviewed_at'], 'trusted review time')
        return cls(**{**value, 'reconciliation_source_sha256': tuple(hashes)})


def load_trusted_review(path, sha256):
    """Caller must obtain BOTH file and SHA out of band after authentic review."""
    data, _ = file_bytes(path, sha256)
    return TrustedReviewPin.from_dict(parse_json(data))


def parse_json(data):
    def unique(items):
        result = {}
        for key, value in items:
            must(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def hash_value(value, label):
    must(type(value) is str and HASH.fullmatch(value), 'Invalid ' + label + ' SHA-256')


def integer(value, label):
    must(type(value) is int and value >= 0, 'Invalid ' + label)


def source_bytes(sources):
    must(type(sources) is dict and 1 <= len(sources) <= 16, 'Bounded retained source map required')
    result = {}
    total = 0
    for name, source in sources.items():
        text(name, 'source ID', maximum=100)
        exact(source, ('media_type', 'sha256', 'size', 'data_base64'))
        text(source['media_type'], 'source media type', maximum=100)
        hash_value(source['sha256'], 'source')
        integer(source['size'], 'source size')
        must(0 < source['size'] <= MAX_SOURCE_BYTES, 'Empty/oversized source')
        must(type(source['data_base64']) is str and len(source['data_base64']) <= MAX_SOURCE_BYTES * 2,
             'Invalid bounded embedded source bytes')
        try:
            data = base64.b64decode(source['data_base64'], validate=True)
        except (ValueError, TypeError):
            must(False, 'Invalid source base64')
        must(len(data) == source['size'] and digest(data) == source['sha256'], 'Retained source size/hash mismatch')
        total += len(data)
        must(total <= MAX_TOTAL_SOURCE_BYTES, 'Retained source bundle exceeds bound')
        result[name] = data
    return result


class TimeGuard:
    def __init__(self, ledger, fresh_times):
        self.ledger, self.fresh_times, self.previous = ledger, fresh_times, None
        self.check()

    def check(self):
        now = self.ledger.clock()
        integer(now, 'current clock')
        must(self.previous is None or now >= self.previous, 'Clock rollback during legacy UI uncertainty reconciliation')
        self.previous = now
        for label, at in self.fresh_times:
            integer(at, label)
            must(now - FRESH_SECONDS <= at <= now, label + ' stale or in future')
        return now


def check_binding(binding, ledger, owner, action, row, writer, run, stop):
    exact(binding, BINDING_FIELDS)
    must(binding['kind'] == row['kind'] == 'repost', 'Only exact repost legacy UI uncertainty is supported')
    for key, expected in (('account', ledger.account), ('db_id', ledger.get('db_id')),
                          ('action_id', action), ('target', row['target_url']),
                          ('payload_hash', row['payload_hash']), ('intent_id', row['intent_id']),
                          ('intent_at', row['intent_at']), ('owner', owner),
                          ('session', writer['session']), ('run_started_at', run['started_at'])):
        must(binding[key] == expected, 'legacy UI uncertainty binding mismatch: ' + key)
    must(row['target_key'] == target_key(row['kind'], row['target_url']), 'Canonical target key changed')
    must(action_key(ledger.account, binding['kind'], binding['target']) == action,
         'Canonical target/action mismatch')
    integer(binding['intent_at'], 'original intent time')
    integer(binding['run_started_at'], 'run start time')
    integer(binding['expected_checkpoint_seq'], 'expected checkpoint sequence')
    must(binding['expected_checkpoint_seq'] == int(ledger.get('checkpoint_seq')), 'Checkpoint sequence changed')
    must(binding['stop'] == dict(stop), 'Exact original STOP identity changed')
    exact(binding['stop'], ('account', 'action_id', 'reason', 'at'))
    must(stop['action_id'] == action, 'Unrelated STOP cannot be cleared')
    for key in ('browser_session', 'tab_id'):
        text(binding[key], key)


def validate_bundles(incident, approval, ih, ah, pin):
    exact(incident, ('schema', 'binding', 'source_sha256', 'bundle'))
    exact(approval, ('schema', 'binding', 'source_sha256', 'proof_sha256', 'bundle'))
    must(incident['schema'] == 'legacy-current-ui-uncertainty-incident-v2', 'Wrong legacy UI uncertainty incident schema')
    must(approval['schema'] == 'uncertain-quarantine-approval-v1', 'Wrong legacy UI uncertainty approval schema')
    exact(incident['binding'], BINDING_FIELDS)
    must(approval['binding'] == incident['binding'], 'Approval binding differs from incident')
    must(pin.incident_sha256 == ih and pin.approval_sha256 == ah, 'Independent trusted incident/approval pin mismatch')
    ib, ab = incident['bundle'], approval['bundle']
    ib_raw, ab_raw = canonical(ib).encode(), canonical(ab).encode()
    must(digest(ib_raw) == incident['source_sha256'], 'Incident self-contained bundle hash mismatch')
    must(approval['source_sha256'] == ih and digest(ab_raw) == approval['proof_sha256'], 'Approval proof/source graph mismatch')
    exact(ib, ('schema', 'disposition', 'failed_call', 'reconciliation', 'observations', 'operator_review', 'sources'))
    exact(ib['disposition'], tuple(DISPOSITION))
    _disposition(ib['disposition'])
    exact(ab, ('schema', 'pending_question_reference', 'affirmative_answer_reference',
               'question_source', 'answer_source', 'context_source', 'question_at', 'answer_at',
               'decision', 'accepted_external_outcome', 'quarantine_scope', 'resume_scope',
               'new_verified_count', 'retry_authorized', 'new_social_dispatch_authorized', 'reviewed_at', 'sources'))
    must(ib['schema'] == 'retained-uncertain-quarantine-sources-v2' and ab['schema'] == 'retained-uncertain-quarantine-approval-v1',
         'Wrong retained bundle schema')
    src, aps = source_bytes(ib['sources']), source_bytes(ab['sources'])
    failed, operator = ib['failed_call'], ib['operator_review']
    exact(failed, ('incident_protocol', 'completed_call_count', 'tool_name', 'original_context_reference', 'tool_call_id', 'missing_call_id_reason',
                   'request_source', 'result_source', 'request_started_at', 'completed_at', 'timestamp_basis', 'timestamp_provenance', 'completion',
                   'execution_stage', 'final_submission', 'subsequent_mutations', 'outstanding_call'))
    must(failed['incident_protocol'] == 'legacy_current_ui_single_call_v1',
         'Native-v4/future incidents require a separately reviewed complete witness/request/attempt closure')
    must(type(failed['completed_call_count']) is int and failed['completed_call_count'] == 1,
         'Exactly one authentic completed call required')
    must(failed['tool_name'] == 'mcp__cua_repl__js', 'Unexpected incident tool')
    must(failed['original_context_reference'] == pin.failed_context_reference, 'Unreviewed failed-call context')
    must(failed['completion'] == 'completed_error' and failed['execution_stage'] == 'after_menu_open_before_final_submit'
         and failed['final_submission'] == 'not_invoked' and failed['subsequent_mutations'] == 'none'
         and failed['outstanding_call'] == 'none', 'Call not conclusively completed before final submission')
    must(failed['tool_call_id'] is None or type(failed['tool_call_id']) is str and failed['tool_call_id'], 'Invalid tool-call ID')
    if failed['tool_call_id'] is None:
        text(failed['missing_call_id_reason'], 'honest missing transport-ID reason')
    else:
        must(failed['missing_call_id_reason'] is None, 'Unexpected missing-ID reason')
    for field, expected in (('request_source', pin.failed_request_sha256), ('result_source', pin.failed_result_sha256)):
        must(failed[field] in src and digest(src[failed[field]]) == expected, 'Unreviewed original failed-call bytes')
    must(b'Unexpected repost menu; no repost selected' in src[failed['result_source']], 'Exact legacy UI uncertainty error missing')
    must(b'Unexpected repost menu; no repost selected' in src[failed['request_source']],
         'Exact guard branch must be retained in the original request')
    must(failed['timestamp_basis'] == 'observed_outer_bounds', 'Honest observed outer timestamp bounds required')
    text(failed['timestamp_provenance'], 'original timestamp boundary provenance')
    # These legacy field names mean conservative lower/upper observed bounds,
    # not exact native request start/completion timestamps.
    for field in ('request_started_at', 'completed_at'):
        integer(failed[field], field)
    must(incident['binding']['intent_at'] <= failed['request_started_at'] <= failed['completed_at'], 'Invalid original call chronology')
    exact(operator, ('reviewer', 'reference', 'reviewed_at', 'source', 'classification', 'trace_classification'))
    must(operator['reviewer'] == pin.reviewer and operator['reference'] == pin.review_context_reference,
         'Trusted operator review identity/context mismatch')
    must(operator['classification'] == CLASSIFICATION and operator['trace_classification'] == 'authentic_completed_single_call_exact_guard_before_final_submission_no_pending_or_later_mutations',
         'Explicit independent source/trace classification required')
    must(operator['source'] in src and digest(src[operator['source']]) == pin.operator_attestation_sha256,
         'Original operator attestation missing or not independently pinned')
    integer(operator['reviewed_at'], 'operator source review time')
    # Original incident binding is immutable. An unavailable original tab is never
    # relabelled to pretend that later readbacks came from that tab.
    reconciliation = ib['reconciliation']
    exact(reconciliation, ('schema', 'original_browser_session', 'original_tab_id',
                           'browser_session', 'tab_id', 'browser_identity_basis', 'account', 'ledger_session', 'target',
                           'classification', 'original_tab_state', 'original_tab_unavailable_reason',
                           'replacement_tab_state', 'mode', 'operator_source'))
    must(reconciliation['schema'] == 'replacement-tab-readback-provenance-v1',
         'Explicit replacement-tab provenance required')
    must(reconciliation['original_browser_session'] == incident['binding']['browser_session']
         and reconciliation['original_tab_id'] == incident['binding']['tab_id'],
         'Replacement provenance must preserve the original incident browser/tab')
    must(reconciliation['browser_session'] == reconciliation['original_browser_session']
         and reconciliation['browser_identity_basis'] == 'observed_cua_browser_instance_not_native_session'
         and re.fullmatch(r'browser-instance:[1-9][0-9]{0,9}', reconciliation['browser_session']),
         'Replacement must use the same explicitly labelled observed browser instance')
    for field, binding_field in (('account', 'account'), ('ledger_session', 'session'), ('target', 'target')):
        must(reconciliation[field] == incident['binding'][binding_field],
             'Replacement provenance account/ledger-session/target mismatch')
    text(reconciliation['original_tab_unavailable_reason'], 'honest original-tab unavailability provenance')
    text(reconciliation['tab_id'], 'actual replacement readback tab')
    must(reconciliation['tab_id'] != reconciliation['original_tab_id']
         and reconciliation['original_tab_state'] == 'not_listed_after_cleanup'
         and reconciliation['classification'] == 'original_tab_unavailable_replacement_read_only'
         and reconciliation['replacement_tab_state'] == 'current'
         and reconciliation['mode'] == 'read_only', 'Unavailable original/current read-only replacement tabs required')
    provenance_source = reconciliation['operator_source']
    must(provenance_source in src and provenance_source not in
         (operator['source'], failed['request_source'], failed['result_source'])
         and digest(src[provenance_source]) == pin.reconciliation_provenance_sha256,
         'Distinct independently pinned current operator provenance required; preserve original attestation')
    observations = ib['observations']
    must(type(observations) is list and len(observations) == 2, 'Retain both limited read observations without inferring absence')
    used = {failed['request_source'], failed['result_source'], operator['source'], provenance_source}
    observation_hashes, signals, references = [], set(), set()
    fresh = [('operator review', operator['reviewed_at']), ('approval review', ab['reviewed_at']), ('trusted review', pin.reviewed_at)]
    for observation in observations:
        exact(observation, ('signal', 'classification', 'coverage', 'limitations', 'account', 'target', 'browser_session', 'tab_id',
                            'mode', 'observed_at', 'refreshed_at', 'reference', 'source_ids'))
        must(observation['signal'] in ('refreshed_target_state', 'limited_account_repost_state'), 'Unsupported corroboration signal')
        must(observation['classification'] == 'unknown' and observation['coverage'] == 'partial'
             and observation['mode'] == 'read_only', 'Read-only partial evidence must remain explicitly unknown')
        text(observation['limitations'], 'explicit limits on current-state corroboration')
        for key in ('account', 'target'):
            must(observation[key] == incident['binding'][key], 'Observation identity mismatch: ' + key)
        for key in ('browser_session', 'tab_id'):
            must(observation[key] == reconciliation[key], 'Replacement readback identity mismatch: ' + key)
        integer(observation['refreshed_at'], 'refresh time')
        integer(observation['observed_at'], 'observation time')
        must(failed['completed_at'] <= observation['refreshed_at'] <= observation['observed_at'] <= operator['reviewed_at'],
             'Fresh evidence must follow the completed call and precede review')
        must(observation['refreshed_at'] >= incident['binding']['stop']['at'], 'Observation predates recorded unknown STOP')
        text(observation['reference'], 'read-only observation context')
        ids = observation['source_ids']
        must(type(ids) is list and 1 <= len(ids) <= 4 and len(set(ids)) == len(ids), 'Missing/duplicate raw observation sources')
        for name in ids:
            must(name in src and name not in used, 'Observation must have distinct retained raw sources')
            used.add(name)
            observation_hashes.append(digest(src[name]))
        signals.add(observation['signal'])
        references.add(observation['reference'])
        fresh.extend([('reconciliation observation', observation['observed_at']), ('limited read refresh', observation['refreshed_at'])])
    must(len(signals) == len(references) == 2, 'Two distinct limited signal types and contexts required')
    must(set(observation_hashes) == set(pin.reconciliation_source_sha256) and len(set(observation_hashes)) == len(observation_hashes),
         'Unreviewed or repeated corroboration bytes')
    must(used == set(src), 'Unreferenced incident sources are not permitted')
    for field, expected in (('pending_question_reference', pin.pending_question_reference),
                            ('affirmative_answer_reference', pin.affirmative_answer_reference)):
        must(ab[field] == expected, 'Approval is unrelated to independently reviewed pending question/answer')
    for field, expected in (('question_source', pin.pending_question_sha256), ('answer_source', pin.affirmative_answer_sha256),
                            ('context_source', pin.approval_context_sha256)):
        must(ab[field] in aps and digest(aps[ab[field]]) == expected, 'Authentic approval source/context pin mismatch')
    must(len({ab['question_source'], ab['answer_source'], ab['context_source']}) == 3 and len(aps) == 3,
         'Retain separate exact uncertainty question, affirmative answer and surrounding context')
    must(ab['decision'] == DECISION and ab['accepted_external_outcome'] == 'unknown'
         and ab['quarantine_scope'] == QUARANTINE_SCOPE and ab['resume_scope'] == RESUME_SCOPE
         and type(ab['new_verified_count']) is int and ab['new_verified_count'] == 0
         and ab['retry_authorized'] is False and ab['new_social_dispatch_authorized'] is False,
         'Specific acceptance of unknown outcome, whole-post quarantine, and checkpoint-bound other-post resumption required')
    for field in ('question_at', 'answer_at', 'reviewed_at'):
        integer(ab[field], field)
    must(failed['completed_at'] <= ab['question_at'] <= ab['answer_at'] <= ab['reviewed_at'] == pin.reviewed_at
         and operator['reviewed_at'] <= pin.reviewed_at, 'Approval chronology or independent review time mismatch')
    return ib_raw, ab_raw, fresh


def eligible_history(ledger, row, owner, failed):
    events = list(ledger.db.execute('SELECT * FROM audit WHERE action_id=? ORDER BY seq', (row['id'],)))
    must([e['event'] for e in events] == ['action_reserved', 'single_write_intent_committed', 'unknown'],
         'Require one original intent and one UI-failure unknown history; no submitted/present/later attempt')
    must(all(e['owner'] == owner and e['account'] == ledger.account for e in events), 'Action audit owner/account mismatch')
    intent = parse_json(events[1]['details'])
    must(intent.get('intent_id') == row['intent_id'] and events[1]['at'] == row['intent_at'], 'Original intent audit changed')
    must(events[0]['at'] <= events[1]['at'] <= failed['request_started_at'] <= failed['completed_at'] <= events[2]['at'],
         'Action history contradicts completed legacy UI uncertainty chronology')
    must(not ledger.db.execute('SELECT 1 FROM observations WHERE action_id=?', (row['id'],)).fetchone()
         and not ledger.db.execute('SELECT 1 FROM receipts WHERE action_id=?', (row['id'],)).fetchone(),
         'Previously observed/present action cannot use this zero-verified legacy closure')
    preflight = intent.get('preflight_hash')
    must(preflight == row['proof_hash'], 'Prior preflight proof must be preserved, not replaced before review')
    for h in (preflight,):
        hash_value(h, 'original preflight')
        saved = ledger.db.execute('SELECT bytes FROM blobs WHERE hash=?', (h,)).fetchone()
        must(saved and digest(bytes(saved[0])) == h, 'Original preflight missing/corrupt')
        obj = parse_json(bytes(saved[0]))
        must(obj.get('outcome') == 'absent', 'Original preflight does not establish absent before intent')
        proof = ledger.db.execute('SELECT bytes FROM blobs WHERE hash=?', (obj.get('proof_sha256'),)).fetchone()
        must(proof and digest(bytes(proof[0])) == obj.get('proof_sha256'), 'Original preflight raw proof missing/corrupt')
    run_events = list(ledger.db.execute('SELECT event,details FROM audit WHERE owner=? OR action_id IN '
                                       '(SELECT id FROM actions WHERE session=?)', (owner, row['session'])))
    verified = sum(e['event'] == 'browser_readback_attested' and parse_json(e['details']).get('state') == 'verified' for e in run_events)
    must(verified == 0 and not ledger.db.execute("SELECT 1 FROM actions WHERE session=? AND state='verified'", (row['session'],)).fetchone(),
         'Run has newly verified actions; cannot report zero-count legacy UI uncertainty closure')
    return verified


def finalize_uncertain_quarantine(ledger, owner, token, action, incident_path, incident_sha256,
                                     approval_path, approval_sha256, *, trusted_review):
    """Atomically close one legacy attempt as UNKNOWN and permanently quarantine its post.

    No source authentication, browser invocation, submission, retry, writer
    acquisition, or checkpoint acknowledgement is performed by this function.
    """
    must(type(trusted_review) is TrustedReviewPin, 'Independent trusted operator review pin required')
    pin_data = {f.name: getattr(trusted_review, f.name) for f in fields(TrustedReviewPin)}
    pin = TrustedReviewPin.from_dict(pin_data)
    iraw, ih = file_bytes(incident_path, incident_sha256)
    araw, ah = file_bytes(approval_path, approval_sha256)
    incident, approval = parse_json(iraw), parse_json(araw)
    ibraw, abraw, fresh = validate_bundles(incident, approval, ih, ah, pin)
    guard = TimeGuard(ledger, fresh)
    ledger.ensure_storage()
    ledger.db.execute('BEGIN IMMEDIATE')
    try:
        guard.check()  # Revalidate after possible lock wait.
        ledger.active()
        quarantine_records(ledger.db, ledger.account)
        writer = ledger.writer(owner, token)
        row = ledger.row(action)
        run = ledger.db.execute('SELECT * FROM runs WHERE owner=?', (owner,)).fetchone()
        stop = ledger.db.execute('SELECT * FROM stops WHERE account=?', (ledger.account,)).fetchone()
        must(row['state'] == 'unknown' and row['session'] == writer['session'] and row['intent_id'],
             'Only the current writer exact unknown intent may be reconciled')
        must(run and run['state'] == 'active' and run['session'] == writer['session'] and run['role'] == writer['role'],
             'Matching active run required')
        must(stop is not None and ledger.db.execute('SELECT COUNT(*) FROM stops').fetchone()[0] == 1,
             'Exactly the incident STOP must be retained before closure')
        check_binding(incident['binding'], ledger, owner, action, row, writer, run, stop)
        failed = incident['bundle']['failed_call']
        count = eligible_history(ledger, row, owner, failed)
        must(not ledger.db.execute("SELECT 1 FROM actions WHERE id!=? AND state IN ('reserved','intent','submitted_unverified','unknown')", (action,)).fetchone(),
             'Other pending/reserved actions prevent closing this run')
        must(not ledger.db.execute("SELECT 1 FROM runs WHERE owner!=? AND state!='released'", (owner,)).fetchone(), 'Other unreleased run exists')
        retained_pin = canonical({'schema': 'retained-independent-uncertain-quarantine-review-pin-v1',
                                  'source_sha256': ah, 'pin': pin_data}).encode()
        for data in (iraw, ibraw, araw, abraw, retained_pin):
            ledger.blob(data)
        now = guard.check()
        ledger.event('target_quarantined_unresolved', owner, action, proof_hash=ih,
                     target_key=row['target_key'], target_url=row['target_url'],
                     quarantine_scope=QUARANTINE_SCOPE, resume_scope=RESUME_SCOPE, **DISPOSITION)
        changed = ledger.db.execute("UPDATE actions SET state='cancelled',updated_at=?,proof_hash=? WHERE id=? AND state='unknown'", (now, ih, action))
        must(changed.rowcount == 1, 'Exact unknown action changed')
        ledger.event(SUBTYPE, owner, action, proof_hash=ih,
                     intent_id=row['intent_id'], preflight_hash=row['proof_hash'],
                     reviewer=pin.reviewer, review_context_reference=pin.review_context_reference,
                     **DISPOSITION)
        ledger.event('uncertain_quarantine_explicitly_approved', owner, action, proof_hash=digest(retained_pin),
                     pending_question_reference=pin.pending_question_reference,
                     affirmative_answer_reference=pin.affirmative_answer_reference,
                     new_social_dispatch_authorized=False, **DISPOSITION)
        must(ledger.db.execute('DELETE FROM stops WHERE account=? AND action_id=? AND at=? AND reason=?',
                               (ledger.account, action, stop['at'], stop['reason'])).rowcount == 1, 'STOP changed during finalization')
        must(ledger.db.execute('DELETE FROM writer WHERE account=? AND owner=? AND session=? AND token_hash=?',
                               (ledger.account, owner, writer['session'], writer['token_hash'])).rowcount == 1, 'Writer changed during finalization')
        must(ledger.db.execute("UPDATE runs SET state='released',ended_at=? WHERE owner=? AND session=? AND state='active'",
                               (now, owner, writer['session'])).rowcount == 1, 'Run changed during finalization')
        seq = incident['binding']['expected_checkpoint_seq'] + 1
        ledger.put('checkpoint_pending', '1')
        ledger.put('checkpoint_seq', str(seq))
        ledger.event('writer_released', owner, session=writer['session'], checkpoint_seq=seq,
                     termination_class=SUBTYPE, newly_verified_actions=count, **DISPOSITION)
        quarantine_records(ledger.db, ledger.account)
        ledger.ensure_storage()
        guard.check()  # Last application callback before COMMIT; detects expiry/rollback during storage/audit.
        ledger.db.execute('COMMIT')
    except BaseException:
        if ledger.db.in_transaction:
            ledger.db.execute('ROLLBACK')
        raise
    return {'action_id': action, 'state': 'cancelled', 'termination_class': SUBTYPE, **DISPOSITION,
            'writer_released': True, 'stop_cleared': True, 'checkpoint_pending': True,
            'checkpoint_seq': seq, 'newly_verified_actions': count, 'new_social_submissions': 0,
            'retry_allowed': False, 'may_dispatch': False}


def _saved_blob(db, sha):
    hash_value(sha, 'immutable evidence')
    row = db.execute('SELECT bytes FROM blobs WHERE hash=?', (sha,)).fetchone()
    must(row is not None, 'Quarantine evidence missing')
    data = bytes(row[0])
    must(digest(data) == sha, 'Quarantine evidence corrupt')
    return data


def _disposition(details):
    for key, value in DISPOSITION.items():
        must(type(details.get(key)) is type(value) and details[key] == value,
             'Quarantine disposition missing or changed: ' + key)


def quarantine_records(db, account):
    """Validate permanent unknown-outcome exclusions from immutable audit + blobs.

    Validation deliberately does not expire old evidence. Freshness was checked
    atomically at closure. Restores need no original path and cannot drop the
    exclusion merely because a source file or mutable row metadata is absent.
    This validates retained review integrity, not retrospective authentication.
    """
    meta = dict(db.execute('SELECT key,value FROM meta'))
    must(meta.get('account') == account, 'Quarantine database account mismatch')
    actions = {r['id']: dict(r) for r in db.execute('SELECT * FROM actions')}
    events = [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY seq')]
    quarantine_names = {'target_quarantined_unresolved', SUBTYPE, 'uncertain_quarantine_explicitly_approved'}
    marked = {e['action_id'] for e in events if e['event'] in quarantine_names}
    # Cancelled is a workflow state only. A committed intent must retain its
    # explicit terminal subtype; a missing quarantine must not become ordinary
    # cancellation. The separately reviewed legacy denial subtype remains valid.
    for row in actions.values():
        if row['state'] == 'cancelled' and row['intent_id'] and row['id'] not in marked:
            denied = [e for e in events if e['action_id'] == row['id'] and e['event'] == 'denied_before_dispatch_recorded']
            must(len(denied) == 1, 'Cancelled committed intent lacks mandatory uncertainty/denial subtype')
            d = parse_json(denied[0]['details'])
            must(d.get('resolution') == 'not_executed' and d.get('proof_hash') == row['proof_hash'],
                 'Cancelled committed intent has invalid denial subtype')
            proof = parse_json(_saved_blob(db, row['proof_hash']))
            must(proof.get('schema') == 'operator-attested-tool-denial-v1', 'Unknown cancellation proof cannot bypass quarantine')
    records = []
    for action in sorted(marked):
        must(action in actions, 'Quarantined action row missing')
        row = actions[action]
        must(row['account'] == account and row['kind'] == 'repost' and row['state'] == 'cancelled'
             and row['intent_id'] and row['session'], 'Quarantined action state/identity changed')
        key = target_key(row['kind'], row['target_url'])
        must(row['target_key'] == key and action_key(account, row['kind'], row['target_url']) == action,
             'Quarantined canonical target changed')
        ae = [e for e in events if e['action_id'] == action]
        expected = ['action_reserved', 'single_write_intent_committed', 'unknown',
                    'target_quarantined_unresolved', SUBTYPE, 'uncertain_quarantine_explicitly_approved']
        must([e['event'] for e in ae] == expected, 'Quarantine original history/subtype missing, duplicated, or changed')
        ds = [parse_json(e['details']) for e in ae]
        qd, cd, ad = ds[3:]
        exact(qd, ('proof_hash', 'target_key', 'target_url', 'quarantine_scope', 'resume_scope', *DISPOSITION))
        exact(cd, ('proof_hash', 'intent_id', 'preflight_hash', 'reviewer', 'review_context_reference', *DISPOSITION))
        exact(ad, ('proof_hash', 'pending_question_reference', 'affirmative_answer_reference',
                   'new_social_dispatch_authorized', *DISPOSITION))
        for d in (qd, cd, ad):
            _disposition(d)
        must(qd['target_key'] == key and qd['target_url'] == row['target_url']
             and qd['quarantine_scope'] == QUARANTINE_SCOPE and qd['resume_scope'] == RESUME_SCOPE,
             'Immutable whole-post quarantine scope changed')
        must(qd['proof_hash'] == cd['proof_hash'] == row['proof_hash'], 'Quarantine proof binding changed')
        retained = parse_json(_saved_blob(db, ad['proof_hash']))
        exact(retained, ('schema', 'source_sha256', 'pin'))
        must(retained['schema'] == 'retained-independent-uncertain-quarantine-review-pin-v1', 'Retained independent review missing')
        pin = TrustedReviewPin.from_dict(retained['pin'])
        must(retained['source_sha256'] == pin.approval_sha256 and pin.incident_sha256 == row['proof_hash'],
             'Retained independent review graph changed')
        iraw = _saved_blob(db, row['proof_hash'])
        araw = _saved_blob(db, pin.approval_sha256)
        incident, approval = parse_json(iraw), parse_json(araw)
        ibraw, abraw, _ = validate_bundles(incident, approval, digest(iraw), digest(araw), pin)
        must(_saved_blob(db, incident['source_sha256']) == ibraw
             and _saved_blob(db, approval['proof_sha256']) == abraw, 'Retained bundle closure differs')
        b = incident['binding']
        must(b['account'] == account and b['db_id'] == meta.get('db_id') and b['action_id'] == action
             and b['kind'] == row['kind'] and b['target'] == row['target_url']
             and b['payload_hash'] == row['payload_hash'] and b['intent_id'] == row['intent_id']
             and b['intent_at'] == row['intent_at'] and b['session'] == row['session'],
             'Quarantine row/original incident binding mismatch')
        must(all(e['owner'] == b['owner'] and e['account'] == account for e in ae),
             'Quarantine original audit owner/account changed')
        exact(b['stop'], ('account', 'action_id', 'reason', 'at'))
        must(b['stop'] == {'account': account, 'action_id': action, 'reason': ds[2].get('reason'), 'at': ae[2]['at']},
             'Retained original unknown STOP changed')
        must(ds[0].get('target') == key and ds[0].get('kind') == row['kind']
             and ds[0].get('payload_hash') == row['payload_hash'] and ae[0]['at'] == row['created_at'],
             'Original reservation changed')
        must(ds[1].get('intent_id') == row['intent_id'] == cd['intent_id'] and ae[1]['at'] == row['intent_at']
             and ds[1].get('preflight_hash') == cd['preflight_hash'], 'Original intent/preflight changed')
        preflight = parse_json(_saved_blob(db, cd['preflight_hash']))
        must(preflight.get('schema') == 'browser-action-evidence-v2' and preflight.get('outcome') == 'absent'
             and preflight.get('account') == account and preflight.get('kind') == row['kind']
             and action_key(account, row['kind'], preflight.get('target')) == action
             and preflight.get('payload_hash') == row['payload_hash'] and preflight.get('intent_id') is None,
             'Original pre-intent evidence changed')
        _saved_blob(db, preflight.get('proof_sha256'))
        must(cd['reviewer'] == pin.reviewer and cd['review_context_reference'] == pin.review_context_reference
             and ad['pending_question_reference'] == pin.pending_question_reference
             and ad['affirmative_answer_reference'] == pin.affirmative_answer_reference
             and ad['new_social_dispatch_authorized'] is False, 'Review/approval audit binding changed')
        failed = incident['bundle']['failed_call']
        must(ae[0]['at'] <= ae[1]['at'] <= failed['request_started_at'] <= failed['completed_at'] <= ae[2]['at']
             <= pin.reviewed_at <= ae[3]['at'] <= ae[4]['at'] <= ae[5]['at'], 'Retained closure chronology changed')
        must(not db.execute('SELECT 1 FROM observations WHERE action_id=?', (action,)).fetchone()
             and not db.execute('SELECT 1 FROM receipts WHERE action_id=?', (action,)).fetchone(),
             'Uncertain quarantine must never mint an observation or receipt')
        run = db.execute('SELECT * FROM runs WHERE owner=?', (b['owner'],)).fetchone()
        must(run and run['state'] == 'released' and run['session'] == b['session']
             and run['started_at'] == b['run_started_at'] and run['ended_at'] == row['updated_at'],
             'Quarantine run closure changed')
        released = [e for e in events if e['event'] == 'writer_released' and e['owner'] == b['owner']]
        must(len(released) == 1 and released[0]['account'] == account and released[0]['seq'] > ae[-1]['seq'],
             'Exact quarantine writer release missing/duplicated')
        rd = parse_json(released[0]['details'])
        exact(rd, ('session', 'checkpoint_seq', 'termination_class', 'newly_verified_actions', *DISPOSITION))
        _disposition(rd)
        must(rd['session'] == b['session'] and rd['termination_class'] == SUBTYPE
             and type(rd['newly_verified_actions']) is int and rd['newly_verified_actions'] == 0
             and type(rd['checkpoint_seq']) is int and rd['checkpoint_seq'] == b['expected_checkpoint_seq'] + 1
             and rd['checkpoint_seq'] <= int(meta['checkpoint_seq']), 'Quarantine checkpoint/release binding changed')
        run_actions = {r['id'] for r in actions.values() if r['session'] == b['session']}
        must(not any(r['state'] == 'verified' for r in actions.values() if r['session'] == b['session'])
             and not any(e['event'] == 'browser_readback_attested' and parse_json(e['details']).get('state') == 'verified'
                         for e in events if e['owner'] == b['owner'] or e['action_id'] in run_actions),
             'Quarantine run cannot acquire a newly verified count retrospectively')
        records.append({'action_id': action, 'target_key': key, 'target_url': row['target_url'],
                        'proof_hash': row['proof_hash'], 'subtype': SUBTYPE, **DISPOSITION})
    return records


def ensure_not_quarantined(ledger, kind, target):
    """Hard gate before reservation or intent; profile follows remain out of scope.

    Preparation must also exclude the whole candidate, including a derived
    conditional follow. This low-level gate cannot infer a follow's provenance.
    """
    records = quarantine_records(ledger.db, ledger.account)
    key = target_key(kind, target)
    if kind in POST_KINDS:
        must(all(record['target_key'] != key for record in records),
             'Permanent uncertain-target quarantine blocks every automated post write; no retry')
