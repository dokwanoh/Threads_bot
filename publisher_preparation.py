"""Bounded cooperative publisher draft permits. No browser or social dispatch.

Audit + immutable blobs are authoritative; original filesystem paths are never
needed to validate a restored preparation. Authentic browser/operator sources
must be supplied by the caller: hashes provide integrity, not authentication.
"""
import json
import secrets
from types import SimpleNamespace
from ledger import (HASH, action_key, target_key, canonical, digest, exact,
                    file_bytes, must, text, owned_receipts)
from quarantine_extension import parse_json, source_bytes

PREFIX = 'publisher_preparation_'
FRESH_SECONDS = 300
STEP_IDS = ('open_root_fill', 'upload_original_image', 'add_fill_reply_1',
            'add_fill_reply_2', 'add_fill_reply_3')
BINDING_FIELDS = ('account', 'db_id', 'action_id', 'owner', 'session',
                  'run_started_at', 'kind', 'target', 'payload_hash',
                  'browser_session', 'tab_id')


def _event_at(l, suffix, owner, action, proof_hash, at):
    """Use the same captured operation time for its immutable record and audit."""
    l.db.execute('INSERT INTO audit(at,account,owner,event,action_id,details) VALUES(?,?,?,?,?,?)',
                 (at, l.account, owner, PREFIX + suffix, action, canonical({'proof_hash': proof_hash})))


def _integer(value, name):
    must(type(value) is int and value >= 0, 'Invalid ' + name)


def _hash(value, name):
    must(type(value) is str and HASH.fullmatch(value), 'Invalid ' + name + ' hash')


def _blob(db, h, hashes):
    _hash(h, 'retained evidence')
    row = db.execute('SELECT bytes FROM blobs WHERE hash=?', (h,)).fetchone()
    must(row is not None, 'Missing publisher preparation evidence')
    data = bytes(row[0])
    must(digest(data) == h, 'Corrupt publisher preparation evidence')
    hashes.add(h)
    return data


def _json_blob(db, h, hashes):
    return parse_json(_blob(db, h, hashes))


def _payload(data, binding):
    p = parse_json(data)
    exact(p, ('account', 'kind', 'target', 'parts', 'image', 'preview'))
    must(data == canonical(p).encode(), 'Exact canonical UTF-8 payload bytes required')
    must(digest(data) == binding['payload_hash'], 'Canonical payload hash mismatch')
    for key in ('account', 'kind', 'target'):
        must(p[key] == binding[key], 'Payload binding mismatch: ' + key)
    must(p['kind'] == 'publish', 'Publisher preparation only')
    target_key('publish', p['target'])
    must(type(p['parts']) is list and len(p['parts']) == 4, 'Exactly four texts required')
    for part in p['parts']:
        text(part, 'exact publisher text', maximum=2000)
    exact(p['image'], ('path', 'sha256', 'attach_part_index'))
    text(p['image']['path'], 'original image provenance path', maximum=4000)
    _hash(p['image']['sha256'], 'original image')
    must(type(p['image']['attach_part_index']) is int and p['image']['attach_part_index'] == 0,
         'Original image must attach to root')
    exact(p['preview'], ('part_index', 'url', 'required'))
    must(type(p['preview']['part_index']) is int and p['preview']['part_index'] == 1
         and p['preview']['url'] == p['target'] and p['preview']['required'] is True,
         'First reply must retain exact numeric URL preview')
    must(p['target'] in p['parts'][1], 'First reply must contain exact numeric article URL')
    return p


def _steps(p):
    return [
        {'id': STEP_IDS[0], 'operation': 'open_composer_and_fill_root',
         'part_index': 0, 'text': p['parts'][0]},
        {'id': STEP_IDS[1], 'operation': 'choose_original_file_once',
         'part_index': 0, 'image_sha256': p['image']['sha256']},
        *[{'id': STEP_IDS[i + 1], 'operation': 'add_one_reply_and_fill',
           'part_index': i, 'text': p['parts'][i]} for i in range(1, 4)]]


def _binding(db, binding, row):
    exact(binding, BINDING_FIELDS)
    meta = dict(db.execute('SELECT key,value FROM meta'))
    run = db.execute('SELECT * FROM runs WHERE owner=?', (binding['owner'],)).fetchone()
    must(run is not None and run['role'] == 'publisher', 'Bound publisher run missing')
    expected = {'account': meta['account'], 'db_id': meta['db_id'],
                'action_id': row['id'], 'session': row['session'], 'kind': row['kind'],
                'target': row['target_url'], 'payload_hash': row['payload_hash'],
                'run_started_at': run['started_at']}
    must(row['kind'] == 'publish', 'Preparation is bound to a publish action')
    must(run['session'] == row['session'], 'Publisher run/action session mismatch')
    for key, value in expected.items():
        must(binding[key] == value, 'Publisher preparation binding mismatch: ' + key)
    for key in ('owner', 'session', 'browser_session', 'tab_id'):
        text(binding[key], key)
    _integer(binding['run_started_at'], 'run start')
    must(action_key(meta['account'], 'publish', binding['target']) == row['id']
         and target_key('publish', binding['target']) == row['target_key'],
         'Original publish key changed')


def _source_graph(db, record, hashes, persist=None):
    # Embedding the bounded raw sources closes the proof graph even when the
    # original DOM/screenshot/request files are no longer available.
    sources = source_bytes(record['sources'])
    for name, data in sources.items():
        h = digest(data)
        if persist is not None:
            persist.blob(data)
        else:
            must(_blob(db, h, hashes) == data, 'Embedded and retained source mismatch')
        hashes.add(h)
    return sources


def _source_name(name, sources, used, label):
    must(type(name) is str and name in sources and name not in used,
         'Distinct retained ' + label + ' source required')
    used.add(name)


def _readback(read, p, count, media, sources, used, earliest, final):
    fields = ('mode', 'observed_at', 'reference', 'parts', 'original_image_sha256',
              'image_present', 'first_reply_preview', 'dom_source')
    if final:
        fields += ('screenshot_source', 'visual_review_source', 'visual_inspected_at',
                   'visual_matches_exact_payload')
    exact(read, fields)
    must(read['mode'] == 'read_only', 'Only read-only browser inspection may attest preparation')
    _integer(read['observed_at'], 'read-only observation time')
    must(read['observed_at'] >= earliest, 'Readback predates completed preparation call')
    text(read['reference'], 'actual read-only observation reference')
    must(read['parts'] == p['parts'][:count], 'Readback texts differ from exact prepared parts')
    must(read['image_present'] is media and read['original_image_sha256'] ==
         (p['image']['sha256'] if media else None), 'Original image readback mismatch')
    preview = {'part_index': 1, 'url': p['target'], 'visible': True}
    must(canonical(read['first_reply_preview']) == canonical(preview if count >= 2 else None),
         'Exact first-reply numeric URL preview must be visible')
    _source_name(read['dom_source'], sources, used, 'DOM')
    if final:
        _source_name(read['screenshot_source'], sources, used, 'screenshot')
        _source_name(read['visual_review_source'], sources, used, 'visual inspection')
        _integer(read['visual_inspected_at'], 'visual inspection time')
        must(read['visual_inspected_at'] >= read['observed_at']
             and read['visual_matches_exact_payload'] is True,
             'Fresh explicit visual match of texts, image and preview required')
        # Media-type/actual-image validation happens against the source manifest
        # below; no OCR or synthetic visual-verification claim is made here.
    return max(read['observed_at'], read.get('visual_inspected_at', 0))


def _validate_record(db, event, manifest, payload, state, hashes, persist=None):
    details = parse_json(event['details'])
    exact(details, ('proof_hash',))
    record = _json_blob(db, details['proof_hash'], hashes)
    typ = event['event'][len(PREFIX):]
    must(record.get('binding') == manifest['binding']
         and record.get('manifest_sha256') == state['manifest_sha256'],
         'Step/seal exact manifest binding mismatch')
    must(event['owner'] == manifest['binding']['owner']
         and event['account'] == manifest['binding']['account'], 'Preparation audit identity mismatch')
    must(event['at'] >= state['last_at'], 'Preparation audit clock rollback')
    if typ == 'step_permit':
        exact(record, ('schema', 'binding', 'manifest_sha256', 'step_id', 'nonce',
                       'issued_at', 'expires_at', 'operation', 'browser_invocations', 'final_submission'))
        must(record['schema'] == 'publisher-draft-step-permit-v1', 'Wrong step permit schema')
        index = state['completed_steps']
        must(state['pending'] is None and not state['sealed'] and not state['stopped']
             and index < len(STEP_IDS), 'Step replay, overlap or post-terminal preparation')
        must(record['step_id'] == STEP_IDS[index] and canonical(record['operation']) == canonical(manifest['steps'][index]),
             'Only the next fixed bounded preparation operation is permitted')
        _hash(record['nonce'], 'step nonce')
        must(record['nonce'] not in state['nonces'], 'Step nonce reused')
        _integer(record['issued_at'], 'permit issue time')
        must(record['expires_at'] == record['issued_at'] + FRESH_SECONDS
             and record['issued_at'] <= event['at'] < record['expires_at'],
             'Permit event time/deadline mismatch')
        must(type(record['browser_invocations']) is int and record['browser_invocations'] == 1
             and record['final_submission'] is False, 'Preparation cannot submit or batch browser calls')
        state['pending'] = record
        state['pending_at'] = event['at']
        state['nonces'].add(record['nonce'])
    elif typ == 'step_completed':
        exact(record, ('schema', 'binding', 'manifest_sha256', 'step_id', 'nonce',
                       'operation', 'call', 'readback', 'sources', 'social_success'))
        must(record['schema'] == 'publisher-draft-step-completion-v1', 'Wrong completion schema')
        pending = state['pending']
        must(pending is not None and not state['stopped'], 'No matching outstanding draft step')
        for key in ('nonce', 'step_id', 'operation'):
            must(canonical(record[key]) == canonical(pending[key]), 'Completion does not match fresh step permit: ' + key)
        call = record['call']
        exact(call, ('reference', 'tool_name', 'started_at', 'completed_at', 'outcome',
                     'browser_invocations', 'final_submission', 'request_source', 'result_source',
                     'operator_review_source', 'operator_reviewed_at', 'operation_matches_permit', 'other_mutations',
                     'timestamp_basis', 'timestamp_provenance'))
        text(call['reference'], 'authentic browser call reference')
        must(call['timestamp_basis'] == 'observed_outer_bounds',
             'Honest observed tool-call time bounds required')
        text(call['timestamp_provenance'], 'call timestamp boundary provenance')
        must(call['reference'] not in state['call_references'], 'Browser call reference reused')
        must(call['tool_name'] == 'mcp__cua_repl__js' and call['outcome'] == 'completed'
             and type(call['browser_invocations']) is int and call['browser_invocations'] == 1
             and call['final_submission'] == 'not_invoked' and call['operation_matches_permit'] is True
             and call['other_mutations'] == 'none' and record['social_success'] is False,
             'Only one reviewed non-submitting draft call may complete')
        for key in ('started_at', 'completed_at', 'operator_reviewed_at'):
            _integer(call[key], key)
        must(state['pending_at'] <= call['started_at'] <= call['completed_at']
             <= call['operator_reviewed_at'] <= event['at']
             and call['completed_at'] < pending['expires_at'],
             'Draft call chronology mismatch or permit expired')
        sources, used = _source_graph(db, record, hashes, persist), set()
        for key in ('request_source', 'result_source', 'operator_review_source'):
            _source_name(call[key], sources, used, key)
        index = state['completed_steps']
        observed = _readback(record['readback'], payload, max(1, index), index >= 1,
                             sources, used, call['completed_at'], False)
        must(observed <= call['operator_reviewed_at'], 'Review predates read-only inspection')
        must(used == set(sources), 'Unreferenced preparation source')
        state['completed_steps'] += 1
        state['pending'] = None
        state['pending_at'] = None
        state['last_read_at'] = observed
        state['call_references'].add(call['reference'])
    elif typ == 'sealed':
        exact(record, ('schema', 'binding', 'manifest_sha256', 'readback', 'sources',
                       'final_submission', 'social_success'))
        must(record['schema'] == 'publisher-draft-final-inspection-v1', 'Wrong final inspection schema')
        must(state['completed_steps'] == len(STEP_IDS) and state['pending'] is None
             and not state['sealed'] and not state['stopped'], 'All five completed draft steps required exactly once')
        must(record['final_submission'] == 'not_invoked' and record['social_success'] is False,
             'Preparation seal cannot assert publication or social success')
        sources, used = _source_graph(db, record, hashes, persist), set()
        observed = _readback(record['readback'], payload, 4, True, sources, used,
                             state['last_at'], True)
        must(observed <= event['at'] and used == set(sources), 'Final inspection chronology/source mismatch')
        screenshot = record['sources'][record['readback']['screenshot_source']]
        must(screenshot['media_type'] in ('image/png', 'image/jpeg'), 'Actual screenshot image source required')
        screenshot_bytes = sources[record['readback']['screenshot_source']]
        must(screenshot_bytes.startswith(b'\x89PNG\r\n\x1a\n') or screenshot_bytes.startswith(b'\xff\xd8\xff'),
             'Screenshot source must contain image bytes')
        state['sealed'] = True
        state['seal_sha256'] = details['proof_hash']
        state['sealed_at'] = event['at']
        state['seal_seq'] = event['seq']
        state['last_read_at'] = record['readback']['observed_at']
    elif typ == 'step_unknown':
        exact(record, ('schema', 'binding', 'manifest_sha256', 'step_id', 'nonce', 'reason',
                       'at', 'external_outcome', 'retry_allowed', 'social_success'))
        must(record['schema'] == 'publisher-draft-step-unknown-v1', 'Wrong unknown step schema')
        must(state['pending'] is not None and not state['stopped'], 'No outstanding draft step to stop')
        must(record['nonce'] == state['pending']['nonce'] and record['step_id'] == state['pending']['step_id'],
             'Unknown STOP must bind the exact pending draft step')
        text(record['reason'], 'unknown draft outcome reason')
        must(record['at'] == event['at'] and record['external_outcome'] == 'unknown'
             and record['retry_allowed'] is False and record['social_success'] is False,
             'Unknown draft step must remain non-retryable without success')
        state['pending'] = None
        state['pending_at'] = None
        state['stopped'] = True
        state['unknown_nonce'] = record['nonce']
    else:
        must(False, 'Unknown publisher preparation audit event')
    state['last_at'] = event['at']


def _validate_denied_terminal(db, row, state, hashes):
    """Replay existing pre-execution denial semantics from retained bytes only."""
    from denial_extension import bind, eligible_history
    meta = dict(db.execute('SELECT key,value FROM meta'))
    context = SimpleNamespace(db=db, account=meta['account'], get=lambda key: meta[key])
    owner = state['binding']['owner']
    events = list(db.execute('SELECT * FROM audit WHERE action_id=? ORDER BY seq', (row['id'],)))
    eligible_history(context, row)
    must(not db.execute('SELECT 1 FROM receipts WHERE action_id=?', (row['id'],)).fetchone()
         and not db.execute('SELECT 1 FROM observations WHERE action_id=?', (row['id'],)).fetchone(),
         'Prepared denied action cannot have public receipts or observations')
    denied = [event for event in events if event['event'] == 'denied_before_dispatch_recorded']
    must(len(denied) == 1 and row['state'] == 'cancelled' and state['sealed'],
         'Cancelled prepared publish requires one original pre-execution denial')
    event = denied[0]; details = parse_json(event['details'])
    exact(details, ('proof_hash', 'source_hash', 'resolution', 'provenance', 'tool_call_id', 'retry_allowed'))
    must(event['owner'] == owner and event['account'] == meta['account']
         and details['proof_hash'] == row['proof_hash'] and details['resolution'] == 'not_executed'
         and details['retry_allowed'] is False
         and details['provenance'] == 'operator_attested_original_tool_context',
         'Exact immutable no-execution/no-retry denial metadata required')
    denial = _json_blob(db, details['proof_hash'], hashes)
    exact(denial, ('schema', 'account', 'db_id', 'action_id', 'kind', 'target', 'payload_hash',
                  'intent_id', 'intent_at', 'owner', 'source_file', 'source_sha256', 'attested_at', 'provenance'))
    must(denial['schema'] == 'operator-attested-tool-denial-v1'
         and denial['provenance'] == details['provenance']
         and denial['source_sha256'] == details['source_hash'], 'Wrong retained denial proof binding')
    source = _json_blob(db, details['source_hash'], hashes)
    exact(source, ('schema', 'account', 'db_id', 'action_id', 'kind', 'target', 'payload_hash',
                  'intent_id', 'intent_at', 'owner', 'tool_name', 'request_text', 'result_text',
                  'result_is_error', 'denied_at', 'tool_call_id', 'missing_call_id_reason',
                  'original_context_reference', 'execution_stage', 'submission_not_sent',
                  'no_subsequent_browser_call', 'request_sha256', 'result_sha256'))
    must(source['schema'] == 'retained-preexecution-denial-context-v1', 'Wrong retained denial context schema')
    bind(context, denial, row, owner); bind(context, source, row, owner)
    must(denial['target'] == source['target'] == row['target_url'], 'Denial exact target changed')
    for key in ('tool_name', 'request_text', 'result_text', 'original_context_reference'):
        text(source[key], key, maximum=100000)
    call_id = source['tool_call_id']
    must(call_id is None or type(call_id) is str and bool(call_id), 'Invalid original denial tool-call ID')
    if call_id is None:
        text(source['missing_call_id_reason'], 'honest missing original denial call ID reason')
    must(call_id == details['tool_call_id']
         and digest(source['request_text']) == source['request_sha256']
         and digest(source['result_text']) == source['result_sha256'], 'Original denied request/result changed')
    must(source['result_is_error'] is True and source['execution_stage'] == 'before_tool_execution'
         and source['submission_not_sent'] is True and source['no_subsequent_browser_call'] is True,
         'Only conclusively rejected-before-tool-execution final Publish is cancelled')
    must('This action was rejected due to unacceptable risk.' in source['result_text']
         and 'Do not bypass this rejection' in source['result_text'],
         'Original explicit authorization rejection required')
    for key in ('denied_at',): _integer(source[key], key)
    _integer(denial['attested_at'], 'denial attestation time')
    intents = [e for e in events if e['event'] == 'single_write_intent_committed']
    must(len(intents) == 1 and intents[0]['owner'] == owner and intents[0]['account'] == meta['account']
         and state['seal_seq'] < intents[0]['seq'] < event['seq']
         and intents[0]['at'] == row['intent_at']
         and state['sealed_at'] <= row['intent_at'] <= source['denied_at']
         <= denial['attested_at'] <= event['at'], 'Denial must follow the separate final publish intent after seal')
    approved = [e for e in events if e['event'] == 'denial_reconciliation_explicitly_approved']
    run = db.execute('SELECT * FROM runs WHERE owner=?', (owner,)).fetchone()
    if not approved:
        stop = db.execute('SELECT * FROM stops WHERE account=?', (meta['account'],)).fetchone()
        writer = db.execute('SELECT * FROM writer WHERE account=?', (meta['account'],)).fetchone()
        must(stop is not None and stop['action_id'] == row['id'] and run['state'] == 'active'
             and writer is not None and writer['owner'] == owner and writer['session'] == row['session'],
             'Denied action must retain exact STOP and writer until explicit finalization')
    else:
        must(len(approved) == 1, 'Duplicate denial finalization')
        final = approved[0]; fd = parse_json(final['details'])
        exact(fd, ('proof_hash', 'approval_reference', 'retry_allowed'))
        must(final['owner'] == owner and final['account'] == meta['account']
             and final['seq'] > event['seq'] and fd['retry_allowed'] is False,
             'Wrong denial finalization audit identity/order')
        approval = _json_blob(db, fd['proof_hash'], hashes)
        exact(approval, ('schema', 'account', 'db_id', 'action_id', 'intent_id', 'intent_at', 'owner',
                         'source_sha256', 'proof_file', 'proof_sha256', 'approval_reference', 'decision',
                         'follow_retry_authorized', 'other_new_dispatch_authorized', 'reviewed_at'))
        must(approval['schema'] == 'operator-approved-denial-finalization-v1'
             and approval['source_sha256'] == row['proof_hash']
             and approval['approval_reference'] == fd['approval_reference']
             and approval['decision'] == 'record_no_execution_release_run_and_require_checkpoint'
             and approval['follow_retry_authorized'] is False
             and approval['other_new_dispatch_authorized'] is False, 'Wrong exact denial finalization approval')
        for key, expected in (('account', meta['account']), ('db_id', meta['db_id']),
                              ('action_id', row['id']), ('intent_id', row['intent_id']),
                              ('intent_at', row['intent_at']), ('owner', owner)):
            must(approval[key] == expected, 'Denial finalization binding mismatch: ' + key)
        text(approval['approval_reference'], 'authentic denial approval reference')
        must(_blob(db, approval['proof_sha256'], hashes), 'Original exact finalization approval missing')
        _integer(approval['reviewed_at'], 'approval review time')
        released = list(db.execute(
            "SELECT * FROM audit WHERE owner=? AND event='writer_released' ORDER BY seq", (owner,)))
        must(len(released) == 1 and released[0]['account'] == meta['account']
             and released[0]['action_id'] is None and released[0]['seq'] > final['seq'],
             'Exact denial writer-release audit required')
        release = released[0]; release_details = parse_json(release['details'])
        exact(release_details, ('session', 'checkpoint_seq', 'termination_class'))
        _integer(release_details['checkpoint_seq'], 'denial release checkpoint sequence')
        must(release_details['session'] == row['session']
             and release_details['termination_class'] == 'denied_before_dispatch'
             and 1 <= release_details['checkpoint_seq'] <= int(meta['checkpoint_seq']),
             'Denial release session/checkpoint/termination mismatch')
        _integer(run['ended_at'], 'denied run end time')
        must(denial['attested_at'] <= approval['reviewed_at'] <= run['ended_at']
             <= final['at'] <= release['at'] and run['state'] == 'released',
             'Denial release/approval chronology mismatch')
        must(not db.execute('SELECT 1 FROM stops WHERE action_id=?', (row['id'],)).fetchone()
             and not db.execute('SELECT 1 FROM writer WHERE owner=?', (owner,)).fetchone(),
             'Finalized denied publisher must be released')
    state['termination_class'] = 'denied_before_dispatch'
    state['retry_allowed'] = False
    state['new_verified_count'] = 0


def _records(db, account):
    records, hashes = {}, set()
    events = list(db.execute('SELECT * FROM audit WHERE event GLOB ? ORDER BY seq', (PREFIX + '*',)))
    for event in events:
        must(event['account'] == account, 'Cross-account preparation audit event')
        action = event['action_id']
        row = db.execute('SELECT * FROM actions WHERE id=?', (action,)).fetchone()
        must(row is not None, 'Preparation action missing')
        if event['event'] == PREFIX + 'created':
            must(action not in records, 'Preparation cannot be reset or registered twice')
            details = parse_json(event['details']); exact(details, ('proof_hash',))
            mh = details['proof_hash']; manifest = _json_blob(db, mh, hashes)
            exact(manifest, ('schema', 'binding', 'payload_sha256', 'image_sha256', 'steps', 'created_at'))
            must(manifest['schema'] == 'publisher-draft-preparation-v1', 'Wrong preparation manifest schema')
            _binding(db, manifest['binding'], row)
            must(event['owner'] == manifest['binding']['owner']
                 and manifest['created_at'] == event['at']
                 and event['at'] >= manifest['binding']['run_started_at'], 'Preparation creation chronology/owner mismatch')
            payload = _payload(_blob(db, manifest['payload_sha256'], hashes), manifest['binding'])
            must(manifest['payload_sha256'] == manifest['binding']['payload_hash']
                 and manifest['image_sha256'] == payload['image']['sha256'], 'Exact payload/image manifest hash mismatch')
            must(_blob(db, manifest['image_sha256'], hashes), 'Missing original image bytes')
            must(canonical(manifest['steps']) == canonical(_steps(payload)), 'Preparation fixed operation list changed')
            reserved = db.execute("SELECT * FROM audit WHERE action_id=? AND event='action_reserved' ORDER BY seq", (action,)).fetchall()
            must(len(reserved) == 1 and reserved[0]['seq'] < event['seq']
                 and reserved[0]['owner'] == manifest['binding']['owner'], 'Original writer reservation required')
            records[action] = {'manifest': manifest, 'payload': payload,
                'action_id': action, 'manifest_sha256': mh, 'binding': manifest['binding'],
                'completed_steps': 0, 'pending': None, 'pending_at': None, 'sealed': False, 'stopped': False,
                'seal_sha256': None, 'sealed_at': None, 'seal_seq': None, 'last_read_at': None,
                'last_at': event['at'], 'nonces': set(), 'call_references': set()}
        else:
            must(action in records, 'Preparation event without manifest')
            state = records[action]
            _validate_record(db, event, state['manifest'], state['payload'], state, hashes)
    for action, state in records.items():
        row = db.execute('SELECT * FROM actions WHERE id=?', (action,)).fetchone()
        if state['stopped']:
            stop = db.execute('SELECT * FROM stops WHERE account=?', (account,)).fetchone()
            must(row['state'] == 'unknown' and row['intent_id'] is None
                 and stop is not None and stop['action_id'] == action,
                 'Unknown preparation must preserve original action and STOP')
        elif not state['sealed']:
            must(row['state'] == 'reserved' and row['intent_id'] is None,
                 'Unsealed preparation cannot change publish state or create intent')
        else:
            must(row['state'] in ('reserved', 'intent', 'submitted_unverified', 'unknown', 'verified', 'cancelled'),
                 'Sealed preparation cannot be cancelled or relabelled already present')
        if row['state'] != 'reserved' and not state['stopped']:
            intent = db.execute("SELECT * FROM audit WHERE action_id=? AND event='single_write_intent_committed' ORDER BY seq", (action,)).fetchall()
            must(len(intent) == 1 and intent[0]['at'] >= state['sealed_at']
                 and intent[0]['seq'] > state['seal_seq'], 'Only separate final publish intent may change prepared action')
        if row['state'] == 'cancelled' or db.execute(
                "SELECT 1 FROM audit WHERE action_id=? AND event='denied_before_dispatch_recorded'", (action,)).fetchone():
            _validate_denied_terminal(db, row, state, hashes)
    return records, hashes


def preparation_records(db, account):
    records, _ = _records(db, account)
    return [{k: v for k, v in state.items() if k not in
             ('manifest', 'payload', 'nonces', 'call_references')}
            for _, state in sorted(records.items())]


def preparation_evidence_hashes(db, account):
    return sorted(_records(db, account)[1])


def ensure_no_preparation_pending(l):
    records, _ = _records(l.db, l.account)
    must(not any(s['pending'] is not None for s in records.values()),
         'Outstanding publisher draft step blocks all new writes; inspect read-only or explicitly record unknown+STOP')


def ensure_preparation_action(l, action):
    records, _ = _records(l.db, l.account)
    must(not any(a != action and l.row(a)['state'] == 'reserved'
                 for a in records),
         'Unfinished exact publisher preparation blocks unrelated changing actions')


def ensure_preparation_transition(l, action, state):
    ensure_preparation_action(l, action)
    records, _ = _records(l.db, l.account)
    must(not any(s['pending'] is not None for s in records.values()),
         'Outstanding draft step may only use exact step unknown+STOP helper')
    must(state != 'cancelled' or action not in records, 'Preparation cannot be cancelled, reset or retried')


def ensure_preparation_verify(l, action, observation=None):
    ensure_preparation_action(l, action)
    records, _ = _records(l.db, l.account)
    must(not any(s['pending'] is not None for s in records.values()), 'Outstanding draft step blocks verification')
    if action in records:
        must(l.row(action)['state'] != 'reserved' and not records[action]['stopped'],
             'Draft preparation cannot count as already-present/verified or clear unknown draft STOP')
        must(type(observation) is dict and len(owned_receipts(l.account, observation.get('receipt_urls'), True)) == 4,
             'Prepared four-part publish requires exactly four distinct owned post receipts')


def ensure_publish_prepared(l, owner, action):
    row = l.row(action)
    if row['kind'] != 'publish':
        return None
    records, _ = _records(l.db, l.account)
    state = records.get(action)
    must(not any(s['pending'] is not None for s in records.values()),
         'Outstanding draft step blocks final publish')
    must(state is not None and state['sealed'] and not state['stopped']
         and state['pending'] is None, 'Fresh sealed exact publisher draft preparation required')
    must(state['binding']['owner'] == owner and row['state'] == 'reserved', 'Final publish writer/state mismatch')
    checked_at = _fresh(l, state['last_read_at'], state['sealed_at'])
    must(checked_at < state['last_read_at'] + FRESH_SECONDS, 'Final preparation deadline reached')
    return {'checked_at': checked_at, 'binding': state['binding'], 'manifest_sha256': state['manifest_sha256'],
            'seal_sha256': state['seal_sha256'], 'prepared_read_at': state['last_read_at'],
            'expires_at': state['last_read_at'] + FRESH_SECONDS,
            'browser_invocations': 1, 'operation': 'final_publish_only'}


def check_prepared_fresh(l, prepared_binding):
    if prepared_binding is not None:
        now = _fresh(l, prepared_binding['prepared_read_at'])
        must(prepared_binding['expires_at'] == prepared_binding['prepared_read_at'] + FRESH_SECONDS
             and prepared_binding['checked_at'] <= now < prepared_binding['expires_at'],
             'Final publish preparation clock rollback or deadline reached')
        prepared_binding['checked_at'] = now


def _fresh(l, *times):
    now = l.clock(); _integer(now, 'current clock')
    for at in times:
        _integer(at, 'fresh evidence time')
        must(now - FRESH_SECONDS <= at <= now, 'Preparation evidence stale or in future')
    return now


def _writer(l, owner, token, action):
    l.active(); w = l.writer(owner, token); row = l.row(action)
    must(w['role'] == 'publisher' and row['kind'] == 'publish'
         and row['session'] == w['session'] and row['state'] == 'reserved'
         and row['intent_id'] is None, 'Original reserved publish and publisher writer required')
    run = l.db.execute('SELECT * FROM runs WHERE owner=?', (owner,)).fetchone()
    must(run is not None and run['state'] == 'active', 'Active publisher run required')
    return w, row, run


def create_preparation(l, owner, token, action, payload_path, payload_sha256,
                       browser_session, tab_id, image_path=None):
    data, ph = file_bytes(payload_path, payload_sha256)
    with l.tx():
        w, row, run = _writer(l, owner, token, action); l.no_pending()
        states, _ = _records(l.db, l.account)
        must(action not in states, 'Preparation already registered; no reset or replay')
        must(not any(s['binding']['session'] == w['session'] and
                     l.row(s['action_id'])['state'] == 'reserved' for s in states.values()),
             'One unfinished publisher draft per writer')
        binding = {'account': l.account, 'db_id': l.get('db_id'), 'action_id': action,
                   'owner': owner, 'session': w['session'], 'run_started_at': run['started_at'],
                   'kind': 'publish', 'target': row['target_url'], 'payload_hash': row['payload_hash'],
                   'browser_session': browser_session, 'tab_id': tab_id}
        _binding(l.db, binding, row)
        must(ph == row['payload_hash'], 'Reservation must bind exact canonical payload')
        p = _payload(data, binding)
        original, ih = file_bytes(image_path or p['image']['path'], p['image']['sha256'])
        must(original, 'Original media bytes required')
        captured_at = l.clock()
        manifest = {'schema': 'publisher-draft-preparation-v1', 'binding': binding,
                    'payload_sha256': ph, 'image_sha256': ih, 'steps': _steps(p), 'created_at': captured_at}
        l.blob(data); l.blob(original); mh = l.blob(canonical(manifest).encode())
        _event_at(l, 'created', owner, action, mh, captured_at)
        _records(l.db, l.account)
        checked_at = l.clock()
        must(checked_at >= captured_at, 'Preparation registration clock rollback')
    must(l.clock() >= checked_at, 'Preparation registration clock rollback after commit')
    return {'action_id': action, 'manifest_sha256': mh, 'binding': binding,
            'steps': manifest['steps'], 'state': 'reserved', 'may_dispatch': False, 'may_prepare': False}


def begin_step(l, owner, token, action, step_id):
    with l.tx():
        _writer(l, owner, token, action); l.no_pending()
        states, _ = _records(l.db, l.account); state = states.get(action)
        must(state is not None and not state['sealed'] and not state['stopped'], 'Open draft preparation required')
        must(state['completed_steps'] < len(STEP_IDS)
             and step_id == STEP_IDS[state['completed_steps']], 'Only next fixed step may receive one permit')
        issued_at = _fresh(l, *([state['last_read_at']] if state['last_read_at'] is not None else []))
        must(issued_at >= state['last_at'], 'Preparation clock rollback')
        permit = {'schema': 'publisher-draft-step-permit-v1', 'binding': state['binding'],
                  'manifest_sha256': state['manifest_sha256'], 'step_id': step_id,
                  'nonce': secrets.token_hex(32), 'issued_at': issued_at,
                  'expires_at': issued_at + FRESH_SECONDS,
                  'operation': state['manifest']['steps'][state['completed_steps']],
                  'browser_invocations': 1, 'final_submission': False}
        h = l.blob(canonical(permit).encode()); _event_at(l, 'step_permit', owner, action, h, issued_at)
        _records(l.db, l.account)
        checked_at = _fresh(l, permit['issued_at'])
        must(permit['issued_at'] <= checked_at < permit['expires_at'], 'Step permit expired or clock rolled back')
    now = _fresh(l, permit['issued_at'])
    must(checked_at <= now < permit['expires_at'], 'Step permit expired or clock rolled back after commit')
    return {'action_id': action, 'permit': permit, 'may_prepare': True, 'may_dispatch': False,
            'exactly_one_browser_call': True, 'lost_response_means_do_not_dispatch': True,
            'external_publication_allowed': False, 'automatic_retry': False,
            'media_source': ({'kind': 'immutable_ledger_blob',
                              'sha256': permit['operation']['image_sha256'],
                              'extract_and_rehash_before_filechooser': True,
                              'attach_part_index': 0}
                             if step_id == 'upload_original_image' else None)}


def _record_event(l, owner, token, action, record_path, sha256, suffix):
    data, h = file_bytes(record_path, sha256); record = parse_json(data)
    with l.tx():
        _writer(l, owner, token, action)
        # A matching completion is the only normal write allowed while its own
        # step is outstanding; no_pending intentionally is not called here.
        must(not l.db.execute('SELECT 1 FROM stops').fetchone(), 'Account STOP remains')
        must(not l.db.execute("SELECT 1 FROM actions WHERE state IN ('intent','submitted_unverified','unknown')").fetchone(),
             'Unresolved account social write blocks draft attestations')
        states, _ = _records(l.db, l.account); state = states.get(action)
        must(state is not None, 'Preparation manifest required')
        must(not any(s['pending'] is not None and a != action for a, s in states.items()),
             'Different outstanding draft step blocks write')
        times = [record['readback']['observed_at']]
        if suffix == 'step_completed':
            times += [record['call']['completed_at'], record['call']['operator_reviewed_at']]
        else:
            times += [record['readback']['visual_inspected_at']]
        initial_at = _fresh(l, *times)
        _source_graph(l.db, record, set(), l)
        l.blob(data); l.event(PREFIX + suffix, owner, action, proof_hash=h)
        _records(l.db, l.account)
        checked_at = _fresh(l, *times)
        must(checked_at >= initial_at, 'Preparation attestation clock rollback')
    now = _fresh(l, *times)
    must(now >= checked_at, 'Preparation attestation clock rollback after commit')
    return {'action_id': action, 'proof_sha256': h, 'state': 'reserved',
            'prepared': suffix == 'sealed', 'may_dispatch': False, 'social_success': False,
            'new_verified_count': 0}


def complete_step(l, owner, token, action, record_path, sha256):
    return _record_event(l, owner, token, action, record_path, sha256, 'step_completed')


def seal_preparation(l, owner, token, action, record_path, sha256):
    return _record_event(l, owner, token, action, record_path, sha256, 'sealed')


def stop_unknown_step(l, owner, token, action, nonce, reason):
    text(reason, 'unknown draft outcome reason')
    with l.tx():
        _writer(l, owner, token, action)
        states, _ = _records(l.db, l.account); state = states.get(action)
        must(state is not None and state['pending'] is not None
             and nonce == state['pending']['nonce'], 'Exact outstanding draft step nonce required')
        must(not l.db.execute('SELECT 1 FROM stops').fetchone(), 'Existing STOP cannot be replaced')
        captured_at = l.clock()
        must(captured_at >= state['last_at'], 'Preparation clock rollback')
        record = {'schema': 'publisher-draft-step-unknown-v1', 'binding': state['binding'],
                  'manifest_sha256': state['manifest_sha256'], 'step_id': state['pending']['step_id'],
                  'nonce': nonce, 'reason': reason, 'at': captured_at, 'external_outcome': 'unknown',
                  'retry_allowed': False, 'social_success': False}
        h = l.blob(canonical(record).encode())
        l.db.execute("UPDATE actions SET state='unknown',updated_at=? WHERE id=?", (captured_at, action))
        l.db.execute('INSERT INTO stops VALUES(?,?,?,?)', (l.account, action, reason, captured_at))
        _event_at(l, 'step_unknown', owner, action, h, captured_at)
        _records(l.db, l.account)
        checked_at = l.clock()
        must(checked_at >= captured_at, 'Unknown draft step clock rollback')
    must(l.clock() >= checked_at, 'Unknown draft step clock rollback after commit')
    return {'action_id': action, 'state': 'unknown', 'stopped': True, 'may_dispatch': False,
            'retry_allowed': False, 'social_success': False, 'new_verified_count': 0}
