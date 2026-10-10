"""EXPERIMENTAL: explicit operator-attested pre-execution denial, no retry path.
Only isolated synthetic tests are supported until explicitly authorized deployment.
Hashes preserve integrity; an operator must review authentic original tool context.
"""
import json
from ledger import ACCOUNT, HASH, action_key, exact, file_bytes, digest, canonical, must, text


def fresh(l,at,label):
    now=l.clock()
    must(type(at) is int and now-3600<=at<=now,label+' stale')


def bind(l,o,row,owner):
    must(o['account']==l.account and o['db_id']==l.get('db_id'),'Denial account/database mismatch')
    must(o['kind']==row['kind'],'Denial kind mismatch')
    must(o['action_id']==row['id'] and action_key(l.account,o['kind'],o['target'])==row['id'],'Denial action/target mismatch')
    must(o['payload_hash']==row['payload_hash'] and o['intent_id']==row['intent_id'] and o['intent_at']==row['intent_at'] and o['owner']==owner,'Denial payload/intent/owner mismatch')


def eligible_history(l,row):
    events=list(l.db.execute('SELECT event,details,at FROM audit WHERE action_id=? ORDER BY seq',(row['id'],)))
    must(not any(e['event'] in ('submitted_unverified','browser_readback_attested') for e in events),'Ever-submitted/observed action cannot be labelled pre-dispatch denied')
    intents=[e for e in events if e['event']=='single_write_intent_committed']
    must(len(intents)==1 and json.loads(intents[0]['details'])['intent_id']==row['intent_id'],'Unique original intent audit required')
    return events


def record_denied(l,owner,token,action,evidence_path,sha256):
    raw,h=file_bytes(evidence_path,sha256);o=json.loads(raw)
    exact(o,('schema','account','db_id','action_id','kind','target','payload_hash','intent_id','intent_at','owner','source_file','source_sha256','attested_at','provenance'))
    must(o['schema']=='operator-attested-tool-denial-v1','Wrong denial evidence schema')
    must(o['provenance']=='operator_attested_original_tool_context','Original tool context must be explicitly reviewed; hashes do not authenticate it')
    fresh(l,o['attested_at'],'Denial attestation')
    source,sh=file_bytes(o['source_file'],o['source_sha256']);s=json.loads(source)
    exact(s,('schema','account','db_id','action_id','kind','target','payload_hash','intent_id','intent_at','owner','tool_name','request_text','result_text','result_is_error','denied_at','tool_call_id','missing_call_id_reason','original_context_reference','execution_stage','submission_not_sent','no_subsequent_browser_call','request_sha256','result_sha256'))
    must(s['schema']=='retained-preexecution-denial-context-v1','Wrong retained context schema')
    for k in ('tool_name','request_text','result_text','original_context_reference'):text(s[k],k,maximum=100000)
    must(s['tool_call_id'] is None or isinstance(s['tool_call_id'],str) and s['tool_call_id'],'Invalid tool call ID')
    if s['tool_call_id'] is None:text(s['missing_call_id_reason'],'explicit missing call ID reason')
    must(digest(s['request_text'])==s['request_sha256'] and digest(s['result_text'])==s['result_sha256'],'Exact original request/result hash mismatch')
    must(s['result_is_error'] is True and s['execution_stage']=='before_tool_execution' and s['submission_not_sent'] is True and s['no_subsequent_browser_call'] is True,'Ambiguous execution cannot use denial terminalization')
    must('This action was rejected due to unacceptable risk.' in s['result_text'] and 'Do not bypass this rejection' in s['result_text'],'Explicit auto-review authorization denial required; ordinary failures are unknown')
    with l.tx():
        fresh(l,o['attested_at'],'Denial attestation')
        l.active();w=l.writer(owner,token);row=l.row(action)
        must(row['state'] in ('intent','unknown') and row['session']==w['session'],'Only this writer\'s intent/unknown may record denial')
        must(row['intent_id'] and row['intent_at'] is not None,'Intent missing')
        bind(l,o,row,owner);bind(l,s,row,owner);eligible_history(l,row)
        must(type(s['denied_at']) is int and row['intent_at']<=s['denied_at']<=o['attested_at']<=l.clock(),'Denial predates intent or is in future')
        stop=l.db.execute('SELECT * FROM stops WHERE account=?',(l.account,)).fetchone()
        must(stop is None or stop['action_id']==action,'A different account STOP cannot be replaced')
        if row['state']=='unknown':must(stop is not None,'Unknown outcome must retain its STOP')
        l.blob(raw);l.blob(source)
        l.db.execute("UPDATE actions SET state='cancelled',updated_at=?,proof_hash=? WHERE id=?",(l.clock(),h,action))
        l.db.execute('INSERT OR IGNORE INTO stops VALUES(?,?,?,?)',(l.account,action,'Pre-execution denial recorded; explicit review/release/checkpoint still required; no retry',l.clock()))
        l.event('denied_before_dispatch_recorded',owner,action,proof_hash=h,source_hash=sh,resolution='not_executed',provenance=o['provenance'],tool_call_id=s['tool_call_id'],retry_allowed=False)
        fresh(l,o['attested_at'],'Denial attestation')
    return {'action_id':action,'state':'cancelled','termination_class':'denied_before_dispatch','stop_retained':True,'writer_released':False,'retry_allowed':False,'may_dispatch':False}


def finalize_denied_run(l,owner,token,action,approval_path,sha256):
    raw,h=file_bytes(approval_path,sha256);a=json.loads(raw)
    exact(a,('schema','account','db_id','action_id','intent_id','intent_at','owner','source_sha256','proof_file','proof_sha256','approval_reference','decision','follow_retry_authorized','other_new_dispatch_authorized','reviewed_at'))
    must(a['schema']=='operator-approved-denial-finalization-v1','Wrong denial approval schema')
    must(a['decision']=='record_no_execution_release_run_and_require_checkpoint' and a['follow_retry_authorized'] is False and a['other_new_dispatch_authorized'] is False,'Only bookkeeping closure is authorized by this command')
    text(a['approval_reference'],'authentic user approval reference')
    fresh(l,a['reviewed_at'],'Approval review')
    approval,ph=file_bytes(a['proof_file'],a['proof_sha256']);must(approval,'Empty approval proof')
    with l.tx():
        fresh(l,a['reviewed_at'],'Approval review')
        l.active();w=l.writer(owner,token);row=l.row(action)
        must(row['state']=='cancelled' and row['session']==w['session'] and row['intent_id'],'Only exact denied terminal action qualifies')
        must(a['account']==l.account and a['db_id']==l.get('db_id') and a['action_id']==action and a['intent_id']==row['intent_id'] and a['intent_at']==row['intent_at'] and a['owner']==owner and a['source_sha256']==row['proof_hash'],'Approval does not bind exact denial')
        eligible_history(l,row)
        events=list(l.db.execute("SELECT details FROM audit WHERE action_id=? AND event='denied_before_dispatch_recorded'",(action,)))
        must(len(events)==1 and json.loads(events[0]['details'])['proof_hash']==row['proof_hash'],'Mandatory denial subtype/evidence missing')
        br=l.db.execute('SELECT bytes FROM blobs WHERE hash=?',(row['proof_hash'],)).fetchone()
        must(br and digest(bytes(br[0]))==row['proof_hash'],'Denial evidence missing/corrupt')
        denial=json.loads(bytes(br[0]));must(a['reviewed_at']>=denial['attested_at'],'Approval review predates denial attestation')
        source=l.db.execute('SELECT bytes FROM blobs WHERE hash=?',(denial['source_sha256'],)).fetchone()
        must(source and digest(bytes(source[0]))==denial['source_sha256'],'Original denial context missing/corrupt')
        stop=l.db.execute('SELECT * FROM stops WHERE account=?',(l.account,)).fetchone();must(stop and stop['action_id']==action,'Exact matching STOP required')
        must(not l.db.execute("SELECT 1 FROM actions WHERE state IN ('reserved','intent','submitted_unverified','unknown')").fetchone(),'Other pending/reserved actions prevent closing run')
        run=l.db.execute('SELECT * FROM runs WHERE owner=?',(owner,)).fetchone();must(run and run['session']==w['session'] and run['state']=='active','Matching active run required')
        l.blob(raw);l.blob(approval)
        l.db.execute('DELETE FROM stops WHERE account=? AND action_id=?',(l.account,action))
        l.db.execute('DELETE FROM writer WHERE account=?',(l.account,))
        l.db.execute("UPDATE runs SET state='released',ended_at=? WHERE owner=?",(l.clock(),owner))
        l.put('checkpoint_pending','1');l.put('checkpoint_seq',str(int(l.get('checkpoint_seq'))+1))
        l.event('denial_reconciliation_explicitly_approved',owner,action,proof_hash=h,approval_reference=a['approval_reference'],retry_allowed=False)
        l.event('writer_released',owner,session=w['session'],checkpoint_seq=int(l.get('checkpoint_seq')),termination_class='denied_before_dispatch')
        fresh(l,a['reviewed_at'],'Approval review')
    return {'action_id':action,'state':'cancelled','termination_class':'denied_before_dispatch','released':True,'checkpoint_pending':True,'checkpoint_seq':int(l.get('checkpoint_seq')),'retry_allowed':False,'may_dispatch':False}
