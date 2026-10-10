#!/usr/bin/env python3
"""Writerless operational checkpoints. Local package only; never upload or write Threads."""
import argparse
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import zipfile
from settings import ACCOUNT
from ledger import Ledger, canonical, digest, must, exact, text, HASH, file_bytes, schema_hash, expected_schema_hash, APP_ID, VERSION

def runtime_manifest(db):
    values=dict(db.execute('SELECT key,value FROM meta'))
    from quarantine_extension import quarantine_records
    quarantines=quarantine_records(db,values['account'])
    from publisher_preparation import preparation_records,preparation_evidence_hashes
    preparations=preparation_records(db,values['account'])
    # ACK bookkeeping does not alter external-action safe-state hash. Its bytes
    # remain in SQLite for audit, but cannot create an endless checkpoint loop.
    excluded=('reconstruction_sealed','verified_backup_activation','checkpoint_verified')
    audit=[dict(r) for r in db.execute('SELECT * FROM audit ORDER BY seq') if r['event'] not in excluded]
    observations=[dict(r) for r in db.execute('SELECT * FROM observations ORDER BY record_hash')]
    actions=[dict(r) for r in db.execute('SELECT * FROM actions ORDER BY id')]
    evidence={values['review_hash']}|{h for o in observations for h in (o['record_hash'],o['source_hash'])}
    evidence|={a['proof_hash'] for a in actions if a['proof_hash']}
    evidence|=set(preparation_evidence_hashes(db,values['account']))
    for a in audit:
        d=json.loads(a['details'])
        evidence|={d[k] for k in ('preflight_hash','proof_hash') if k in d}
    # Hash-bound saved browser records point to their actual public proof bytes.
    pending=list(evidence)
    while pending:
        h=pending.pop();must(HASH.fullmatch(h or ''),'Invalid checkpoint evidence hash')
        row=db.execute('SELECT bytes FROM blobs WHERE hash=?',(h,)).fetchone();must(row is not None,'Checkpoint evidence missing')
        data=bytes(row[0]);must(digest(data)==h,'Checkpoint evidence corrupt')
        try:o=json.loads(data)
        except (ValueError,UnicodeDecodeError):continue
        if type(o) is dict:
            for k in ('source_sha256','proof_sha256'):
                if k in o and o[k] not in evidence:evidence.add(o[k]);pending.append(o[k])
    return {'schema':'threads-runtime-safe-state-v1','account':values['account'],'db_id':values['db_id'],'baseline_hash':values['baseline_hash'],'checkpoint_seq':int(values['checkpoint_seq']),
        'actions':actions,'quarantines':quarantines,'publisher_preparations':preparations,'observations':observations,'receipts':[dict(r) for r in db.execute('SELECT * FROM receipts ORDER BY receipt_key')],
        'runs':[dict(r) for r in db.execute('SELECT * FROM runs ORDER BY owner')],'stops':[dict(r) for r in db.execute('SELECT * FROM stops ORDER BY account')],
        'audit':audit,'evidence_hashes':sorted(evidence)}

def check_snapshot(db):
    db.row_factory=sqlite3.Row
    must(db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','Checkpoint integrity failure')
    must(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID and db.execute('PRAGMA user_version').fetchone()[0]==VERSION,'Checkpoint identity/schema mismatch')
    must(schema_hash(db)==expected_schema_hash(),'Checkpoint schema guards mismatch')
    v=dict(db.execute('SELECT key,value FROM meta'))
    must(v['phase']=='active' and v['checkpoint_pending']=='1' and v['backup_hash'] and v['baseline_library_id'],'Checkpoint must be active and pending after release')
    must(not db.execute('SELECT 1 FROM writer').fetchone(),'Writer exists; no checkpoint of credentials')
    must(not db.execute('SELECT 1 FROM stops').fetchone(),'Unresolved STOP blocks checkpoint')
    must(not db.execute("SELECT 1 FROM actions WHERE state IN ('reserved','intent','submitted_unverified','unknown')").fetchone(),'Unresolved action blocks checkpoint')
    must(not db.execute("SELECT 1 FROM runs WHERE state!='released'").fetchone(),'Unreleased run blocks checkpoint')
    m=runtime_manifest(db);return v,m,digest(canonical(m))

def package(db_path,output,source_dir=None,account=ACCOUNT):
    source_dir=Path(source_dir or Path(__file__).parent);output=Path(output).absolute()
    must(not output.exists(),'Refuse checkpoint overwrite')
    l=Ledger(db_path,account)
    try:
        l.ensure_storage();v,m,h=check_snapshot(l.db)
        with tempfile.TemporaryDirectory(prefix='threads-checkpoint-') as tmp:
            snap=Path(tmp)/'runtime.sqlite';dest=sqlite3.connect(snap)
            try:
                l.db.backup(dest);l.ensure_storage();dest.execute('PRAGMA journal_mode=DELETE');dest.commit();dest.execute('VACUUM')
                sv,sm,sh=check_snapshot(dest);must(sh==h,'Runtime state changed during checkpoint')
                blobs=[(r['hash'],bytes(r['bytes'])) for r in dest.execute('SELECT hash,bytes FROM blobs ORDER BY hash')]
                for bh,b in blobs:must(digest(b)==bh,'Corrupt archived blob')
            finally:dest.close()
            members={'runtime.sqlite':snap.read_bytes(),'RUNTIME_MANIFEST.json':canonical(sm).encode()}
            for name in ('ledger.py','checkpoint.py','denial_extension.py','quarantine_extension.py','QUARANTINE.md','publisher_preparation.py','PREPARATION.md','package_recovery.py','settings.py','RECOVERY.md','FAIL_FAST.md','CHECKPOINT.md'):
                data,_=file_bytes(source_dir/name);members[name]=data
            for bh,b in blobs:members['evidence/'+bh+'.bin']=b
            pm={'schema':'threads-ledger-checkpoint-v1','account':account,'db_id':sv['db_id'],'baseline_hash':sv['baseline_hash'],'checkpoint_seq':int(sv['checkpoint_seq']),'checkpoint_hash':sh,'members':{n:digest(b) for n,b in sorted(members.items())}}
            fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as stream:
                with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as z:
                    for n,b in sorted(members.items()):z.writestr(n,b)
                    z.writestr('PACKAGE_MANIFEST.json',canonical(pm))
            # Verify state still matches; output alone can never clear pending.
            l.ensure_storage();must(check_snapshot(l.db)[2]==sh,'State changed after packaging')
            b,_=file_bytes(output,limit=64_000_000)
            return {'package':str(output),'archive_sha256':digest(b),'bytes':len(b),'db_id':sv['db_id'],'baseline_hash':sv['baseline_hash'],'checkpoint_seq':int(sv['checkpoint_seq']),'checkpoint_hash':sh,'previous_library_id':sv['checkpoint_library_id'],'previous_library_version':sv['checkpoint_library_version'],'may_dispatch':False,'checkpoint_pending':True,'uploaded':False,'roundtrip_verified':False}
    finally:l.close()

def acknowledge(l,receipt_path,sha256):
    data,rh=file_bytes(receipt_path,sha256);r=json.loads(data)
    exact(r,('schema','account','db_id','baseline_hash','checkpoint_seq','checkpoint_hash','library_file_id','library_version','previous_version','archive_sha256','downloaded_archive','transport_reference','verified_at'))
    must(r['schema']=='library-checkpoint-roundtrip-v1' and r['account']==l.account,'Checkpoint receipt schema/account mismatch')
    for k in ('library_file_id','library_version','transport_reference'):text(r[k],k)
    must(isinstance(r['previous_version'],str) and type(r['checkpoint_seq']) is int,'Invalid checkpoint version/sequence')
    must(type(r['verified_at']) is int and l.clock()-3600<=r['verified_at']<=l.clock(),'Checkpoint download verification stale')
    archive,ah=file_bytes(r['downloaded_archive'],r['archive_sha256'],limit=64_000_000)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        must(len(z.namelist())==len(set(z.namelist())),'Duplicate checkpoint entries')
        must('PACKAGE_MANIFEST.json' in z.namelist(),'Checkpoint archive manifest missing')
        must(z.getinfo('PACKAGE_MANIFEST.json').file_size<=1_000_000,'Archive manifest exceeds bound')
        pm=json.loads(z.read('PACKAGE_MANIFEST.json'))
        exact(pm,('schema','account','db_id','baseline_hash','checkpoint_seq','checkpoint_hash','members'))
        must(pm['schema']=='threads-ledger-checkpoint-v1','Wrong checkpoint package')
        for k in ('account','db_id','baseline_hash','checkpoint_seq','checkpoint_hash'):must(pm[k]==r[k],'Checkpoint archive binding mismatch')
        must(type(pm['members']) is dict and set(z.namelist())==set(pm['members'])|{'PACKAGE_MANIFEST.json'},'Undeclared checkpoint member')
        must({'runtime.sqlite','ledger.py','checkpoint.py','denial_extension.py','quarantine_extension.py','QUARANTINE.md','publisher_preparation.py','PREPARATION.md','settings.py','CHECKPOINT.md'}<=set(pm['members']),'Required checkpoint members missing')
        total=0
        for name,h in pm['members'].items():
            must(not name.startswith('/') and '..' not in Path(name).parts,'Unsafe checkpoint path')
            size=z.getinfo(name).file_size;total+=size
            must(size<=32_000_000 and total<=64_000_000,'Checkpoint expansion exceeds bound')
            must(digest(z.read(name))==h,'Checkpoint member hash mismatch')
        verify=sqlite3.connect(':memory:')
        try:
            verify.deserialize(z.read('runtime.sqlite'));v,m,h=check_snapshot(verify)
            must(h==r['checkpoint_hash'],'Downloaded checkpoint DB differs from safe state')
            for k in ('account','db_id','baseline_hash'):must(v[k]==r[k],'Downloaded checkpoint DB binding mismatch')
            must(int(v['checkpoint_seq'])==r['checkpoint_seq'],'Downloaded checkpoint sequence mismatch')
            downloaded_values=v.copy()
        finally:verify.close()
    with l.tx():
        v,m,h=check_snapshot(l.db)
        must(v==downloaded_values,'Downloaded checkpoint metadata differs from live pre-ACK state')
        must(h==r['checkpoint_hash'] and v['db_id']==r['db_id'] and v['baseline_hash']==r['baseline_hash'] and int(v['checkpoint_seq'])==r['checkpoint_seq'],'Live state differs from downloaded checkpoint')
        must(r['library_file_id']!=v['baseline_library_id'],'Immutable baseline Library file must not be replaced by runtime checkpoints')
        must(not v['checkpoint_library_id'] or r['library_file_id']==v['checkpoint_library_id'],'Runtime Library identity changed')
        must(r['previous_version']==v['checkpoint_library_version'] and r['library_version']!=r['previous_version'],'Library expected-version chain mismatch')
        l.blob(data);l.put('checkpoint_pending','0');l.put('checkpoint_library_id',r['library_file_id']);l.put('checkpoint_library_version',r['library_version']);l.put('checkpoint_archive_hash',ah)
        l.event('checkpoint_verified',checkpoint_seq=r['checkpoint_seq'],checkpoint_hash=h,archive_sha256=ah,library_file_id=r['library_file_id'],library_version=r['library_version'],receipt_hash=rh)
    return {'checkpoint_pending':False,'checkpoint_seq':r['checkpoint_seq'],'checkpoint_hash':h,'archive_sha256':ah,'may_dispatch':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--db',required=True);p.add_argument('--output',required=True);p.add_argument('--account',default=ACCOUNT);a=p.parse_args()
    try:print(canonical({'ok':True,**package(a.db,a.output,account=a.account)}))
    except Exception as e:print(canonical({'ok':False,'may_dispatch':False,'automatic_retry':False,'error':str(e)}));raise SystemExit(2)
