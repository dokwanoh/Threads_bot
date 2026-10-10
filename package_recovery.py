#!/usr/bin/env python3
"""Create a secret-free, self-contained sealed-recovery package. No upload/activation."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import zipfile
from settings import ACCOUNT
from ledger import Ledger,Blocked,must,digest,canonical,schema_hash,expected_schema_hash,database_manifest

def package(db_path,output,source_dir=None,account=ACCOUNT):
    source_dir=Path(source_dir or Path(__file__).parent)
    output=Path(output).absolute()
    must(not output.exists(),'Refuse to overwrite a backup package')
    l=Ledger(db_path,account)
    try:
        l.ensure_storage()
        must(l.get('phase')=='sealed','Only sealed recovery can be packaged')
        must(not l.db.execute('SELECT 1 FROM writer').fetchone(),'Active writer credentials cannot enter backup')
        l.no_pending()
        with tempfile.TemporaryDirectory(prefix='ledger-package-') as tmp:
            snap=Path(tmp)/'reconstructed.sqlite'
            dest=sqlite3.connect(snap)
            try:
                l.db.backup(dest)
                l.ensure_storage()
                dest.execute('PRAGMA journal_mode=DELETE');dest.commit();dest.row_factory=sqlite3.Row
                must(dest.execute('PRAGMA integrity_check').fetchone()[0]=='ok','Snapshot integrity failure')
                must(schema_hash(dest)==expected_schema_hash(),'Snapshot schema mismatch')
                values=dict(dest.execute('SELECT key,value FROM meta'))
                must(values['phase']=='sealed' and dest.execute('SELECT COUNT(*) FROM writer').fetchone()[0]==0,'Snapshot changed during packaging')
                must(dest.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0 and dest.execute('SELECT COUNT(*) FROM stops').fetchone()[0]==0,'Recovery snapshot contains runtime/STOP state')
                manifest=database_manifest(dest);must(digest(canonical(manifest))==values['baseline_hash'],'Snapshot no longer matches reviewed baseline')
                blobs=[(r['hash'],bytes(r['bytes'])) for r in dest.execute('SELECT hash,bytes FROM blobs ORDER BY hash')]
                for h,data in blobs:must(digest(data)==h,'Corrupt evidence blob')
            finally:dest.close()
            members={'reconstructed.sqlite':snap.read_bytes(),
                     'BASELINE_MANIFEST.json':(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()}
            # Explicit code/test/doc allowlist: no run token file, arbitrary directory
            # walk, .env, browser profile, or unrelated workspace material is included.
            names=['ledger.py','checkpoint.py','denial_extension.py','quarantine_extension.py','QUARANTINE.md','package_recovery.py','settings.py','RECOVERY.md','FAIL_FAST.md','CHECKPOINT.md']
            test_names=('test_independent.py','test_checkpoint_independent.py','test_denial_independent.py','test_denial_freshness.py','test_denial_cli.py','test_quarantine_extension.py','test_quarantine_plumbing.py','test_archive_closure.py')
            names += [name for name in test_names if (source_dir/name).exists()]
            for name in names:
                p=source_dir/name;must(p.is_file() and not p.is_symlink(),'Missing package source '+name)
                members[name]=p.read_bytes()
            for h,data in blobs:members['evidence/'+h+'.bin']=data
            pm={'schema':'threads-ledger-backup-v1','account':account,'db_id':values['db_id'],
                'baseline_hash':values['baseline_hash'],'members':{n:digest(data) for n,data in sorted(members.items())}}
            fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:
                with os.fdopen(fd,'wb') as stream:
                    with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as z:
                        for name,data in sorted(members.items()):z.writestr(name,data)
                        z.writestr('PACKAGE_MANIFEST.json',json.dumps(pm,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
            except BaseException:
                # Keep any incomplete output as failed evidence; never silently retry.
                raise
            data=output.read_bytes()
            return {'package':str(output),'archive_sha256':digest(data),'bytes':len(data),
                    'db_id':values['db_id'],'baseline_hash':values['baseline_hash'],'members':len(members)+1,
                    'uploaded':False,'roundtrip_verified':False,'activated':False}
    finally:l.close()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--db',required=True);p.add_argument('--output',required=True);p.add_argument('--account',default=ACCOUNT);a=p.parse_args()
    try:print(json.dumps({'ok':True,**package(a.db,a.output,account=a.account)},ensure_ascii=False,sort_keys=True))
    except (Blocked,OSError,sqlite3.Error,ValueError) as e:
        print(json.dumps({'ok':False,'error':str(e),'automatic_retry':False}));raise SystemExit(2)
