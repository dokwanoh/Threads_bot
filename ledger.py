#!/usr/bin/env python3
"""Reconstructed cooperative browser ledger. No network, browser, or social writer."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
from urllib.parse import urlsplit
import zipfile

VERSION=2
APP_ID=0x544C5232
from settings import ACCOUNT, BLOG_HOST, PRODUCTION_ROOT
HASH=re.compile(r'[a-f0-9]{64}\Z')
KINDS=('publish','reply','self_reply','like','repost','follow')
PENDING=('intent','submitted_unverified','unknown')
OLD_RUNTIME=PRODUCTION_ROOT

class Blocked(Exception): pass
def must(ok,message):
    if not ok: raise Blocked(message)
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(value):return hashlib.sha256(value if isinstance(value,bytes) else value.encode()).hexdigest()
def account_name(value):
    must(isinstance(value,str),'Account must be text')
    value=value.removeprefix('@').lower()
    must(re.fullmatch(r'[a-z0-9_.]{1,64}',value),'Invalid account')
    return value
def text(value,label,maximum=2000):
    must(isinstance(value,str) and 0<len(value)<=maximum and '\x00' not in value,'Invalid '+label)
    return value
def exact(value,fields):must(type(value) is dict and set(value)==set(fields),'Unexpected/missing record fields')
def file_bytes(path,expected=None,limit=8_000_000):
    p=Path(path);st=p.lstat()
    must(stat.S_ISREG(st.st_mode) and not p.is_symlink() and st.st_size<=limit,'Expected bounded regular non-symlink file')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:data=f.read(limit+1)
    must(len(data)<=limit,'File exceeds limit')
    h=digest(data)
    if expected is not None:must(HASH.fullmatch(expected or '') and secrets.compare_digest(expected,h),'File SHA-256 mismatch')
    return data,h
def target_key(kind,url):
    must(kind in KINDS,'Unknown action kind');text(url,'target')
    u=urlsplit(url)
    must(u.scheme=='https' and u.username is None and u.password is None and u.port is None,'Public HTTPS target without credentials/port required')
    must(not u.query and not u.fragment,'Target query/fragment must be resolved before binding')
    path=u.path.rstrip('/')
    if kind=='publish':
        must(u.hostname==BLOG_HOST and re.fullmatch(r'/[1-9][0-9]*',path),'Verified numeric article URL required')
        return 'blog:article:'+path[1:]
    must(u.hostname in ('threads.com','www.threads.com','threads.net','www.threads.net'),'Expected Threads target')
    if kind=='follow':
        m=re.fullmatch(r'/@([A-Za-z0-9_.]{1,64})',path);must(m,'Exact profile target required')
        return 'threads:account:'+m[1].lower()
    m=re.fullmatch(r'/@([A-Za-z0-9_.]{1,64})/post/([A-Za-z0-9_-]{1,100})',path)
    must(m,'Exact post permalink required')
    return 'threads:post:'+m[2]
def action_key(account,kind,url):return digest(canonical([account,'reply' if kind=='self_reply' else kind,target_key(kind,url)]))
def owned_receipts(account,urls,required=False):
    must(isinstance(urls,list) and len(urls)<=20,'Invalid receipt list')
    if required:must(urls,'Owned receipt required')
    keys=[]
    for url in urls:
        key=target_key('reply',url)
        must(urlsplit(url).path.split('/')[1].lower()=='@'+account,'Receipt must belong to our account')
        must(key not in keys,'Duplicate receipt URL');keys.append(key)
    return keys

SCHEMA='''
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;
CREATE TABLE writer(account TEXT PRIMARY KEY,session TEXT NOT NULL UNIQUE,owner TEXT NOT NULL,
 role TEXT NOT NULL,token_hash TEXT NOT NULL,acquired_at INTEGER NOT NULL) STRICT;
CREATE TABLE runs(owner TEXT PRIMARY KEY,session TEXT NOT NULL,role TEXT NOT NULL,state TEXT NOT NULL,
 started_at INTEGER NOT NULL,ended_at INTEGER) STRICT;
CREATE TABLE actions(id TEXT PRIMARY KEY,account TEXT NOT NULL,kind TEXT NOT NULL,target_key TEXT NOT NULL,
 target_url TEXT NOT NULL,payload_hash TEXT,state TEXT NOT NULL,session TEXT,created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,intent_id TEXT,intent_at INTEGER,proof_hash TEXT,
 CHECK(state IN ('historical_observed','current_observed','reserved','intent','submitted_unverified',
 'unknown','verified','already_present','cancelled'))) STRICT;
CREATE TABLE observations(record_hash TEXT PRIMARY KEY,action_id TEXT NOT NULL,classification TEXT NOT NULL,
 observed_at INTEGER,source_hash TEXT NOT NULL,reference TEXT NOT NULL) STRICT;
CREATE TABLE blobs(hash TEXT PRIMARY KEY,bytes BLOB NOT NULL,recorded_at INTEGER NOT NULL) STRICT;
CREATE TABLE receipts(receipt_key TEXT PRIMARY KEY,action_id TEXT NOT NULL,proof_hash TEXT NOT NULL) STRICT;
CREATE TABLE stops(account TEXT PRIMARY KEY,action_id TEXT NOT NULL,reason TEXT NOT NULL,at INTEGER NOT NULL) STRICT;
CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER NOT NULL,account TEXT NOT NULL,
 owner TEXT,event TEXT NOT NULL,action_id TEXT,details TEXT NOT NULL) STRICT;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER blobs_no_update BEFORE UPDATE ON blobs BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
CREATE TRIGGER blobs_no_delete BEFORE DELETE ON blobs BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
'''
def schema_hash(db):
    return digest(canonical([list(r) for r in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]))
def expected_schema_hash():
    db=sqlite3.connect(':memory:')
    try:db.executescript(SCHEMA);return schema_hash(db)
    finally:db.close()

def database_manifest(db):
    observations=[dict(r) for r in db.execute('SELECT * FROM observations ORDER BY record_hash')]
    meta=dict(db.execute('SELECT key,value FROM meta'))
    evidence=sorted({h for r in observations for h in (r['record_hash'],r['source_hash'])})
    return {'schema':'reconstructed-ledger-manifest-v1','account':meta['account'],'db_id':meta['db_id'],
            'actions':[dict(r) for r in db.execute('SELECT id,kind,target_key,target_url,payload_hash,state FROM actions ORDER BY id')],
            'observations':observations,'evidence_hashes':evidence,
            'receipts':[dict(r) for r in db.execute('SELECT * FROM receipts ORDER BY receipt_key')],
            'runs':[dict(r) for r in db.execute('SELECT * FROM runs ORDER BY owner')],
            'stops':[dict(r) for r in db.execute('SELECT * FROM stops ORDER BY account')],
            'reconstruction_audit':[dict(r) for r in db.execute("SELECT * FROM audit WHERE event NOT IN ('reconstruction_sealed','verified_backup_activation') ORDER BY seq")]}

class Ledger:
    @staticmethod
    def init_recovery(path,account=ACCOUNT):
        requested=Path(path).absolute()
        must(not any(x.is_symlink() for x in requested.parents),'Symlinked recovery directory is forbidden')
        p=requested.parent.resolve(strict=True)/requested.name;account=account_name(account)
        must(p.name!='live.sqlite' and OLD_RUNTIME not in (p,*p.parents),'Empty production initialization is forbidden')
        must(p.parent.is_dir(),'Explicit recovery directory must exist')
        fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        db=sqlite3.connect(p,isolation_level=None)
        try:
            db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;'+SCHEMA+f'PRAGMA user_version={VERSION}; PRAGMA application_id={APP_ID};')
            items={'account':account,'db_id':secrets.token_hex(16),'phase':'recovery','baseline_hash':'','review_hash':'','backup_hash':'','baseline_library_id':'','checkpoint_pending':'0','checkpoint_seq':'0','checkpoint_library_id':'','checkpoint_library_version':'','checkpoint_archive_hash':''}
            db.executemany('INSERT INTO meta VALUES(?,?)',items.items())
            db.execute('INSERT INTO audit(at,account,event,details) VALUES(?,?,?,?)',(int(time.time()),account,'reconstruction_initialized_inactive','{}'))
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:db.execute('ROLLBACK')
            raise
        finally:db.close()
        return {'phase':'recovery','may_dispatch':False,'original_database_restored':False}

    def __init__(self,path,account=ACCOUNT,clock=None):
        self.path=Path(path).absolute();self.account=account_name(account);self.clock=clock or (lambda:int(time.time()))
        must(self.path.is_file() and not self.path.is_symlink(),'Database missing; stop, never initialize automatically')
        st=self.path.stat();self.storage_identity=(st.st_dev,st.st_ino)
        self.sidecar_identity={};self.expected_db_id=None
        self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=5)
        self.db.row_factory=sqlite3.Row
        try:
            self.db.execute('PRAGMA busy_timeout=5000');self.db.execute('PRAGMA synchronous=FULL')
            must(self.db.execute('PRAGMA application_id').fetchone()[0]==APP_ID and self.db.execute('PRAGMA user_version').fetchone()[0]==VERSION,'Wrong database application/schema')
            must(schema_hash(self.db)==expected_schema_hash(),'Schema structure/guards mismatch')
            must(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','Expected WAL mode')
            must(self.get('account')==self.account,'Database account mismatch')
            self.expected_db_id=self.get('db_id')
            self.ensure_storage()
        except BaseException:self.db.close();raise
    def close(self):self.db.close()
    def ensure_storage(self):
        try:st=self.path.lstat()
        except OSError:raise Blocked('Database storage disappeared; stop, never recreate automatically')
        must(stat.S_ISREG(st.st_mode) and (st.st_dev,st.st_ino)==self.storage_identity,'Database storage identity changed; stop')
        for suffix in ('-wal','-shm'):
            side=Path(str(self.path)+suffix)
            try:
                s=side.lstat();must(stat.S_ISREG(s.st_mode),'Invalid SQLite sidecar')
                identity=(s.st_dev,s.st_ino)
            except FileNotFoundError:identity=None
            previous=self.sidecar_identity.get(suffix)
            if previous is not None:must(identity==previous,'SQLite WAL/shared-memory storage disappeared or changed; stop')
            if identity is not None:self.sidecar_identity[suffix]=identity
        must(self.db.execute('PRAGMA application_id').fetchone()[0]==APP_ID and self.db.execute('PRAGMA user_version').fetchone()[0]==VERSION,'Database identity/schema changed during use')
        must(schema_hash(self.db)==expected_schema_hash(),'Database guards changed during use')
        must(self.get('account')==self.account and (self.expected_db_id is None or self.get('db_id')==self.expected_db_id),'Database account/identity changed during use')
    def get(self,key):
        row=self.db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone();must(row,'Missing database metadata')
        return row[0]
    def put(self,key,value):
        r=self.db.execute('UPDATE meta SET value=? WHERE key=?',(value,key));must(r.rowcount==1,'Metadata update failed')
    @contextlib.contextmanager
    def tx(self):
        self.ensure_storage()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.ensure_storage()
            self.db.execute('COMMIT')
            self.ensure_storage()
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def event(self,event,owner=None,action=None,**details):
        self.db.execute('INSERT INTO audit(at,account,owner,event,action_id,details) VALUES(?,?,?,?,?,?)',
                        (self.clock(),self.account,owner,event,action,canonical(details)))
    def blob(self,data):
        h=digest(data);self.db.execute('INSERT OR IGNORE INTO blobs VALUES(?,?,?)',(h,data,self.clock()));return h
    def row(self,action):
        row=self.db.execute('SELECT * FROM actions WHERE id=? AND account=?',(action,self.account)).fetchone()
        must(row,'Unknown action');return row
    def writer(self,owner,token):
        must(isinstance(token,str) and HASH.fullmatch(token),'Explicit writer token required')
        w=self.db.execute('SELECT * FROM writer WHERE account=?',(self.account,)).fetchone()
        must(w and w['owner']==owner and secrets.compare_digest(w['token_hash'],digest(token)),'Missing or mismatched writer owner/token')
        return w
    def active(self):
        must(self.get('phase')=='active' and self.get('backup_hash'),'Recovery/backup gate blocks runtime writes')
        must(self.get('checkpoint_pending')=='0','Released run checkpoint must be verified before another write')
    def no_pending(self):
        from quarantine_extension import quarantine_records
        quarantine_records(self.db,self.account)  # Corrupt/missing quarantine proof blocks all acquisition.
        must(not self.db.execute('SELECT 1 FROM stops').fetchone(),'Account STOP remains')
        must(not self.db.execute("SELECT 1 FROM actions WHERE state IN ('intent','submitted_unverified','unknown')").fetchone(),'Unresolved account write blocks all dispatch')

    def import_observation(self,record_path,record_sha256):
        data,rh=file_bytes(record_path,record_sha256);o=json.loads(data)
        exact(o,('schema','account','kind','target','classification','observed_at','reference','source_file','source_sha256','payload','receipt_urls'))
        must(o['schema']=='public-action-observation-v1' and account_name(o['account'])==self.account,'Observation schema/account mismatch')
        must(o['classification'] in ('historical_observed','current_observed','unknown'),'Invalid observation class')
        text(o['reference'],'reference');key=action_key(self.account,o['kind'],o['target'])
        at=o['observed_at'];must(at is None or type(at) is int and 0<=at<=self.clock(),'Invalid observation time')
        if o['classification']=='current_observed':must(type(at) is int and self.clock()-3600<=at,'Fresh recovery readback required')
        source,sh=file_bytes(o['source_file'],o['source_sha256'])
        must(o['payload'] is None or type(o['payload']) is dict,'Payload must be explicit public record or null')
        ph=digest(canonical(o['payload'])) if o['payload'] is not None else None
        receipt_keys=owned_receipts(self.account,o['receipt_urls'],o['kind'] in ('publish','reply','self_reply') and o['classification']!='unknown')
        with self.tx():
            must(self.get('phase')=='recovery','Recovery imports are closed')
            must(not self.db.execute('SELECT 1 FROM writer').fetchone(),'No import with a writer')
            if self.db.execute('SELECT 1 FROM observations WHERE record_hash=?',(rh,)).fetchone():
                return {'action_id':key,'duplicate_observation':True,'may_dispatch':False}
            previous=self.db.execute('SELECT * FROM actions WHERE id=?',(key,)).fetchone()
            state=o['classification']
            if previous:
                must(previous['state'] in ('historical_observed','current_observed','unknown'),'Cannot import over execution state')
                if state=='historical_observed':state=previous['state']
                if previous['state']=='unknown' and state!='current_observed':state='unknown'
                self.db.execute('UPDATE actions SET state=?,updated_at=? WHERE id=?',(state,self.clock(),key))
            else:
                self.db.execute('INSERT INTO actions(id,account,kind,target_key,target_url,payload_hash,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',
                    (key,self.account,o['kind'],target_key(o['kind'],o['target']),o['target'],ph,state,self.clock(),self.clock()))
            self.blob(data);self.blob(source)
            self.db.execute('INSERT INTO observations VALUES(?,?,?,?,?,?)',(rh,key,o['classification'],at,sh,o['reference']))
            for receipt in receipt_keys:
                prior=self.db.execute('SELECT action_id FROM receipts WHERE receipt_key=?',(receipt,)).fetchone()
                must(prior is None or prior[0]==key,'Owned receipt already bound to another action')
                self.db.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,?)',(receipt,key,rh))
            self.event('recovery_observation_imported',action=key,record_hash=rh,source_hash=sh,classification=o['classification'])
        return {'action_id':key,'state':state,'original_database_restored':False,'may_dispatch':False}

    def manifest(self):
        self.ensure_storage()
        return database_manifest(self.db)
    def seal(self,review_path,sha256):
        data,h=file_bytes(review_path,sha256);review=json.loads(data)
        exact(review,('schema','account','manifest_sha256','review_reference','known_gaps','fresh_duplicate_checks_required','reviewed_at'))
        must(review['schema']=='recovery-review-v1' and account_name(review['account'])==self.account,'Review schema/account mismatch')
        text(review['review_reference'],'review reference')
        must(isinstance(review['known_gaps'],list) and all(isinstance(x,str) for x in review['known_gaps']),'Explicit gap list required')
        must(review['fresh_duplicate_checks_required'] is True,'Incomplete history cannot waive fresh duplicate checks')
        must(type(review['reviewed_at']) is int and self.clock()-3600<=review['reviewed_at']<=self.clock(),'Review is stale')
        with self.tx():
            must(self.get('phase')=='recovery','Only collecting recovery may be sealed')
            must(not self.db.execute('SELECT 1 FROM writer').fetchone(),'Writer must be absent')
            must(self.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0]>0,'Empty recovery cannot be sealed')
            must(self.db.execute("SELECT COUNT(*) FROM observations WHERE classification='current_observed'").fetchone()[0]>0,'Current browser reconciliation evidence required')
            self.no_pending();manifest=self.manifest();mh=digest(canonical(manifest))
            must(review['manifest_sha256']==mh,'Review does not cover exact current recovery manifest')
            self.blob(data);self.put('baseline_hash',mh);self.put('review_hash',h);self.put('phase','sealed')
            self.event('reconstruction_sealed',manifest_hash=mh,review_hash=h,known_gaps=review['known_gaps'])
        return {'phase':'sealed','baseline_hash':mh,'may_dispatch':False,'backup_required':True}

    def activate(self,receipt_path,sha256):
        data,h=file_bytes(receipt_path,sha256);r=json.loads(data)
        exact(r,('schema','account','db_id','baseline_hash','library_file_id','library_version','archive_sha256','downloaded_archive','transport_reference','verified_at'))
        must(r['schema']=='library-roundtrip-verification-v1' and account_name(r['account'])==self.account,'Backup receipt schema/account mismatch')
        for field in ('library_file_id','library_version','transport_reference'):text(r[field],field)
        must(type(r['verified_at']) is int and self.clock()-3600<=r['verified_at']<=self.clock(),'Backup verification is stale')
        archive_bytes,archive_hash=file_bytes(r['downloaded_archive'],r['archive_sha256'],limit=64_000_000)
        # Inspect the actual downloaded ZIP, not an assertion that upload succeeded.
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            must(len(z.namelist())==len(set(z.namelist())),'Duplicate archive entries')
            must('PACKAGE_MANIFEST.json' in z.namelist(),'Downloaded archive manifest missing')
            must(z.getinfo('PACKAGE_MANIFEST.json').file_size<=1_000_000,'Archive manifest exceeds bound')
            pm=json.loads(z.read('PACKAGE_MANIFEST.json'))
            exact(pm,('schema','account','db_id','baseline_hash','members'))
            must(pm['schema']=='threads-ledger-backup-v1' and pm['account']==self.account and pm['db_id']==r['db_id'] and pm['baseline_hash']==r['baseline_hash'],'Downloaded backup binding mismatch')
            must(type(pm['members']) is dict and set(z.namelist())==set(pm['members'])|{'PACKAGE_MANIFEST.json'},'Archive contains undeclared files')
            must({'reconstructed.sqlite','ledger.py','denial_extension.py','quarantine_extension.py','QUARANTINE.md','settings.py','RECOVERY.md'}<=set(pm['members']),'Required backup members missing')
            total=0
            for name,expected in pm['members'].items():
                must(not name.startswith('/') and '..' not in Path(name).parts,'Unsafe archive member')
                info=z.getinfo(name);total+=info.file_size
                must(info.file_size<=32_000_000 and total<=64_000_000,'Archive expansion exceeds bound')
                must(digest(z.read(name))==expected,'Downloaded member hash mismatch')
            # Decode the downloaded DB in memory; do not create or replace a runtime DB.
            verify=sqlite3.connect(':memory:')
            try:
                verify.deserialize(z.read('reconstructed.sqlite'))
                verify.row_factory=sqlite3.Row
                must(verify.execute('PRAGMA integrity_check').fetchone()[0]=='ok','Backup DB integrity failure')
                must(schema_hash(verify)==expected_schema_hash(),'Backup DB schema mismatch')
                values=dict(verify.execute('SELECT key,value FROM meta'))
                must(values.get('phase')=='sealed' and values.get('db_id')==r['db_id'] and values.get('baseline_hash')==r['baseline_hash'],'Backup DB is not this sealed reconstruction')
                must(verify.execute('SELECT COUNT(*) FROM writer').fetchone()[0]==0,'Backup includes active writer credentials')
                must(verify.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0 and verify.execute('SELECT COUNT(*) FROM stops').fetchone()[0]==0,'Recovery snapshot includes runtime or STOP state')
                must(verify.execute("SELECT COUNT(*) FROM actions WHERE state IN ('reserved','intent','submitted_unverified','unknown')").fetchone()[0]==0,'Backup contains unresolved work')
                actual_manifest=database_manifest(verify)
                must(digest(canonical(actual_manifest))==r['baseline_hash'],'Downloaded DB contents differ from reviewed baseline')
                for bh in actual_manifest['evidence_hashes']:
                    br=verify.execute('SELECT bytes FROM blobs WHERE hash=?',(bh,)).fetchone()
                    must(br is not None and digest(bytes(br[0]))==bh,'Downloaded DB evidence missing or corrupt')
                rr=verify.execute('SELECT bytes FROM blobs WHERE hash=?',(values.get('review_hash'),)).fetchone()
                must(rr is not None and digest(bytes(rr[0]))==values.get('review_hash'),'Backup review evidence missing/corrupt')
                must(json.loads(bytes(rr[0]))['manifest_sha256']==r['baseline_hash'],'Backup review does not bind baseline')
            finally:verify.close()
        with self.tx():
            must(self.get('phase')=='sealed' and self.get('db_id')==r['db_id'] and self.get('baseline_hash')==r['baseline_hash'],'Only the exact sealed reconstruction may activate')
            must(digest(canonical(self.manifest()))==r['baseline_hash'],'Candidate changed after review/backup')
            must(not self.db.execute('SELECT 1 FROM writer').fetchone(),'Writer exists during activation');self.no_pending()
            self.blob(data);self.put('backup_hash',archive_hash);self.put('baseline_library_id',r['library_file_id']);self.put('phase','active')
            self.event('verified_backup_activation',backup_receipt_hash=h,archive_hash=archive_hash,library_file_id=r['library_file_id'],library_version=r['library_version'])
        return {'phase':'active','may_dispatch':False,'backup_sha256':archive_hash,'original_database_restored':False}

    def acquire(self,owner,role):
        must(re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}',owner or ''),'Explicit run owner required')
        must(role in ('publisher','spreader','commenter','reconciler'),'Unknown role')
        token,session=secrets.token_hex(32),secrets.token_hex(16)
        with self.tx():
            self.active();self.no_pending()
            must(not self.db.execute('SELECT 1 FROM writer').fetchone(),'Exclusive writer held; no timeout takeover')
            must(not self.db.execute('SELECT 1 FROM runs WHERE owner=?',(owner,)).fetchone(),'Run owner already used; no duplicate scheduled run')
            self.db.execute('INSERT INTO writer VALUES(?,?,?,?,?,?)',(self.account,session,owner,role,digest(token),self.clock()))
            self.db.execute('INSERT INTO runs VALUES(?,?,?,?,?,NULL)',(owner,session,role,'active',self.clock()))
            self.event('writer_acquired',owner,session=session,role=role)
        return {'owner':owner,'token':token,'session':session,'may_dispatch':False,'automatic_expiry':False}

    def claim(self,owner,token,kind,target,payload_hash):
        must(HASH.fullmatch(payload_hash or ''),'Exact public payload hash required');key=action_key(self.account,kind,target)
        with self.tx():
            self.active();w=self.writer(owner,token);self.no_pending()
            from quarantine_extension import ensure_not_quarantined
            ensure_not_quarantined(self,kind,target)
            row=self.db.execute('SELECT * FROM actions WHERE id=?',(key,)).fetchone()
            if row:return {'action_id':key,'state':row['state'],'duplicate':True,'payload_matches':row['payload_hash']==payload_hash,'may_dispatch':False}
            self.db.execute("INSERT INTO actions(id,account,kind,target_key,target_url,payload_hash,state,session,created_at,updated_at) VALUES(?,?,?,?,?,?,'reserved',?,?,?)",(key,self.account,kind,target_key(kind,target),target,payload_hash,w['session'],self.clock(),self.clock()))
            self.event('action_reserved',owner,key,payload_hash=payload_hash,kind=kind,target=target_key(kind,target))
        return {'action_id':key,'state':'reserved','duplicate':False,'may_dispatch':False}

    def observation(self,path,row,outcome):
        data,h=file_bytes(path);o=json.loads(data)
        exact(o,('schema','account','kind','target','payload_hash','intent_id','outcome','observed_at','reference','proof_file','proof_sha256','receipt_urls'))
        must(o['schema']=='browser-action-evidence-v2' and account_name(o['account'])==self.account,'Evidence schema/account mismatch')
        must(action_key(self.account,o['kind'],o['target'])==row['id'] and o['payload_hash']==row['payload_hash'],'Evidence action/payload mismatch')
        must(o['intent_id']==row['intent_id'] and o['outcome']==outcome,'Evidence intent/outcome mismatch')
        at=o['observed_at'];must(type(at) is int and self.clock()-300<=at<=self.clock(),'Fresh browser evidence required')
        must(row['intent_at'] is None or at>=row['intent_at'],'Readback predates write intent')
        text(o['reference'],'actual browser observation reference');proof,_=file_bytes(o['proof_file'],o['proof_sha256'])
        must(proof,'Empty proof is not evidence')
        owned_receipts(self.account,o['receipt_urls'],outcome=='present' and row['kind'] in ('publish','reply','self_reply'))
        if outcome=='absent':must(not o['receipt_urls'],'Absence proof cannot assert receipts')
        return data,h,proof
    def begin_write(self,owner,token,action,evidence_path):
        data,h,proof=self.observation(evidence_path,self.row(action),'absent')
        with self.tx():
            self.active();w=self.writer(owner,token);row=self.row(action);self.no_pending()
            must(row['state']=='reserved' and row['session']==w['session'],'Action not reserved by this writer')
            from quarantine_extension import ensure_not_quarantined
            ensure_not_quarantined(self,row['kind'],row['target_url'])
            must(json.loads(data)['observed_at']>=self.clock()-300,'Preflight expired')
            self.blob(data);self.blob(proof);nonce=secrets.token_hex(32)
            self.db.execute("UPDATE actions SET state='intent',intent_id=?,intent_at=?,updated_at=?,proof_hash=? WHERE id=?",(nonce,self.clock(),self.clock(),h,action))
            self.event('single_write_intent_committed',owner,action,intent_id=nonce,preflight_hash=h)
        return {'action_id':action,'intent_id':nonce,'state':'intent','may_dispatch':True,'exactly_one_browser_call':True,'lost_response_means_do_not_dispatch':True}
    def transition(self,owner,token,action,state,reason=''):
        allowed={'submitted_unverified':('intent',),'unknown':PENDING,'cancelled':('reserved',)}
        must(state in allowed,'Unsupported transition')
        with self.tx():
            self.active();w=self.writer(owner,token);row=self.row(action)
            must(row['session']==w['session'] and row['state'] in allowed[state],'Wrong owner/state')
            if state=='unknown':
                text(reason,'unknown-outcome reason')
                self.db.execute('INSERT OR IGNORE INTO stops VALUES(?,?,?,?)',(self.account,action,reason,self.clock()))
            self.db.execute('UPDATE actions SET state=?,updated_at=? WHERE id=?',(state,self.clock(),action))
            self.event(state,owner,action,reason=reason)
        return {'action_id':action,'state':state,'may_dispatch':False}
    def verify(self,owner,token,action,evidence_path):
        data,h,proof=self.observation(evidence_path,self.row(action),'present');o=json.loads(data)
        with self.tx():
            self.active();w=self.writer(owner,token);row=self.row(action)
            must(row['session']==w['session'] and row['state'] in ('reserved',)+PENDING,'Action not reconcilable by this writer')
            must(o['intent_id']==row['intent_id'] and o['observed_at']>=self.clock()-300,'Evidence changed/stale while acquiring transaction')
            must(row['intent_at'] is None or o['observed_at']>=row['intent_at'],'Readback predates current intent')
            self.blob(data);self.blob(proof)
            if row['kind'] in ('publish','reply','self_reply'):
                for key in owned_receipts(self.account,o['receipt_urls'],True):
                    prior=self.db.execute('SELECT action_id FROM receipts WHERE receipt_key=?',(key,)).fetchone()
                    must(prior is None or prior[0]==action,'Receipt already consumed by another action')
                    self.db.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,?)',(key,action,h))
            state='already_present' if row['state']=='reserved' else 'verified'
            self.db.execute('UPDATE actions SET state=?,updated_at=?,proof_hash=? WHERE id=?',(state,self.clock(),h,action))
            self.event('browser_readback_attested',owner,action,state=state,proof_hash=h)
        return {'action_id':action,'state':state,'may_dispatch':False,'stop_cleared':False}
    def acknowledge_reconciliation(self,owner,token,action):
        with self.tx():
            self.active();self.writer(owner,token);row=self.row(action)
            stop=self.db.execute('SELECT * FROM stops WHERE account=?',(self.account,)).fetchone()
            must(stop and stop['action_id']==action and row['state']=='verified' and row['proof_hash'],'Exact stopped action needs verified evidence')
            must(not self.db.execute("SELECT 1 FROM actions WHERE state IN ('intent','submitted_unverified','unknown')").fetchone(),'Unresolved writes remain')
            self.db.execute('DELETE FROM stops WHERE account=?',(self.account,));self.event('reconciliation_explicitly_acknowledged',owner,action)
        return {'stopped':False,'may_dispatch':False}
    def release(self,owner,token):
        with self.tx():
            self.active();w=self.writer(owner,token);self.no_pending()
            must(not self.db.execute("SELECT 1 FROM actions WHERE session=? AND state='reserved'",(w['session'],)).fetchone(),'Unfinished reservations remain')
            self.db.execute('DELETE FROM writer WHERE account=?',(self.account,))
            self.db.execute("UPDATE runs SET state='released',ended_at=? WHERE owner=?",(self.clock(),owner))
            self.put('checkpoint_pending','1');self.put('checkpoint_seq',str(int(self.get('checkpoint_seq'))+1))
            self.event('writer_released',owner,session=w['session'],checkpoint_seq=int(self.get('checkpoint_seq')))
        return {'released':True,'checkpoint_pending':True,'checkpoint_seq':int(self.get('checkpoint_seq')),'may_dispatch':False}
    def status(self):
        with self.tx():
            from quarantine_extension import quarantine_records
            quarantines=quarantine_records(self.db,self.account)
            dispositions={r['action_id']:r for r in quarantines}
            actions=[dict(r) for r in self.db.execute('SELECT * FROM actions ORDER BY created_at,id')]
            for row in actions:
                if row['id'] in dispositions:
                    row.update(external_outcome='unknown',termination='operator_accepted_uncertainty',new_verified_count=0,retry_allowed=False,quarantined=True)
            w=self.db.execute('SELECT account,session,owner,role,acquired_at FROM writer').fetchone()
            return {'account':self.account,'db_id':self.get('db_id'),'phase':self.get('phase'),'baseline_hash':self.get('baseline_hash'),'backup_hash':self.get('backup_hash'),
                    'checkpoint_pending':self.get('checkpoint_pending')=='1','checkpoint_seq':int(self.get('checkpoint_seq')),'checkpoint_library_id':self.get('checkpoint_library_id'),'checkpoint_library_version':self.get('checkpoint_library_version'),'checkpoint_archive_hash':self.get('checkpoint_archive_hash'),
                    'writer':dict(w) if w else None,'stops':[dict(r) for r in self.db.execute('SELECT * FROM stops')],
                    'actions':actions,'quarantines':quarantines,
                    'observations':self.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],
                    'audit_events':self.db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],
                    'may_dispatch':False,'original_database_restored':False,'browser_integration':'not_observed_by_cli'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=('init-recovery','status','manifest','import-observation','seal','activate','acquire','claim','begin-write','submitted','unknown','cancel','verify','acknowledge-reconciliation','release','checkpoint-ack','record-denied-before-dispatch','finalize-denied-run','finalize-uncertain-quarantine','quarantines','hash-file'))
    for name in ('db','account','owner','token','role','kind','target','payload-hash','action','evidence','record','sha256','reason','source','incident','incident-sha256','approval','approval-sha256','trusted-review','trusted-review-sha256'):p.add_argument('--'+name)
    args=vars(p.parse_args());command=args.pop('command');db=None
    def need(*keys):
        values=[args[k.replace('-','_')] for k in keys]
        must(all(v is not None for v in values),'Required arguments: '+', '.join('--'+k for k in keys));return values
    try:
        if command=='hash-file':_,h=file_bytes(*need('source'));out={'sha256':h,'may_dispatch':False}
        elif command=='init-recovery':out=Ledger.init_recovery(*need('db','account'))
        else:
            db=Ledger(*need('db','account'))
            if command=='status':out=db.status()
            elif command=='manifest':
                out=db.manifest();out={'manifest':out,'sha256':digest(canonical(out)),'may_dispatch':False}
            elif command=='import-observation':out=db.import_observation(*need('record','sha256'))
            elif command=='seal':out=db.seal(*need('record','sha256'))
            elif command=='activate':out=db.activate(*need('record','sha256'))
            elif command in ('record-denied-before-dispatch','finalize-denied-run'):
                from denial_extension import record_denied,finalize_denied_run
                method=record_denied if command=='record-denied-before-dispatch' else finalize_denied_run
                out=method(db,*need('owner','token','action','record','sha256'))
            elif command=='finalize-uncertain-quarantine':
                from quarantine_extension import finalize_uncertain_quarantine,load_trusted_review
                trusted=load_trusted_review(*need('trusted-review','trusted-review-sha256'))
                out=finalize_uncertain_quarantine(db,*need('owner','token','action',
                    'incident','incident-sha256','approval','approval-sha256'),trusted_review=trusted)
            elif command=='quarantines':
                from quarantine_extension import quarantine_records
                with db.tx():
                    out={'account':db.account,'db_id':db.get('db_id'),'quarantines':quarantine_records(db.db,db.account),'may_dispatch':False}
            elif command=='checkpoint-ack':
                from checkpoint import acknowledge
                out=acknowledge(db,*need('record','sha256'))
            elif command=='acquire':out=db.acquire(*need('owner','role'))
            elif command=='claim':out=db.claim(*need('owner','token','kind','target','payload-hash'))
            elif command=='begin-write':out=db.begin_write(*need('owner','token','action','evidence'))
            elif command in ('submitted','unknown','cancel'):out=db.transition(*need('owner','token','action'),{'submitted':'submitted_unverified','unknown':'unknown','cancel':'cancelled'}[command],args['reason'] or '')
            elif command=='verify':out=db.verify(*need('owner','token','action','evidence'))
            elif command=='acknowledge-reconciliation':out=db.acknowledge_reconciliation(*need('owner','token','action'))
            elif command=='release':out=db.release(*need('owner','token'))
        print(canonical({'ok':True,**out}));return 0
    except (Blocked,OSError,sqlite3.Error,ValueError,TypeError,KeyError,IndexError,zipfile.BadZipFile) as error:
        print(canonical({'ok':False,'may_dispatch':False,'automatic_retry':False,'error':str(error)}),file=sys.stderr);return 2
    finally:
        if db:db.close()

if __name__=='__main__':
    # Helpers import ledger; preserve one module/Blocked class when this file is
    # executed as a script (or python -m ledger), not a second imported copy.
    sys.modules['ledger']=sys.modules[__name__]
    sys.exit(main())
