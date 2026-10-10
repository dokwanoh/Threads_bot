"""Independent-review archive regression, disposable synthetic sources only."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import ledger as m
import package_recovery as package
NOW=1800000000


class BaselineClosureTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='synthetic-quarantine-baseline-');self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.path=self.root/'synthetic.sqlite';m.Ledger.init_recovery(self.path)
        self.l=m.Ledger(self.path,clock=lambda:NOW);self.addCleanup(self.l.close)
        proof=self.root/'public.txt';proof.write_text('Synthetic archived public observation.')
        record={'schema':'public-action-observation-v1','account':self.l.account,'kind':'like',
            'target':'https://threads.com/@synthetic/post/ArchiveClosure','classification':'current_observed',
            'observed_at':NOW,'reference':'synthetic only','source_file':str(proof),
            'source_sha256':m.digest(proof.read_bytes()),'payload':None,'receipt_urls':[]}
        self.l.import_observation(*self.save('observation.json',record))
        review={'schema':'recovery-review-v1','account':self.l.account,
            'manifest_sha256':m.digest(m.canonical(self.l.manifest())),'review_reference':'synthetic only',
            'known_gaps':['Synthetic fixture only'],'fresh_duplicate_checks_required':True,'reviewed_at':NOW}
        self.l.seal(*self.save('review.json',review))
        self.archive=self.root/'baseline.zip';package.package(self.path,self.archive,source_dir=ROOT)

    def save(self,name,value):
        path=self.root/name;path.write_text(m.canonical(value));return path,m.digest(path.read_bytes())

    def activate(self,path):
        return self.l.activate(*self.save('receipt.json',{'schema':'library-roundtrip-verification-v1',
            'account':self.l.account,'db_id':self.l.get('db_id'),'baseline_hash':self.l.get('baseline_hash'),
            'library_file_id':'synthetic-baseline','library_version':'1','archive_sha256':m.digest(path.read_bytes()),
            'downloaded_archive':str(path),'transport_reference':'SYNTHETIC LOCAL ONLY; no Library transfer','verified_at':NOW}))

    def test_complete_new_baseline_activates(self):
        self.assertEqual(self.activate(self.archive)['phase'],'active')
        self.assertEqual(self.l.status()['quarantines'],[])

    def test_missing_new_required_dependency_never_activates(self):
        for dropped in ['quarantine_extension.py','QUARANTINE.md']:
            with self.subTest(dropped=dropped):
                with zipfile.ZipFile(self.archive) as z:members={n:z.read(n) for n in z.namelist()}
                manifest=json.loads(members['PACKAGE_MANIFEST.json']);del members[dropped];del manifest['members'][dropped]
                members['PACKAGE_MANIFEST.json']=m.canonical(manifest).encode()
                path=self.root/('missing-'+dropped+'.zip')
                with zipfile.ZipFile(path,'w') as z:
                    for name,data in members.items():z.writestr(name,data)
                before='\n'.join(self.l.db.iterdump())
                with self.assertRaisesRegex(m.Blocked,'Required backup members missing'):self.activate(path)
                self.assertEqual(before,'\n'.join(self.l.db.iterdump()))
                self.assertEqual(self.l.get('phase'),'sealed')

if __name__=='__main__':unittest.main()
