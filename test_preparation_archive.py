"""Synthetic archive dependency regression; no service or runtime operations."""
import json
from pathlib import Path
import unittest
import zipfile

import test_quarantine_plumbing as plumbing
m,cp=plumbing.m,plumbing.cp


class PreparationArchiveTests(unittest.TestCase):
    def test_runtime_archive_requires_preparation_dependencies(self):
        fixture=plumbing.PlumbingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        archive,receipt,path=fixture.checkpoint()
        f=fixture.f
        for dropped in ['publisher_preparation.py','PREPARATION.md','settings.py']:
            with self.subTest(dropped=dropped):
                with zipfile.ZipFile(archive) as z:
                    members={n:z.read(n) for n in z.namelist()}
                self.assertIn(dropped,members)
                del members[dropped]
                manifest=json.loads(members['PACKAGE_MANIFEST.json'])
                del manifest['members'][dropped]
                members['PACKAGE_MANIFEST.json']=m.canonical(manifest).encode()
                modified=f.root/('missing-'+dropped+'.zip')
                with zipfile.ZipFile(modified,'w') as z:
                    for name,data in members.items():z.writestr(name,data)
                broken={**receipt,'downloaded_archive':str(modified),
                        'archive_sha256':m.digest(modified.read_bytes())}
                path.write_text(m.canonical(broken))
                before=f.snapshot()
                with self.assertRaisesRegex(m.Blocked,'Required checkpoint members missing'):
                    cp.acknowledge(f.l,path,m.digest(path.read_bytes()))
                self.assertEqual(before,f.snapshot())
                self.assertEqual(f.l.get('checkpoint_pending'),'1')


if __name__=='__main__':unittest.main()
