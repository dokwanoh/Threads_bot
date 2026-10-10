"""Portable-publication regressions; all identities and databases are synthetic."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import checkpoint
import ledger
import package_recovery
from settings import ConfigurationError, load_settings
from test_independent import Fixture, ROOT, ACCOUNT


class SettingsTests(unittest.TestCase):
    def test_defaults_are_synthetic_and_disjoint(self):
        settings = load_settings({})
        self.assertEqual(settings.account, "example.bot")
        self.assertEqual(settings.blog_host, "blog.example")
        self.assertFalse(settings.staging_root.is_relative_to(settings.production_root))
        self.assertFalse(settings.production_root.is_relative_to(settings.staging_root))

    def test_explicit_non_secret_settings(self):
        with tempfile.TemporaryDirectory() as root:
            settings = load_settings({"THREADS_BOT_ACCOUNT": "other.example",
                "THREADS_BOT_BLOG_HOST": "articles.example.org",
                "THREADS_BOT_STAGING_ROOT": str(Path(root) / "staging"),
                "THREADS_BOT_PRODUCTION_ROOT": str(Path(root) / "production")})
            self.assertEqual(settings.account, "other.example")
            self.assertEqual(settings.blog_host, "articles.example.org")
            self.assertFalse(settings.staging_root.exists())
            self.assertFalse(settings.production_root.exists())

    def test_rejects_invalid_account_and_blog(self):
        for key, values in {
            "THREADS_BOT_ACCOUNT": ["", "@someone", "MixedCase", "contains space", "a" * 65],
            "THREADS_BOT_BLOG_HOST": ["", "https://blog.example", "blog.example:443",
                "blog.example/path", "Blog.Example", "localhost", "-bad.example", "bad-.example"],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                    load_settings({key: value})

    def test_rejects_relative_root_filesystem_root_and_overlap(self):
        with tempfile.TemporaryDirectory() as root:
            for staging, production in [("relative", str(Path(root) / "production")),
                    ("/", str(Path(root) / "production")), (root, root),
                    (str(Path(root) / "nested"), root), (root, str(Path(root) / "nested"))]:
                with self.subTest(staging=staging, production=production), self.assertRaises(ConfigurationError):
                    load_settings({"THREADS_BOT_STAGING_ROOT": staging,
                                   "THREADS_BOT_PRODUCTION_ROOT": production})

    def test_rejects_symlinked_root(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "actual").mkdir()
            (root / "alias").symlink_to(root / "actual", target_is_directory=True)
            with self.assertRaises(ConfigurationError):
                load_settings({"THREADS_BOT_STAGING_ROOT": str(root / "alias" / "child")})

    def test_configured_blog_keys_match_across_both_gates(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("THREADS_BOT_")}
        env.update(THREADS_BOT_ACCOUNT="other.example", THREADS_BOT_BLOG_HOST="articles.example.org")
        script = """
import json, ledger
from dispatch_gate import action_id, GateBlocked
url='https://articles.example.org/123'
assert ledger.action_key(ledger.ACCOUNT,'publish',url)==action_id(ledger.ACCOUNT,'publish',url)
for fn in (ledger.action_key,action_id):
    try: fn(ledger.ACCOUNT,'publish','https://blog.example/123')
    except (ledger.Blocked,GateBlocked): pass
    else: raise AssertionError('Unconfigured host accepted')
print(json.dumps({'account':ledger.ACCOUNT,'matched':True}))
"""
        out = subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT,
                             env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), {"account": "other.example", "matched": True})

    def test_configured_production_root_still_rejects_empty_initialization(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(ledger, "OLD_RUNTIME", Path(root)):
                with self.assertRaises(ledger.Blocked):
                    ledger.Ledger.init_recovery(Path(root) / "candidate.sqlite", ACCOUNT)
                self.assertFalse((Path(root) / "candidate.sqlite").exists())


class PortableArchiveTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    def test_recovery_archive_contains_settings_and_excludes_unallowlisted_files(self):
        self.fixture.seal()
        out = self.fixture.root / "recovery.zip"
        package_recovery.package(self.fixture.path, out, account=ACCOUNT)
        with zipfile.ZipFile(out) as archive:
            self.assertIn("settings.py", archive.namelist())
            self.assertNotIn(".env.example", archive.namelist())
            self.assertNotIn("test_settings.py", archive.namelist())
            self.assertNotIn("test_coordinator.py", archive.namelist())
        p, h = self.fixture.receipt(out)
        self.assertEqual(self.fixture.l.activate(p, h)["phase"], "active")

    def test_recovery_without_settings_fails_closed(self):
        self.fixture.seal()
        archive = self.fixture.make_archive()
        with zipfile.ZipFile(archive) as source:
            members = {name: source.read(name) for name in source.namelist() if name != "settings.py"}
        manifest = json.loads(members["PACKAGE_MANIFEST.json"])
        del manifest["members"]["settings.py"]
        members["PACKAGE_MANIFEST.json"] = ledger.canonical(manifest).encode()
        with zipfile.ZipFile(archive, "w") as destination:
            for name, data in members.items():
                destination.writestr(name, data)
        p, h = self.fixture.receipt(archive)
        with self.assertRaises(ledger.Blocked):
            self.fixture.l.activate(p, h)
        self.assertEqual(self.fixture.l.get("phase"), "sealed")

    def test_checkpoint_archive_contains_settings(self):
        auth = self.fixture.active()
        self.fixture.l.release(auth["owner"], auth["token"])
        path = self.fixture.root / "checkpoint.zip"
        checkpoint.package(self.fixture.path, path, account=ACCOUNT)
        with zipfile.ZipFile(path) as archive:
            self.assertIn("settings.py", archive.namelist())


if __name__ == "__main__":
    unittest.main(verbosity=2)
