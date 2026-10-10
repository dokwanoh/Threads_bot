"""Synthetic regression tests for time passing while acquiring/holding SQLite TX."""
import contextlib
import unittest
from unittest import mock
import denial_extension as de
from test_denial_independent import IndependentDenialTests

class DenialFreshnessTests(unittest.TestCase):
    def delay_transaction(self):
        original=self.f.l.tx
        @contextlib.contextmanager
        def delayed():
            with original():
                self.f.now+=3601
                yield
        return mock.patch.object(self.f.l,'tx',delayed)

    def test_attestation_expiring_during_transaction_acquisition_rejected(self):
        self.prepare();p,h=self.evidence();before=self.snapshot()
        with self.delay_transaction():
            self.blocked(de.record_denied,self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertEqual(self.snapshot(),before)

    def test_attestation_expiring_after_audit_rolls_back_everything(self):
        self.prepare();p,h=self.evidence();before=self.snapshot();original=self.f.l.event
        def event(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='denied_before_dispatch_recorded':self.f.now+=3601
            return result
        with mock.patch.object(self.f.l,'event',side_effect=event):
            self.blocked(de.record_denied,self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertEqual(self.snapshot(),before)

    def test_approval_expiring_during_transaction_acquisition_rejected(self):
        self.prepare();self.record();p,h=self.approval();before=self.snapshot()
        with self.delay_transaction():
            self.blocked(de.finalize_denied_run,self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertEqual(self.snapshot(),before)

    def test_approval_expiring_after_release_audit_rolls_back_everything(self):
        self.prepare();self.record();p,h=self.approval();before=self.snapshot();original=self.f.l.event
        def event(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='writer_released':self.f.now+=3601
            return result
        with mock.patch.object(self.f.l,'event',side_effect=event):
            self.blocked(de.finalize_denied_run,self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertEqual(self.snapshot(),before)

    def test_exact_attestation_age_boundary_remains_valid(self):
        self.prepare();p,h=self.evidence();self.f.now+=3600
        out=de.record_denied(self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertTrue(out['stop_retained']);self.assertFalse(out['may_dispatch'])

    def test_exact_approval_age_boundary_remains_valid(self):
        self.prepare();self.record();p,h=self.approval();self.f.now+=3600
        out=de.finalize_denied_run(self.f.l,self.auth['owner'],self.auth['token'],self.key,p,h)
        self.assertTrue(out['checkpoint_pending']);self.assertFalse(out['may_dispatch'])

for name in ('setUp','tearDown','blocked','prepare','evidence','record','approval','finalize','snapshot'):
    setattr(DenialFreshnessTests,name,getattr(IndependentDenialTests,name))
# Imported TestCase class is not exported, so unittest does not double-count it.
del IndependentDenialTests
if __name__=='__main__':unittest.main(verbosity=2)
