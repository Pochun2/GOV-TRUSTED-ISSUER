import copy
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import Mock

from validator.issuer_transaction import Ledger, Intent, FakePublisher, SimulatedCrash
from validator.issuer_reconciliation import (
    ReconciliationError, EXPECTED_APP, EXPECTED_NAME, EXPECTED_REPO,
    MAX_CHECKS, read_local_transaction, reconcile, main,
)


class FakeReader:
    def __init__(self, response):
        self.response = response
        self.paths = []
    def get(self, path):
        self.paths.append(path)
        if isinstance(self.response, Exception):
            raise self.response
        return copy.deepcopy(self.response)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ledger.sqlite'
        self.ledger = Ledger(self.path)
        self.intent = Intent(EXPECTED_REPO, 'a'*40, 'b'*64, 'c'*64, EXPECTED_APP, 19)
        self.key = self.ledger.prepare(self.intent)
        with self.assertRaises(SimulatedCrash):
            self.ledger.publish_mock(self.intent, FakePublisher('crash_after'))
        self.check_id = 123456789
        self.check = dict(id=self.check_id, external_id=self.key, name=EXPECTED_NAME,
                          head_sha=self.intent.head_sha, app={'id':EXPECTED_APP},
                          status='completed', conclusion='success')
        self.checks = {'total_count':1, 'check_runs':[self.check]}
    def observe(self, checks=None, **kwargs):
        reader = FakeReader(self.checks if checks is None else checks)
        result = reconcile(reader, self.path, self.intent,
                           expected_check_id=kwargs.pop('expected_check_id', self.check_id))
        self.assertEqual(reader.paths, [f'/repos/{EXPECTED_REPO}/commits/{self.intent.head_sha}/check-runs?per_page=100'])
        return result
    def denied(self, response=None, **kwargs):
        with self.assertRaises(ReconciliationError):
            self.observe(response, **kwargs)
    def test_success_observation_only(self):
        self.assertEqual(self.observe()['state'], 'REMOTE_MATCH_OBSERVED_NOT_ATTESTED')
        self.assertEqual(self.ledger.state(self.key), 'PUBLISHING')
    def test_returns_only_safe_fields(self):
        self.assertEqual(set(self.observe()), {'state','transaction_id','check_run_id','note'})
    def test_local_record_unchanged(self):
        before=self.path.read_bytes()
        self.observe()
        self.assertEqual(self.path.read_bytes(), before)
    def test_expected_path_is_exact(self):
        self.observe()
    def test_second_observation_no_state_change(self):
        self.observe(); self.observe()
        self.assertEqual(self.ledger.state(self.key),'PUBLISHING')
    def test_unrelated_check_ignored(self):
        other=copy.deepcopy(self.check); other['id']=987; other['external_id']='z'*64
        self.checks={'total_count':2,'check_runs':[other,self.check]}
        self.observe()
    def test_missing_remote(self):
        self.denied({'total_count':0,'check_runs':[]})
    def test_mismatch_external_id(self):
        self.check['external_id']='f'*64;self.denied()
    def test_duplicate_external_id(self):
        other=copy.deepcopy(self.check);other['id']=987
        self.denied({'total_count':2,'check_runs':[self.check,other]})
    def test_duplicate_check_id(self):
        self.denied({'total_count':2,'check_runs':[self.check,self.check]})
    def test_bad_check_id_pin(self):
        self.denied(expected_check_id=2)
    def test_bad_check_id_boolean(self):
        self.denied(expected_check_id=True)
    def test_wrong_app_id(self):
        self.check['app']['id']=15368;self.denied()
    def test_boolean_app_id(self):
        self.check['app']['id']=True;self.denied()
    def test_missing_app(self):
        del self.check['app'];self.denied()
    def test_wrong_name(self):
        self.check['name']='validate';self.denied()
    def test_wrong_head_sha(self):
        self.check['head_sha']='d'*40;self.denied()
    def test_wrong_check_id(self):
        self.check['id']=987;self.denied()
    def test_missing_status(self):
        del self.check['status'];self.denied()
    def test_in_progress(self):
        self.check['status']='in_progress';self.denied()
    def test_failure_conclusion(self):
        self.check['conclusion']='failure';self.denied()
    def test_missing_conclusion(self):
        del self.check['conclusion'];self.denied()
    def test_pagination_rejected(self):
        self.checks['total_count']=2;self.denied()
    def test_more_than_100_rejected(self):
        self.checks['total_count']=101;self.denied()
    def test_bad_shape(self):
        self.denied({'check_runs':[]})
    def test_count_bool_rejected(self):
        self.denied({'total_count':True, 'check_runs':[self.check]})
    def test_list_bad_type(self):
        self.denied({'total_count':1,'check_runs':'x'})
    def test_malformed_check_element(self):
        self.denied({'total_count':1,'check_runs':[None]})
    def test_missing_id(self):
        del self.check['id'];self.denied()
    def test_remote_reader_error(self):
        self.denied(OSError('secret redaction'))
    def test_prepared_not_eligible(self):
        other=replace(self.intent, evidence_sha256='e'*64)
        self.ledger.prepare(other)
        self.denied_for(other)
    def denied_for(self, intent):
        with self.assertRaises(ReconciliationError):
            reconcile(FakeReader(self.checks), self.path, intent, expected_check_id=self.check_id)
    def test_blocked_not_eligible(self):
        self.ledger.seal_uncertain(self.key)
        self.denied()
    def test_mock_published_not_eligible(self):
        other=replace(self.intent, evidence_sha256='e'*64)
        self.ledger.prepare(other)
        self.ledger.publish_mock(other, FakePublisher())
        self.denied_for(other)
    def test_unknown_intent(self):
        self.denied_for(replace(self.intent, policy_sha256='f'*64))
    def test_unapproved_repo(self):
        self.denied_for(replace(self.intent, repo='Pochun2/GOV-TRUSTED-ISSUER'))
    def test_unapproved_app(self):
        self.denied_for(replace(self.intent, app_id=15368))
    def test_invalid_intent_type(self):
        self.denied_for({'repo':EXPECTED_REPO})
    def test_symlink_denied(self):
        alias=Path(self.tmp.name)/'alias.sqlite'
        try: alias.symlink_to(self.path)
        except (OSError,NotImplementedError): self.skipTest('Symlink unavailable')
        with self.assertRaises(ReconciliationError):
            reconcile(FakeReader(self.checks),alias,self.intent,expected_check_id=self.check_id)
    def test_missing_ledger_denied(self):
        with self.assertRaises(ReconciliationError):
            reconcile(FakeReader(self.checks),Path(self.tmp.name)/'absent.sqlite',self.intent,expected_check_id=self.check_id)
    def test_corrupt_ledger_denied(self):
        self.path.write_bytes(b'corrupt')
        self.denied()
    def test_tampered_local_record_denied(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE issuance SET repo='evil/repo'")
            db.commit()
        self.denied()
    def test_forged_receipt_denied(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE issuance SET receipt='MOCK:fake'")
            db.commit()
        self.denied()
    def test_reader_not_called_if_local_invalid(self):
        self.ledger.seal_uncertain(self.key)
        reader=FakeReader(self.checks)
        with self.assertRaises(ReconciliationError):
            reconcile(reader,self.path,self.intent,expected_check_id=self.check_id)
        self.assertEqual(reader.paths,[])
    def test_zero_remote_check_id(self):
        self.denied(expected_check_id=0)
    def test_cli_selfcheck(self):
        self.assertEqual(main(['--self-check']),0)
    def test_cli_default_blocked(self):
        self.assertEqual(main([]),2)


if __name__ == '__main__': unittest.main()
