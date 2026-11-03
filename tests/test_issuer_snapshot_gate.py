"""Synthetic snapshot and durable replay tests: never contact GitHub."""
import dataclasses
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from validator.issuer_snapshot_gate import Check, Snapshot, reserve_replay, validate_snapshot

class IssuerSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.sc=Check('mf002078/GOV-GITHUB','validate','a'*40,'success',15368,11,1)
        self.vc=Check('mf002078/GOV-PROTECTED-VALIDATOR','self-test','b'*40,'success',15368,12,1)
        self.s=Snapshot('mf002078/GOV-GITHUB','a'*40,'c'*40,
            'mf002078/GOV-PROTECTED-VALIDATOR','b'*40,'d'*64,'e'*64,
            'REVIEWED_NO_ATTESTATION','a'*40,self.sc,self.vc,'2026-11-03T05:00:00Z')
    def decision(self,s=None,**kw):
        return validate_snapshot(s or self.s,source_head=kw.get('source','a'*40),
             validator_head=kw.get('validator','b'*40),policy_sha256=kw.get('policy','d'*64),
             now_utc=kw.get('now','2026-11-03T05:00:05Z'))
    def test_consistent_snapshot_not_attestation(self):
        self.assertEqual(self.decision(),'ELIGIBLE_FOR_AUTHENTICATED_ISSUER_RECHECK')
    def test_stale_source_head(self):self.assertEqual(self.decision(source='f'*40),'BLOCKED')
    def test_stale_validator_head(self):self.assertEqual(self.decision(validator='f'*40),'BLOCKED')
    def test_wrong_policy(self):self.assertEqual(self.decision(policy='f'*64),'BLOCKED')
    def test_cross_repo_check_swapped(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,source_check=self.vc)),'BLOCKED')
    def test_wrong_source_check_app(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,source_check=dataclasses.replace(self.sc,app_id=14))),'BLOCKED')
    def test_boolean_app_id(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,source_check=dataclasses.replace(self.sc,app_id=True))),'BLOCKED')
    def test_wrong_validator_sha(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,validator_check=dataclasses.replace(self.vc,sha='f'*40))),'BLOCKED')
    def test_failed_ci(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,source_check=dataclasses.replace(self.sc,conclusion='failure'))),'BLOCKED')
    def test_untrusted_model_claim(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,model_state='PASS')),'BLOCKED')
    def test_future_observation(self):self.assertEqual(self.decision(now='2026-11-03T04:59:59Z'),'BLOCKED')
    def test_expired_observation(self):self.assertEqual(self.decision(now='2026-11-03T05:05:01Z'),'BLOCKED')
    def test_invalid_observation(self):self.assertEqual(self.decision(dataclasses.replace(self.s,observed_at_utc='2026-13-03T05:00:00Z')),'BLOCKED')
    def test_bad_run_number(self):
        self.assertEqual(self.decision(dataclasses.replace(self.s,source_check=dataclasses.replace(self.sc,run_id=0))),'BLOCKED')
    def test_source_base_equals_head(self):self.assertEqual(self.decision(dataclasses.replace(self.s,source_base='a'*40)),'BLOCKED')
    def test_invalid_report_digest(self):self.assertEqual(self.decision(dataclasses.replace(self.s,model_report_sha256='bad')),'BLOCKED')
    def test_replay_sqlite_persistent(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'replay.sqlite'
            args=dict(source_sha='a'*40,validator_sha='b'*40,source_run=11,
                      source_attempt=1,validator_run=12,validator_attempt=1,
                      model_report_sha256='e'*64)
            with closing(sqlite3.connect(path, isolation_level=None)) as c:
                self.assertTrue(reserve_replay(c,**args))
            with closing(sqlite3.connect(path, isolation_level=None)) as c:
                self.assertFalse(reserve_replay(c,**args))
                self.assertTrue(reserve_replay(c,**dict(args,validator_attempt=2)))
    def test_replay_invalid_values(self):
        with closing(sqlite3.connect(':memory:',isolation_level=None)) as c:
            args=dict(source_sha='a'*40,validator_sha='b'*40,source_run=11,
                      source_attempt=1,validator_run=12,validator_attempt=1,model_report_sha256='e'*64)
            self.assertFalse(reserve_replay(c,**dict(args,source_run=True)))
            self.assertFalse(reserve_replay(c,**dict(args,source_sha='x')))

if __name__=='__main__':unittest.main()
