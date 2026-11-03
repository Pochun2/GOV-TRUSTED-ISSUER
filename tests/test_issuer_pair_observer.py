import copy
import hashlib
import json
import sqlite3
from contextlib import closing
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from validator.github_api_evidence import EvidenceError, SOURCE_REPO, VALIDATOR_REPO
from validator.issuer_pair_observer import (
    SCHEMA, POLICY, read_policy_bytes, observe_pair, record_observation,
    _utc, _check_time, main,
)
from test_github_api_evidence import fixtures

A='a'*40; B='b'*40; BASE='d'*40
NOW=datetime(2026,11,3,12,0,0,tzinfo=timezone.utc)

class FakeReader:
    def __init__(self, data): self.data=data
    def get(self,path):
        if path not in self.data: raise EvidenceError('NOT_FOUND')
        return copy.deepcopy(self.data[path])

def policy():
    return {'schema':SCHEMA,'policy':POLICY,'max_age_seconds':3600,'max_skew_seconds':300,
        'targets':[
          {'repo':SOURCE_REPO,'pr':5,'head':A,'base':BASE,'run':101,'attempt':1,'job':'validate'},
          {'repo':VALIDATOR_REPO,'pr':6,'head':B,'base':BASE,'run':202,'attempt':1,'job':'self-test'}]}

def data_fixture():
    d=fixtures()
    for repo,sha,number,run in ((SOURCE_REPO,A,5,101),(VALIDATOR_REPO,B,6,202)):
        root='/repos/'+repo
        d[root+f'/pulls/{number}']={'number':number,'state':'open',
            'head':{'sha':sha,'repo':{'full_name':repo}},
            'base':{'sha':BASE,'repo':{'full_name':repo}}}
        d[root+f'/actions/runs/{run}'].update({
            'event':'pull_request', 'pull_requests':[{'number':number,'head':{'sha':sha}}]})
        job=d[root+f'/actions/runs/{run}/jobs?per_page=100']['jobs'][0]
        job.update({'started_at':'2026-11-03T11:48:00Z',
                    'completed_at':'2026-11-03T11:50:00Z'})
    return d

class PairObservationTests(unittest.TestCase):
    def setUp(self):
        self.data=data_fixture(); self.p=policy()
    def result(self):return observe_pair(FakeReader(self.data),self.p,now=NOW)
    def denied(self):
        with self.assertRaises(EvidenceError): self.result()
    def test_positive_pair(self):
        result=self.result();self.assertEqual(result['state'],'PAIR_OBSERVED_NOT_ATTESTED')
    def test_missing_validator(self):
        del self.data[f'/repos/{VALIDATOR_REPO}/pulls/6'];self.denied()
    def test_validator_run_failure(self):
        self.data[f'/repos/{VALIDATOR_REPO}/actions/runs/202']['conclusion']='failure';self.denied()
    def test_stale_source_job(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['completed_at']='2026-11-03T08:00:00Z';self.denied()
    def test_future_source_job(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['completed_at']='2026-11-03T12:01:00Z';self.denied()
    def test_job_timestamp_missing(self):
        del self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['completed_at'];self.denied()
    def test_job_reverse_time(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['started_at']='2026-11-03T11:51:00Z';self.denied()
    def test_source_validator_skew(self):
        job=self.data[f'/repos/{VALIDATOR_REPO}/actions/runs/202/jobs?per_page=100']['jobs'][0]
        job.update({'started_at':'2026-11-03T11:33:00Z','completed_at':'2026-11-03T11:35:00Z'});self.denied()
    def test_duplicate_time_jobs(self):
        entry=self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']
        entry['jobs'].append(copy.deepcopy(entry['jobs'][0]));entry['total_count']=2;self.denied()
    def test_run_missing_pr_association(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['pull_requests']=[];self.denied()
    def test_bad_current_head(self):
        self.data[f'/repos/{SOURCE_REPO}/pulls/5']['head']['sha']=B;self.denied()
    def test_policy_parse_positive(self):
        self.assertEqual(read_policy_bytes(json.dumps(self.p).encode())['schema'],SCHEMA)
    def test_policy_duplicate_repo(self):
        p=copy.deepcopy(self.p);p['targets'][1]['repo']=SOURCE_REPO
        with self.assertRaises(EvidenceError):read_policy_bytes(json.dumps(p).encode())
    def test_policy_unknown_job(self):
        p=copy.deepcopy(self.p);p['targets'][0]['job']='unsafe'
        with self.assertRaises(EvidenceError):read_policy_bytes(json.dumps(p).encode())
    def test_policy_bool_run(self):
        p=copy.deepcopy(self.p);p['targets'][0]['run']=True
        with self.assertRaises(EvidenceError):read_policy_bytes(json.dumps(p).encode())
    def test_policy_invalid_age(self):
        p=copy.deepcopy(self.p);p['max_age_seconds']=86401
        with self.assertRaises(EvidenceError):read_policy_bytes(json.dumps(p).encode())
    def test_policy_extra_fields(self):
        p=copy.deepcopy(self.p);p['token']='secret'
        with self.assertRaises(EvidenceError):read_policy_bytes(json.dumps(p).encode())
    def test_bad_utc_timezone(self):
        with self.assertRaises(EvidenceError):_utc('2026-11-03T11:50:00+08:00')
    def test_observation_ledger_replay(self):
        r=self.result()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'observation.sqlite'
            ident=record_observation(p,'e'*64,r)
            self.assertEqual(len(ident),64)
            with self.assertRaises(EvidenceError): record_observation(p,'e'*64,r)
            with closing(sqlite3.connect(p)) as c:
                self.assertEqual(c.execute('SELECT COUNT(*) FROM observation').fetchone()[0],1)
    def test_ledger_preserves_distinct_policy(self):
        r=self.result()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'observation.sqlite'
            self.assertNotEqual(record_observation(p,'e'*64,r),record_observation(p,'f'*64,r))
    def test_ledger_missing_parent(self):
        with self.assertRaises(EvidenceError):record_observation('/this/path/not/existing/ledger.db','e'*64,self.result())
    def test_ledger_invalid_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EvidenceError):record_observation(Path(tmp)/'x.sqlite','invalid',self.result())

if __name__=='__main__':unittest.main()
