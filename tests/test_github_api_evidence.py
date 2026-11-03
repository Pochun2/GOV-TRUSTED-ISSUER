import unittest
from copy import deepcopy
from validator.github_api_evidence import (Target, verify_pair, verify_one, EvidenceError,
    SOURCE_REPO, VALIDATOR_REPO)

A='a'*40
B='b'*40

def fixtures():
    d={}
    for repo,sha,run_id,job in [(SOURCE_REPO,A,101,'validate'),(VALIDATOR_REPO,B,202,'self-test')]:
        root='/repos/'+repo
        d[root+f'/actions/runs/{run_id}']={
            'id':run_id,'run_attempt':1,'head_sha':sha,'status':'completed',
            'conclusion':'success','repository':{'full_name':repo}}
        d[root+f'/actions/runs/{run_id}/jobs?per_page=100']={
            'total_count':1,'jobs':[{'id':run_id+1,'run_id':run_id,'run_attempt':1,
            'name':job,'head_sha':sha,'status':'completed','conclusion':'success',
            'check_run_url':f'https://api.github.com/repos/{repo}/check-runs/{run_id+1}'}]}
        d[root+f'/commits/{sha}/check-runs?per_page=100']={
            'total_count':1,'check_runs':[{'id':run_id+1,'name':job,'head_sha':sha,
            'status':'completed','conclusion':'success','app':{'id':15368}}]}
    return d

class FakeReader:
    def __init__(self, data): self.data=data
    def get(self,path): return deepcopy(self.data[path])

class APIEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.data=fixtures()
        self.src=Target(SOURCE_REPO,A,101,1,'validate')
        self.val=Target(VALIDATOR_REPO,B,202,1,'self-test')
    def check(self): return verify_pair(FakeReader(self.data),self.src,self.val)
    def rejected(self):
        with self.assertRaises(EvidenceError): self.check()
    def test_positive_not_attestation(self): self.assertEqual(self.check()['state'],'ELIGIBLE_FOR_FURTHER_ISSUER_POLICY_REVIEW')
    def test_cross_repo_swapped(self):
        with self.assertRaises(EvidenceError): verify_pair(FakeReader(self.data),self.val,self.src)
    def test_source_run_stale_sha(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['head_sha']=B;self.rejected()
    def test_validator_run_stale_sha(self):
        self.data[f'/repos/{VALIDATOR_REPO}/actions/runs/202']['head_sha']=A;self.rejected()
    def test_run_incomplete(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['status']='in_progress';self.rejected()
    def test_run_failure(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['conclusion']='failure';self.rejected()
    def test_attempt_mismatch(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['run_attempt']=2;self.rejected()
    def test_repository_mismatch(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101']['repository']['full_name']=VALIDATOR_REPO;self.rejected()
    def test_job_failure(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['conclusion']='failure';self.rejected()
    def test_job_missing(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['name']='other';self.rejected()
    def test_job_duplicate(self):
        d=self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100'];d['jobs'].append(deepcopy(d['jobs'][0]));d['total_count']=2;self.rejected()
    def test_jobs_pagination(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['total_count']=101;self.rejected()
    def test_check_app_spoof(self):
        self.data[f'/repos/{SOURCE_REPO}/commits/{A}/check-runs?per_page=100']['check_runs'][0]['app']['id']=1;self.rejected()
    def test_check_failure(self):
        self.data[f'/repos/{VALIDATOR_REPO}/commits/{B}/check-runs?per_page=100']['check_runs'][0]['conclusion']='failure';self.rejected()
    def test_wrong_check_identity(self):
        self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['check_run_url']='https://evil.example/check-runs/102';self.rejected()
    def test_missing_check_identity(self):
        del self.data[f'/repos/{SOURCE_REPO}/actions/runs/101/jobs?per_page=100']['jobs'][0]['check_run_url'];self.rejected()
    def test_checks_pagination(self):
        self.data[f'/repos/{SOURCE_REPO}/commits/{A}/check-runs?per_page=100']['total_count']=101;self.rejected()
    def test_boolean_run_id(self):
        with self.assertRaises(EvidenceError): verify_one(FakeReader(self.data),Target(SOURCE_REPO,A,True,1,'validate'))
    def test_wrong_job(self):
        with self.assertRaises(EvidenceError): verify_one(FakeReader(self.data),Target(SOURCE_REPO,A,101,1,'self-test'))
    def test_invalid_sha(self):
        with self.assertRaises(EvidenceError): verify_one(FakeReader(self.data),Target(SOURCE_REPO,'bad',101,1,'validate'))

if __name__=='__main__': unittest.main()
