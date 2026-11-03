import copy
import unittest
from validator.github_api_evidence import SOURCE_REPO, VALIDATOR_REPO, EvidenceError
from validator.live_api_probe import verify_pr_run, LiveReader
from test_github_api_evidence import fixtures

A='a'*40
B='b'*40
M='c'*40
BASE='d'*40

class FakeReader:
    def __init__(self, data): self.data=data
    def get(self,path):
        if path not in self.data: raise EvidenceError('NOT_FOUND')
        return copy.deepcopy(self.data[path])

class LiveEvidenceTests(unittest.TestCase):
    def setUp(self):
        r=SOURCE_REPO
        self.root='/repos/'+r
        self.data=fixtures()
        self.pr={'number':5,'state':'open','head':{'sha':A,'repo':{'full_name':r}},
                 'base':{'sha':BASE,'repo':{'full_name':r}}}
        self.data[self.root+'/pulls/5']=self.pr
        run=self.data[self.root+'/actions/runs/101']
        run['event']='pull_request'
        run['pull_requests']=[{'number':5,'head':{'sha':A}}]
        self.kw=dict(repo=r,pr_number=5,expected_head=A,expected_base=BASE,
                     run_id=101,run_attempt=1,expected_job='validate')
    def check(self): return verify_pr_run(FakeReader(self.data),**self.kw)
    def rejected(self):
        with self.assertRaises(EvidenceError): self.check()
    def test_direct_head_observation(self):
        self.assertEqual(self.check()['sha_mode'],'DIRECT_HEAD')
    def test_not_attested(self):
        self.assertEqual(self.check()['state'],'OBSERVED_API_CONSISTENCY_ONLY_NOT_ATTESTED')
    def test_pr_head_mismatch(self):
        self.data[self.root+'/pulls/5']['head']['sha']=B;self.rejected()
    def test_pr_base_mismatch(self):
        self.data[self.root+'/pulls/5']['base']['sha']=B;self.rejected()
    def test_pr_closed(self):
        self.data[self.root+'/pulls/5']['state']='closed';self.rejected()
    def test_run_wrong_event(self):
        self.data[self.root+'/actions/runs/101']['event']='workflow_dispatch';self.rejected()
    def test_run_no_association(self):
        self.data[self.root+'/actions/runs/101']['pull_requests']=[];self.rejected()
    def test_run_wrong_pr_number(self):
        self.data[self.root+'/actions/runs/101']['pull_requests'][0]['number']=9;self.rejected()
    def test_run_wrong_pr_sha(self):
        self.data[self.root+'/actions/runs/101']['pull_requests'][0]['head']['sha']=B;self.rejected()
    def test_wrong_base_repo(self):
        self.data[self.root+'/pulls/5']['base']['repo']['full_name']=VALIDATOR_REPO;self.rejected()
    def test_wrong_job(self):
        self.kw['expected_job']='self-test';self.rejected()
    def test_bool_pr(self):
        self.kw['pr_number']=True
        with self.assertRaises(EvidenceError):self.check()
    def test_merge_parent_spoof(self):
        self.data[self.root+'/actions/runs/101']['head_sha']=M
        self.data[self.root+'/commits/'+M]={'sha':M,'parents':[{'sha':BASE},{'sha':B}]}
        self.rejected()
    def test_merge_missing_second_parent(self):
        self.data[self.root+'/actions/runs/101']['head_sha']=M
        self.data[self.root+'/commits/'+M]={'sha':M,'parents':[{'sha':BASE}]}
        self.rejected()
    def test_merge_success(self):
        self.data[self.root+'/actions/runs/101']['head_sha']=M
        self.data[self.root+'/commits/'+M]={'sha':M,'parents':[{'sha':BASE},{'sha':A}]}
        self.data[self.root+'/actions/runs/101/jobs?per_page=100']['jobs'][0]['head_sha']=M
        self.data[self.root+'/actions/runs/101/jobs?per_page=100']['jobs'][0]['check_run_url']=f'https://api.github.com/repos/{SOURCE_REPO}/check-runs/102'
        check=self.data.pop(self.root+'/commits/'+A+'/check-runs?per_page=100')
        check['check_runs'][0]['head_sha']=M
        self.data[self.root+'/commits/'+M+'/check-runs?per_page=100']=check
        self.assertEqual(self.check()['sha_mode'],'SYNTHETIC_MERGE')
    def test_merge_job_stale(self):
        self.data[self.root+'/actions/runs/101']['head_sha']=M
        self.data[self.root+'/commits/'+M]={'sha':M,'parents':[{'sha':BASE},{'sha':A}]}
        self.rejected()
    def test_unapproved_repo(self):
        self.kw['repo']='bad/repo'
        with self.assertRaises(EvidenceError): self.check()
    def test_reader_reject_unknown_domain(self):
        with self.assertRaises(EvidenceError): LiveReader().get('https://example.com')
    def test_reader_reject_unknown_repository_pr(self):
        with self.assertRaises(EvidenceError): LiveReader().get('/repos/evil/repo/pulls/1')

if __name__=='__main__':unittest.main()
