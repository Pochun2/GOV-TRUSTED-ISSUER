import base64
import copy
import hashlib
import json
import unittest
from validator.github_api_evidence import SOURCE_REPO, VALIDATOR_REPO, EvidenceError
from validator.issuer_trust_boundary import (parse_trust_policy, verify_trust_boundary_pair,
    verify_workflow_boundary, WorkflowReader)

A='a'*40; B='b'*40; C='c'*40; D='d'*40
PATH='.github/workflows/governance.yml'
BLOB=b'name: Trusted test\non: pull_request\npermissions: {}\n'
DIGEST=hashlib.sha256(BLOB).hexdigest()
BLOB_SHA=hashlib.sha1(b'blob '+str(len(BLOB)).encode()+b'\x00'+BLOB).hexdigest()

def policy():
    return {'schema':'issuer-workflow-binding-v1','policy':'stage012a-readonly-v1',
       'targets':[{'repo':r,'run':run,'attempt':1,'head':head,'base':base,
                   'workflow_path':PATH,'workflow_id':wf,'workflow_sha256':DIGEST}
                  for r,run,head,base,wf in ((SOURCE_REPO,101,A,B,1001),(VALIDATOR_REPO,202,C,D,2002))]}

def contents(blob=BLOB):
    return {'type':'file','path':PATH,'size':len(blob),'sha':hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest(),
            'encoding':'base64','content':base64.b64encode(blob).decode()}

def fixtures():
    data={};p=policy()
    for t in p['targets']:
        root='/repos/'+t['repo']
        data[root+'/actions/runs/'+str(t['run'])]={
            'id':t['run'],'run_attempt':1,'workflow_id':t['workflow_id'],
            'path':PATH,'event':'pull_request','head_sha':t['head'],
            'repository':{'full_name':t['repo']},'status':'completed','conclusion':'success'}
        for ref in (t['head'],t['base']):
            data[root+'/contents/'+PATH+'?ref='+ref]=contents()
    return data
class FakeReader:
    def __init__(self,data):self.data=data
    def get(self,path):
        if path not in self.data: raise EvidenceError('EVIDENCE_NOT_FOUND')
        return copy.deepcopy(self.data[path])
class TrustBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.p=policy();self.d=fixtures()
    def attempt(self):
        raw=json.dumps(self.p,sort_keys=True).encode()
        return verify_trust_boundary_pair(FakeReader(self.d),raw,hashlib.sha256(raw).hexdigest())
    def rejected(self):
        with self.assertRaises(EvidenceError):self.attempt()
    def test_positive_pair_not_attestation(self):
        self.assertEqual(self.attempt()['state'],'PAIR_WORKFLOW_BOUNDARY_OBSERVED_NOT_ATTESTED')
    def test_run_workflow_id_spoof(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['workflow_id']=999;self.rejected()
    def test_run_workflow_path_spoof(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['path']='.github/workflows/evil.yml';self.rejected()
    def test_run_head_stale(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['head_sha']=C;self.rejected()
    def test_run_attempt_stale(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['run_attempt']=2;self.rejected()
    def test_run_failure(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['conclusion']='failure';self.rejected()
    def test_run_wrong_event(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['event']='workflow_dispatch';self.rejected()
    def test_run_wrong_repo(self):
        self.d[f'/repos/{SOURCE_REPO}/actions/runs/101']['repository']['full_name']=VALIDATOR_REPO;self.rejected()
    def test_head_workflow_tampered(self):
        path=f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={A}'
        self.d[path]=contents(BLOB+b'# attack\n');self.rejected()
    def test_base_workflow_tampered(self):
        path=f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={B}'
        self.d[path]=contents(BLOB+b'# malicious base\n');self.rejected()
    def test_content_metadata_path_spoof(self):
        self.d[f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={A}']['path']='other.yml';self.rejected()
    def test_content_blob_sha_spoof(self):
        self.d[f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={A}']['sha']=A;self.rejected()
    def test_content_invalid_base64(self):
        self.d[f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={A}']['content']='%%';self.rejected()
    def test_content_oversize(self):
        self.d[f'/repos/{SOURCE_REPO}/contents/{PATH}?ref={A}']['size']=300000;self.rejected()
    def test_policy_digest_mismatch(self):
        raw=json.dumps(self.p).encode()
        with self.assertRaises(EvidenceError):parse_trust_policy(raw,'f'*64)
    def test_policy_changed_workflow(self):
        self.p['targets'][0]['workflow_path']='.github/workflows/untrusted.yml';self.rejected()
    def test_policy_extra_field(self):
        self.p['private_key']='secret';self.rejected()
    def test_policy_duplicate_repository(self):
        self.p['targets'][1]['repo']=SOURCE_REPO;self.rejected()
    def test_policy_invalid_workflow_id_boolean(self):
        self.p['targets'][0]['workflow_id']=True;self.rejected()
    def test_policy_invalid_path_traversal(self):
        self.p['targets'][0]['workflow_path']='.github/workflows/../evil.yml';self.rejected()
    def test_policy_bad_sha(self):
        self.p['targets'][0]['head']='not-sha';self.rejected()
    def test_policy_no_pinning_authority(self):
        raw=json.dumps(self.p).encode()
        with self.assertRaises(EvidenceError):parse_trust_policy(raw,'0'*64)
    def test_reader_reject_unapproved_contents_repo(self):
        reader=WorkflowReader()
        with self.assertRaises(EvidenceError):reader.get('/repos/evil/evil/contents/'+PATH+'?ref='+A)
    def test_reader_reject_url_attack(self):
        reader=WorkflowReader()
        with self.assertRaises(EvidenceError):reader.get('https://example.com/evil')

if __name__=='__main__':unittest.main()
