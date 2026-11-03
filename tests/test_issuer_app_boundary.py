import copy
import hashlib
import json
import unittest
from validator.issuer_app_boundary import (
    APP_SCHEMA, APP_POLICY, PERMISSIONS, BoundaryError,
    policy_from_bytes, verify_offline_contract)


def fixture():
    p = dict(schema=APP_SCHEMA, policy=APP_POLICY, app_id=5475837,
             app_slug='gov-protected-validator', installation_id=12345,
             account_id=62813082, account_login='mf002078',
             repository_id=1432125680, repository='mf002078/GOV-GITHUB',
             permissions=copy.deepcopy(PERMISSIONS), token_expiry_seconds=3600)
    app = {'id':p['app_id'], 'slug':p['app_slug'], 'permissions':copy.deepcopy(PERMISSIONS)}
    ins = {'id':p['installation_id'], 'app_id':p['app_id'],
           'account':{'id':p['account_id'],'login':p['account_login']},
           'repository_selection':'selected', 'suspended_at':None,
           'permissions':copy.deepcopy(PERMISSIONS)}
    repos = {'total_count':1, 'repositories':[{'id':p['repository_id'],
              'full_name':p['repository'],'owner':{'id':p['account_id'],'login':p['account_login']}}]}
    request = {'repository_ids':[p['repository_id']], 'permissions':copy.deepcopy(PERMISSIONS)}
    return p, app, ins, repos, request

class AppBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.p,self.a,self.i,self.r,self.t=fixture()
    def runcheck(self):
        return verify_offline_contract(self.p,app_view=self.a,installation_view=self.i,
                                       repository_view=self.r,token_request=self.t)
    def denied(self):
        with self.assertRaises(BoundaryError): self.runcheck()
    def test_positive_not_authenticated(self):
        self.assertEqual(self.runcheck()['state'],'APP_SCOPE_CONTRACT_CONSISTENT_NOT_AUTHENTICATED')
    def test_app_id(self): self.a['id']=9;self.denied()
    def test_boolean_app_id(self): self.a['id']=True;self.denied()
    def test_app_slug(self): self.a['slug']='evil';self.denied()
    def test_app_privilege_escalation(self): self.a['permissions']['issues']='write';self.denied()
    def test_app_permission_missing(self): del self.a['permissions']['checks'];self.denied()
    def test_installation_id(self): self.i['id']=2;self.denied()
    def test_installation_app(self): self.i['app_id']=3;self.denied()
    def test_installation_account(self): self.i['account']['login']='other';self.denied()
    def test_installation_account_id(self): self.i['account']['id']=7;self.denied()
    def test_installation_suspended(self): self.i['suspended_at']='2026-11-03T00:00:00Z';self.denied()
    def test_installation_all_repos(self): self.i['repository_selection']='all';self.denied()
    def test_installation_excess_permission(self): self.i['permissions']['administration']='write';self.denied()
    def test_installation_ambiguous_repo_list(self): self.i['repositories']=[];self.denied()
    def test_token_repos_empty(self): self.r['repositories']=[];self.denied()
    def test_token_repo_count_truncated(self): self.r['total_count']=2;self.denied()
    def test_token_extra_repo(self): self.r['repositories'].append(copy.deepcopy(self.r['repositories'][0]));self.denied()
    def test_token_repo_id_swapped(self): self.r['repositories'][0]['id']=7;self.denied()
    def test_token_repo_owner_id(self): self.r['repositories'][0]['owner']['id']=9;self.denied()
    def test_token_request_extra_repo(self): self.t['repository_ids'].append(99);self.denied()
    def test_token_request_other_repo(self): self.t['repository_ids']=[99];self.denied()
    def test_token_request_wider_permissions(self): self.t['permissions']['contents']='write';self.denied()
    def test_token_request_extraneous_field(self): self.t['token']='secret';self.denied()
    def test_policy_sha_pin(self):
        raw=json.dumps(self.p,sort_keys=True).encode()
        self.assertEqual(policy_from_bytes(raw,hashlib.sha256(raw).hexdigest()),self.p)
    def test_policy_pin_mismatch(self):
        with self.assertRaises(BoundaryError):
            policy_from_bytes(json.dumps(self.p).encode(),'0'*64)
    def test_policy_boolean_id(self):
        self.p['installation_id']=True
        raw=json.dumps(self.p).encode()
        with self.assertRaises(BoundaryError):policy_from_bytes(raw,hashlib.sha256(raw).hexdigest())
    def test_policy_privilege_escalation(self):
        self.p['permissions']['issues']='write'
        raw=json.dumps(self.p).encode()
        with self.assertRaises(BoundaryError):policy_from_bytes(raw,hashlib.sha256(raw).hexdigest())
    def test_policy_untrusted_fields(self):
        self.p['token']='redacted'
        raw=json.dumps(self.p).encode()
        with self.assertRaises(BoundaryError):policy_from_bytes(raw,hashlib.sha256(raw).hexdigest())
    def test_policy_ttl_reject(self):
        self.p['token_expiry_seconds']=3601
        raw=json.dumps(self.p).encode()
        with self.assertRaises(BoundaryError):policy_from_bytes(raw,hashlib.sha256(raw).hexdigest())
    def test_policy_no_owner(self):
        self.p['repository']='other/GOV-GITHUB'
        raw=json.dumps(self.p).encode()
        with self.assertRaises(BoundaryError):policy_from_bytes(raw,hashlib.sha256(raw).hexdigest())

if __name__=='__main__': unittest.main()
