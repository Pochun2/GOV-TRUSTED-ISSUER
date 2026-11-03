import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import unittest

from validator.issuer_app_boundary import PERMISSIONS
from validator.issuer_auth_lifecycle import (
    APP_ID, AuthError, SCHEMA, STATES, MockLifecycle, TokenLease,
    policy_checked, verify_jwt_claims, verify_token_metadata, utc, main,
)

NOW = 1793700000

def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace('+00:00', 'Z')

def policy():
    return dict(schema='issuer-app-boundary-v1', policy='stage012b-offline-v1',
                app_id=APP_ID, app_slug='gov-protected-validator',
                installation_id=42, account_id=11, account_login='mf002078',
                repository_id=77, repository='mf002078/GOV-GITHUB',
                permissions=copy.deepcopy(PERMISSIONS), token_expiry_seconds=3600)

def claims():
    return {'iss': str(APP_ID), 'iat': NOW-30, 'exp':NOW+300}

def metadata():
    return dict(app_id=APP_ID, installation_id=42, repository_ids=[77],
                permissions=copy.deepcopy(PERMISSIONS), issued_at=iso(NOW-30),
                expires_at=iso(NOW+1800), token_type='installation')

def lease():
    return TokenLease('a'*64,NOW+1800,APP_ID,42,77)

class AuthLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.policy=policy()

    def denied(self, f, *args, **kwargs):
        with self.assertRaises(AuthError): f(*args, **kwargs)

    def test_policy_positive(self):
        raw=json.dumps(self.policy).encode()
        self.assertEqual(policy_checked(raw,hashlib.sha256(raw).hexdigest()),self.policy)
    def test_policy_hash_wrong(self):
        raw=json.dumps(self.policy).encode()
        self.denied(policy_checked,raw,'0'*64)
    def test_policy_wrong_app(self):
        self.policy['app_id']=15368
        raw=json.dumps(self.policy).encode()
        self.denied(policy_checked,raw,hashlib.sha256(raw).hexdigest())
    def test_policy_wrong_repo(self):
        self.policy['repository']='mf002078/GOV-PROTECTED-VALIDATOR'
        raw=json.dumps(self.policy).encode()
        self.denied(policy_checked,raw,hashlib.sha256(raw).hexdigest())
    def test_policy_secret_field(self):
        self.policy['private_key']='not-allowed'
        raw=json.dumps(self.policy).encode()
        self.denied(policy_checked,raw,hashlib.sha256(raw).hexdigest())
    def test_policy_non_bytes(self):
        self.denied(policy_checked,'invalid','0'*64)
    def test_policy_permission_escalation(self):
        self.policy['permissions']['administration']='write'
        raw=json.dumps(self.policy).encode()
        self.denied(policy_checked,raw,hashlib.sha256(raw).hexdigest())
    def test_schema_and_states(self):
        self.assertEqual(SCHEMA,'issuer-auth-lifecycle-v1');self.assertEqual(len(STATES),5)
    def test_jwt_positive(self):
        self.assertEqual(verify_jwt_claims(claims(),self.policy,now=NOW)['state'],'JWT_CLAIMS_CONSISTENT_NOT_AUTHENTICATED')
    def test_jwt_missing_claim(self):
        c=claims();del c['exp'];self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_extra_token(self):
        c=claims();c['token']='secret';self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_issuer_actions_app(self):
        c=claims();c['iss']='15368';self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_issuer_integer(self):
        c=claims();c['iss']=APP_ID;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_iat_bool(self):
        c=claims();c['iat']=True;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_exp_bool(self):
        c=claims();c['exp']=True;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_expired(self):
        c=claims();c['exp']=NOW;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_future_issued(self):
        c=claims();c['iat']=NOW+61;c['exp']=NOW+200;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_overlong(self):
        c=claims();c['exp']=NOW+601;self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_reverse(self):
        c=claims();c['exp']=c['iat'];self.denied(verify_jwt_claims,c,self.policy,now=NOW)
    def test_jwt_invalid_skew(self):
        self.denied(verify_jwt_claims,claims(),self.policy,now=NOW,max_skew=61)
    def test_jwt_bool_now(self):
        self.denied(verify_jwt_claims,claims(),self.policy,now=True)
    def test_jwt_invalid_policy(self):
        self.denied(verify_jwt_claims,claims(),{},now=NOW)
    def test_token_metadata_positive(self):
        self.assertEqual(verify_token_metadata(metadata(),self.policy,now=NOW)['state'],'TOKEN_METADATA_CONSISTENT_NOT_AUTHENTICATED')
    def test_token_secret_field(self):
        m=metadata();m['token']='secret';self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_wrong_app(self):
        m=metadata();m['app_id']=15368;self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_wrong_installation(self):
        m=metadata();m['installation_id']=43;self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_cross_repo(self):
        m=metadata();m['repository_ids']=[99];self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_multiple_repos(self):
        m=metadata();m['repository_ids']=[77,99];self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_bool_repo(self):
        m=metadata();m['repository_ids']=[True];self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_escalated(self):
        m=metadata();m['permissions']['administration']='write';self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_missing_permission(self):
        m=metadata();del m['permissions']['checks'];self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_user_type(self):
        m=metadata();m['token_type']='user';self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_expired(self):
        m=metadata();m['expires_at']=iso(NOW);self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_future_issued(self):
        m=metadata();m['issued_at']=iso(NOW+61);self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_ttl_over_limit(self):
        m=metadata();m['expires_at']=iso(NOW+3601);self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_invalid_utc(self):
        m=metadata();m['expires_at']='not utc';self.denied(verify_token_metadata,m,self.policy,now=NOW)
    def test_token_bad_clock(self):
        self.denied(verify_token_metadata,metadata(),self.policy,now=NOW,max_skew=True)
    def test_utc_timezone_requirement(self):
        self.denied(utc,'2026-11-03T12:00:00+08:00')
    def test_lease_positive_once(self):
        l=MockLifecycle(self.policy)
        self.assertEqual(l.activate(lease(),now=NOW),'MOCK_ACTIVE_NOT_AUTHENTICATED')
        self.assertEqual(l.use_once(now=NOW),'MOCK_USE_ONLY_NO_REMOTE_SIDE_EFFECT')
        self.assertEqual(l.state,'ACTIVE')
    def test_lease_double_activate(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);self.denied(l.activate,lease(),now=NOW)
    def test_lease_double_use(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);l.use_once(now=NOW);self.denied(l.use_once,now=NOW)
    def test_lease_wrong_scope(self):
        l=MockLifecycle(self.policy);self.denied(l.activate,replace(lease(),repository_id=78),now=NOW)
    def test_lease_wrong_app(self):
        l=MockLifecycle(self.policy);self.denied(l.activate,replace(lease(),app_id=15368),now=NOW)
    def test_lease_bad_id(self):
        l=MockLifecycle(self.policy);self.denied(l.activate,replace(lease(),lease_id='bad'),now=NOW)
    def test_lease_bad_ttl(self):
        l=MockLifecycle(self.policy);self.denied(l.activate,replace(lease(),expires_at=NOW+3601),now=NOW)
    def test_lease_expires_and_stays_blocked(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);self.denied(l.use_once,now=NOW+1800);self.assertEqual(l.state,'EXPIRED');self.denied(l.use_once,now=NOW)
    def test_revoke_prevents_use(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);l.revoke();self.assertEqual(l.state,'REVOKED');self.denied(l.use_once,now=NOW)
    def test_revoke_twice(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);l.revoke();self.denied(l.revoke)
    def test_block_prevents_use(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);l.block();self.assertEqual(l.state,'BLOCKED');self.denied(l.use_once,now=NOW)
    def test_unissued_cannot_use(self):
        self.denied(MockLifecycle(self.policy).use_once,now=NOW)
    def test_no_activate_after_revoke(self):
        l=MockLifecycle(self.policy);l.activate(lease(),now=NOW);l.revoke();self.denied(l.activate,lease(),now=NOW)
    def test_bad_lease_type(self):
        self.denied(MockLifecycle(self.policy).activate,{'lease_id':'a'*64},now=NOW)
    def test_cli_selfcheck(self):
        self.assertEqual(main(['--self-check']),0)
    def test_cli_default_blocked(self):
        self.assertEqual(main([]),2)

if __name__=='__main__': unittest.main()
