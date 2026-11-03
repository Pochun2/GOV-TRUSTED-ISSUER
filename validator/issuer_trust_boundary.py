"""Stage 012A — independently pinned workflow-file content and run identity.

PRE-PRODUCTION. This module does not attest, sign, publish Checks or approve.
Expectations must be established by an independent Pochun2-owned policy authority,
never by untrusted candidate pull requests or their Actions outputs.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request
from validator.github_api_evidence import EvidenceError, SOURCE_REPO, VALIDATOR_REPO
from validator.live_api_probe import LiveReader

REPOS = (SOURCE_REPO, VALIDATOR_REPO)
WORKFLOW_PATH = re.compile(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 256_000


def fail(reason):
    raise EvidenceError(reason)


def _strict_int(v):
    return type(v) is int and v > 0


def parse_trust_policy(raw: bytes, expected_sha256: str):
    """Check an independently pinned byte-level SHA256 before JSON interpretation."""
    if not isinstance(raw, bytes) or len(raw) > 24000:
        fail('INVALID_TRUST_POLICY_BYTES')
    if type(expected_sha256) is not str or not DIGEST.fullmatch(expected_sha256):
        fail('INVALID_PINNED_POLICY_DIGEST')
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        fail('TRUST_POLICY_DIGEST_MISMATCH')
    try:
        p = json.loads(raw)
    except (ValueError, UnicodeError):
        fail('INVALID_TRUST_POLICY_JSON')
    if type(p) is not dict or set(p) != {'schema','policy','targets'} or p['schema'] != 'issuer-workflow-binding-v1' or p['policy'] != 'stage012a-readonly-v1':
        fail('INVALID_TRUST_POLICY_SHAPE')
    targets = p['targets']
    if type(targets) is not list or len(targets) != 2:
        fail('INVALID_WORKFLOW_TARGETS')
    seen = set()
    for t in targets:
        if type(t) is not dict or set(t) != {'repo','run','attempt','head','base','workflow_path','workflow_id','workflow_sha256'}:
            fail('INVALID_WORKFLOW_TARGET_FIELDS')
        repo=t['repo']
        if type(repo) is not str or repo not in REPOS or repo in seen:
            fail('INVALID_WORKFLOW_REPOSITORY')
        seen.add(repo)
        if not all(_strict_int(t[k]) for k in ('run','attempt','workflow_id')):
            fail('INVALID_WORKFLOW_IDS')
        if any(type(t[k]) is not str or not SHA.fullmatch(t[k]) for k in ('head','base')) or t['head']==t['base']:
            fail('INVALID_WORKFLOW_SHAS')
        if type(t['workflow_path']) is not str or not WORKFLOW_PATH.fullmatch(t['workflow_path']):
            fail('INVALID_WORKFLOW_PATH')
        if type(t['workflow_sha256']) is not str or not DIGEST.fullmatch(t['workflow_sha256']):
            fail('INVALID_WORKFLOW_DIGEST')
    if seen != set(REPOS):
        fail('MISSING_WORKFLOW_REPOSITORY')
    return p


class WorkflowReader(LiveReader):
    """Exact GitHub Contents endpoint allowlist; no redirects or arbitrary URLs."""
    def get(self, path):
        m = re.fullmatch(r'/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/contents/(\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)\?ref=([0-9a-f]{40})', path) if type(path) is str else None
        if m is None:
            return super().get(path)
        if m.group(1) not in REPOS:
            fail('UNAPPROVED_WORKFLOW_REPOSITORY')
        headers = {'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        if self._token:
            headers['Authorization'] = 'Bearer '+self._token
        req = Request('https://api.github.com'+path, headers=headers, method='GET')
        try:
            with self._opener.open(req, timeout=10) as response:
                if getattr(response,'status',200) != 200:
                    fail('WORKFLOW_HTTP_NOT_OK')
                raw=response.read(450_001)
                if len(raw)>450_000:
                    fail('WORKFLOW_RESPONSE_TOO_LARGE')
        except (HTTPError,URLError,OSError,TimeoutError) as e:
            raise EvidenceError('WORKFLOW_API_UNAVAILABLE') from e
        try:
            obj=json.loads(raw)
        except (UnicodeError,ValueError) as e:
            raise EvidenceError('WORKFLOW_BAD_JSON') from e
        if type(obj) is not dict:
            fail('WORKFLOW_BAD_SHAPE')
        return obj


def _read_workflow_bytes(reader, target, ref):
    root='/repos/'+target['repo']
    path=target['workflow_path']
    data=reader.get(root+'/contents/'+path+'?ref='+ref)
    if (type(data) is not dict or data.get('type')!='file' or data.get('path')!=path or
            data.get('encoding')!='base64' or type(data.get('content')) is not str or
            type(data.get('size')) is not int or not 0 < data['size'] <= MAX_FILE or
            type(data.get('sha')) is not str or not SHA.fullmatch(data['sha'])):
        fail('INVALID_WORKFLOW_CONTENT_METADATA')
    try:
        encoded=''.join(data['content'].splitlines())
        blob=base64.b64decode(encoded,validate=True)
    except (ValueError,binascii.Error):
        fail('INVALID_WORKFLOW_BASE64')
    if not blob or len(blob)!=data['size'] or len(blob)>MAX_FILE:
        fail('WORKFLOW_CONTENT_LENGTH_MISMATCH')
    git_blob_sha=hashlib.sha1(b'blob '+str(len(blob)).encode('ascii')+b'\0'+blob).hexdigest()
    if git_blob_sha!=data['sha']:
        fail('WORKFLOW_GIT_BLOB_SHA_MISMATCH')
    if hashlib.sha256(blob).hexdigest()!=target['workflow_sha256']:
        fail('WORKFLOW_CONTENT_PIN_MISMATCH')
    return git_blob_sha


def verify_workflow_boundary(reader, target):
    """Check a pinned run's declared workflow identity and immutable file at head/base.

    This is a content binding check, NOT proof of the runner's actual executed
    workflow or that the pinned policy was chosen by an independent authority.
    """
    if type(target) is not dict or target['repo'] not in REPOS:
        fail('UNAPPROVED_WORKFLOW_TARGET')
    root='/repos/'+target['repo']
    run=reader.get(root+'/actions/runs/'+str(target['run']))
    run_path=run.get('path')
    # GitHub may append @refs to a workflow-run path; accept only exact safe ref.
    if (type(run_path) is not str or run_path != target['workflow_path'] or
            type(run.get('workflow_id')) is not int or run['workflow_id']!=target['workflow_id'] or
            type(run.get('id')) is not int or run['id']!=target['run'] or
            type(run.get('run_attempt')) is not int or run['run_attempt']!=target['attempt'] or
            run.get('event')!='pull_request' or run.get('head_sha')!=target['head'] or
            run.get('repository',{}).get('full_name')!=target['repo'] or
            run.get('status')!='completed' or run.get('conclusion')!='success'):
        fail('UNTRUSTED_WORKFLOW_RUN_IDENTITY')
    head_blob=_read_workflow_bytes(reader,target,target['head'])
    base_blob=_read_workflow_bytes(reader,target,target['base'])
    if head_blob!=base_blob:
        fail('WORKFLOW_HEAD_BASE_BLOB_MISMATCH')
    return {'state':'WORKFLOW_CONTENT_OBSERVED_NOT_ATTESTED',
            'repo':target['repo'],'run_id':target['run'],
            'workflow_id':target['workflow_id'],
            'workflow_sha256':target['workflow_sha256']}


def verify_trust_boundary_pair(reader, raw_policy: bytes, expected_sha256: str):
    policy=parse_trust_policy(raw_policy,expected_sha256)
    by_repo={x['repo']:x for x in policy['targets']}
    source=verify_workflow_boundary(reader,by_repo[SOURCE_REPO])
    validator=verify_workflow_boundary(reader,by_repo[VALIDATOR_REPO])
    return {'state':'PAIR_WORKFLOW_BOUNDARY_OBSERVED_NOT_ATTESTED',
            'policy_sha256':expected_sha256,'source':source,'validator':validator}
