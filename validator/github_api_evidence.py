"""Stage 009: independent READ-ONLY GitHub Actions evidence lookup.

No issuer permission, App private key, check publication, approval, or merge.
This module returns verification eligibility only, NEVER attestation.
"""
from dataclasses import dataclass
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

SOURCE_REPO = 'mf002078/GOV-GITHUB'
VALIDATOR_REPO = 'mf002078/GOV-PROTECTED-VALIDATOR'
ACTIONS_APP = 15368
SHA = re.compile(r'[0-9a-f]{40}\Z')

class EvidenceError(Exception):
    pass

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ReadOnlyGitHub:
    """GitHub-only TLS reader. Optional token is injected, never logged."""
    def __init__(self, token=None, opener=None):
        self._token = token
        self._opener = opener or build_opener(_NoRedirect)

    def get(self, path):
        if not isinstance(path, str) or not re.fullmatch(r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:actions/runs/[0-9]+|actions/runs/[0-9]+/jobs\?per_page=100|commits/[0-9a-f]{40}/check-runs\?per_page=100)', path):
            raise EvidenceError('INVALID_API_PATH')
        headers = {'Accept':'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28'}
        if self._token:
            headers['Authorization'] = 'Bearer ' + self._token
        req = Request('https://api.github.com'+path, headers=headers, method='GET')
        try:
            with self._opener.open(req, timeout=10) as response:
                if getattr(response, 'status', 200) != 200:
                    raise EvidenceError('HTTP_NOT_OK')
                raw = response.read(4_000_001)
                if len(raw)>4_000_000:
                    raise EvidenceError('OVERSIZED_RESPONSE')
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            raise EvidenceError('API_UNAVAILABLE') from e
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as e:
            raise EvidenceError('BAD_API_JSON') from e
        if not isinstance(value, dict):
            raise EvidenceError('BAD_API_SHAPE')
        return value

@dataclass(frozen=True)
class Target:
    repo: str
    commit_sha: str
    run_id: int
    run_attempt: int
    job_name: str


def _fail(reason):
    raise EvidenceError(reason)


def verify_one(reader, target):
    """Require self-consistent API-owned run, job and Actions Check Run for exact SHA."""
    if not isinstance(target, Target) or target.repo not in (SOURCE_REPO, VALIDATOR_REPO):
        _fail('UNAPPROVED_REPOSITORY')
    if target.job_name != ({SOURCE_REPO:'validate', VALIDATOR_REPO:'self-test'}[target.repo]):
        _fail('UNAPPROVED_JOB')
    if not isinstance(target.commit_sha,str) or not SHA.fullmatch(target.commit_sha):
        _fail('INVALID_SHA')
    if any(type(n) is not int or n <= 0 for n in (target.run_id,target.run_attempt)):
        _fail('INVALID_RUN')
    root = '/repos/' + target.repo
    run = reader.get(root + '/actions/runs/' + str(target.run_id))
    # Do not silently accept a PR synthetic merge SHA for the PR head SHA.
    if (run.get('id') != target.run_id or run.get('run_attempt') != target.run_attempt
            or run.get('head_sha') != target.commit_sha or run.get('status') != 'completed'
            or run.get('conclusion') != 'success'
            or run.get('repository',{}).get('full_name') != target.repo):
        _fail('RUN_MISMATCH')
    jobs = reader.get(root + '/actions/runs/' + str(target.run_id) + '/jobs?per_page=100')
    # Partial evidence must fail closed; pagination not supported in prototype.
    if (type(jobs.get('total_count')) is not int or jobs['total_count'] != len(jobs.get('jobs',[]))
            or not isinstance(jobs.get('jobs'), list)):
        _fail('PAGINATED_OR_MALFORMED_JOBS')
    matched = [j for j in jobs['jobs'] if isinstance(j,dict) and j.get('name') == target.job_name]
    if len(matched) != 1:
        _fail('MISSING_OR_DUPLICATE_JOB')
    job=matched[0]
    if (type(job.get('id')) is not int or job.get('run_id') != target.run_id
            or job.get('run_attempt',target.run_attempt) != target.run_attempt
            or job.get('head_sha') != target.commit_sha
            or job.get('status') != 'completed' or job.get('conclusion') != 'success'):
        _fail('JOB_MISMATCH')
    check_url=job.get('check_run_url')
    if not isinstance(check_url,str) or not check_url.startswith('https://api.github.com/repos/'+target.repo+'/check-runs/'):
        _fail('JOB_CHECK_IDENTITY_MISSING')
    check_id=check_url.rsplit('/',1)[-1]
    if not check_id.isdecimal():
        _fail('JOB_CHECK_IDENTITY_INVALID')
    checks=reader.get(root+'/commits/'+target.commit_sha+'/check-runs?per_page=100')
    if (type(checks.get('total_count')) is not int or checks['total_count'] != len(checks.get('check_runs',[]))
            or not isinstance(checks.get('check_runs'),list)):
        _fail('PAGINATED_OR_MALFORMED_CHECKS')
    matches=[c for c in checks['check_runs'] if isinstance(c,dict) and c.get('id') == int(check_id)]
    if len(matches)!=1:
        _fail('CHECK_RUN_ID_NOT_FOUND')
    check=matches[0]
    if (check.get('name') != target.job_name or check.get('head_sha') != target.commit_sha
            or check.get('status') != 'completed' or check.get('conclusion') != 'success'
            or check.get('app',{}).get('id') != ACTIONS_APP):
        _fail('CHECK_MISMATCH')
    return {'repository':target.repo,'sha':target.commit_sha,'run_id':target.run_id,
            'run_attempt':target.run_attempt,'job_id':job['id'],'check_id':int(check_id),
            'status':'API_EVIDENCE_CONSISTENT_NOT_ATTESTED'}


def verify_pair(reader, source, validator):
    """Both repositories must be independently verified. No signing/publication."""
    if source.repo != SOURCE_REPO or validator.repo != VALIDATOR_REPO:
        _fail('CROSS_REPO_SWAP')
    try:
        left=verify_one(reader,source)
        right=verify_one(reader,validator)
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise EvidenceError('MALFORMED_API_EVIDENCE') from e
    return {'state':'ELIGIBLE_FOR_FURTHER_ISSUER_POLICY_REVIEW', 'source':left,'validator':right}
