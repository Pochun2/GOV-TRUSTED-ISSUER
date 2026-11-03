"""Stage 010: read-only PR -> workflow SHA provenance before Stage 009 checks.

Read-only, NO issuer credentials, NO signing, NO check-run publication.
Requires independent expected SHA, PR number, and Workflow Run ID from operator.
A positive result is observations only, not an attestation.
"""
import argparse
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from validator.github_api_evidence import (ReadOnlyGitHub, _NoRedirect,
    EvidenceError, Target, verify_one, SOURCE_REPO, VALIDATOR_REPO)

HEX_SHA = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED = (SOURCE_REPO, VALIDATOR_REPO)


def _sha(v):
    return type(v) is str and HEX_SHA.fullmatch(v) is not None


class LiveReader(ReadOnlyGitHub):
    """Read-only reader with two extra, exact API endpoint shapes.

    The inherited reader restricts workflow and check-run paths. Never follow
    redirects or trust URL fields supplied by API responses as request targets.
    """
    def get(self, path):
        if not isinstance(path, str):
            raise EvidenceError('INVALID_API_PATH')
        m = re.fullmatch(
            r'/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:pulls/([1-9][0-9]*)|commits/([0-9a-f]{40}))',
            path)
        if m is None:
            return super().get(path)
        if m.group(1) not in ALLOWED:
            raise EvidenceError('UNAPPROVED_REPOSITORY')
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        if self._token:
            headers['Authorization']='Bearer '+self._token
        req=Request('https://api.github.com'+path,headers=headers,method='GET')
        try:
            with self._opener.open(req,timeout=10) as response:
                if getattr(response,'status',200)!=200:
                    raise EvidenceError('HTTP_NOT_OK')
                raw=response.read(1_000_001)
                if len(raw)>1_000_000:
                    raise EvidenceError('OVERSIZED_RESPONSE')
        except (HTTPError,URLError,TimeoutError,OSError) as e:
            raise EvidenceError('API_UNAVAILABLE') from e
        try:
            data=json.loads(raw)
        except (ValueError,UnicodeError) as e:
            raise EvidenceError('BAD_API_JSON') from e
        if not isinstance(data,dict):
            raise EvidenceError('BAD_API_SHAPE')
        return data


def verify_pr_run(reader, *, repo, pr_number, expected_head, expected_base,
                  run_id, run_attempt, expected_job):
    """Require live PR identity plus run SHA provenance, then Stage 009 checks.

    A pull_request run may check out the PR head or a synthetic merge commit.
    A synthetic merge must have precisely the expected head and base as parents.
    PR state may change; this verifies current state, NOT a historical snapshot.
    """
    if repo not in ALLOWED or expected_job != {SOURCE_REPO:'validate', VALIDATOR_REPO:'self-test'}[repo]:
        raise EvidenceError('UNAPPROVED_TARGET')
    if not _sha(expected_head) or not _sha(expected_base) or expected_head==expected_base:
        raise EvidenceError('INVALID_EXPECTED_SHAS')
    if type(pr_number) is not int or pr_number<=0 or any(type(v) is not int or v<=0 for v in (run_id,run_attempt)):
        raise EvidenceError('INVALID_IDS')
    root='/repos/'+repo
    pr=reader.get(root+'/pulls/'+str(pr_number))
    if (type(pr.get('number')) is not int or pr['number']!=pr_number or
        pr.get('base',{}).get('repo',{}).get('full_name')!=repo or
        pr.get('head',{}).get('repo',{}).get('full_name')!=repo or
        pr['head'].get('sha')!=expected_head or pr['base'].get('sha')!=expected_base or
        pr.get('state')!='open'):
        raise EvidenceError('PR_CURRENT_STATE_MISMATCH')
    run=reader.get(root+'/actions/runs/'+str(run_id))
    associations=run.get('pull_requests')
    if (type(run.get('id')) is not int or run['id']!=run_id or
        type(run.get('run_attempt')) is not int or run['run_attempt']!=run_attempt or
        run.get('event')!='pull_request' or
        run.get('repository',{}).get('full_name')!=repo or
        not isinstance(associations,list) or
        not any(type(p) is dict and p.get('number')==pr_number and
                p.get('head',{}).get('sha')==expected_head for p in associations)):
        raise EvidenceError('RUN_PR_ASSOCIATION_MISMATCH')
    actual=run.get('head_sha')
    if not _sha(actual):
        raise EvidenceError('INVALID_RUN_SHA')
    if actual!=expected_head:
        commit=reader.get(root+'/commits/'+actual)
        parents=commit.get('parents')
        if (commit.get('sha')!=actual or not isinstance(parents,list) or
            len(parents)!=2 or {p.get('sha') for p in parents if isinstance(p,dict)}!={expected_base,expected_head}):
            raise EvidenceError('UNTRUSTED_MERGE_SHA')
    result=verify_one(reader,Target(repo,actual,run_id,run_attempt,expected_job))
    return {'state':'OBSERVED_API_CONSISTENCY_ONLY_NOT_ATTESTED',
            'repo':repo,'pr_number':pr_number,'expected_head':expected_head,
            'expected_base':expected_base,'observed_run_sha':actual,
            'sha_mode':'DIRECT_HEAD' if actual==expected_head else 'SYNTHETIC_MERGE',
            'run_id':run_id,'run_attempt':run_attempt,'job_id':result['job_id']}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Issuer-owned read-only PR run provenance (no attestation)')
    parser.add_argument('--repo',required=True,choices=ALLOWED)
    parser.add_argument('--pr',type=int,required=True)
    parser.add_argument('--head',required=True)
    parser.add_argument('--base',required=True)
    parser.add_argument('--run',type=int,required=True)
    parser.add_argument('--attempt',type=int,default=1)
    parser.add_argument('--job',required=True)
    args=parser.parse_args(argv)
    try:
        # Public API only. No token or private key is retrieved or logged.
        value=verify_pr_run(LiveReader(),repo=args.repo,pr_number=args.pr,
            expected_head=args.head,expected_base=args.base,run_id=args.run,
            run_attempt=args.attempt,expected_job=args.job)
    except (EvidenceError,KeyError,ValueError,TypeError,AttributeError) as e:
        print(json.dumps({'state':'BLOCKED','reason':str(e)}))
        return 2
    print(json.dumps(value,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
