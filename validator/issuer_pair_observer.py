"""Stage 011B: independent paired GitHub observations; NOT an attestation.

Only reads public GitHub API through Stage 010's fail-closed LiveReader.
The SQLite journal records observations, never authorizes Check Run issuance.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from validator.github_api_evidence import EvidenceError, SOURCE_REPO, VALIDATOR_REPO
from validator.live_api_probe import LiveReader, verify_pr_run

SCHEMA = 'issuer-pair-observation-v1'
POLICY = 'stage011b-readonly-v1'
EXPECTED_JOBS = {SOURCE_REPO: 'validate', VALIDATOR_REPO: 'self-test'}
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def fail(reason):
    raise EvidenceError(reason)


def _utc(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        fail('INVALID_UTC_TIMESTAMP')
    try:
        d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        fail('INVALID_UTC_TIMESTAMP')
    if d.tzinfo is None:
        fail('INVALID_UTC_TIMESTAMP')
    return d.astimezone(timezone.utc)


def _positive_int(v):
    return type(v) is int and v > 0


def read_policy_bytes(raw: bytes):
    """Policy digest is caller-pinned independently; not a trust anchor alone."""
    if len(raw) > 20000:
        fail('POLICY_TOO_LARGE')
    try:
        obj = json.loads(raw)
    except (UnicodeError, ValueError):
        fail('INVALID_POLICY_JSON')
    if not isinstance(obj, dict) or set(obj) != {'schema', 'policy', 'max_age_seconds', 'max_skew_seconds', 'targets'}:
        fail('INVALID_POLICY_SHAPE')
    if obj['schema'] != SCHEMA or obj['policy'] != POLICY:
        fail('UNKNOWN_POLICY')
    if not _positive_int(obj['max_age_seconds']) or not 60 <= obj['max_age_seconds'] <= 86400:
        fail('UNSAFE_MAX_AGE')
    if not _positive_int(obj['max_skew_seconds']) or not 1 <= obj['max_skew_seconds'] <= 3600:
        fail('UNSAFE_MAX_SKEW')
    targets = obj['targets']
    if not isinstance(targets, list) or len(targets) != 2:
        fail('INVALID_TARGETS')
    seen = set()
    for t in targets:
        if not isinstance(t, dict) or set(t) != {'repo', 'pr', 'head', 'base', 'run', 'attempt', 'job'}:
            fail('INVALID_TARGET_FIELDS')
        repo = t['repo']
        if repo not in EXPECTED_JOBS or repo in seen or t['job'] != EXPECTED_JOBS[repo]:
            fail('INVALID_TARGET_IDENTITY')
        seen.add(repo)
        if not all(_positive_int(t[x]) for x in ('pr', 'run', 'attempt')):
            fail('INVALID_TARGET_IDS')
        if not all(isinstance(t[x], str) and HEX40.fullmatch(t[x]) for x in ('head', 'base')) or t['head'] == t['base']:
            fail('INVALID_TARGET_SHAS')
    if seen != set(EXPECTED_JOBS):
        fail('MISSING_TARGET_REPOSITORY')
    return obj


def _check_time(reader, target, now, max_age):
    """Require canonical matched job finishing recently, not run.updated_at."""
    path = '/repos/' + target['repo'] + '/actions/runs/' + str(target['run']) + '/jobs?per_page=100'
    jobs = reader.get(path)
    items = jobs.get('jobs')
    if not isinstance(items, list) or type(jobs.get('total_count')) is not int or jobs['total_count'] != len(items):
        fail('JOBS_INCOMPLETE')
    matched = [x for x in items if isinstance(x, dict) and x.get('name') == target['job']]
    if len(matched) != 1:
        fail('JOB_TIME_IDENTITY_MISMATCH')
    job = matched[0]
    if job.get('run_id') != target['run'] or job.get('run_attempt', target['attempt']) != target['attempt']:
        fail('JOB_TIME_ATTEMPT_MISMATCH')
    if job.get('status') != 'completed' or job.get('conclusion') != 'success':
        fail('JOB_TIME_NOT_SUCCESS')
    started = _utc(job.get('started_at'))
    finished = _utc(job.get('completed_at'))
    if started > finished or finished > now or (now-finished).total_seconds() > max_age:
        fail('STALE_OR_FUTURE_JOB')
    return finished


def observe_pair(reader, policy, *, now=None):
    """Fetch both sources independently; no result if either fails closed."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        fail('NAIVE_CLOCK')
    now = now.astimezone(timezone.utc)
    results = {}
    finish = {}
    for repo in (SOURCE_REPO, VALIDATOR_REPO):
        t = next(x for x in policy['targets'] if x['repo'] == repo)
        result = verify_pr_run(reader, repo=repo, pr_number=t['pr'], expected_head=t['head'],
                               expected_base=t['base'], run_id=t['run'], run_attempt=t['attempt'],
                               expected_job=t['job'])
        finished = _check_time(reader, t, now, policy['max_age_seconds'])
        results[repo] = result
        finish[repo] = finished
    if abs((finish[SOURCE_REPO] - finish[VALIDATOR_REPO]).total_seconds()) > policy['max_skew_seconds']:
        fail('CROSS_REPO_TIME_SKEW')
    return {'state': 'PAIR_OBSERVED_NOT_ATTESTED', 'policy': POLICY,
            'source': results[SOURCE_REPO], 'validator': results[VALIDATOR_REPO],
            'observed_at_utc': now.isoformat().replace('+00:00','Z')}


def record_observation(db_path, policy_digest, result):
    """BEGIN IMMEDIATE + UNIQUE identity; DB path must be locally controlled.

    This is a local observation ledger ONLY, not a durable signing or issuance
    ledger. Loss of this file destroys replay history and must not be tolerated
    by a future issuer implementation.
    """
    key = '|'.join([policy_digest,
                    str(result['source']['run_id']), str(result['source']['run_attempt']),
                    str(result['validator']['run_id']), str(result['validator']['run_attempt']),
                    result['source']['expected_head'], result['validator']['expected_head']])
    digest = hashlib.sha256(key.encode('ascii')).hexdigest()
    if not HEX64.fullmatch(policy_digest):
        fail('INVALID_POLICY_DIGEST')
    path = Path(db_path)
    if not path.parent.is_dir() or path.is_symlink():
        fail('INVALID_LEDGER_LOCATION')
    try:
        with closing(sqlite3.connect(str(path), timeout=5, isolation_level=None)) as conn:
            conn.execute('PRAGMA busy_timeout=5000')
            conn.execute('PRAGMA synchronous=FULL')
            conn.execute('CREATE TABLE IF NOT EXISTS observation (identity TEXT PRIMARY KEY, policy_digest TEXT NOT NULL, observed_at TEXT NOT NULL, payload_digest TEXT NOT NULL)')
            conn.execute('BEGIN IMMEDIATE')
            payload = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
            conn.execute('INSERT INTO observation(identity, policy_digest, observed_at, payload_digest) VALUES(?,?,?,?)',
                         (digest, policy_digest, result['observed_at_utc'], payload))
            conn.execute('COMMIT')
    except sqlite3.IntegrityError as e:
        fail('REPLAY_OBSERVATION')
    except sqlite3.Error as e:
        fail('LEDGER_UNAVAILABLE')
    return digest


def main(argv=None, *, reader_factory=LiveReader):
    ap = argparse.ArgumentParser(description='Read-only paired observations; no attestation')
    ap.add_argument('--policy', required=True, help='Local non-secret policy JSON')
    ap.add_argument('--expected-sha256', required=True, help='Independently verified policy file hash')
    ap.add_argument('--ledger', required=True, help='Local persistent SQLite observation ledger')
    args = ap.parse_args(argv)
    try:
        if not HEX64.fullmatch(args.expected_sha256.lower()):
            fail('INVALID_POLICY_DIGEST')
        raw = Path(args.policy).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != args.expected_sha256.lower():
            fail('POLICY_HASH_MISMATCH')
        policy = read_policy_bytes(raw)
        result = observe_pair(reader_factory(), policy)
        observation_id = record_observation(args.ledger, digest, result)
        report = {'state': 'PAIR_OBSERVED_NOT_ATTESTED', 'policy_sha256': digest,
                  'observation_id': observation_id, 'source_run_id': result['source']['run_id'],
                  'validator_run_id': result['validator']['run_id'],
                  'note': 'READ_ONLY_NO_CHECK_RUN_NO_APP_KEY_GATE_A_BLOCKED'}
        print(json.dumps(report, sort_keys=True))
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, AttributeError):
        # Do not serialize untrusted exception strings, HTTP payloads or filesystem paths.
        print(json.dumps({'state': 'BLOCKED', 'reason': 'EVIDENCE_OR_LEDGER_REJECTED',
                          'note': 'NO_ATTESTATION_GATE_A_BLOCKED'}, sort_keys=True))
        return 2


if __name__ == '__main__':
    sys.exit(main())
