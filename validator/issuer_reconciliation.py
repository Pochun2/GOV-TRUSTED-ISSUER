"""Stage 012D read-only remote Check Run reconciliation contract.

No token acquisition, no GitHub POST/PATCH, no ledger modification, no attestation.
The *caller* supplies a trusted reader, pinned Check Run ID, and local Intent.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import json
import re
import sqlite3

from validator.issuer_transaction import Intent, validate_intent, SHA256, BoundaryError
from validator.github_api_evidence import ReadOnlyGitHub, EvidenceError

EXPECTED_APP = 5475837
EXPECTED_NAME = 'GOV-Protected-Validator'
EXPECTED_REPO = 'mf002078/GOV-GITHUB'
MAX_CHECKS = 100

class ReconciliationError(ValueError):
    """Sanitized fail-closed read-only reconciliation failure."""

def reject(reason):
    raise ReconciliationError(reason)

def _int(v):
    return type(v) is int and v > 0

def _sha(v):
    return type(v) is str and SHA256.fullmatch(v) is not None


def read_local_transaction(ledger_path, intent):
    """Open SQLite in read-only mode: NEVER create or mutate a DB or row.

    Parent directory must be operator-controlled, persistent, and trusted.
    This read does not establish multi-host durability or rollback protection.
    """
    identity = validate_intent(intent)
    p = Path(ledger_path)
    if not p.is_file() or p.is_symlink():
        reject('LEDGER_NOT_TRUSTED')
    try:
        # sqlite3's mode=ro never creates the database, unlike a default connect.
        with closing(sqlite3.connect(p.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
            db.execute('PRAGMA query_only=ON')
            row = db.execute('SELECT identity,repo,head_sha,evidence_sha256,policy_sha256,'
                             'app_id,installation_id,check_name,state,receipt,reason,revision '
                             'FROM issuance WHERE identity=?', (identity,)).fetchone()
    except (sqlite3.Error, OSError, ValueError):
        reject('LEDGER_UNAVAILABLE')
    if row is None:
        reject('INTENT_NOT_IN_LEDGER')
    expected = (identity, intent.repo, intent.head_sha, intent.evidence_sha256,
                intent.policy_sha256, intent.app_id, intent.installation_id,
                intent.check_name)
    if (row[:8] != expected or row[8] not in ('PUBLISHING','PUBLISHED','BLOCKED')
            or type(row[11]) is not int or row[11] < 1):
        reject('LOCAL_TRANSACTION_MISMATCH')
    # 012C's PUBLISHED means MOCK-only; it cannot be reinterpreted as real issuance.
    if row[8] == 'PUBLISHED' or (row[9] is not None and str(row[9]).startswith('MOCK:')):
        reject('MOCK_PUBLICATION_NOT_REMOTE_PROOF')
    if row[8] == 'BLOCKED':
        reject('TRANSACTION_ALREADY_BLOCKED')
    if row[9] is not None or row[10] is not None:
        reject('UNEXPECTED_LOCAL_RECEIPT_OR_REASON')
    return identity


def reconcile(reader, ledger_path, intent, *, expected_check_id):
    """Read-only exact-SHA Check Run observation; NEVER authorizes issuance.

    The expected ID is independently pinned (never derived from returned API list).
    This cannot authenticate untrusted fixture data or prove a GitHub publication.
    """
    if type(intent) is not Intent:
        reject('INVALID_INTENT')
    try:
        key = validate_intent(intent)
    except BoundaryError:
        reject('INVALID_INTENT')
    if not _int(expected_check_id):
        reject('INVALID_PINNED_CHECK_ID')
    if intent.repo != EXPECTED_REPO or intent.app_id != EXPECTED_APP or intent.check_name != EXPECTED_NAME:
        reject('UNAPPROVED_ISSUER')
    if read_local_transaction(ledger_path, intent) != key:
        reject('LOCAL_IDENTITY_MISMATCH')
    path = f'/repos/{EXPECTED_REPO}/commits/{intent.head_sha}/check-runs?per_page=100'
    try:
        data = reader.get(path)
    except Exception:
        # Do not expose exception text or HTTP payloads.
        reject('REMOTE_UNAVAILABLE')
    if (type(data) is not dict or type(data.get('total_count')) is not int
            or data['total_count'] < 0 or data['total_count'] > MAX_CHECKS
            or type(data.get('check_runs')) is not list
            or len(data['check_runs']) != data['total_count']):
        reject('PAGINATED_OR_INVALID_REMOTE_RESULT')
    # Pin by externally controlled transaction ID, not just name and head SHA.
    related = []
    ids = set()
    for c in data['check_runs']:
        if type(c) is not dict or not _int(c.get('id')) or c['id'] in ids:
            reject('INVALID_OR_DUPLICATED_REMOTE_ID')
        ids.add(c['id'])
        # Missing external_id on other checks is allowed, but never qualifies.
        if c.get('external_id') == key:
            related.append(c)
    if len(related) == 0:
        reject('REMOTE_RESULT_MISSING_UNCERTAIN_NO_RETRY')
    if len(related) != 1:
        reject('DUPLICATE_REMOTE_ISSUANCE')
    c = related[0]
    app = c.get('app')
    if (c['id'] != expected_check_id or c.get('name') != intent.check_name
            or c.get('head_sha') != intent.head_sha
            or type(app) is not dict or type(app.get('id')) is not int
            or app['id'] != intent.app_id):
        reject('REMOTE_ISSUER_IDENTITY_MISMATCH')
    if c.get('status') != 'completed' or c.get('conclusion') != 'success':
        reject('REMOTE_CHECK_NOT_SUCCESSFUL')
    # IMPORTANT: no DB state transition even on positive observation.
    return {'state':'REMOTE_MATCH_OBSERVED_NOT_ATTESTED', 'transaction_id':key,
            'check_run_id':expected_check_id,
            'note':'READ_ONLY_NO_LEDGER_PROMOTION_NO_APP_KEY_NO_TOKEN_NO_CHECK_RUN_GATE_A_BLOCKED'}


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description='Issuer offline reconciliation self-check only')
    p.add_argument('--self-check', action='store_true')
    args = p.parse_args(argv)
    if not args.self_check:
        print(json.dumps({'state':'BLOCKED','reason':'OFFLINE_SELF_CHECK_ONLY'},sort_keys=True))
        return 2
    print(json.dumps({'state':'OFFLINE_ONLY','note':'NO_APP_KEY_NO_TOKEN_NO_WRITE_NO_ATTESTATION_GATE_A_BLOCKED'},sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
