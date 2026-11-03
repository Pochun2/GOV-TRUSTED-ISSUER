"""Stage 012E: OFFLINE metadata-only GitHub App authentication lifecycle contract.

No JWT signing or parsing, no cryptographic identity verification, no tokens,
network I/O, private keys, or Check Run writes. All inputs are UNTRUSTED fixtures.
Positive results never authorize publishing, issuance or Gate A changes.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json

from validator.issuer_app_boundary import (APP_SCHEMA, APP_POLICY, PERMISSIONS,
                                            policy_from_bytes, BoundaryError as AppBoundaryError)

APP_ID = 5475837
SCHEMA = 'issuer-auth-lifecycle-v1'
STATES = ('UNISSUED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'BLOCKED')


class AuthError(ValueError):
    """Sanitized fail-closed rejection; never contains credentials."""


def deny(reason):
    raise AuthError(reason)


def exact(obj, fields, label):
    if type(obj) is not dict or set(obj) != set(fields):
        deny(label)


def posint(value):
    return type(value) is int and value > 0


def utc(s):
    if type(s) is not str or not s.endswith('Z') or len(s) > 40:
        deny('INVALID_UTC')
    try:
        d = datetime.fromisoformat(s[:-1] + '+00:00')
    except ValueError:
        deny('INVALID_UTC')
    if d.utcoffset() is None or d.utcoffset().total_seconds() != 0:
        deny('INVALID_UTC')
    return d.timestamp()


def policy_checked(raw: bytes, independent_sha256: str):
    """012B owner-approved policy hash must be pinned outside candidate PR."""
    try:
        p = policy_from_bytes(raw, independent_sha256)
    except (AppBoundaryError, TypeError):
        deny('APP_POLICY_REJECTED')
    if p['app_id'] != APP_ID or p['repository'] != 'mf002078/GOV-GITHUB':
        deny('UNAPPROVED_ISSUER_SCOPE')
    if p['permissions'] != PERMISSIONS:
        deny('UNAPPROVED_PERMISSIONS')
    return p


def verify_jwt_claims(claims, policy, *, now: int, max_skew: int = 60):
    """ONLY structural/clock contract for already independently verified claims.

    This function DOES NOT authenticate JWT bytes/signature, kid or issuer.
    Never treat an arbitrary dict/decoded JWT as authenticated.
    """
    exact(claims, ('iss', 'iat', 'exp'), 'JWT_CLAIM_FIELDS')
    if not posint(now) or type(max_skew) is not int or not 0 <= max_skew <= 60:
        deny('INVALID_CLOCK_POLICY')
    if type(policy) is not dict or policy.get('app_id') != APP_ID:
        deny('INVALID_POLICY')
    if type(claims['iss']) is not str or claims['iss'] != str(APP_ID):
        deny('JWT_ISSUER_MISMATCH')
    if type(claims['iat']) is not int or type(claims['exp']) is not int:
        deny('JWT_TIME_TYPE')
    issued, expiry = claims['iat'], claims['exp']
    if issued <= 0 or expiry <= issued or expiry-issued > 600:
        deny('JWT_LIFETIME_INVALID')
    if issued > now + max_skew or expiry <= now:
        deny('JWT_CLOCK_OR_EXPIRY')
    # A too-old iat is rejected, even if exp appears to be in the future.
    if now-issued > 600 + max_skew:
        deny('JWT_TOO_OLD')
    return {'state': 'JWT_CLAIMS_CONSISTENT_NOT_AUTHENTICATED', 'app_id': APP_ID}


def verify_token_metadata(meta, policy, *, now: int, max_skew: int = 60):
    """ONLY metadata from mocked issuance; does not contain or accept token bytes.

    A token must be authenticated through an independent trusted GitHub channel
    before such metadata could carry authority. NO real credential path here.
    """
    exact(meta, ('app_id', 'installation_id', 'repository_ids', 'permissions',
                 'issued_at', 'expires_at', 'token_type'), 'TOKEN_METADATA_FIELDS')
    if type(policy) is not dict or policy.get('app_id') != APP_ID:
        deny('INVALID_POLICY')
    if not posint(now) or type(max_skew) is not int or not 0 <= max_skew <= 60:
        deny('INVALID_CLOCK_POLICY')
    if type(meta['app_id']) is not int or meta['app_id'] != policy['app_id']:
        deny('TOKEN_APP_MISMATCH')
    if type(meta['installation_id']) is not int or meta['installation_id'] != policy['installation_id']:
        deny('TOKEN_INSTALLATION_MISMATCH')
    if (type(meta['repository_ids']) is not list or len(meta['repository_ids']) != 1
            or type(meta['repository_ids'][0]) is not int or meta['repository_ids'][0] != policy['repository_id']):
        deny('TOKEN_REPOSITORY_MISMATCH')
    if type(meta['permissions']) is not dict or meta['permissions'] != PERMISSIONS:
        deny('TOKEN_PERMISSION_MISMATCH')
    if meta['token_type'] != 'installation':
        deny('TOKEN_TYPE_MISMATCH')
    start, expiry = utc(meta['issued_at']), utc(meta['expires_at'])
    if start > now + max_skew or expiry <= now or expiry <= start:
        deny('TOKEN_CLOCK_OR_EXPIRY')
    if expiry-start > policy['token_expiry_seconds'] or now-start > policy['token_expiry_seconds'] + max_skew:
        deny('TOKEN_TTL_EXCEEDED')
    return {'state': 'TOKEN_METADATA_CONSISTENT_NOT_AUTHENTICATED',
            'app_id': APP_ID, 'installation_id': policy['installation_id'],
            'repository_id': policy['repository_id']}


@dataclass(frozen=True)
class TokenLease:
    """Synthetic, non-secret lease used for deterministic state tests."""
    lease_id: str
    expires_at: int
    app_id: int
    installation_id: int
    repository_id: int


class MockLifecycle:
    """Offline per-process state guard, NOT durable, NOT real token revocation.

    No token bytes are stored and no real GitHub credentials are ever requested.
    A restart loses state. Production must use durable rollback-resistant controls.
    """
    def __init__(self, policy):
        if type(policy) is not dict or policy.get('app_id') != APP_ID:
            deny('INVALID_POLICY')
        self._policy = policy
        self._state = 'UNISSUED'
        self._lease = None
        self._used = False

    @property
    def state(self):
        return self._state

    def activate(self, lease: TokenLease, *, now: int):
        if self._state != 'UNISSUED':
            deny('REPLAY_LEASE')
        if type(lease) is not TokenLease or type(lease.lease_id) is not str or len(lease.lease_id) != 64:
            deny('INVALID_LEASE')
        if any(c not in '0123456789abcdef' for c in lease.lease_id):
            deny('INVALID_LEASE')
        if not posint(now) or type(lease.expires_at) is not int or lease.expires_at <= now:
            deny('LEASE_EXPIRED')
        if any(type(v) is not int for v in (lease.app_id, lease.installation_id, lease.repository_id)):
            deny('INVALID_LEASE_IDENTITY')
        if (lease.app_id != self._policy['app_id'] or
            lease.installation_id != self._policy['installation_id'] or
            lease.repository_id != self._policy['repository_id']):
            deny('LEASE_SCOPE_MISMATCH')
        if lease.expires_at-now > self._policy['token_expiry_seconds']:
            deny('LEASE_TTL_EXCEEDED')
        self._lease = lease
        self._state = 'ACTIVE'
        return 'MOCK_ACTIVE_NOT_AUTHENTICATED'

    def use_once(self, *, now: int):
        if self._state != 'ACTIVE' or self._lease is None:
            deny('LEASE_NOT_ACTIVE')
        if not posint(now) or now >= self._lease.expires_at:
            self._state = 'EXPIRED'
            deny('LEASE_EXPIRED')
        if self._used:
            deny('LEASE_REPLAY')
        self._used = True
        return 'MOCK_USE_ONLY_NO_REMOTE_SIDE_EFFECT'

    def revoke(self):
        if self._state != 'ACTIVE':
            deny('REVOKE_STATE_CONFLICT')
        self._state = 'REVOKED'
        return 'MOCK_REVOKED_NOT_GITHUB_REVOKED'

    def block(self):
        if self._state != 'ACTIVE':
            deny('BLOCK_STATE_CONFLICT')
        self._state = 'BLOCKED'
        return 'MOCK_BLOCKED'


def main(argv=None):
    p = argparse.ArgumentParser(description='Stage 012E offline metadata-only self-check')
    p.add_argument('--self-check', action='store_true')
    args = p.parse_args(argv)
    if not args.self_check:
        print(json.dumps({'state':'BLOCKED','reason':'OFFLINE_SELF_CHECK_ONLY'},sort_keys=True))
        return 2
    print(json.dumps({'state':'OFFLINE_ONLY','note':'NO_JWT_SIGNING_NO_TOKEN_NO_KEY_NO_CHECK_RUN_GATE_A_BLOCKED'},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
