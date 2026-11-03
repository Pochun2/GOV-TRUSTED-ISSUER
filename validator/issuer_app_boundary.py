"""Stage 012B: offline GitHub App / installation / token-scope *contract* checks.

Untrusted JSON, even if self-consistent, is never an authenticated App proof.
NO credential access, token minting, installation API, Check Run or attestation.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re

class BoundaryError(ValueError):
    pass

APP_SCHEMA = "issuer-app-boundary-v1"
APP_POLICY = "stage012b-offline-v1"
PERMISSIONS = {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def deny(reason):
    raise BoundaryError(reason)


def positive_int(v):
    return type(v) is int and v > 0


def require_keys(d, keys, reason):
    if type(d) is not dict or set(d) != set(keys):
        deny(reason)


def policy_from_bytes(raw: bytes, pinned_sha256: str):
    """Independent digest must originate OUTSIDE candidate PR/control plane."""
    if type(raw) is not bytes or len(raw) > 16_384:
        deny("INVALID_POLICY_BYTES")
    if type(pinned_sha256) is not str or not HEX64.fullmatch(pinned_sha256):
        deny("INVALID_PIN")
    if hashlib.sha256(raw).hexdigest() != pinned_sha256:
        deny("POLICY_DIGEST_MISMATCH")
    try:
        p = json.loads(raw)
    except (UnicodeError, ValueError):
        deny("INVALID_POLICY_JSON")
    require_keys(p, ("schema", "policy", "app_id", "app_slug", "installation_id", "account_id", "account_login", "repository_id", "repository", "permissions", "token_expiry_seconds"), "INVALID_POLICY_FIELDS")
    if p["schema"] != APP_SCHEMA or p["policy"] != APP_POLICY:
        deny("UNRECOGNIZED_POLICY")
    for name in ("app_id", "installation_id", "account_id", "repository_id"):
        if not positive_int(p[name]):
            deny("INVALID_IDENTIFIERS")
    if type(p["app_slug"]) is not str or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", p["app_slug"]):
        deny("INVALID_APP_SLUG")
    if type(p["account_login"]) is not str or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", p["account_login"]):
        deny("INVALID_ACCOUNT_LOGIN")
    if type(p["repository"]) is not str or not REPO.fullmatch(p["repository"]) or p["repository"].split('/')[0] != p["account_login"]:
        deny("INVALID_REPOSITORY")
    if type(p["permissions"]) is not dict or p["permissions"] != PERMISSIONS:
        deny("UNAPPROVED_PERMISSIONS")
    if type(p["token_expiry_seconds"]) is not int or not 60 <= p["token_expiry_seconds"] <= 3600:
        deny("UNSAFE_TOKEN_TTL")
    return p


def _permissions(perms, required):
    """Reject both escalation and missing permissions; null means unavailable."""
    if type(perms) is not dict or perms != required:
        deny("PERMISSION_SCOPE_MISMATCH")


def _repo(r, policy):
    if type(r) is not dict or type(r.get("id")) is not int or r.get("id") != policy["repository_id"] or r.get("full_name") != policy["repository"]:
        deny("REPOSITORY_IDENTITY_MISMATCH")
    owner = r.get("owner")
    if type(owner) is not dict or type(owner.get("id")) is not int or owner.get("id") != policy["account_id"] or owner.get("login") != policy["account_login"]:
        deny("REPOSITORY_OWNER_MISMATCH")


def verify_offline_contract(policy, *, app_view, installation_view, repository_view, token_request):
    """Verify four independently sourced *shapes*, not cryptographic origin.

    app_view: proposed GET /app response (JWT context).
    installation_view: proposed GET /app/installations/{id} response (JWT context).
    repository_view: proposed GET /installation/repositories response (installation token context).
    token_request: approved POST access-token REQUEST BODY (no actual token).
    Never pass a bearer token/response containing a secret to this function.
    """
    require_keys(policy, ("schema", "policy", "app_id", "app_slug", "installation_id", "account_id", "account_login", "repository_id", "repository", "permissions", "token_expiry_seconds"), "INVALID_POLICY_FIELDS")
    if policy.get("schema") != APP_SCHEMA or policy.get("policy") != APP_POLICY or policy.get("permissions") != PERMISSIONS:
        deny("UNAPPROVED_POLICY")
    if type(app_view) is not dict or type(app_view.get("id")) is not int or app_view.get("id") != policy["app_id"] or app_view.get("slug") != policy["app_slug"]:
        deny("APP_IDENTITY_MISMATCH")
    _permissions(app_view.get("permissions"), policy["permissions"])
    if type(installation_view) is not dict or type(installation_view.get("id")) is not int or installation_view["id"] != policy["installation_id"]:
        deny("INSTALLATION_ID_MISMATCH")
    a = installation_view.get("app_id")
    if type(a) is not int or a != policy["app_id"]:
        deny("INSTALLATION_APP_MISMATCH")
    account = installation_view.get("account")
    if type(account) is not dict or type(account.get("id")) is not int or account.get("id") != policy["account_id"] or account.get("login") != policy["account_login"]:
        deny("INSTALLATION_ACCOUNT_MISMATCH")
    if installation_view.get("repository_selection") != "selected" or installation_view.get("suspended_at") is not None:
        deny("INSTALLATION_SCOPE_OR_SUSPENSION")
    _permissions(installation_view.get("permissions"), policy["permissions"])
    repos = installation_view.get("repositories")
    # GitHub installation detail may not contain complete repository list.
    # It must be checked independently with a scoped installation token.
    if repos is not None:
        deny("AMBIGUOUS_INSTALLATION_REPOSITORIES")
    if type(repository_view) is not dict or type(repository_view.get("total_count")) is not int or repository_view["total_count"] != 1:
        deny("TOKEN_REPOSITORY_COUNT_MISMATCH")
    items = repository_view.get("repositories")
    if type(items) is not list or len(items) != 1:
        deny("TOKEN_REPOSITORY_LIST_MISMATCH")
    _repo(items[0], policy)
    # POST /app/installations/{id}/access_tokens request *intent*, no mint.
    require_keys(token_request, ("repository_ids", "permissions"), "TOKEN_REQUEST_FIELDS")
    if type(token_request["repository_ids"]) is not list or len(token_request["repository_ids"]) != 1 or type(token_request["repository_ids"][0]) is not int or token_request["repository_ids"][0] != policy["repository_id"]:
        deny("TOKEN_REQUEST_REPOSITORY_MISMATCH")
    _permissions(token_request["permissions"], policy["permissions"])
    return {"state": "APP_SCOPE_CONTRACT_CONSISTENT_NOT_AUTHENTICATED",
            "app_id": policy["app_id"], "installation_id": policy["installation_id"],
            "repository_id": policy["repository_id"], "permissions": sorted(PERMISSIONS),
            "note": "OFFLINE_ONLY_NO_TOKEN_NO_APP_KEY_NO_CHECK_RUN_GATE_A_BLOCKED"}
