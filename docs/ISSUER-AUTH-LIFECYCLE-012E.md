# Stage 012E — offline GitHub App authentication lifecycle contract

## Scope (NO actual credentials)
This module validates **untrusted metadata shapes** for a hypothetical GitHub App JWT and GitHub App installation token, using an independently-pinned Stage 012B policy. **No JWT bytes, signatures, private keys, bearer tokens, JWT signing/decoding, GitHub API calls, token minting, credential storage, or Check Run creation exist in this stage.** A positive result is **NOT_AUTHENTICATED** and does not authorize issuance.

- App ID pinned to `5475837`; source repository pinned to `mf002078/GOV-GITHUB`. Do not confuse GitHub Actions App ID `15368` with the independently-owned issuer.
- Policy input must pass Stage 012B's strict structure and caller-supplied independent policy SHA256, which must originate outside candidate PR control. Caller-supplied digests alone are not a trust root.
- `verify_jwt_claims` accepts only `iss`, `iat`, `exp` fixtures and enforces App ID, positive integers, <=600s lifetime, <=60s clock skew and non-expiry. This is **not signature verification**, nor proof of a valid GitHub-issued JWT.
- `verify_token_metadata` accepts a **token-free mock descriptor**: App/installation ID, one repository ID, exact least-privilege permission dictionary, issued/expiry UTC values, and token type `installation`. Unknown keys (including `token`) fail closed. There is no actual OAuth/installation-token introspection in this stage.
- `MockLifecycle` uses in-memory synthetic, non-secret `TokenLease` identifiers and one-time mock `use_once` semantics. Expired/revoked/blocked leases reject later use. Mock revoke does **not** call GitHub token revocation. In-memory state does not survive restarts, protect against concurrent hosts, or provide durable anti-replay.

## Testing and exit contract

```powershell
py -3.13 -B -m unittest discover -s tests -v
py -3.13 -B -m validator.issuer_auth_lifecycle --self-check
```

The self-check prints `OFFLINE_ONLY` with `NO_JWT_SIGNING_NO_TOKEN_NO_KEY_NO_CHECK_RUN_GATE_A_BLOCKED`. On unapproved usage, CLI returns `BLOCKED`, exit=2. Unit tests cover mismatched App ID, Actions App spoofing, token-shaped secret fields, expiration, clock drift, cross-repository access, permission escalation, token type confusion, replay, revocation and blocking.

## What remains unimplemented
Trusted private-key custody by Pochun2, actual GitHub App JWT signing and cryptographic validation, installation selection through authenticated GitHub API, token minting and rotation, token securely held in memory, remote revocation, real Check Run publishing, independently durable issuer authority, and cross-system reconciliation. Those require separate controlled deployment and explicit approval; do not replace mocks with credentials in PR CI.

**Gate A = BLOCKED / UNVERIFIED; Trusted Issuer = NOT_DEPLOYED; T+1 = PAUSED_MANUAL.**
