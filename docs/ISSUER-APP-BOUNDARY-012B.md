# GOV-AUTO-REVIEW-012B — GitHub App identity / installation scope (offline)

**Candidate-only:** deterministic checks of four *untrusted response shapes* and a proposed scoped token request. They are NOT authenticated proof, and are NOT a token-issuance implementation. All tests use synthetic objects. No App JWT, GitHub App private key, installation token, network operation, signed report or Check Run publication is performed.

## Required trust contract

- Keep independently pinned policy bytes + SHA256 **outside the candidate PR and GitHub Actions**. A self-computed digest is not a trust root.
- Independently verify `GET /app` using an App JWT on the **issuer-controlled host only**; `GET /app/installations/{id}` needs an appropriate App JWT; and `GET /installation/repositories` requires a separately scoped Installation Token. This package **does not** perform those authenticated calls.
- Verify app ID and slug, exact installation ID, owner login and numeric ID, `selected` repository selection, not suspended, exact permissions, numeric repository ID/full name/owner, one-page count exactly 1. Reject unknown or broadened permissions.
- A token request plan is limited to one `repository_ids` entry and exactly four expected permissions: `checks:write`, `contents:read`, `pull_requests:read`, `metadata:read`. The ability to *request* such a token does not prove a token was issued with those claims. GitHub may include implicit metadata permission; validate actual API semantics in a subsequent isolated production integration.
- App ID `5475837` and owner ID `62813082` occur in synthetic test fixtures; **these are not deployment configuration**. Installation ID `12345` is fictional. Obtain and independently pin verified IDs before deployment.
- The caller must never pass token material into responses or log it. The helper only returns `APP_SCOPE_CONTRACT_CONSISTENT_NOT_AUTHENTICATED`.
- Environment and token binding, issuer host identity, authenticated response provenance, expiry, revocation, installation ownership and issuer-controlled immutable policy are not established here. Stage 012C must not publish until these are resolved.

## Testing

```powershell
py -3.13 -B -m unittest discover -s tests -v
```

The unit tests are a compatibility gate, not a separation-of-duties proof. Candidate-controlled CI cannot by itself attest to an independent reviewer.
