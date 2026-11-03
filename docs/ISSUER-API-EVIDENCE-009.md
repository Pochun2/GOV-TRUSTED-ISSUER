# Stage 009 — read-only GitHub API evidence contract (pre-production)

This is a candidate owner-side prototype. It provides independently fetched GitHub Actions run, job and check-run evidence with fail-closed matching to exact expected repository and SHA. **All tests are offline mocks.** `verify_pair` returns `ELIGIBLE_FOR_FURTHER_ISSUER_POLICY_REVIEW`, never PASS or issuer attestation.

Important limitations:

- There is **no live end-to-end GitHub API test** and no model API or GitHub App identity/credential execution.
- `Target.commit_sha` and the run IDs must come from independently established trusted issuer state. The source/validator contracts currently use PR workflows; their GitHub Actions `head_sha` may refer to a synthetic PR merge commit rather than the PR head. A mismatch is BLOCKED; explicit PR/head-to-merge provenance must be researched and implemented before real issuance.
- Strict `total_count == page length` fails closed for more than 100 jobs/check runs; future pagination requires deliberate implementation.
- No freshness bounds, immutable workflow-path policy, worklog policy verification, PR base ancestry, installation scope check, actor authentication, storage lock/atomic replay-to-attestation, or policy report verification. These are REQUIRED before trust release.
- Read-only requests use TLS to `api.github.com`; may use an independent caller-provided GitHub bearer token. Never place credentials in PR-triggered workflows or commits. Response objects are untrusted until checked against issuer-controlled expected inputs.
- No candidate-provided API JSON may be treated as verified evidence. The fake reader in tests is only a deterministic mock.
- `issuer-api-evidence-offline` CI runs untrusted PR code, hence is a **code quality check**, NOT a trusted issuing check. Do not relax Gate A or any other repo's security Ruleset.
