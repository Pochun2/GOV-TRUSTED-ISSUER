# GOV-AUTO-REVIEW-007 — Pochun2 Issuer handoff, unprivileged prototype

This is an OFFLINE integration candidate under `mf002078/GOV-PROTECTED-VALIDATOR`, **not installed in** `Pochun2/GOV-TRUSTED-ISSUER`. `issuer_snapshot_gate.py` consumes a synthetic typed Snapshot and validates cross-repository exact SHA consistency (source `validate`, independent validator `self-test`), policy/model report digests, 5-minute freshness, and a durable sqlite replay key. This does NOT authenticate an API result: any candidate can construct a matching Snapshot. A positive result is only `ELIGIBLE_FOR_AUTHENTICATED_ISSUER_RECHECK`, not PASS, ATTESTED or a Check Run.

## Pochun2-owned implementation prerequisites

1. Under a Pochun2-controlled runner, fetch the HEAD and relevant PR metadata separately from the GitHub REST API for `mf002078/GOV-GITHUB` and `mf002078/GOV-PROTECTED-VALIDATOR`. Verify branch, merge base, workflow run check IDs, exact SHA, all run attempts, GitHub Actions app identity and success conclusion by **independent authenticated reads**. Do not deserialize a candidate-provided `Snapshot` as source of truth.
2. Obtain exact immutable validator SHA and protected policy digest from a trusted control plane; compare source/validator check run status in *each respective repository*, not a fake combined list.
3. Keep App private key and model credentials outside source PR workflows, candidate repos and chat, use a fixed allowed installation/repository; never expose them to PR checks or LLMs. Use protected workflow and runner with pinned dependencies, no untrusted code execution, outbound filtering and secret/PII review.
4. Persist anti-replay records on a Pochun2-controlled durable volume with backups, constrained permissions and concurrent transactional writes. Reserving a key is not sufficient proof of model authenticity. Design crash/retry/reconciliation handling before live issuance.
5. Re-fetch PR HEAD and policy immediately before publication; issue an App-owned GitHub Check Run only from the authenticated trusted App identity after all independently verified controls pass. Verify negative cases including forged App ID, replay, SHA drift, failure checks, policy changes and revoked installation.
6. Bootstrap under Pochun2's own credentials and current `ISSUER-MAIN-PROTECTION`; DO NOT grant candidate account Write, create App PEM in candidate repo, bypass Rulesets, or assert Gate A acceptance. Human review requirements remain until a governed and verified transition to CI-only.

**Status:** OFFLINE_PROTOTYPE; no real LLM inference, GitHub API reads, trusted issuer deployment, GitHub Check Run issuance, Ruleset modification, main merge or Gate A acceptance. `Gate A = BLOCKED / UNVERIFIED`.
