# Stage 011B — paired evidence observations, NO attestation

## Scope
Two independent, sequential real GitHub API observations from `mf002078/GOV-GITHUB` (job `validate`) and `mf002078/GOV-PROTECTED-VALIDATOR` (job `self-test`) via Stage 010. Both must match operator-pinned SHA/PR/run/attempt, identical to the strict Stage 010 contract. This does **not** mean one historical CI run authorizes a future issuance.

Policy input JSON must contain exactly `schema`, `policy`, `max_age_seconds`, `max_skew_seconds`, `targets`. Each target specifies `repo`, `pr`, `head`, `base`, `run`, `attempt`, `job`. The exact policy file bytes are checked against a **separately pinned SHA256**. Do not generate the hash from untrusted PR code as a substitute for an independent trust anchor. No secrets in the policy file. A template is provided separately with intentionally invalid placeholder SHAs.

Timing: uses the matched successful job's `started_at`/`completed_at` timestamps, not `run.updated_at`. Both must be fresh and finish within configured skew. A historical 2026-10-25 run will be rejected on 2026-11-03 as STALE. Default suggested `max_age_seconds` 3600 and `max_skew_seconds` 300. Test clocks are injected only by unit tests; CLI uses current UTC. Historical runs are **never grandfathered**.

SQLite provides a **local observation ledger**, with `BEGIN IMMEDIATE`, a UNIQUE identity key and persistent file. Never put this DB in the repository or an ephemeral directory. SQLite is **not** an attestation ledger, does not prevent a separate machine from recording the same evidence, and does not safely handle crash consistency between future external Check Run publishing and local state. Formal publishing must later use a separate transactional design and issuer-controlled durable storage.

## Run (Pochun2-controlled local host only)

Use the installed Python 3.13 from the repo root, with policy file placed in a private local directory (no secrets in policy):

```powershell
py -3.13 -B -m validator.issuer_pair_observer --policy 'C:\\issuer-local\\policy.json' --expected-sha256 '<independently-pinned-64-hex-hash>' --ledger 'C:\\issuer-local\\observations.sqlite'
```

Success output is a **minimal SAFE report**: policy digest, observation identity and run IDs; no symbols, prices, filesystem paths, credentials, raw API payloads. On any API mismatch, replay, missing permission, missing timestamp, policy mismatch, disk error or timeout, returns `BLOCKED`, exit code 2. Never treat exit 0 as a trusted attestation.

## Important boundaries
- No GitHub App credentials, no token handling, no account access, no Check Run publication, no merge, no Gate A change.
- PR code-controlled GitHub Actions still cannot provide an independent trusted proof. A workflow App ID 15368 alone is insufficient.
- Current-state PR validation is not a historical immutable snapshot. Forked PRs, paginated API data and missing run `pull_requests` are rejected by the earlier-stage modules.
- Workflow-file contents, GitHub ref integrity, PR base ancestry, branch-rule mutations, trusted policy authority, durable issuer identity and atomic publish are **not yet validated**. Therefore NOT_DEPLOYED remains mandatory.
- Runs are checked sequentially; external state may change between reads. This package is an observation prototype, not transactional snapshot isolation or formal external attestation.
