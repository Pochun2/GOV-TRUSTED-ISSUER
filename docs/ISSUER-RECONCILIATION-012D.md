# Stage 012D — read-only remote Check Run reconciliation contract

## Scope and authority

`validator/issuer_reconciliation.py` is a **read-only contract** for reconciling an unresolved Stage 012C SQLite `PUBLISHING` transaction with a GitHub Check Run. Tests use in-memory fake reader responses only. The module does not mint App tokens, possess an App private key, publish or update Check Runs, connect a production issuer, promote a ledger state, or grant Gate A. An offline fake response is NOT authenticated GitHub evidence.

An approved caller may inject Stage 009 `ReadOnlyGitHub` (HTTPS GET only) for an independently authorized, read-only remote observation. That is a separate operator-controlled operation, not part of the CLI or test workflow. A supplied `reader.get()` implementation MUST be trusted and independently authorized. A caller-selected Check Run ID is an **independent pin**; never select the ID from the same untrusted list as the sole authority.

## Contract

- Requires Stage 012C's exact `Intent` and `validate_intent` (`mf002078/GOV-GITHUB`, App ID `5475837`, check name `GOV-Protected-Validator`, 40-character lowercase head SHA, evidence and policy SHA256, installation ID).
- Reads existing persistent SQLite via `mode=ro`/`query_only=ON`, rejects symlinks and missing/unreadable/corrupt databases. Requires exact intent row in `PUBLISHING`, with no receipt/reason and revision >= 1. `PUBLISHED` in Stage 012C was mock-only and **cannot** be promoted to real proof. `BLOCKED` and `PREPARED` are not eligible.
- Fetches one exact `GET /repos/mf002078/GOV-GITHUB/commits/{head_sha}/check-runs?per_page=100` read-only API path, requires a complete page (`total_count == len(check_runs) <= 100`), positive unique Check Run IDs, exactly one matching `external_id == transaction_id`, and that matching run's independent pinned ID, name, SHA, GitHub App ID, completed status and success conclusion.
- Any absent, duplicate, untrusted, future/pending, failed or malformed result returns `ReconciliationError` and **must not trigger automatic retry**. This includes an empty response: absence is ambiguous, not evidence that a prior write did not occur.
- A positive result is only `REMOTE_MATCH_OBSERVED_NOT_ATTESTED`; the ledger remains `PUBLISHING`. This stage never calls `Ledger._transition()` or GitHub POST/PATCH.

## Critical limitations

1. The existing Stage 012C publisher is a mock. No real GitHub App Check Run exists as a consequence of these tests. A synthetic fixture with matching IDs cannot prove a genuine external publication.
2. `external_id` correlates an observed Check Run to a transaction but is not an unforgeable signature. Real proof requires an authenticated GitHub API channel, independent App identity, true provenance of external evidence, and operator-controlled trust pins.
3. The SQLite ledger is not protected against filesystem rollback, deletion, multi-host duplication or malicious database edits. Read-only does not equal an authenticated local ledger.
4. Pagination is **not** supported; more than 100 Check Runs or truncated results fail closed.
5. A positive observation does not solve cross-system ACID, exactly-once delivery, durable repair or activation. Publishing and `PUBLISHING -> PUBLISHED` require a future explicitly approved protocol.

## Local verification

```powershell
py -3.13 -B -m unittest discover -s tests -v
py -3.13 -B -m validator.issuer_reconciliation --self-check
```

The `--self-check` CLI prints an `OFFLINE_ONLY` SAFE report. Without `--self-check`, it exits 2 and prints `BLOCKED`. There is no network CLI mode, no credentials, and no production endpoint.

**Governance:** `Gate A = BLOCKED/UNVERIFIED`; `Trusted Issuer = NOT_DEPLOYED`; `T+1 = PAUSED_MANUAL`.
