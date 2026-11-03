# Stage 012C — offline mock issuance transaction, NOT attestation

## Scope
A deterministic mock exercises the `PREPARED -> PUBLISHING -> PUBLISHED` path, with `BLOCKED` on ordinary simulated failures. The **only allowed publisher** is in-process `FakePublisher`; there are no HTTP clients, installation tokens, GitHub Check Run writes, private keys, account/order operations or real issuance. No external eligibility decision is made. The source repository and app identity are fixed in a demonstration `Intent`; these inputs are NOT an authenticated GitHub App session.

## Durable state
The SQLite ledger uses `BEGIN IMMEDIATE`, a unique identity derived from canonical intent fields, `synchronous=FULL`, and a compare-and-swap SQL update on expected states. The file must be kept on a locally trusted persistent disk, outside the repository; it must **never** be committed or deleted between runs. The caller must pin evidence and policy SHA256 externally; accepting arbitrarily chosen digests proves nothing. The ledger does not guard against administrative DB rollback, symlink races, machine compromise, or duplicate issuance from another host.

`PUBLISHING` is deliberately ambiguous. A process crash may occur before or **after** a remote side effect. A subsequent invocation may **not retry**; an operator can locally quarantine the transaction with `seal_uncertain()`, but this does not reconcile an actual remote Check Run. With a real publisher, reconciliation needs a trusted remote lookup and identity linkage; this stage does **not** implement that mechanism. `PUBLISHED` is **MOCK_PUBLISHED_NOT_ATTESTED**, not production issuance. Exceptions cannot guarantee remote non-delivery.

## How to run
From issuer repository root:

```powershell
py -3.13 -B -m unittest discover -s tests -v
py -3.13 -B -m validator.issuer_transaction --self-check
```

Tests use `TemporaryDirectory`, close each SQLite connection using `contextlib.closing`, run concurrent prepare/publish attempts, crash simulations, corruption rejection, and double-publish rejection. On Windows, optional symlink support may vary (the symlink-specific test skips only if the OS disallows creation). Never substitute a real remote publisher for the Mock in this phase.

## Deployment and next gates
`Gate A = BLOCKED/UNVERIFIED`, `Trusted Issuer = NOT_DEPLOYED`, `T+1 = PAUSED_MANUAL`. Stage 012C is a **local mock transaction** only: it does not establish cross-system ACID or exactly-once GitHub issuance. Next work requires independent GitHub App identity/provenance, remote idempotency, trusted lookup, rollback protection and explicit controlled activation approval.
