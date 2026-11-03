# Stage 012A — Workflow identity and pinned immutable contents (candidate)

This module is **READ-ONLY, PRE-PRODUCTION, NOT ATTESTED**. It checks two explicitly approved repositories independently, the workflow run's `workflow_id`, `path`, `head_sha`, `run_attempt`, event, and successful result; it reads a workflow file at exactly the expected head and base SHA and verifies the Git blob SHA-1, decoded size, and an **issuer-authority-pinned SHA-256 of the bytes**. Head/base workflow content must match. A mismatch blocks both.

Inputs are a small JSON policy matching `issuer-workflow-binding-v1` and an independently established SHA-256 digest of **the exact policy file bytes**. There is deliberately no self-approval or dynamic digest discovery from PR-controlled data. The policy itself must be reviewed and pinned in a separately controlled issuer environment. Policy record fields: `schema`, `policy`, `targets` (exactly one `mf002078/GOV-GITHUB` and one `mf002078/GOV-PROTECTED-VALIDATOR`); target fields `repo`, `run`, `attempt`, `head`, `base`, `workflow_path`, `workflow_id`, `workflow_sha256`.

## Security boundaries and limitations

- **Important:** GitHub `workflow_run.path` and `workflow_id` plus pinned repository content do **not cryptographically prove which executable workflow definition was run**. This prototype only binds API-declared identifiers and current immutable Git contents to independent expectations. The final issuer needs stronger trusted-ref/runner provenance, workflow reachability/ancestry and reconciliation against an independently controlled workflow catalog.
- It does not enforce branch protection or run a new Check, sign/approve, use tokens, or execute CI as a trusted issuer. GitHub Actions tests here execute candidate PR code: they are quality tests, **not** independent evidence.
- It does not substitute for Stage 011B's PR/run/job/check validation, freshness, replay or multi-Repository skew. Its successful result must not be used alone to relax any gates.
- For `pull_request` events, GitHub may report synthetic merge SHA or a workflow path with a ref suffix. Both are rejected by this strict prototype unless an explicitly verified updated contract is implemented. No fallback to treating missing evidence as approval.
- GitHub Contents REST response is verified in-memory with a strict size/encoding/path/file SHA contract. No file URLs from responses are followed. The SHA-1 blob check validates GitHub's conventional SHA-1 object format, **not** a new security root of trust; SHA256 is the issuer-pinned byte identity.
- No stored App key, install token, Check Run publication, account/order API, Gate A mutation or scheduler.

## Validation

Run all existing tests from the repository root:

```powershell
py -3.13 -B -m unittest discover -s tests -v
```

No real GitHub API calls occur in the CI test suite. The real endpoint reader `WorkflowReader` is available for a **later explicitly controlled, independently pinned read-only test**. No default policy is shipped: the candidate PR must not define its own trusted pin.
