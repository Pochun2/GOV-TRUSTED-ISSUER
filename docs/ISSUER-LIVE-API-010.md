# GOV-AUTO-REVIEW-010 — PR/run provenance, read-only

This stage extends Stage 009. Run the CLI only under a Pochun2-controlled
execution identity against public GitHub REST data. No token/private key is
included, and it does **not** publish any Check Run. CI executes mocked tests
only. A positive observation is not an attestation or permission to merge.

The expected PR HEAD SHA, base SHA, run ID, attempt and job name must be
independently supplied and checked. If a workflow run is associated with a
synthetic merge SHA, retrieve that commit and demand exactly the expected
head and base as parents. Direct-head runs are also supported. Stage 009
validates Actions run/job/check identities and GitHub Actions App ID 15368.

Limitations: This is current-state PR checking, not historical attestation.
It blocks closed PRs. GitHub's workflow-run `pull_requests` response can be
empty or structured differently; this candidate **fails closed** then, rather
than treating the missing association as success. In particular, run/check
semantics for synthetic merge SHA must be validated against authentic GitHub
responses before claiming full practical compatibility. One-page evidence
limit remains. No token auth, independent issuer App identity, trusted
workflow pinning, replay/nonce transaction, durable journal, policy hash,
complete base ancestry, freshness, or check publication. All are mandatory
before a trusted issuer can operate.

For local tests, after copying files into the owner repo:

    py -3.13 -B -m unittest discover -s tests -v

Example public read-only probe (use real inputs, never secrets):

    py -3.13 -B -m validator.live_api_probe --repo mf002078/GOV-GITHUB --pr 6 --head <40HEX_SHA> --base <40HEX_SHA> --run <ID> --attempt 1 --job validate

The command returns a JSON `BLOCKED` reason and exit code 2 on any mismatch;
only returns `OBSERVED_API_CONSISTENCY_ONLY_NOT_ATTESTED` for fully matching
provenance/evidence. No credentials are printed. Do NOT run it with a token
in shared logs or untrusted PR-triggered workflow contexts.
