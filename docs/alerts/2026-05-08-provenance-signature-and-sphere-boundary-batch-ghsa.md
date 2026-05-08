# Provenance, signature, and sphere-boundary batch

**Signal:** The **2026-05-08 23:15 UTC** scan added supply-chain verification and control-sphere advisories where tools disagreed about what artifact, commit, or resource was actually being authorized.

## Advisory cluster

- **gitsign normalized-object trust confusion** — [GHSA-7rmh-48mx-2vwc](https://github.com/advisories/GHSA-7rmh-48mx-2vwc): `gitsign verify` and `verify-tag` checked signatures over go-git-normalized bytes rather than raw git object bytes, allowing malformed duplicate-header objects to verify differently than git-core resolves them. Patch to **0.16.0+**.
- **in-toto negation mismatch** — [GHSA-pmwq-pjrm-6p5r](https://github.com/advisories/GHSA-pmwq-pjrm-6p5r): in-toto-golang and in-toto-python interpreted glob character-class negation differently, so layouts could apply artifact rules inconsistently. Patch `in-toto-golang` to **0.11.0+** and test layouts across implementations.
- **OpenStack Ironic resource-transfer issue** — [GHSA-54w4-233h-x86g](https://github.com/advisories/GHSA-54w4-233h-x86g): an Ironic control-sphere boundary issue was updated in the feed; keep this with the existing OpenStack/Ironic authorization guidance and verify patched packages in exposed clouds.
- **Withdrawn duplicate handling** — [GHSA-jpr7-q523-hx25](https://github.com/advisories/GHSA-jpr7-q523-hx25) was withdrawn as a duplicate of the phpseclib ASN.1 issue; do not let duplicate IDs create conflicting triage state.

## Why this matters

Verification systems fail when they sign one representation but deploy another. Git object normalization, artifact glob dialects, and cloud resource-sphere transitions all need canonical “what exactly is being authorized?” checks before a signature, policy rule, or control-plane decision is trusted.

## Triage

1. Patch gitsign and in-toto-golang where release, CI, or deployment gates rely on them.
2. Re-run verification on protected branches/tags using raw git object bytes and reject malformed duplicate-header commits or tags.
3. Cross-test in-toto layouts with both Python and Go implementations, especially rules using negated character classes.
4. Confirm OpenStack/Ironic deployments have vendor fixes for the resource-transfer issue and audit recent node/resource ownership transitions.
5. Normalize duplicate GHSA/CVE records in ticketing so the canonical advisory drives remediation status.

## Durable controls

- Verify signatures over the exact bytes the downstream tool will consume, not a re-encoded approximation.
- Keep policy languages implementation-compatible with golden fixtures in CI.
- Treat resource transfer between tenants, projects, or control spheres as a first-class authorization check with audit logs.
- Track withdrawn duplicate advisories as aliases, not separate vulnerabilities.
