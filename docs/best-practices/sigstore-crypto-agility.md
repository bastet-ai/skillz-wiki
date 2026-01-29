# Sigstore crypto agility (controlled algorithms, long-lived signatures)

Software signatures have an **expiration date**: artifacts may be deployed for decades, while today’s algorithms may be deprecated (policy, practical attacks, or post-quantum pressure).

Sigstore historically favored safety by hard-coding a narrow set of algorithms. Recent work adds **controlled cryptographic agility** without repeating classic “agile crypto” failures.

## What can go wrong (why “agility” is dangerous)

Crypto agility often fails due to **in-band algorithm signaling** (“the data tells you how to verify it”). This has produced real-world classes of bugs such as:

- Accepting `alg: none` (no signature) as valid
- **Algorithm confusion** (e.g., verifying HMAC with an RSA public key)

**Defender rule:** do not let attacker-controlled data choose algorithms.

## The safe pattern: suites + allowlists (not mix-and-match)

Prefer **predefined suites** (coherent, audited combinations) over ad-hoc composition.

Example concept:

- `PKIX_ECDSA_P256_SHA_256` (ECDSA P-256 + SHA-256)
- `PKIX_ECDSA_P384_SHA_384` (ECDSA P-384 + SHA-384)
- `PKIX_ED25519` (Ed25519 + its associated hashing behavior)

This prevents dangerous combinations (e.g., strong key + weak hash) and reduces “footguns”.

## Implementation takeaways (what actually changed)

Key design choices that map directly to defensive guidance:

- **Algorithm registry as a single source of truth** (central list of allowed algorithms/suites).
- **Service-side restrictions**: deployments can explicitly restrict what client signing algorithms are accepted.
- **Correct hash-by-key-type behavior** (avoid “everything hashes with SHA-256” mistakes when key types vary).
- **Client support for selecting an approved suite** (without creating arbitrary combos).

## Operational guidance (high leverage)

### 1) Decide algorithm policy **out-of-band**

- Choose accepted algorithms via **deployment configuration / policy**, not from signed payload metadata.
- Treat “algorithm negotiation” as a configuration management problem.

### 2) Enforce an allowlist on verification services

For private Sigstore deployments, restrict what clients may use:

- Configure Rekor/Fulcio (or equivalent) to accept only an approved set of client signing algorithms.
- Reject entries that don’t match policy (“algorithms are not allowed”).

Practical examples to look for in your stack:

- **Fulcio/Rekor allowlist flags** like `--client-signing-algorithms=...` (deployment-time restriction).
- **Cosign** client selection like `--signing-algorithm=...` (client must pick from what the deployment allows).

### 3) Plan for re-signing and long-term verification

- Record provenance + bundles/attestations so artifacts can be re-verified even as ecosystems change.
- Maintain a migration plan to **re-sign** critical artifacts when algorithms are deprecated.

### 4) Test your policy against downgrade/confusion attempts

Validation tests to run periodically:

- Attempt to sign with a disallowed algorithm and confirm the log/service rejects it.
- Attempt to verify artifacts signed with multiple algorithms and confirm verification follows policy.
- Ensure defaults are safe when flags/config are missing.

## Why this matters for defenders

- **Incident response:** algorithm agility expands attack surface; you want strict policy + logs for forensics.
- **Compliance:** some orgs require specific suites (e.g., NIST-approved curves/hashes).
- **Future-proofing:** post-quantum readiness starts with architectures that can evolve without “accept anything”.

## References

- Trail of Bits: *Building cryptographic agility into Sigstore* (2026-01-29)
