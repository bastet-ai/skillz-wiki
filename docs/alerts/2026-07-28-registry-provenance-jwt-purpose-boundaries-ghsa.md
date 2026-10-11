---
title: Registry provenance and JWT purpose boundaries from July 28 GHSA updates
---

# Registry provenance and JWT purpose boundaries from July 28 GHSA updates

Two July 28 GitHub-reviewed advisories yield durable operator checks: deleting local package provenance makes a registry pack easier to load, and a panel-signed JWT for one action can be replayed at a different node endpoint. Both are **valid artifact, wrong security meaning** bugs. Test the missing-metadata state and token-purpose binding directly rather than stopping at signature validity.

Sources:

- [GHSA-hc4m-q9jh-xw4j: nono registry-pack verification can fail open](https://github.com/always-further/nono/security/advisories/GHSA-hc4m-q9jh-xw4j)
- [nono fail-closed verification fix](https://github.com/nolabs-ai/nono/commit/db07375031642f089d549b4f7b9abece87e39f87)
- [GHSA-8r6w-3qq5-4p4r: Pterodactyl cross-purpose panel JWT replay](https://github.com/pterodactyl/panel/security/advisories/GHSA-8r6w-3qq5-4p4r)
- [Pterodactyl Panel scoped-token fix](https://github.com/pterodactyl/panel/commit/7ffcd636310bb72b54bac3280d2a15e727feded7)
- [Pterodactyl Wings scope-enforcement fix](https://github.com/pterodactyl/wings/commit/d0ddc80844479302abdaf9654de3bacd511c0f5c)

The reviewed ranges are nono-cli `<=0.61.2`, Pterodactyl Panel `<1.12.3`, and Pterodactyl Wings `<1.12.2`. GitHub's package metadata names nono-cli `0.61.3` as the first patched version, while the advisory references a `v0.62.0` release; preserve that discrepancy and verify the exact fixed artifact you can install.

!!! warning "Authorized validation only"
    Use a disposable home directory, inert registry pack, isolated Pterodactyl server, synthetic subuser, short-lived lab JWTs, and uniquely named text files. Never alter a real user's package store, run pack-provided host hooks, upload executable content, overwrite application or server configuration, expose a panel signing key, or reuse production tokens.

## Boundary matrix

| Surface | Trusted decision | Attacker-controlled state | Safe proof |
| --- | --- | --- | --- |
| nono registry pack load | selected pack is locked and provenance-verified | installed pack plus missing lockfile entry and trust bundle | tampered text artifact loads only in the dual-missing state |
| Pterodactyl Wings upload | panel signature authorizes this endpoint and action | valid JWT issued for WebSocket or download purpose | unique text marker accepted at upload endpoint in a disposable server |

For both surfaces, save the baseline, mutate one state variable at a time, and repeat against a fixed build. A missing file or decoded JWT alone is not a finding; prove the later load or endpoint decision.

## nono: provenance checks must be monotonic

GHSA-hc4m-q9jh-xw4j describes two local provenance records for registry packs:

- `packages/lockfile.json`, which binds installed artifacts to hashes; and
- `<namespace>/<pack>/.nono-trust.bundle`, which carries trust metadata.

The affected verifier rejects a pack when its trust bundle exists but the lockfile entry is absent. If the trust bundle is also removed, however, the installed pack may load. The reusable pattern is **removing more security metadata converts a rejection into acceptance**.

### Disposable-home decision table

Prerequisites:

- affected and fixed nono-cli binaries with hashes recorded;
- an inert registry pack whose files and expected behavior are known;
- a temporary directory used as `HOME` and `XDG_CONFIG_HOME`; and
- a profile that selects only that pack and cannot reach production credentials, repositories, sockets, or networks after installation.

Procedure:

1. Pull the inert pack normally into the disposable home. Archive the resulting lockfile and `.nono-trust.bundle`; record hashes for both metadata files and every installed artifact.
2. Confirm the unmodified profile loads. Do not invoke a pack session hook or any host-executed command.
3. Change one harmless text artifact to a random marker while keeping both metadata files. Confirm the normal integrity check rejects it.
4. Restore the pack, then remove only its lockfile entry while leaving `.nono-trust.bundle` present. Confirm the affected build rejects the profile and save the error.
5. From the same tampered-artifact snapshot, remove both the lockfile entry and `.nono-trust.bundle`. Attempt only profile resolution or another no-hook load path. Record whether the profile is accepted and whether the altered marker remains the selected artifact.
6. Add controls for lock-present/bundle-missing, lock-missing/bundle-present, both present, and both missing. Reset from the same snapshot between rows so stale state cannot influence the result.
7. Repeat the matrix with the fixed artifact available to you. The fix commit requires a matching lockfile entry and present trust bundle; either missing record should fail closed with a re-pull instruction.

Suggested evidence table:

| Lock entry | Trust bundle | Artifact hash | Affected result | Fixed result |
| --- | --- | --- | --- | --- |
| present | present | expected | load | load |
| present | present | altered canary | reject | reject |
| absent | present | altered canary | reject | reject |
| absent | absent | altered canary | **load** | reject |

A bounded positive result is **the same altered inert pack is rejected when one provenance record is missing but accepted after both records are removed**. This proves a fail-open verification state. Do not claim host execution unless a separate, explicitly approved assessment establishes a reachable pack-provided hook; profile acceptance is sufficient to report the provenance bypass.

## Pterodactyl: a signature must not substitute for token purpose

GHSA-8r6w-3qq5-4p4r describes Panel-issued JWTs that shared claims such as `server_uuid`, `user_uuid`, and `unique_id` but did not identify their intended action. Wings' `/upload/file` handler accepted any valid panel-signed token with the expected structural claims. A subuser permitted to connect to a console or obtain a download link could therefore reuse that token to upload to the **same server** without `file.create`.

The fixed Panel adds a `scope` claim such as `websocket`, `file-upload`, `file-download`, `backup-download`, or `transfer`; fixed Wings checks the required scope at each sink. This is a general token-confusion heuristic: inventory every minting route and every verifier that shares a signing key, then test whether audience, purpose, scope, object, and single-use rules are enforced independently.

### Same-server, marker-only replay fixture

Prerequisites:

- an isolated Panel/Wings lab at affected versions;
- one disposable server containing no real workloads or secrets;
- a synthetic subuser granted `websocket.connect` but not `file.create`;
- an empty writable test directory inside that server; and
- request capture configured to redact the token value.

Procedure:

1. As the server owner, confirm the synthetic subuser cannot request the normal file-upload URL through the Panel API. Save the status and effective permission set.
2. As that subuser, request a short-lived WebSocket token through the normal client API. Decode it locally without logging its signature or full serialized value; record only claim names, redacted subject identifiers, timestamps, and whether a purpose/scope claim exists.
3. Send the token to the affected Wings upload endpoint for the same disposable server. Upload one uniquely named `.txt` file containing a random marker. Do not upload scripts, archives, server configuration, startup files, plugins, or symlinks.
4. Verify only that exact marker through the server owner's normal file view, record its hash, and delete it during fixture teardown.
5. Repeat with a token issued for file download or backup download if those permissions are separately in scope. Use a fresh token for every row; do not test another server or user.
6. Add negative controls: expired token, corrupted signature, wrong synthetic server UUID, and a token from a lab user with no access to the server. These should fail and demonstrate that the result is cross-purpose replay, not signature or object-binding failure.
7. Upgrade **both** sides to Panel `1.12.3` and Wings `1.12.2`. Confirm a WebSocket-scoped token is rejected at upload while a normally issued `file-upload` token works for a user explicitly granted `file.create`.

Suggested decision table:

| Issued purpose | User permission | Target sink | Expected affected result | Expected fixed result |
| --- | --- | --- | --- | --- |
| WebSocket | `websocket.connect` | WebSocket | allow | allow |
| WebSocket | no `file.create` | same-server upload | **allow** | reject |
| File download | no `file.create` | same-server upload | **allow** | reject |
| File upload | `file.create` | same-server upload | allow | allow |
| WebSocket | no access to another server | other-server upload | reject | reject |

A bounded positive result is **a valid token minted for one low-privilege action reaches a different same-server sink and creates only the unique text marker despite the missing upload permission**. Do not describe this as signing-key compromise, unauthenticated arbitrary upload, or cross-server access; the advisory requires an authenticated subuser who can obtain a different Panel-signed token.

## Reporting checklist

Include:

- exact package/build hashes and whether source, release, or GitHub range metadata was used;
- nono disposable-home paths, lock/trust presence, artifact hashes, profile load result, and proof no hook ran;
- Pterodactyl Panel and Wings versions, subuser permissions, token minting route, redacted claim-name table, sink, and same-server binding;
- baseline, one-variable mutations, negative controls, and fixed-build results;
- random marker names and hashes plus teardown confirmation; and
- a narrow impact statement separating provenance bypass from host-hook execution, and purpose confusion from signing-key, cross-server, or unauthenticated claims.

Never include a complete JWT, panel key, registry trust material, real package contents, server files, credentials, or production identifiers.

## October 11 follow-up: hyper-mcp — Cosign verifies the tag, the loader runs the manifest, and any Sigstore identity passes (2 GHSAs, high)

The same "valid artifact, wrong security meaning" family, now in WASM plugin supply-chain form. hyper-mcp `<=0.8.3` (MCP-over-HTTP host that loads signed OCI WebAssembly plugins) shipped **two independent breaks in the same trust decision** ([GHSA-phv4-c98f-77h3 / CVE-2026-108698](https://github.com/advisories/GHSA-phv4-c98f-77h3), [GHSA-4j25-h357-wg62 / CVE-2026-108699](https://github.com/advisories/GHSA-4j25-h357-wg62)):

- **[GHSA-phv4-c98f-77h3](https://github.com/advisories/GHSA-phv4-c98f-77h3)** — `load_wasm` in `src/wasm/oci.rs` verifies the Cosign signature of a **separately resolved tag** while executing a **differently resolved manifest**. An attacker who controls registry responses for the tag reference can serve the signature-checker a signed manifest and the loader an unsigned malicious one. The verified object and the executed object are two different network fetches — TOCTOU at the registry layer. Operator rule: **signature-coverage gap analysis** — for any signature-verified fetcher, identify which resolved digest the verifier consumes and which digest the executor consumes; if the flow resolves by mutable reference (tag) more than once, or re-resolves after verification, the signature proves nothing about the loaded bytes. Fingerprint: `verify(tag)` + `fetch(tag)` call pairs instead of `fetch(digest)` + `verify(digest)`.
- **[GHSA-4j25-h357-wg62](https://github.com/advisories/GHSA-4j25-h357-wg62)** — `cosign_verify_args()` accepts **any signer identity and OIDC issuer by default**: no `--certificate-identity` / `--certificate-oidc-issuer` pinning means a freely-obtainable Sigstore keyless certificate (any GitHub account, any public repo workflow) satisfies "signed." Operator rule: **an unpinned keyless verification policy is signature-worthless** — the bar is "signed by anyone," and anyone includes the attacker with a free account. On any product advertising "cosign-verified plugins/images," check whether an identity/issuer allowlist is configured; if not, the supply-chain control is decorative and any image you keyless-sign loads.

Combined attack path in a lab: keyless-sign a malicious WASM plugin via public Sigstore (free cert), reference it by tag — passes both defaults. Plugin executes with the host's configured capabilities (filesystem, environment). Validation boundary: disposable hyper-mcp instance, inert marker-emitting WASM plugin, your own registry or public repo; never target a third-party plugin registry or ship payload code. Proven positive = host loads and runs the attacker-signed plugin under default config. This generalizes the page's nono fail-open theme: **provenance metadata can be missing (nono), verified-against-the-wrong-object, or verified-against-a-vacuous-policy (hyper-mcp) — test the verification decision, not the presence of a signature pipeline.**
