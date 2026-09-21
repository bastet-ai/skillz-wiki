# Bouncy Castle certificate, signature, and authenticated-content boundary checks

Sources: hourly offensive-security scan, 2026-08-03 GitHub Security Advisory feed and the [Bouncy Castle Java security-advisory index](https://github.com/bcgit/bc-java/wiki). Primary entries are linked in the matrices below.

The Bouncy Castle 1.85 advisory wave exposes a durable testing rule: a cryptographic API returning success is not enough. The application must prove that the accepted proof is bound to the intended certificate, signer, hostname, content, policy, and authenticated-decryption result.

!!! warning "Authorized validation only"
    Use locally generated keys, certificates, CMS/OpenPGP objects, LDAP entries, and ciphertext in a disposable JVM harness. Do not replay production certificates, signatures, mail, keystores, directory queries, or encrypted traffic. Keep parser-cost and oracle tests offline and bounded.

## Affected branches and prerequisites

- Bouncy Castle for Java before `1.85` is affected by the entries below.
- Java LTS and FIPS artifact fix levels differ by component; use each linked Bouncy Castle advisory as the source of truth rather than assuming the community version number applies to every artifact.
- Build one affected fixture and one patched fixture with the same application code and generated test corpus.
- Record exact Maven/Gradle coordinates because `bcprov`, `bcpkix`, `bctls`, `bcpg`, and mail artifacts can resolve independently.

```bash
mvn -q dependency:tree -Dincludes=org.bouncycastle
./gradlew -q dependencyInsight --dependency bouncycastle --configuration runtimeClasspath
```

Capture artifact, resolved version, provider order, API entry point, input fixture ID, result, exception class, and whether any plaintext or side effect became observable before final validation.

## Certificate and identity-policy matrix

| Boundary | Primary source | Differential fixture | Positive evidence |
| --- | --- | --- | --- |
| Stapled OCSP response -> certificate being checked | [GHSA-j295-77c3-9frf](https://github.com/advisories/GHSA-j295-77c3-9frf) / [CVE-2026-58062](https://github.com/bcgit/bc-java/wiki/CVE-2026-58062) | Generate certificates A and B under a test CA, staple a valid response for A while validating B, and compare with the correctly bound A/A control. | The affected path accepts a response whose certificate ID does not identify B; the patched path rejects it before treating B as good. |
| X.509 name constraint -> canonical mailbox or URI host | [GHSA-9pwp-9qqc-pr26](https://github.com/advisories/GHSA-9pwp-9qqc-pr26) / [CVE-2026-8763](https://github.com/bcgit/bc-java/wiki/CVE-2026-8763) | Use a constrained synthetic domain and compare exact, subdomain, trailing-dot, mixed-case, and out-of-scope `rfc822Name` and URI values. | A trailing dot changes the decision without changing the intended DNS identity boundary. |
| TLS endpoint identity -> SAN/CN policy | [GHSA-8rxj-3p7p-rq39](https://github.com/advisories/GHSA-8rxj-3p7p-rq39) / [CVE-2026-59638](https://github.com/bcgit/bc-java/wiki/CVE-2026-59638) | Generate a certificate with a matching CN but absent or non-matching SAN; run with default settings and explicit CN-fallback opt-in. | The affected default accepts CN fallback even though the behavior is documented as opt-in; patched default and explicit opt-in diverge. |
| S/MIME validation time -> trusted validation clock | [GHSA-vgvx-fcjw-w4m8](https://github.com/advisories/GHSA-vgvx-fcjw-w4m8) / [CVE-2026-59641](https://github.com/bcgit/bc-java/wiki/CVE-2026-59641) | Sign synthetic mail with a certificate outside its validity window and vary only the signer-asserted `signingTime`. | Caller-controlled signed metadata changes path-validity acceptance instead of a trusted validation-time input controlling the decision. |

For every identity test, preserve both the textual input and the canonical identity used by the application. A parser difference is not yet impact: show that it reaches certificate acceptance, trust-path selection, or endpoint authorization.

## Signature and content-binding matrix

| Boundary | Primary source | Differential fixture | Positive evidence |
| --- | --- | --- | --- |
| CMS verification success -> at least one required signer | [GHSA-r3rc-x3pq-jmw7](https://github.com/advisories/GHSA-r3rc-x3pq-jmw7) / [CVE-2026-59639](https://github.com/bcgit/bc-java/wiki/CVE-2026-59639) | Compare valid one-signer, invalid one-signer, and structurally valid zero-signer `SignedData`. | `verifySignatures()` returns true for zero signers and the application equates that vacuous result with an authenticated artifact. |
| CMS `AuthenticatedData` MAC -> exact content returned to the caller | [GHSA-cfjh-c47f-gprf](https://github.com/advisories/GHSA-cfjh-c47f-gprf) / [CVE-2026-59642](https://github.com/bcgit/bc-java/wiki/CVE-2026-59642) | With `authAttrs` present, mutate only the synthetic content while preserving the authenticated attributes and MAC fixture. | Verification succeeds while the returned content is not the bytes bound by the MAC. |
| OpenPGP inline-signature policy -> overall verification result | [GHSA-r7xx-x336-xqqr](https://github.com/advisories/GHSA-r7xx-x336-xqqr) / [CVE-2026-59643](https://github.com/bcgit/bc-java/wiki/CVE-2026-59643) | Build a locally signed message that is cryptographically valid but violates one configured inline-signature policy, alongside valid and bad-signature controls. | The policy callback records failure but the affected high-level operation still reports success. |
| Authenticated decryption -> plaintext release | [GHSA-cwc6-73j8-3qm6](https://github.com/advisories/GHSA-cwc6-73j8-3qm6) / [CVE-2026-58061](https://github.com/bcgit/bc-java/wiki/CVE-2026-58061) | Encrypt a short canary under CCM, alter only the tag, and instrument caller-buffer writes before finalization. | Unauthenticated plaintext reaches the caller buffer before tag failure; do not claim disclosure unless the application can consume or retain those bytes. |

### Application-level validation sequence

1. Identify the high-level operation the application trusts: package import, signed configuration, S/MIME approval, authenticated message, or decrypted record.
2. Interpose a recorder immediately after the Bouncy Castle call. Record whether the application checks signer count, required signer identity, policy callbacks, final authentication status, and content digest.
3. Change one binding at a time. Do not combine a zero-signer object, content mutation, and policy failure into one opaque fixture.
4. Run the same corpus against affected and patched artifacts. Keep application logic and provider order fixed.
5. Report the full chain: **crafted local object -> library result -> missing application invariant -> harmless synthetic action selected**.

## Directory, key-agreement, and keystore boundaries

| Boundary | Primary source | Safe validation pattern |
| --- | --- | --- |
| Certificate selector -> LDAP filter grammar | [GHSA-mf66-6236-xhfw](https://github.com/advisories/GHSA-mf66-6236-xhfw) / [CVE-2026-59652](https://github.com/bcgit/bc-java/wiki/CVE-2026-59652) | Point the legacy `jdk1.4` `LDAPStoreHelper` at a local fake LDAP recorder. Supply synthetic selector values containing `*`, `(`, `)`, NUL, and backslash and compare the emitted filter AST, not real directory results. |
| MTI/A0 peer public value -> valid DH group element | [GHSA-ghgq-7g74-28wp](https://github.com/advisories/GHSA-ghgq-7g74-28wp) / [CVE-2026-59650](https://github.com/bcgit/bc-java/wiki/CVE-2026-59650) | Use a tiny test-only group or mocked exponentiation boundary to compare valid, identity, zero, negative, and out-of-range peer values. Prove whether validation occurs before exponentiation; do not derive or reuse real session keys. |
| Parsed BKS version -> required integrity strength | [GHSA-mwmr-38hj-q7gm](https://github.com/advisories/GHSA-mwmr-38hj-q7gm) / [CVE-2026-59651](https://github.com/bcgit/bc-java/wiki/CVE-2026-59651) | Generate a keystore containing only a canary key and compare modern BKS with the legacy version using a 16-bit integrity-MAC key. Record format/version acceptance separately from any application trust decision. |

LDAP metacharacters in a filter string, an unusual DH value, or an old keystore version are structural observations. Escalate only when the application reaches an unauthorized directory match, agreement success, trusted-key import, or another concrete synthetic sink.

## Oracle and downgrade checks

[GHSA-w983-hf44-gcww](https://github.com/advisories/GHSA-w983-hf44-gcww) / [CVE-2026-59640](https://github.com/bcgit/bc-java/wiki/CVE-2026-59640) reports an OpenPGP CFB quick-check oracle on symmetric/session-key paths. Validate it only in a local process:

1. Produce one small OpenPGP canary with a generated key or password.
2. Mutate the quick-check bytes and unrelated ciphertext positions in a bounded fixture set.
3. Compare return class, exception type, response length, and coarse repeated timing distributions.
4. Confirm whether an application exposes a stable remote distinction before claiming an oracle. Do not automate plaintext recovery or send probes to a shared service.

The BKS legacy-integrity issue is similarly a format downgrade, not proof of key recovery. A report should separate **weak format accepted** from **application imports and trusts attacker-controlled key material**.

## August 3 follow-up: bind every authenticated result to all of its inputs

A later advisory-feed wave adds five integrity failures that fit the same operator rule. Use generated keys and short local messages, change one field per fixture, and instrument the application boundary after the high-level API returns. Do not reuse production ciphertext, signatures, or key material.

| Boundary | Primary source | Differential fixture | Positive evidence |
| --- | --- | --- | --- |
| IES stream-mode MAC -> exact KDF split and message length | [GHSA-834p-whmm-rg5r](https://github.com/advisories/GHSA-834p-whmm-rg5r) / CVE-2026-12816 | Generate one test-only IES key pair and short plaintexts on both sides of the relevant length boundary. Preserve a valid control, then alter only the stream length/ciphertext arrangement presented for verification. | The affected artifact accepts a modified message under a MAC derived from the wrong length-dependent KDF split; the patched artifact rejects it. |
| OpenPGP AEAD success -> final chunk tag | [GHSA-9q38-7pr7-8j6w](https://github.com/advisories/GHSA-9q38-7pr7-8j6w) / CVE-2026-12817 | Produce local AEAD messages whose plaintext is exactly chunk-aligned and one byte off the boundary. Corrupt only the final tag and consume the stream to EOF. | The affected chunk-aligned path reports successful completion or releases a trusted result without validating the final tag; the off-boundary and patched controls reject. |
| KCCM authentication -> nonce as well as ciphertext | [GHSA-4r33-j73q-cw77](https://github.com/advisories/GHSA-4r33-j73q-cw77) / CVE-2026-12803 | Encrypt a tiny canary with no AAD, then replay the ciphertext/tag under a second generated nonce. Repeat with non-empty AAD as a control. | The affected no-AAD path accepts the cross-nonce pair; the patched path binds the nonce and rejects it. |
| CMS `AuthEnvelopedData` success -> required authentication-tag length | [GHSA-833g-4xxm-r9cx](https://github.com/advisories/GHSA-833g-4xxm-r9cx) / CVE-2026-12802 | Create a local authenticated envelope and compare its full tag with carefully truncated tag lengths while keeping recipients, algorithm, AAD, and content fixed. | A shortened tag reaches authenticated success or trusted plaintext on the affected path; the patched path enforces the algorithm's required tag length. |
| RSA PKCS#1 verification -> complete expected digest | [GHSA-cggx-vw4r-j93f](https://github.com/advisories/GHSA-cggx-vw4r-j93f) / CVE-2026-12860 | In a disposable harness, exercise only the NULL-omitted `DigestInfo` representation and mutate each of the final digest bytes independently. Keep a standards-conforming encoding as the positive control. | The affected verifier accepts a signature representation despite a mismatch in either of the final two expected hash bytes; the patched verifier compares the complete digest. |

For each result, show the application consequence with a harmless recorder such as `accepted fixture A`, `selected canary config`, or `released synthetic plaintext`. Library-level acceptance is important evidence, but it is not automatically proof that a remote product accepts attacker-controlled content.

### Parser-cost items from the same wave

The same feed also lists lazy ASN.1 depth-guard reset ([GHSA-qp49-qgx5-5m26](https://github.com/advisories/GHSA-qp49-qgx5-5m26)), MLS declared-length allocation ([GHSA-p2mp-577q-8vh2](https://github.com/advisories/GHSA-p2mp-577q-8vh2)), PKCS#12 iteration-cost handling ([GHSA-pxw2-f34f-xjvr](https://github.com/advisories/GHSA-pxw2-f34f-xjvr)), and definite-length up-front allocation ([GHSA-4hc3-69f9-4wfx](https://github.com/advisories/GHSA-4hc3-69f9-4wfx)). Treat these as bounded parser-cost checks, not exploit chains:

1. Run only in a subprocess or container with strict heap, CPU, and wall-clock limits.
2. Start with tiny synthetic depth, length, and iteration values and increase gradually; never begin with maximum-width fields.
3. Record whether rejection happens before recursive forcing, allocation, or KDF work.
4. Compare affected and patched artifacts with the same corpus and limits.
5. Do not send resource-exhaustion probes to shared or production services, and do not promote a local crash unless a specific authorized ingestion path makes the input attacker-controlled.

## Python `cryptography` PKCS#7 oracle follow-up

[GHSA-g6cj-pr64-35w5 / CVE-2026-69247](https://github.com/advisories/GHSA-g6cj-pr64-35w5) extends the authenticated-result rule to Python `cryptography` 44.0.0 through 49.x. The `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime` paths can distinguish RSA PKCS#1 v1.5 encrypted-key failures by exception text and timing when the linked backend lacks implicit rejection. The documented preconditions are narrow: an application must repeatedly decrypt attacker-supplied `EnvelopedData` for the target certificate and reflect an adaptively observable outcome. OpenSSL 3.2+ implicit rejection changes one error path, so record the actual backend rather than inferring exposure from the Python package version.

### Bounded oracle decision harness

1. Generate one disposable RSA recipient certificate and short PKCS#7 envelopes locally. Run affected and 50.0.0 fixtures with the same backend build and record `cryptography`, OpenSSL/LibreSSL/BoringSSL, and wheel provenance.
2. Wrap the application's decryption endpoint with a recorder that returns one constant synthetic failure externally. Internally capture only outcome class, normalized exception category, response length, and coarse duration; never log recovered key bytes or plaintext.
3. Compare a valid envelope, invalid RSA padding, a conforming RSA block that yields the wrong AES-key length, a correct-length wrong key, and altered encrypted content. Use the upstream regression fixtures or locally generated equivalents—do not develop adaptive ciphertext mutations against a service.
4. Repeat each fixed fixture a bounded number of times in an isolated process. Use distributions to establish whether outcome classes are separable; do not run key-recovery or plaintext-recovery automation.
5. Separately verify application reachability: untrusted envelope accepted, recipient selected, private-key operation attempted, and response observable. A library exception difference without an attacker-reachable repeated endpoint is not a remote oracle finding.

Report **attacker-supplied PKCS#7 envelope -> recipient private-key decryption -> distinguishable synthetic failure class or timing distribution -> fixed 50.0.0 converges on one failure path**. Keep the advisory's RSA encrypted-key oracle separate from unauthenticated CBC `encryptedContent` behavior, which the upstream record identifies as a format property rather than a fix in this release. Never test mail gateways with real keys/messages, generate high-volume adaptive queries, or recover a key or plaintext.

## Python `cryptography` name-constraint and path-cost follow-up

[GHSA-m2h6-j472-rp4c / CVE-2026-69248](https://github.com/advisories/GHSA-m2h6-j472-rp4c) adds a certificate-policy mismatch in Python `cryptography` through 48.0.0, fixed in 49.0.0. A constrained intermediate permitted only for a specific DNS name such as `foo.example.test` can issue a leaf containing the broader wildcard `*.example.test`; the affected verifier can accept that leaf for a sibling such as `bar.example.test`. The durable operator lesson is to bind a wildcard's complete match set—not merely its suffix—to every permitted subtree.

### Generated-chain differential

1. Create a local root and constrained intermediate with generated EC keys. Give the intermediate one `permittedSubtrees` DNS constraint for a synthetic exact host. Do not use a public hostname or production CA material.
2. Issue four leaves while keeping issuer, key usage, validity, and all unrelated extensions fixed: the exact permitted host, an in-scope narrower name if the chosen constraint permits one, a wildcard whose expansion includes names outside the constraint, and an unrelated name.
3. For each leaf, ask the server verifier about the exact host, one wildcard-matched sibling, and an unrelated control. Record the textual SAN, normalized reference identity, constraint, chain result, and selected chain.
4. Run the same corpus against 48.0.0 and 49.0.0 in separate disposable virtual environments. Keep the validation clock and extension policy fixed.
5. Add an application recorder after verification that logs only `accepted fixture <id>` and aborts before any network connection, token use, or privileged action.

The bounded positive is **intermediate constrained to exact host A -> leaf wildcard spans A and sibling B -> affected verifier accepts leaf for B -> 49.0.0 rejects before the application recorder**. A wildcard SAN or name constraint by itself is not a finding; show the accepted chain and the out-of-constraint reference identity. Do not present an upstream proof script as evidence unless it reproduces in the target application's actual verifier configuration.

[GHSA-jwv3-5hgf-82ww / CVE-2026-69249](https://github.com/advisories/GHSA-jwv3-5hgf-82ww) is an adjacent availability-only path-building issue through 48.0.0. Duplicate copies of a self-signed intermediate can cause exponential candidate exploration even though the invalid chain is eventually rejected. Keep it as a bounded parser-cost fixture rather than a standalone exploit path:

- use only generated, invalid chains and an unrelated generated trust anchor;
- run each affected and 49.0.0 case in a subprocess with strict CPU, memory, and wall-clock limits;
- start with one duplicate and a shallow maximum depth, increasing one dimension at a time only while the prior case remains within budget;
- record duplicate count, maximum depth, candidate visits if instrumented, result, elapsed time, and forced termination separately; and
- stop at a small reproducible affected-versus-fixed growth curve—never send certificate-amplification probes to a shared TLS or artifact-validation service.

Report the resource issue only when an authorized application accepts attacker-controlled chain material and performs the expensive path build. Certificate parsing in an isolated library benchmark proves the algorithmic differential, not remote availability impact.

## September 21 follow-up: capability inference from absent subpackets — sequoia-openpgp back-signature bypass

[GHSA-g33h-rrj9-75qv / CVE-2026-42784](https://github.com/advisories/GHSA-g33h-rrj9-75qv) (sequoia-openpgp, enriched in the September 21 update wave): when an older OpenPGP certificate has **no Key Flags subpacket**, the library *infers* capabilities from the algorithm and public-key packet rather than defaulting to none. The inferred view disagrees with verifiers that require explicit flags, letting an attacker bind an arbitrary subkey to their own certificate and **defeat the back-signature check** — the primary-key signature that proves the subkey-holder actually owns the parent key — so a forged subkey binding verifies and signatures forge.

The reusable axis extends this page's rule ("a crypto API returning success must bind the result to every intended input") to a *default-inference* variant: **capability, policy, or permission fields that are inferred when absent are a differential between two conforming implementations.** Testing workflow:

1. Generate two OpenPGP certs in a disposable harness (test CA-less, generated keys only): one modern cert with an explicit Key Flags subpacket denying certification/signing on a canary subkey, and one constructed legacy cert with the Key Flags subpacket **removed** and the same subkey.
2. Run the same verify/bind operation through affected and patched builds, and — when an application consumes the library — through the application's own policy check. A bounded positive is **the affected path treats the flagless cert's subkey as cert-capable and accepts the missing back-signature while the explicit-flags control rejects**.
3. Generalize the sweep to any format with optional capability subpackets/attributes (X.509 KeyUsage, SAML `AuthnContext`, OIDC `scope` defaults, macOS code-signing entitlements): enumerate every consumer's absent-field default and diff them. Two parsers answering "what may this key do?" differently on identical bytes is the finding; report the byte-level absence, the inferred answer, and the downstream authorization that consumed it.

Keep proofs to generated keys and synthetic bindings; no production keys, mail, or real signatures.

## Evidence and reporting checklist

- [ ] Absent-field inference findings record the exact packet/subpacket omitted and each verifier's inferred vs explicit answer.
- [ ] Exact Bouncy Castle artifact coordinates, provider order, and affected/patched versions are recorded.
- [ ] Every fixture uses generated keys, certificates, names, content, and directory entries.
- [ ] One trust binding changes per test, with valid, invalid, empty, and patched controls.
- [ ] Library return values are separated from the application's authorization or import decision.
- [ ] Signer count, signer identity, authenticated content bytes, certificate ID, hostname, and validation clock are recorded where relevant.
- [ ] Authenticated-decryption evidence states whether pre-verification plaintext was actually consumed.
- [ ] Oracle evidence includes stable externally visible classes; local exception differences alone are not reported as remote plaintext recovery.
- [ ] Wildcard SAN evidence records the full permitted-subtree match set and the exact out-of-constraint reference identity accepted by the affected verifier.
- [ ] Duplicate-chain path-cost cases run in bounded subprocesses and are not presented as integrity or authentication bypasses.
- [ ] AEAD/MAC tests bind nonce, AAD, ciphertext, message length, full tag, and finalization state independently.
- [ ] RSA verification evidence identifies the exact encoded form and altered digest byte; no private-key or collision claim is inferred.
- [ ] Parser-cost fixtures run under explicit resource limits and are reported separately from integrity failures.
- [ ] No private keys, production mail, directory data, keystores, ciphertext, or decrypted content appears in evidence.
