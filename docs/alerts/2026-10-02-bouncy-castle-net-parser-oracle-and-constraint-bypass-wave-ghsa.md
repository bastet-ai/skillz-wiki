---
title: "Bouncy Castle .NET parser, oracle, and constraint-bypass wave (Oct 2 09:31Z)"
---

# Bouncy Castle .NET parser, oracle, and constraint-bypass wave (Oct 2 09:31Z)

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-10-02. ~20 GHSAs published 09:31Z for **bc-csharp before 2.7.0** ("Legion of the Bouncy Castle Inc."), plus three Java BC pre-1.86 items in the same wave. Companion pages: [July 1 BC CTR keystream](2026-07-01-bouncy-castle-ctr-keystream-boundary-ghsa.md), [Aug 3 BC crypto-policy boundaries](2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md).

Why this matters to an operator: bc-csharp is embedded in .NET apps, Windows services, CMS document pipelines, PKI tooling, and IoT/OT management stacks. This wave is a complete catalogue of **what an attacker gets when a product parses untrusted crypto objects with this library**: padding oracles that recover plaintext keys, PKIX name-constraint bypasses for enterprise-pivot certificates, a forged-attribute-certificate auth bypass, and a resource-exhaustion inventory reachable pre-authentication.

## Decision oracles: decrypt-and-report paths are key-recovery machines

| Component | GHSA / CVE | Oracle |
| --- | --- | --- |
| CMS RSA PKCS#1 v1.5 key transport (`KeyTransRecipientInformation.UnwrapKey`) | [GHSA-xx4m-xv2j-xx6g](https://github.com/advisories/GHSA-xx4m-xv2j-xx6g) / CVE-2026-63573 | Invalid padding rejected with a **distinct "bad padding" exception** instead of the RFC-required random-key substitution → textbook **Bleichenbacher adaptive chosen-ciphertext**: submit modified captured `EnvelopedData`, read the error taxonomy, recover the content key. |
| IES/ECIES block-cipher mode (`IesEngine.DecryptBlock`) | [GHSA-6w4x-4wpp-m6r4](https://github.com/advisories/GHSA-6w4x-4wpp-m6r4) / CVE-2026-63567 | Decrypt + PKCS#7 padding strip happen **before MAC verification**; padding failure returns a different message and *skips the MAC computation* (also a timing differential) → **CBC padding oracle** on any app that surfaces decrypt errors. |
| IES stream mode (no block cipher) | [GHSA-43qj-h4fh-p2h4](https://github.com/advisories/GHSA-43qj-h4fh-p2h4) / CVE-2026-16001 | KDF output is laid out as keystream-then-MAC-key with the derivation input bound only to the **static key pair**, so the keystream revealed by **one observed message with known plaintext contains the MAC key** for every shorter message → forge arbitrary shorter ciphertexts accepted as authentic, permanently, for that key pair. |
| CCM AEAD (`CcmBlockCipher`, CMS `EnvelopedData` paths) | [GHSA-499v-wjw6-fvpx](https://github.com/advisories/GHSA-499v-wjw6-fvpx) / CVE-2026-15999 | Decrypt accepts an `AlgorithmIdentifier` whose `aes-ICVlen` is **zero or outside the RFC 5084 set** (tag length is validated only on *encrypt*); on-path attacker swaps parameters to a zero-length tag → content modification without detection. |
| DSTU 7624 CCM (`KCcmBlockCipher`) | [GHSA-m3jv-gj9x-qwrv](https://github.com/advisories/GHSA-m3jv-gj9x-qwrv) / CVE-2026-16000 | The G1 block binding nonce+length+flags into the CBC-MAC is processed **only when associated data is present**; no-AD messages get a nonce-independent tag → ciphertext forgery from known/chosen-plaintext observations. |
| CCM unverified-plaintext release | [GHSA-v84x-v65q-m82v](https://github.com/advisories/GHSA-v84x-v65q-m82v) / CVE-2026-103601 | Failed decryption **leaves recovered plaintext in the caller's output buffer** (buffer reuse/logging oracle → chosen-ciphertext decryption service). |
| Raw DH agreement (`DHAgreement.CalculateAgreement`, MTI/A0) — **critical** | [GHSA-m2m9-m35w-rfxg](https://github.com/advisories/GHSA-m2m9-m35w-rfxg) / CVE-2026-63569 | Peer ephemeral value raised to the static private key with **no range/subgroup check**: crafted small-order/out-of-range value makes both parties compute a key the on-path attacker already knows, and leaks the static private key modulo small factors of p−1. |

**Operator rules.**

1. **Error taxonomy is the probe.** For any endpoint that decrypts attacker-supplied crypto objects (CMS in document/email pipelines, ECIES in device provisioning, PFX upload forms), the finding is not "vulnerable library" — it is *does a padding failure produce a different response than a MAC/tag failure?* Differential battery: untampered / padding-corrupted / MAC-corrupted / truncated inputs; compare status, exception class, message text, and latency. A per-class differential = key-recovery oracle; report the exact differentiating field.
2. **Parameter-bearing AlgorithmIdentifiers are attacker-chosen and often only validated on the encrypt path.** Sweep every AEAD/KDF/PBE algorithm parameter (`aes-ICVlen`, PBKDF2 iterations, scrypt `N/r/p`, OAEP label) through the **decrypt/verify direction** with degenerate values (0, 1, 2^31−1, out-of-set enums).
3. **Test static-DH APIs for small-order inputs.** If a product calls raw DH agreement (not the authenticated TLS stack), submit a `g^(p−1)`-style order-1 element as the peer ephemeral and check whether the session proceeds.

## PKIX validation bypasses (enterprise-pivot class)

| Check | GHSA / CVE | Bypass shape |
| --- | --- | --- |
| `directoryName` name constraints | [GHSA-437r-hr8h-5f45](https://github.com/advisories/GHSA-437r-hr8h-5f45) / CVE-2026-63577 | Subtree match searches for the constraint's **first RDN anywhere** in the subject and compares the rest from that position — prepend unrelated RDNs ahead of a copy of the permitted sequence → cert whose DN is *outside* the permitted subtree validates. |
| URI (`uniformResourceIdentifier`) constraints | [GHSA-3248-8mh4-pcmr](https://github.com/advisories/GHSA-3248-8mh4-pcmr) / CVE-2026-63576 | Host extracted by **string slicing without isolating the RFC 3986 authority** — a URI with `@` or `:` in path/query/fragment userinfo makes the string compared against constraints differ from the real host. |
| DNS/email constraints, excluded subtrees | [GHSA-mx2f-845p-2h26](https://github.com/advisories/GHSA-mx2f-845p-2h26) / CVE-2026-103602 | **Trailing-dot root label** (`evil.example.com.`) fails to match an excluded subtree written without the dot → excluded names validate. |
| Attribute certificates (`PkixAttrCertPathValidator`) | [GHSA-cwfr-988g-hf77](https://github.com/advisories/GHSA-cwfr-988g-hf77) / CVE-2026-63571 | The RFC 3281 validation routine checks holder/issuer paths, validity, extensions, revocation — and **never verifies the attribute certificate's own signature**. A forged AC naming a trusted issuer grants whatever roles the app reads from its attributes. |
| PKCS#12 chain building | [GHSA-g2c8-ppvq-rq73](https://github.com/advisories/GHSA-g2c8-ppvq-rq73) / CVE-2026-63570 | Chain loop follows AuthorityKeyIdentifier links **without visited-set and without checking signatures**; two certs whose AKIs point at each other = infinite loop (CPU + OOM). |

**Operator rules.**

- **Name constraints are the least-tested PKIX control.** If an engagement yields any issuance capability from an enterprise intermediate (even a "locked-down" name-constrained one), test the three shapes above against a lab verifier before concluding the constraint actually confines you: prepend-RDN, authority-slicing URI (`uri:user@real-host?` shapes), trailing-dot FQDN. Constraint enforcement is verifier-side: also test client-side validators (TLS libraries, document signers, code-signing policy chains) separately from the CA's own issuance checks.
- **Attribute/role certificates: does the validator verify the signature at all?** Any app granting privileges from X.509 ACs or holder-issuer bindings deserves a forged-AC test with an issuer name copied from a real AA. Zero cost, and the validation-stack skip is exactly what this advisory proves is plausible.
- **Path-building loops that trust unsigned identifier links are DoS + confusion primitives.** Feed AKI-cycle pairs to any PFX/PKCS#12 loader.

## Pre-authentication work-before-authentication: the resource-exhaustion inventory

The recurring shape across this wave: **cost/length parameters are read from the untrusted object and consumed before any MAC, password, or signature can reject the input.** That ordering — work first, authenticate later — is the audit predicate, not "is it a DoS."

| Parser path | GHSA / CVE | Unbounded input → work |
| --- | --- | --- |
| ASN.1 (`Asn1InputStream`/`Asn1StreamParser`) | [GHSA-xp76-rp77-x5w9](https://github.com/advisories/GHSA-xp76-rp77-x5w9) / CVE-2026-103600 | No depth bound; ~2,000 nested SEQUENCEs (**8 KB DER**) exhaust the default .NET thread stack → **uncatchable** `StackOverflowException` kills the whole process. Any cert/CRL/CMS/PKCS#7 accepting path is a crash switch. |
| PKCS#12 load (`Pkcs12Store.Load`) | [GHSA-v54c-wxx6-mjh6](https://github.com/advisories/GHSA-v54c-wxx6-mjh6) / CVE-2026-63572 + [GHSA-7c84-x75c-5j8m](https://github.com/advisories/GHSA-7c84-x75c-5j8m) / CVE-2026-63575 | MacData/PBE iteration count taken from the file up to ~2^31 → KDF runs **before the MAC or password is checked**; zero/negative count wraps the loop through ~2^32 iterations. A 75-byte PFX ties up a worker for minutes. |
| Encrypted private keys (`PbeUtilities`, PBES1/PBES2/PKCS#12 PBE/CMS PBE) | [GHSA-4583-5v2w-p3vq](https://github.com/advisories/GHSA-4583-5v2w-p3vq) / CVE-2026-63578 | Same shape on `ENCRYPTED PRIVATE KEY` PEM upload forms. |
| CMP/CRMF PBMAC verifier | [GHSA-mm8p-p4g9-932c](https://github.com/advisories/GHSA-mm8p-p4g9-932c) / CVE-2026-63568 | Iteration cap enforced **only when the caller used the explicit-maximum constructor** — the convenient constructor runs attacker-chosen iterations up to 2^31 before the MAC check. |
| OpenPGP subpacket parsers | [GHSA-576x-9vpc-g3jj](https://github.com/advisories/GHSA-576x-9vpc-g3jj) / CVE-2026-63574 | Five-octet length form allocates up to ~2 GB from a few header bytes, never compared to the enclosing packet size. |
| HSS/LMS signatures | [GHSA-gpr4-c479-xrw4](https://github.com/advisories/GHSA-gpr4-c479-xrw4) / CVE-2026-103603 | Level count from the public key unchecked against RFC 8554 max 8 → one verify allocates up to ~17 GB. |
| DTLS handshake reassembly | [GHSA-496x-2f25-59fj](https://github.com/advisories/GHSA-496x-2f25-59fj) / CVE-2026-63566 | Fragment buffer sized from the 24-bit declared length **without the max-handshake-size check TLS already applies**; an empty fragment allocates ~16 MB × 16 pending messages **before the handshake is authenticated**. |
| DN-to-string escaping (`X509Name.ToString`, `RdnAreEqual`) | [GHSA-p48w-99f8-9598](https://github.com/advisories/GHSA-p48w-99f8-9598) / CVE-2026-103604 | Escaping inserts into the buffer being scanned → CPU grows quadratically with escaped-character count; fires when a cert name is logged/displayed or compared during PKIX directoryName constraint checks (same validator as the bypass items above). |

**Operator rules.**

- **Fuzz battery for every untrusted ASN.1/PKCS/OpenPGP consumer** (cert/CRL upload, PFX import, S/MIME handler, OpenPGP key server, DTLS listener, CMP enrollment endpoint): depth-nested SEQUENCEs (8 KB → process death on .NET defaults), max-length five-octet subpacket headers, iteration-count 2^31−1 and −1, HSS/LMS level-count 2^32, DTLS fragments declaring 16 MB with zero payload. These are the shapes with *published, specific* thresholds now — they are one-liner generators, and pre-auth ones.
- **"Cap-before-derive" is also an audit rule for integrators**: when a product embeds this library, its own wrappers frequently reintroduce the unbounded constructor path (the PBMAC constructor split is the exemplar — the safe API exists, the default one is unsafe).

## Java BC (before 1.86) adjacent legs

- **NTRU secret-dependent division** ([GHSA-frjj-v5w4-68pc](https://github.com/advisories/GHSA-frjj-v5w4-68pc) / CVE-2026-18036): `modQ`/`mod3` helpers used integer `%` on secret operands where the reference implementations are deliberately division-free — variable-latency division on the **decapsulation path** (dividend derives from the private key). Post-quantum KEM side channel in the *reduced-secret handling*, not the core math — audit pattern: check every modular reduction in a PQC port against the reference's division-free construction.
- **MLS signed/unsigned leaf index** ([GHSA-x7w3-c4mv-whm4](https://github.com/advisories/GHSA-x7w3-c4mv-whm4) / CVE-2026-17507): RFC 9420's `uint32 leaf_index` held in a signed `int`; a wire value with the top bit set is a *legal encoding* (interop vectors round-trip the full range), and signed comparison against leaf count makes **any negative index pass the membership check** → any group member DoSes the whole group via unbounded `directPath` arithmetic. Axis: **signed/unsigned parse differential** — same family as the negative-length/offset items on the parser pages; a spec says "full uint32 range decodes", so the fix must reinterpret, not reject-on-negative. (MLS roster-trust companion to the Oct 2 Discord libdave item on the messaging-SDK page.)
- **KDF cost parameters from untrusted input** ([GHSA-m3x3-p27c-whhp](https://github.com/advisories/GHSA-m3x3-p27c-whhp) / CVE-2026-17508): PBMAC1 iteration count, scrypt `p` (bounded `N`/`r` but scratch scales with `r×p`, evading the memory ceiling), raw JCA PBKDF2, bcrypt rounds read from an OpenSSH v1 key's own `kdfoptions` — the Java twin of the .NET work-before-authentication class; OpenSSH rounds now capped via `org.bouncycastle.openssh.max_rounds`.

## Validation workflow (lab scope only)

!!! warning "No production crypto endpoints"
    All oracle and exhaustion proofs run against lab builds/disposable services you own with synthetic keys and certs. Bleichenbacher/padding-oracle proofs need only enough iterations to show the differential exists (a handful of classification queries), not full key recovery. Never run memory-exhaustion shapes against shared or production hosts — allocate in a constrained VM and measure.

1. **Oracle decision table:** for each decrypt endpoint, submit untampered / padding-corrupt / tag-corrupt / truncated variants; table status+message+latency per class. Any separation = oracle; stop there.
2. **Parameter-degeneracy sweep:** replay CMS/PKCS structures with `aes-ICVlen=0`, iterations 0/−1/2^31−1, scrypt p unbounded — assert the decrypt direction validates parameters, not just encrypt.
3. **Lab PKIX constraint harness (Java/Go, no network):** build a name-constrained test CA with openssl, issue prepend-RDN, trailing-dot, and authority-sliced URIs certs; run the target verifier and diff accept/reject vs RFC 5280 expected.
4. **ASN.1 depth generator:** 8 KB nested-SEQUENCE DER sent to cert/CRL/CMS ingestion in a lab process with default thread stack; observe StackOverflow vs caught exception (this also tells you whether the app's host swallows crashes).
5. **PFX micro-DoS timer:** 75-byte PFX with negative MacData iterations against a lab PFX import form; measure worker occupancy with a stopwatch, not a profiler.

## Tracked without publication (same Oct 2 09:31Z wave)

- cPanel/WHM trio: Mass Modify Accounts stored XSS→code execution ([GHSA-jc78-m6vr-f88f](https://github.com/advisories/GHSA-jc78-m6vr-f88f)), Manage SSL Hosts stored XSS ([GHSA-cc4m-c4vh-cj6w](https://github.com/advisories/GHSA-cc4m-c4vh-cj6w)), Multilang adminbin cmdi ([GHSA-hw2c-444c-65c4](https://github.com/advisories/GHSA-hw2c-444c-65c4)) — all critical but zero technical detail; admin-panel-position XSS class already canonical, revisit if sink detail lands.
- JSON API Auth cached-cookie ATO folded separately onto the Sept 19 WP alternate-surface page.
- MStore API <4.22.1 client-controlled order fields → unpaid→paid ([GHSA-2gpc-rx3g-g49h](https://github.com/advisories/GHSA-2gpc-rx3g-g49h)); WebToffee Gift Cards <1.3.1 unvalidated/negative gift-card amount as cart price ([GHSA-5v9w-gc32-w7g2](https://github.com/advisories/GHSA-5v9w-gc32-w7g2)) — client-trusted-amount/price axis canonical on the Sept 23 WC payment page.
- Dc Woocommerce Multi Vendor ≤5.0.18 `order_by` ORDER BY SQLi where `esc_sql()` protects only quoted literals ([GHSA-xgpw-mm25-3whc](https://github.com/advisories/GHSA-xgpw-mm25-3whc)) — sort-column-into-SQL class already canonical (Fleet/ClickHouse, TDuckCloud, iFlytek).
- HAVELSAN Sef AI Chatbot SSRF/cert-validation/missing-authz trio ([GHSA-pg74-28w9-6j58](https://github.com/advisories/GHSA-pg74-28w9-6j58), [GHSA-679g-qgm4-wf24](https://github.com/advisories/GHSA-679g-qgm4-wf24), [GHSA-352f-59q8-5jw5](https://github.com/advisories/GHSA-352f-59q8-5jw5)) — detail-free single-vendor pack.
- gotop local argument injection on process-kill ([GHSA-pm6f-qrm6-v363](https://github.com/advisories/GHSA-pm6f-qrm6-v363)) — local-position class.
- FreeType CID font loader flaw, Repasat XSS trio, Event Tickets generic SQLi, and ~25 generic WP stored/reflected XSS + option-write singles (Relevanssi pair, CMB2 pair, Download Manager/Monitor, Greenshift, Smash Balloon, JetFormBuilder, Kubio, MW WP Form, Newsletter, GSpeech, Otter, DoFollow, No External Links, Customer Reviews, Listdom, Mang Board, BA Book Everything, WP Edit Password, Easy PayPal button, WP User Frontend, WP Mail Logging, Popup Maker, Motors, Events Calendar, CTX Feed admin eval) — sanitizer/IDOR/missing-cap singles with no new axis; several are siblings of items already canonical on the Sept 19 WP pages.
