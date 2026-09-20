# Rejection-path message smuggling (Exim) and UTF-16 surrogate markup hiding (Expat)

Source: hourly offensive-security scan, 2026-09-20. GitHub advisories [GHSA-3mrg-v8x6-xfjw](https://github.com/advisories/GHSA-3mrg-v8x6-xfjw) / [CVE-2026-94057](https://nvd.nist.gov/vuln/detail/CVE-2026-94057) (Exim SMTP smuggling) and [GHSA-rfp9-ffqc-h4x8](https://github.com/advisories/GHSA-rfp9-ffqc-h4x8) / [CVE-2026-93990](https://nvd.nist.gov/vuln/detail/CVE-2026-93990) (Expat lone-surrogate markup hiding).

The September 20 00:30Z wave is small, but two records generalize into reusable grammar-desync testing patterns: an MTA that lets **post-rejection bytes influence the accepted message**, and an XML decoder that lets **invalid UTF-16 hide markup from one parser and reveal it to another**.

## 1. Exim SMTP smuggling via data sent after a DATA-phase rejection

[GHSA-3mrg-v8x6-xfjw](https://github.com/advisories/GHSA-3mrg-v8x6-xfjw) / [CVE-2026-94057](https://nvd.nist.gov/vuln/detail/CVE-2026-94057) (4.0, fixed in Exim 4.100.1): Exim before 4.100.1 allows SMTP smuggling **in which the received message does not match any sent message, and instead depends on crafted data sent after a rejection during DATA processing**.

Operator value:

1. **Rejection is a state transition, and the interesting bug class is what survives it.** When a server 5xx-rejects mid-DATA (content-rule trigger, ACL, quota, filter error), the client is required to discard the transaction and the server must discard buffered message state. Any residue — partial buffers, filter staging files, queue entries marked "rejected", partially written `*-D` files — that later merges into a *subsequent accepted* transaction yields a third message state that neither party sent. This is the message-integrity twin of HTTP request-smuggling parser differentials: the session-level state machine and the per-transaction buffer disagree about what the current transaction contains.
2. **The test is a three-way comparison, not a delivery test.** For each canary sequence, compare (a) bytes sent before the rejection, (b) bytes sent in the retried transaction, (c) the message actually delivered/queued. A positive result is a delivered message that matches **neither** (a) nor (b). Use an owned MTA pair (sender + receiver you control) with a local delivery sink; capture the queue file and the final delivered body.
3. **Why hunters care even at CVSS 4.0:** message-content integrity failures sit under DKIM/ARC signing boundaries, content-filter evasion, and spam/phishing filter training evasion. Where an authorized scope includes an Exim-fronted gateway, the durable finding is "the signed/filtered message differs from any transmitted message," not inbox delivery.

Safe validation boundaries:

1. Lab only: a disposable Exim < 4.100.1 instance (or the vendor test harness) with local delivery to a mailbox you own; never test against a production relay or third-party MX.
2. Script one SMTP session that sends `DATA`, body lines including a line that provokes the server-side rejection, additional `X-CANARY-*` header lines after the rejection response, then `RSET`/new `MAIL FROM`/`RCPT TO`/`DATA` with a distinct marker body; repeat with variants (rejection from an ACL vs a filter vs a syntax rule; canary before vs after the rejecting line; `RSET` vs connection reuse).
3. Evidence: the raw session transcript, the queue-file/delivered-body bytes, and a three-column decision table (sent-pre / sent-retry / delivered). Stop at the byte-level mismatch.
4. Negative control: Exim 4.100.1 must deliver exactly the retried transaction body.

Reporting heuristic: title as **Exim post-rejection DATA bytes splice into accepted message (message-smuggling)**; include Exim version, the triggering rejection rule class, session transcript excerpt, and the delivered-body diff. Related framing: the Sept 15 Sanic post-terminal-chunk trailer smuggling item (leftover bytes after a "closed" structure re-enter the parser) and the aiosmtplib plaintext-buffer-carryover item on the July 28 page — same "buffer survives the boundary that should have killed it" family.

## 2. Expat UTF-16 lone surrogates hide markup from the parser-gate

[GHSA-rfp9-ffqc-h4x8](https://github.com/advisories/GHSA-rfp9-ffqc-h4x8) / [CVE-2026-93990](https://nvd.nist.gov/vuln/detail/CVE-2026-93990) (7.5, Expat through 2.8.4): Expat fails to validate that a low surrogate follows a high surrogate in UTF-16 input, so malformed sequences are accepted. A crafted UTF-16 XML document can place a **lone high surrogate that consumes the following code unit**, hiding markup characters (`<`, `>`, `&`) from the parser and enabling XML injection attacks.

Operator value:

1. **Encoding-decoder state is part of the grammar attack surface.** In UTF-16 decoding, a high surrogate expects a following low surrogate; a decoder that "consumes" the next code unit to complete a non-existent pair makes the *pair* invisible. The next byte pair after that decodes normally — so what one decoder sees as junk, a stricter (or differently-buggy) decoder downstream may see as `<`, `>`, or `&`. Gate-vs-sink divergence: the validator/WAF/normalizer rejects or ignores the payload, the consuming parser assembles markup from it.
2. **This is the byte-encoding sibling of the Sept 25 Grav `preg_match /u` lesson** (invalid UTF-8 subject makes the "bad-pattern" check return false, silently marking everything clean) and the URL-canonicalization differential family: **security decisions made on one decoder's output while a second decoder assembles the actual structure.**
3. **Blast radius:** Expat is the XML engine under a huge install base of uploads, SAML/SOAP stacks, SVG/icon pipelines, RSS importers, and language bindings. Wherever UTF-16 (`<?xml encoding="UTF-16"?>` or BOM-detected) XML input is accepted, re-run your XXE/schema-validation battery with **invalid** surrogate sequences around the markup of your existing payloads — most XXE suites test entity syntax, none test decoder-state concealment.

Safe validation boundaries:

1. Build a two-view harness on your own parse pipeline: dump (a) what the validator/normalizer sees and (b) what Expat's parse tree/`XML_Error` reports for the same UTF-16 bytes. Use a minimal Python/`xml.parsers.expat` or C harness — no target systems.
2. Canary documents: a benign `<note>` element where the `<` of a nested element is preceded by a lone high surrogate consuming it; then the same document with a valid surrogate pair as control; and a variant where the hidden element is a DOCTYPE/entity declaration to observe whether the hidden markup assembles at the sink.
3. For products, test only on owned instances with synthetic documents; the finding is the parse-tree/markup-assembly divergence, not exploitation of a specific app.
4. Negative controls: fixed Expat (> 2.8.4) must reject the lone-high-surrogate sequence; confirm your harness's UTF-8 path is inert so you don't misattribute.

Reporting heuristic: title as **lone UTF-16 high surrogate hides XML markup from <gate> but assembles it in <parser/product>**; attach the byte layout table (code units before/after consumption), both parsers' outputs, and version fingerprints. Same audit rule as Grav `detectXss` and the mail-parser pages: enumerate every decoder state (invalid UTF-8, lone surrogates, overlong forms, BOM mixes) that makes a truthiness check on a validation call mean "clean."

## Tracked from the same wave without publication

- [GHSA-xcfp-8rjq-j39w](https://github.com/advisories/GHSA-xcfp-8rjq-j39w) / CVE-2026-94056 and [GHSA-r24f-7cqq-88w4](https://github.com/advisories/GHSA-r24f-7cqq-88w4) / CVE-2026-94054 (Exim PROXY-protocol stack-memory disclosure / OOB write with an attacker-controlled proxy) — folded onto the [June 8 SMTP PROXY trust page](2026-06-08-vm2-proxy-protocol-and-1panel-boundary-batch-ghsa.md) as a native-parser attack-surface note; memory-safety detail too sparse to build a harness from.
- [GHSA-jpgj-v2p6-hc2c](https://github.com/advisories/GHSA-jpgj-v2p6-hc2c) / CVE-2026-94055 — Exim GnuTLS UAF under non-default TLS settings (memory-safety only).
- [GHSA-3fwg-9p8x-37mv](https://github.com/advisories/GHSA-3fwg-9p8x-37mv) / CVE-2026-93991 — Argo Workflows `ListArchivedWorkflows` skips cluster-scoped access review when the `metadata.namespace` field selector uses **NotEquals** → namespace-scoped permission lists every other namespace's archived workflows (spec arguments, parameters, annotations). Folded onto the [Sept 17 guard-composition page](2026-09-17-request-derived-identity-vendure-guard-composition-and-blind-ssrf-oracle-ghsa.md): injected/implicit authorization filters must be re-applied under **every operator the caller can choose**, including negations.
- [GHSA-92v2-hh9v-6vj5](https://github.com/advisories/GHSA-92v2-hh9v-6vj5) / CVE-2026-93993 — Mistral Vibe before 2.25.5 executes repository `post-checkout` git hooks during worktree creation **before trust validation** → repo-supplied shell execution as the user running Vibe. Folded onto the [June 12 developer-control page](2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md) (flatpak-builder hook family): the `git worktree add` leg of the "any Git invocation over untrusted content runs repo hooks" rule.
- [GHSA-x8rx-77vv-c6pq](https://github.com/advisories/GHSA-x8rx-77vv-c6pq) / CVE-2026-93992 (Gopeed AutoExtract archive traversal), [GHSA-pjph-5h96-886c](https://github.com/advisories/GHSA-pjph-5h96-886c) / CVE-2026-93988 (QloApps admin AJAX file read) — existing archive-extraction and authenticated-file-read axes, no new operator pattern.
- [GHSA-pc5q-2x89-w436](https://github.com/advisories/GHSA-pc5q-2x89-w436) / CVE-2026-93989 (vLLM `bad_words` out-of-bounds token indices corrupting concurrent-request logits) — vLLM single continues tracked-not-published precedent; note the cross-request state-corruption angle if a PoC chain ever lands.
- grimmory/Booklore authz pair (CVE-2026-93954/93955), PHP-FTS search-highlight XSS (CVE-2026-93956), rejected CVE-2026-89155 — sparse VulDB-style singles, no reusable axis.
