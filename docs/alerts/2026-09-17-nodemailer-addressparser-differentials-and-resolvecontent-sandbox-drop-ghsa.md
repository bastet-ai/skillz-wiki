---
title: "Mail-parser differentials and sandbox-option drop: Nodemailer addressparser divergences and resolveContent bypass"
---

# Mail-parser differentials and sandbox-option drop: Nodemailer addressparser divergences and resolveContent bypass

The September 17 GitHub wave ships a Nodemailer cluster that generalizes far beyond one npm package: **two recipient-address parser differentials that defeat domain allow-lists by making the sender's parser disagree with the validator's parser**, and **a documented sandbox option silently dropped when content is resolved through the public plugin API**.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-8pjj-q6q6-qm29](https://github.com/advisories/GHSA-8pjj-q6q6-qm29) / CVE-2026-92597 | `lib/addressparser` mis-parses RFC 5322 comments: a comment closed immediately before a non-break character causes the atoms around the comment to **concatenate** — `user@good-corp.com (x)evil.com` reads as the single domain `good-corp.comevil.com` (attacker-registrable `comevil.com`) in both the SMTP envelope and the emitted headers, while a conformant parser terminates the domain at the comment (≥6.9.16, <9.1.0) | Any app that validates the recipient with a strict parser and then hands the **raw string** to the delivery library crosses a validator/sender differential |
| [GHSA-r7q5-h7cx-p54x](https://github.com/advisories/GHSA-r7q5-h7cx-p54x) / CVE-2026-92598 | No UTS-46 normalization when encoding IDN domains: the resolver computes a different Punycode A-label than standards-compliant parsers, so invisible characters / compatibility mappings pass allow-list checks but deliver to attacker-controlled domains (<9.1.0) | IDN variant classes (confusables, ignorable code points, compatibility mappings) are allow-list bypass payloads whenever validator and sender normalize differently |
| [GHSA-5635-p6jj-6g9p](https://github.com/advisories/GHSA-5635-p6jj-6g9p) / CVE-2026-92595 | `disableFileAccess`/`disableUrlAccess` are **not honored** when message content is resolved via the legacy three-argument `MailMessage.resolveContent(data, key, callback)` signature: the missing options argument normalizes to `{}`, the message-level flags are discarded, and untrusted content reaches `fs.createReadStream(path)` or `nmfetch(url)` → arbitrary local file read / SSRF through plugin code (≤9.1.0, fixed 9.1.1) | Sandbox flags set at object construction can be dropped by an alternate public entry point — enumerate every API that reaches the same sink and check which ones thread the security options |
| GHSA-v554-hhrr-96v5 / CVE-2026-92596 | Quadratic-time `addressparser` input (tracked; DoS only) | — |

!!! warning "Lab-only validation"
    Prove differentials against your own mail lab (disposable SMTP sink you own, e.g. a local server that records the actual `RCPT TO`). Registering an attacker-domain lookalike is only acceptable for your own bug-bounty scope labs. Never inject test recipients into real user mailflows.

## Why this is durable: the validator/sender differential pattern

The two addressparser bugs are one class: **the application's allow-list parser and the mail-sending library's parser disagree on where the domain ends**. The defensive assumption "we validated the domain, so delivery goes to the validated domain" fails whenever the sender re-parses the raw string with different grammar.

1. **Comment-atom concatenation.** Test matrix around RFC 5322 comment placement: `(x)user@domain`, `user@(x)domain`, `user@dom(x)ain`, and the shipped payload `user@good-corp.com (x)evil.com`. A conformant parser sees `good-corp.com`; the vulnerable parser sees a single concatenated label. The observable is which domain the **delivery layer** connects to — capture `RCPT TO` and the resolved MX on your own sink, not just the app's validation verdict.
2. **IDN normalization.** Build a small corpus: zero-width joiners, U+00A8 vs U+0064 U+0069 diaeresis variants, full-width mappings, and a registered homograph lab domain. Submit through any address field feeding a mail or notification path. Evidence is a validation-accept/delivery-divergence decision table.
3. **Prefix/substring allow-lists first.** The advisory notes naive `startsWith('good-corp.com')` checks fail on the concatenated form even without parser differences. Test both layers separately: does the validator catch it, and does the sender deliver it?
4. This is the same family as the URL-parser differential findings on the Sept 15 Http4s/Traefik page and the Angular SSR trim-divergence page: **two parsers, one string, security decision made by the wrong one.** Generalize the audit to any validate-then-delegate pipeline (URL fetchers, git remotes, package specifiers, mail).

## Sandbox-option drop via alternate entry point

The `resolveContent` bug is the reusable pattern for every library that advertises a sandbox:

1. List every public function that reaches the guarded sink (file open, URL fetch, deserialization). Here `transporter.sendMail()` internal paths honored the flags; the **public plugin API** legacy signature did not.
2. Read the option-threading code path: a missing argument normalized to an empty object is a silent security-option loss. Grep for `options || {}` / parameter-default collapse anywhere security flags travel.
3. In a plugin-based mail app, identify which code resolves message content — attachment paths, `href`s, `html` fields from user input — and whether it goes through the affected signature. Proof is a synthetic path read of a lab marker file or an owned no-content callback hit, never a real secret file.

## Reporting heuristics

- Lead with the **exact string where the parsers diverge** plus the parsed-domain output of both parsers side by side; the pair is the whole finding.
- Frame the impact honestly: delivery to an attacker-registrable domain requires the app's validation to gate a security decision (invite emails, verification links, invoice delivery). State which decision is bypassed; don't claim phishing success.
- For the sandbox drop, name the entry point that bypasses the control and show the internal path that honors it — the differential, not the file read itself, is the vulnerability.

## Tracked without publication

- Quadratic-complexity `addressparser` DoS (GHSA-v554-hhrr-96v5) and joi `isoDate()` unanchored-regex ReDoS (GHSA-mrx9-2rrp-rhpx / CVE-2026-92599) — availability-only, no reusable operator workflow beyond "cap input length," which the advisories already say.
- TCH QRing BLE firmware item and quay-builder-qemu supply-chain note — hardware/scope-specific, tracked.
- HKUDS nanobot `< 0.3.0` WebFetchTool SSRF (GHSA-mpqf-rmwr-h7wr / CVE-2026-92576, `_validate_url()` doesn't block RFC1918/localhost/metadata ranges) — tracked as another instance of the agent-fetch pattern already on the [August 6 agent authority page](2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md); no new boundary beyond final-peer enforcement already documented there.
- The n8n, Craft, and AVideo siblings of this wave live on their own pages ([Craft wave](2026-09-17-craft-cms-hmac-purpose-binding-ssti-graphql-field-auth-and-install-gate-ghsa.md), [n8n page June-24 follow-up](2026-06-24-hono-n8n-flowise-picklescan-boundaries-ghsa.md#september-17-n8n-git-node-sandbox-escape-and-source-control-push-destruction-follow-up), [AVideo page](2026-09-05-avideo-notify-filewrite-socket-callback-rate-limit-ghsa.md#september-17-avideo-wave-hash-as-password-auth-bypass-csrf-allowlist-basename-collisions-and-clonesite-command-injection)).

---

*Source: hourly offensive-security scan, 2026-09-17 (00:31Z GitHub advisory wave). Tracked in the [source index](../notes/source-index.md).*
