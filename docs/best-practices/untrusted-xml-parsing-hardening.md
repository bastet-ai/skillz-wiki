# Untrusted XML parsing hardening (Node.js + general)

When you parse **XML you didn't generate**, treat it like a code-adjacent input format: it can be used for **DoS**, **data exfiltration**, and in some ecosystems, even **RCE**.

This page is a quick checklist of durable defenses that repeatedly show up in real-world advisories.

## 1) Prefer “safe mode”: disable entity expansion and DTDs

If your parser supports it, default to:

- **Disable DTD parsing** (blocks most XXE-style issues)
- **Disable external entity resolution** (prevents SSRF / local file reads)
- **Disable entity expansion** (reduces “billion laughs” / amplification DoS risk)

If you *must* support entities:

- Set **strict limits** (depth, total expansions, total output size)
- Reject documents with a DTD unless explicitly required

## 2) Always treat parse as a failure-prone operation

A parse error should be a normal outcome for untrusted inputs.

- Wrap parsing in `try/catch`.
- Return a generic error (e.g., 400) without leaking internals.
- Ensure you **don’t crash the whole process** (especially important in Node.js).

### Why this matters (example)

A class of vulnerabilities is simply: **“uncaught exception = remote DoS.”**

For example, some XML parsers convert numeric entities into code points. If an out-of-range code point is accepted by a regex and then passed to `String.fromCodePoint()`, Node will throw a `RangeError`. If the library doesn’t catch it, your service crashes.

**Mitigation:** catch exceptions at the boundary (request handler / ingestion pipeline) *even if you trust the library*.

## 3) Enforce input limits before parsing

Before the parser runs:

- Cap request body size (`Content-Length` and streaming limits)
- Cap decompressed size (zip/gzip bombs)
- Apply timeouts and per-request CPU budgets (where possible)

If you accept XML via file upload, also:

- Verify file type and encoding
- Normalize line endings and reject invalid encodings early

## 4) Do not parse XML in privileged contexts

- Run parsers in a **least-privileged** runtime/container.
- Keep file system access minimal.
- No ambient cloud credentials.

If possible, parse in an isolated worker (separate process) so a crash doesn’t take down the API.

## 5) Log for triage, but don’t leak

- Log: parser errors, size limits hit, DTD/entity usage detected.
- Don’t return: stack traces, internal parser error strings, file paths.

## 6) Dependency hygiene for parsers

XML parsers tend to be “deep dependency” components.

- Track them explicitly in SBOM / dependency inventory.
- Patch fast on parser advisories.
- Consider pinning versions and using Renovate/Dependabot with security PR auto-merge (with tests).

## Quick checklist

- [ ] DTD disabled (or strictly gated)
- [ ] External entities disabled
- [ ] Entity expansion disabled or strictly limited
- [ ] Body size limits
- [ ] Decompression limits
- [ ] Parse wrapped in try/catch (no process crash)
- [ ] Parsing isolated / least privilege
- [ ] Observability: log blocks + anomalies
- [ ] Rapid patch process for parser advisories
