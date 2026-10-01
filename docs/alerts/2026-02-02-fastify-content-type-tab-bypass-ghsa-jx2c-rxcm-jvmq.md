# 2026-02-02 — Fastify Content-Type header tab character can bypass body validation (GHSA-jx2c-rxcm-jvmq)

## Summary

A GitHub Security Advisory reports that **Fastify** can be tricked into **bypassing request body validation** by using a **tab character** in the `Content-Type` header.

This is a variant of a common parsing/normalization failure: **different components interpret “the same” header differently**, creating validation gaps.

- Advisory: https://github.com/advisories/GHSA-jx2c-rxcm-jvmq

## What to do (durable guidance)

### If you operate affected software

1. **Upgrade Fastify**
   - Apply the vendor-recommended fixed versions from the advisory.
   - Treat this as a *correctness and security* update (not “optional”).

2. **Normalize and strictly validate `Content-Type` at the edge**
   - Reject requests with **CTL characters** (tabs, newlines, carriage returns) in header values.
   - Consider allowlisting expected media types (e.g., `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`).

3. **Add defense-in-depth validation**
   - If your system relies on schema validation (JSON schema / zod / yup / ajv), also validate:
     - request size (`Content-Length` / streaming limits)
     - expected routes/methods
     - authentication before parsing large bodies

### If you build services (how to avoid this class)

- **Do not trust `Content-Type` strings as-is**: normalize whitespace and reject control characters.
- **Test header smuggling/normalization cases**:
  - `Content-Type: application/json\t; charset=utf-8`
  - unusual whitespace around delimiters
- **Prefer single parser of truth**: avoid having one component decide “this is JSON” while another does validation.

## Related Wisdom

- [SMTP header injection (CRLF)](../best-practices/smtp-header-injection.md)

## October 1 follow-up: the Fastify validator/encapsulation quartet (CVE-2026-76169, CVE-2026-84469, CVE-2026-84428, CVE-2026-84504)

Four more September-2026 advisories confirm this page's thesis — *Fastify's guarantees are per-shape, and each shape is a test target*:

- **Malformed-URL not-found dispatch escapes encapsulation** ([GHSA-p68q-wchp-6fh7](https://github.com/advisories/GHSA-p68q-wchp-6fh7), CVE-2026-76169): a malformed request target with no matching method route reaches the shared internal not-found router **before URL decoding**, dispatched through a single handler pointer — an unauthenticated request to a public prefix gets the **auth-protected not-found handler of a sibling plugin, including its full response, with its `setNotFoundHandler` `preHandler` skipped**. Operator check: send malformed targets (`//`, bad percent-encoding, absolute-form oddities) to each prefix and diff which not-found body comes back — cross-prefix not-found responses = encapsulation break + auth bypass on whatever the handler reveals.
- **Boolean-`false` schemas skip validation** ([GHSA-hwr6-493r-vm6h](https://github.com/advisories/GHSA-hwr6-493r-vm6h), CVE-2026-84469): `schema: false` shapes in nested positions silently disable the validator — probe routes with a property set to `false`-shaped schema definitions in your fuzz corpus.
- **Header-validation case normalization is incomplete** ([GHSA-9q9j-q6p8-xq58](https://github.com/advisories/GHSA-9q9j-q6p8-xq58), CVE-2026-84428): header names outside the normalized case set bypass header schema checks — sweep case variants (`X-Test`, `x-TEST`, mixed) against every schema-validated header.
- **`$async` validator unwrapping lets the payload replace itself** ([GHSA-667r-xxjv-c9mm](https://github.com/advisories/GHSA-667r-xxjv-c9mm), CVE-2026-84504, 8.1): Fastify unwraps `{value, error}`-shaped validator results (a sync-compiler convention); an `$async` JSON-Schema validator resolves with the validated data itself, so a request body containing a top-level `value` key **replaces the whole validated request part with attacker-chosen nested data that never satisfied the schema**. Where apps dispatch operations from the body, that is validation bypass by shape collision.

Durable axis for any framework with pluggable validators: enumerate the **result-shape conventions** the framework trusts (`{value,error}`, `$async`, custom compilers) and test whether untrusted input can *arrive already shaped like a validator result or a validator-disabling directive*. The not-found case generalizes further: error/404 handlers are frequently registered with auth semantics *around* them but execute on a different dispatch path than normal routes — include malformed-target 404 probes in every auth-boundary sweep, per prefix.
