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
