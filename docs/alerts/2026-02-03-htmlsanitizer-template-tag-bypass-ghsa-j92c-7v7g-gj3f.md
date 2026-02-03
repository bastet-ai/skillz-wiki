# 2026-02-03 — HtmlSanitizer bypass via `<template>` tag (GHSA-j92c-7v7g-gj3f)

**What happened:** HtmlSanitizer had an XSS sanitization bypass involving the `<template>` tag.

**Why it matters:** HTML sanitizers are notoriously hard to get right; bypasses often appear via:
- overlooked elements (`template`, `svg`, `math`)
- parser differentials between sanitizer and browser
- attribute/namespace edge-cases

## Durable guidance (defensive)

1. **Prefer context-aware output encoding** over sanitization
   - If you can render as text, do that.

2. If you must accept rich HTML:
   - Use a **well-maintained** sanitizer and keep it updated.
   - Apply a **strict allowlist** (tags + attributes) and ban high-risk elements (`script`, `style`, `template`, `svg`, `math`).

3. **Backstop with CSP**
   - `Content-Security-Policy` with `script-src` nonces/hashes reduces exploitability.

4. **Test bypasses in real browsers**
   - Add regression tests with known payloads.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-j92c-7v7g-gj3f>
