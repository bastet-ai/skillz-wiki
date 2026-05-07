# Deserialization, render, and model-trust boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** execution-boundary batch involving incomplete deserialization fixes, Markdown rendering, and AI model/code trust controls.

## Advisories covered

- **Apache MINA incomplete deserialization fix for CVE-2026-41635** — [GHSA-vf5j-865m-mq7c](https://github.com/advisories/GHSA-vf5j-865m-mq7c): untrusted data deserialization remained exploitable after an incomplete patch.
- **Apache MINA incomplete deserialization fix for CVE-2026-41409** — [GHSA-995c-6rp3-4m4x](https://github.com/advisories/GHSA-995c-6rp3-4m4x): a related deserialization path still needed a complete boundary fix.
- **@diplodoc/search-extension stored XSS via Markdown title** — [GHSA-rjmp-rwj4-mv82](https://github.com/advisories/GHSA-rjmp-rwj4-mv82): Markdown-derived titles could become stored script execution.
- **Diffusers `None.py` trust-remote-code bypass** — [GHSA-j7w6-vpvq-j3gm](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm): model loading could bypass intended remote-code trust restrictions.

## Why this is durable

Execution boundaries often fail in the "almost fixed" layer: a denylist patch that misses a gadget path, a sanitized Markdown body with an unsanitized title, or a model loader that protects one code path but not another. Fixes need positive allowlists and shared enforcement points.

## Immediate triage

1. Patch Apache MINA, @diplodoc/search-extension, and Diffusers consumers; prioritize internet-facing services and ML systems that load third-party models.
2. Identify all Java deserialization entry points and block untrusted serialized objects at protocol boundaries where possible.
3. Re-sanitize every rendered Markdown field, including titles, metadata, search snippets, and generated table-of-contents entries.
4. Audit model-loading jobs for `trust_remote_code`, local cache poisoning, unexpected `.py` files, and loaders that bypass central policy.

## Durable controls

- Prefer data-only formats over Java/native object deserialization; when unavoidable, use strict class allowlists and versioned protocol envelopes.
- Make rendering safe by construction: HTML-escape metadata, sanitize after Markdown conversion, and apply CSP as a backstop.
- Centralize model trust decisions so every loader path, cache path, and fallback path checks the same policy.
- Treat incomplete-fix advisories as a signal to regression-test the entire class, not only the named CVE path.
