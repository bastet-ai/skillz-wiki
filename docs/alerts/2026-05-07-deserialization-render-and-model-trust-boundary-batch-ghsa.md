# Deserialization, render, and model-trust boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** execution-boundary batch involving incomplete deserialization fixes, Markdown rendering, and AI model/code trust controls. A later REST fallback refresh added more evidence around AI-agent remote execution, model-loader bypasses, and Apache MINA deserialization regressions.

## Advisories covered

- **Apache MINA incomplete deserialization fix for CVE-2026-41635** — [GHSA-vf5j-865m-mq7c](https://github.com/advisories/GHSA-vf5j-865m-mq7c): untrusted data deserialization remained exploitable after an incomplete patch.
- **Apache MINA incomplete deserialization fix for CVE-2026-41409** — [GHSA-995c-6rp3-4m4x](https://github.com/advisories/GHSA-995c-6rp3-4m4x): a related deserialization path still needed a complete boundary fix.
- **Apache MINA deserialization exposure** — [GHSA-8297-v2rf-2p32](https://github.com/advisories/GHSA-8297-v2rf-2p32): another critical advisory reinforces that MINA-facing services should remove or tightly gate serialized object handling rather than relying on partial gadget filtering.
- **@diplodoc/search-extension stored XSS via Markdown title** — [GHSA-rjmp-rwj4-mv82](https://github.com/advisories/GHSA-rjmp-rwj4-mv82): Markdown-derived titles could become stored script execution.
- **Diffusers `None.py` trust-remote-code bypass** — [GHSA-j7w6-vpvq-j3gm](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm): model loading could bypass intended remote-code trust restrictions.
- **Diffusers `custom_pipeline` and local-component trust bypass** — [GHSA-98h9-4798-4q5v](https://github.com/advisories/GHSA-98h9-4798-4q5v): `trust_remote_code` controls can be bypassed when alternate pipeline/component loading paths do not share the same policy gate.
- **Hugging Face smolagents remote Python executor RCE** — [GHSA-q9r5-6hrr-9ph7](https://github.com/advisories/GHSA-q9r5-6hrr-9ph7): unsafe deserialization in the remote executor can become code execution.
- **Hugging Face smolagents SSRF** — [GHSA-jxgv-6j54-wwc7](https://github.com/advisories/GHSA-jxgv-6j54-wwc7): agent/tooling network fetch paths can reach unintended internal targets when URL policy is not enforced centrally.

## Why this is durable

Execution boundaries often fail in the "almost fixed" layer: a denylist patch that misses a gadget path, a sanitized Markdown body with an unsanitized title, or a model/agent loader that protects one code path but not another. Fixes need positive allowlists and shared enforcement points across deserialization, rendering, model loading, executor, and network-fetch paths.

## Immediate triage

1. Patch Apache MINA, @diplodoc/search-extension, Diffusers, and smolagents consumers; prioritize internet-facing services and ML/agent systems that load third-party models, execute remote code, or process untrusted serialized payloads.
2. Identify all Java deserialization entry points and block untrusted serialized objects at protocol boundaries where possible.
3. Re-sanitize every rendered Markdown field, including titles, metadata, search snippets, and generated table-of-contents entries.
4. Audit model-loading and agent-executor jobs for `trust_remote_code`, `custom_pipeline`, local cache poisoning, unexpected `.py` files, unsafe pickle/deserialization formats, and loaders that bypass central policy.
5. Put agent/tool network fetches behind the same SSRF controls used for application egress: canonical DNS/IP checks, redirect revalidation, metadata-service blocking, and explicit destination allowlists.

## Durable controls

- Prefer data-only formats over Java/native object deserialization; when unavoidable, use strict class allowlists and versioned protocol envelopes.
- Make rendering safe by construction: HTML-escape metadata, sanitize after Markdown conversion, and apply CSP as a backstop.
- Centralize model and agent-executor trust decisions so every loader path, cache path, fallback path, custom component path, and remote execution path checks the same policy.
- Treat incomplete-fix advisories as a signal to regression-test the entire class, not only the named CVE path.
- Run agent frameworks in isolated sandboxes with constrained filesystem, network, secrets, and process privileges; deserialization bugs should not automatically become host compromise.
