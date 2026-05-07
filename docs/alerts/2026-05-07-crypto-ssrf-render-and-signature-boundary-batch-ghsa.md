# Crypto, SSRF, render, and signature-boundary batch

**Sources:** GHSA-xv59-967r-8726 / CVE-2026-44662, GHSA-39j6-4867-gg4w / CVE-2026-44661, GHSA-v7qw-hx66-4w9x, GHSA-jggh-5rmh-r6h5 / CVE-2026-7689

## Why this matters

Four advisories from this scan share a useful defensive pattern: boundary checks must happen at the operation that consumes authority, not only at discovery, object creation, or an upstream API wrapper.

- `openssl` for Rust `< 0.10.79` can undersize output buffers for AES key-wrap-with-padding ciphers (`EVP_aes_{128,192,256}_wrap_pad`). Non-multiple-of-8 attacker-influenced plaintext can drive OpenSSL up to seven bytes past the Rust-managed buffer.
- `utcp-http <= 1.1.1` validates the manual OpenAPI discovery URL, then later trusts the spec-controlled `servers[0].url` during tool invocation. A prompt-injected or attacker-hosted HTTPS spec can turn an agent tool into blind SSRF against cloud metadata or internal services. The old localhost prefix check also allowed hostnames such as `localhost.evil.com`.
- `netbox-data-flows <= 1.5.0` stores `ObjectAlias.name` values and later renders them into `DataFlow` table links through `mark_safe()` without escaping, giving authenticated low-privilege users a stored-XSS path against operators viewing NetBox plugin tables.
- Dolibarr's Online Signature Module advisory reports weak authenticity verification in `dol_verifyHash` with public exploit material. GitHub/NVD metadata is inconsistent on affected version ranges, so treat the module as a review target until vendor guidance is confirmed.

The durable lesson: cryptographic wrappers, agent-tool specs, table renderers, and signature modules are all authority transitions. Validate dimensions, destinations, HTML, and signatures exactly where the sensitive operation happens.

## Operator triage

1. Upgrade Rust `openssl` to `0.10.79+` wherever AES key-wrap-with-padding ciphers may be used for key wrapping, token wrapping, envelope encryption, or protocol compatibility layers.
2. Upgrade `utcp-http` to `1.1.2+`; disable or sandbox manual tool discovery from untrusted LLM context until every tool invocation revalidates its final destination URL.
3. Upgrade `netbox-data-flows` to `1.5.1+`; treat any plugin instance where non-admin users could edit aliases as a stored-XSS exposure.
4. For Dolibarr deployments using online signatures, inventory versions and module exposure, monitor for vendor clarification, and avoid relying on `dol_verifyHash` decisions for high-value approval flows until patched or compensating controls are in place.
5. Re-run tests around the consuming operation: `CipherCtxRef::cipher_update*` / `Crypter::update`, UTCP `call_tool*`, NetBox table rendering, and Dolibarr signature verification.

## Hunt prompts

- Rust services using `EVP_aes_*_wrap_pad` or `Cipher::aes_*_wrap_pad()` with input lengths not fixed or controlled by trusted code.
- UTCP/OpenAPI specs whose discovery URL is trusted HTTPS but whose `servers` entries point at loopback, link-local metadata, RFC1918, cluster DNS, Unix-socket proxies, or unexpected schemes.
- Agent logs where an LLM registers or calls newly discovered HTTP tools shortly before internal-only endpoints receive requests.
- NetBox audit records for `ObjectAlias` names containing `<`, `>`, quotes, event handlers, SVG/MathML payloads, or HTML entities; correlate with admin page views and session reuse.
- Dolibarr online-signature verification failures, repeated signature submissions, or document state changes made through public signing routes.

## Durable controls

- Size crypto output buffers from the exact primitive contract, then fuzz wrapper APIs across boundary lengths; do not assume Rust `Vec` growth protects FFI writes.
- Revalidate final network destinations at call time after OpenAPI conversion, redirects, DNS resolution, IDNA normalization, and localhost/private-range canonicalization.
- Keep agent tool execution in an egress-restricted network namespace where metadata endpoints and internal control planes are unreachable by default.
- Escape user-controlled object names at the last render point; avoid `mark_safe()` around strings that combine trusted markup with untrusted labels.
- Treat signature-verification helpers as security boundaries: bind signatures to canonicalized document bytes, signer identity, algorithm, timestamp, and intended action; log and alert on verification ambiguity.
