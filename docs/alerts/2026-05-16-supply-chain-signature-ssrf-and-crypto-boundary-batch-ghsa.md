# Supply-chain, signature, SSRF, and crypto-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch is durable because package/install tooling, signature verification, registry identity, protocol plugins, and crypto bindings all fail dangerously when they normalize or trust attacker-controlled metadata before containment. Treat plugin manifests, Git objects, PKCS7 certificates, OIDC audiences, OpenAPI server URLs, DTLS fingerprints, and certificate fields as untrusted parser inputs that must be validated before they influence trust decisions.

## Advisories covered

- **Microsoft APM CLI's plugin.json component paths escape plugin root and copy arbitrary host files during install** — [GHSA-xhrw-5qxx-jpwr](https://github.com/advisories/GHSA-xhrw-5qxx-jpwr) / CVE-2026-44641 (high).
- **gitsign verify accepts signatures over go-git-normalized bytes, enabling trust confusion on malformed commits** — [GHSA-7rmh-48mx-2vwc](https://github.com/advisories/GHSA-7rmh-48mx-2vwc) / CVE-2026-44309 (medium).
- **bitcoinj has a ScriptExecution P2PKH/P2WPKH Verification Bypass** — [GHSA-hfcf-v2f8-x9pc](https://github.com/advisories/GHSA-hfcf-v2f8-x9pc) / CVE-2026-44714 (high).
- **gitsign --verify panics on empty-certificate PKCS7 and exits 0, bypassing exit-code callers** — [GHSA-7c37-gx6w-8vc5](https://github.com/advisories/GHSA-7c37-gx6w-8vc5) / CVE-2026-44310 (medium).
- **ex_webrtc client-role handshake is missing DTLS peer fingerprint validation** — [GHSA-qwfw-ggxw-577c](https://github.com/advisories/GHSA-qwfw-ggxw-577c) / CVE-2026-44700 (high).
- **rust-openssl vulnerable to heap buffer overflow when encrypting with AES key-wrap-with-padding** — [GHSA-xv59-967r-8726](https://github.com/advisories/GHSA-xv59-967r-8726) / CVE-2026-44662 (medium).
- **utcp-http vulnerable to SSRF via attacker-controlled OpenAPI servers[0].url in HTTP communication protocol** — [GHSA-39j6-4867-gg4w](https://github.com/advisories/GHSA-39j6-4867-gg4w) / CVE-2026-44661 (medium).
- **rust-openssl has undefined behavior in X509Ref::ocsp_responders for certificates with non-UTF-8 OCSP URLs** — [GHSA-xp3w-r5p5-63rr](https://github.com/advisories/GHSA-xp3w-r5p5-63rr) / CVE-2026-42327 (high).
- **MCP Registry's GitHub OIDC tokens are replayable across registry deployments due to shared audience** — [GHSA-95c3-6vvw-4mrq](https://github.com/advisories/GHSA-95c3-6vvw-4mrq) / CVE-2026-44428 (low).
- **MCP Registry has an unauthenticated SSRF: HTTP namespace verification dials 6to4 / NAT64 / site-local IPv6 addresses, bypassing private-address allowlist** — [GHSA-r48c-v28r-pf6v](https://github.com/advisories/GHSA-r48c-v28r-pf6v) / CVE-2026-44430 (medium).

## Operator triage

1. Run installer and plugin workflows for Microsoft APM and similar tools in throwaway sandboxes; inspect manifests for component paths that escape plugin roots or copy host files.
2. For gitsign/go-git verification, avoid using exit code alone as a trust signal until malformed commits, empty-certificate PKCS7 objects, and byte-normalization edge cases are tested in your pipeline.
3. For MCP Registry or UTCP HTTP namespace verification, test private-address bypasses including redirects, IPv6 literals, 6to4, NAT64, and site-local ranges at the final dial step.
4. For crypto/protocol libraries, add negative tests for missing DTLS fingerprint validation, non-UTF-8 certificate fields, AES key-wrap edge cases, and consensus/script-verification bypasses.

## Durable controls

- Installer manifests may name files, but they must not choose arbitrary host read/write paths. Normalize, resolve, and enforce root containment before every copy/extract.
- Signature verification must bind exactly the bytes that downstream consumers trust; alternate normalizations create trust-confusion vulnerabilities.
- Verification tooling must fail closed on parser panics, malformed certificates, empty certificate sets, unsupported encodings, and ambiguous errors.
- OIDC audience, issuer, subject, repository, and deployment identity should all be scoped per registry/deployment. A shared audience makes replay a feature.
- SSRF filters need canonical network-layer enforcement for every protocol adapter, not just user-facing URL parsing.
