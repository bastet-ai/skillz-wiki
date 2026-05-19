# Open WebUI, OpenClaw, Nomad, and filesystem boundary batch

Source: GitHub Security Advisories, updated 2026-05-19:
[Open WebUI advisories](https://github.com/advisories?query=Open+WebUI),
[OpenClaw advisories](https://github.com/advisories?query=OpenClaw),
[GHSA-hx53-77qj-8663](https://github.com/advisories/GHSA-hx53-77qj-8663),
[GHSA-3934-423w-4jq3](https://github.com/advisories/GHSA-3934-423w-4jq3),
[GHSA-wqwc-x3rc-2xw6](https://github.com/advisories/GHSA-wqwc-x3rc-2xw6),
[GHSA-crhj-59gh-8x96](https://github.com/advisories/GHSA-crhj-59gh-8x96),
[GHSA-c656-jcx2-7pqj](https://github.com/advisories/GHSA-c656-jcx2-7pqj),
[GHSA-fpxj-m5q8-fphw](https://github.com/advisories/GHSA-fpxj-m5q8-fphw),
[GHSA-x5w9-xh9r-mvfc](https://github.com/advisories/GHSA-x5w9-xh9r-mvfc),
[GHSA-hv85-774v-26fg](https://github.com/advisories/GHSA-hv85-774v-26fg),
[GHSA-xm96-gfjx-jcrc](https://github.com/advisories/GHSA-xm96-gfjx-jcrc),
[GHSA-h98r-wv3h-fr38](https://github.com/advisories/GHSA-h98r-wv3h-fr38),
[GHSA-rg3g-4rw9-gqrp](https://github.com/advisories/GHSA-rg3g-4rw9-gqrp),
[GHSA-x5w9-xh9r-mvfc](https://github.com/advisories/GHSA-x5w9-xh9r-mvfc),
[GHSA-5c46-x3qw-q7j7](https://github.com/advisories/GHSA-5c46-x3qw-q7j7),
[GHSA-xmpw-2vmm-p4p6](https://github.com/advisories/GHSA-xmpw-2vmm-p4p6),
[GHSA-4gph-2hhr-5mwg](https://github.com/advisories/GHSA-4gph-2hhr-5mwg),
[GHSA-f9f8-rm49-7jv2](https://github.com/advisories/GHSA-f9f8-rm49-7jv2),
[GHSA-3875-8gcx-7v46](https://github.com/advisories/GHSA-3875-8gcx-7v46),
[GHSA-fhvh-vw7h-9xf3](https://github.com/advisories/GHSA-fhvh-vw7h-9xf3),
[GHSA-hc3c-63hc-2r9f](https://github.com/advisories/GHSA-hc3c-63hc-2r9f), and related reviewed advisories in the 2026-05-19 16:15 UTC GitHub batch.

This batch is durable because it repeats the same failures across AI workbenches, agent runtimes, CI/test tooling, cluster schedulers, WebDAV/OCI/Git clients, mail testing servers, and legacy frameworks: caller-controlled strings crossed into code execution, filesystem writes, internal fetches, browser script, or privileged control-plane APIs without a hard boundary check.

## What changed

- **Open WebUI** disclosed a large cluster of authorization, render, SSRF, and upload issues across notes, memories, files, channels, model/tool access, Office/SVG/HTML previews, profile images, OAuth picture fetching, audio transcription cache serving, PDF generation, and unauthenticated embedding generation. The recurring root is that user-controlled content or IDs reached privileged model, file, cache, or browser-render paths with incomplete ownership, type, or origin checks.
- **OpenClaw** published runtime-boundary fixes covering cwd-based JavaScript loading during provider setup resolution, stale SecretRef webhook secrets after rotation, workspace dotenv host overrides, hook session-key opt-in bypass, cron trust labeling, ACP child-session security-envelope propagation, MCP stdio dangerous startup env, MiniMax host override, and owner-command wildcard sender handling.
- **Nomad / exec2, zrok, go-git, ORAS Java, tar-rs, and n8n** reinforced host-filesystem boundaries: symlink and traversal flaws could read/write host files, execute on clients, escape output roots, alter `.git` internals, write OCI layer blobs outside the destination, ignore PAX sizes, or bypass configured workflow file restrictions.
- **Mailpit, Caddy, Nuxt, Envoy AI Gateway, auth-fetch-mcp, n8n, and zrok Python** added service-boundary fixes: unauthenticated memory exhaustion and crash paths, incomplete SSRF protection, remote admin path-normalization confusion, development-source exposure over LAN, reflected redirect XSS, MCP JSON-RPC case-smuggling, MCP URL fetch/disk exfiltration, credentialed HTTP-request domain bypass, and absolute-URL proxy SSRF.
- **Supply-chain and secret exposure items** included malicious `guardrails-ai==0.10.1`, WebdriverIO BrowserStack branch-name command injection, Composer leaking new-format GitHub Actions `GITHUB_TOKEN` values into logs, Hyperledger Fabric chaincode TLS private-key password logging, Netmaker hardcoded DNS/admin keys, GraphiQL header leakage into URLs, and Bouncy Castle FIPS implementation issues.
- **Framework, crypto, and app backlog updates** included legacy Django XSS/CSRF/GIS SQLi/password-reset DoS, Apache Avro Rust reader memory exhaustion, libcrux ML-DSA verification and ChaCha20-Poly1305 panic fixes, MantisBT global-profile authorization bypass, FacturaScripts cookie XSS and EXIF leakage, Anchor system-program validation, kanidm/scim parser stack exhaustion, Caddy admin normalization, Argo CD annotation XSS and secret-diff leakage, and MCP Registry OCI ownership validation fail-open behavior.

## Operator triage

1. **Patch AI workbenches first where exposed to users.** For Open WebUI, treat every uploaded file preview, rendered HTML/SVG/Office document, profile/channel image, OAuth picture URL, model/tool selection, notes, memories, files, and channels endpoint as untrusted until patched and regression-tested. Disable optional Notes/Beta features and public sharing if patch timing is uncertain.
2. **Upgrade OpenClaw before using untrusted workspaces.** Avoid running older OpenClaw releases from attacker-controlled repositories; rotate webhook route secrets after upgrading, not before, if an old process may have cached resolved secrets.
3. **Harden filesystem clients and schedulers.** Patch Nomad/exec2, go-git, zrok, ORAS Java, tar-rs, and n8n. Until then, do not pull/copy/dump from untrusted repositories, WebDAV shares, OCI manifests, tar archives, or local workflow paths as a privileged user.
4. **Treat fetch tools as SSRF-capable by default.** For Mailpit HTML checks, Caddy admin APIs, Nuxt dev servers, n8n dynamic node parameters, auth-fetch-mcp, zrok proxy shares, Open WebUI OAuth images/PDFs, and MCP fetchers, block loopback, link-local, private ranges, `file://`, and rebinding destinations after DNS resolution.
5. **Run supply-chain response, not just package updates.** For `guardrails-ai==0.10.1`, compromised OpenSearch client versions, or command-injection-capable CI/test helpers, rebuild from clean images, rotate secrets observed by the process, and inspect postinstall/build/test logs.
6. **Scrub logs and URLs.** Remove Fabric chaincode TLS passwords and leaked Composer/GitHub Actions tokens from retained logs, rotate associated secrets where exposure is plausible, and prevent GraphiQL or similar consoles from persisting Authorization headers in URLs.
7. **Keep old-framework and crypto advisories actionable.** Legacy Django, Avro, and libcrux items matter most in long-lived internal apps and cryptographic services. Inventory unsupported versions and either patch, isolate, or retire them; do not assume age makes the finding irrelevant.

## Replayable validation boundaries

- **Ownership boundary:** every object API must check both authentication and object ownership/capability for read and write paths. Regression-test notes, memories, files, channels, messages, models, profiles, workflows, and global profiles with a second low-privileged user.
- **Render boundary:** user-uploaded or model-generated HTML, SVG, Office, spreadsheet, audio-cache, and profile-image content must be served with safe MIME types, `Content-Disposition: attachment` where appropriate, sanitizer allowlists, and no ambient privileged tokens in the same origin.
- **Filesystem boundary:** normalize paths after archive/manifest/DAV/Git metadata is applied; reject absolute paths, `..`, symlink escapes, device paths, platform-specific alternate spellings, and writes outside the chosen root.
- **Fetch boundary:** parse URLs once, canonicalize hostnames, resolve DNS with rebinding-aware checks, deny internal ranges, and attach credentials only to exact configured origins.
- **Process-start boundary:** workspace config, branch names, environment variables, token formats, and cwd-relative helper paths must not influence command execution, secret logging, or module loading without explicit operator trust.
- **Control-plane boundary:** admin APIs, proxies, and schedulers should authorize and parse the same object that the handler later mutates. Array-index normalization, JSON-RPC field case changes, path traversal, or templated session keys must not change what was authorized.
- **Resource boundary:** parsers for SCIM filters, IDNA, Avro, mail bodies, JSON requests, tar headers, and templates need size/depth/time limits before allocation or recursion.

## Durable controls

- Separate user-content origins from admin/model-control origins; browser sanitization is defense-in-depth, not the primary isolation boundary.
- Keep workspace-provided config out of process-startup, network-host, and secret-routing decisions unless the workspace is already trusted.
- Put root containment and SSRF checks in shared libraries with unit tests for symlinks, alternate path syntaxes, absolute URLs, DNS rebinding, and loopback aliases.
- Treat AI, MCP, and automation integrations as privileged confused-deputy surfaces: prompt-injected tools can drive file, URL, and model APIs exactly like malicious users.
- For any advisory involving malicious packages, command injection, or secret logging, assume secrets handled by that process are exposed until rotated from a clean host.
