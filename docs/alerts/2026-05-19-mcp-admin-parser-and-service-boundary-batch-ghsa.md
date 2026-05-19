# MCP, admin, parser, and service-boundary batch

Source: GitHub Security Advisories, updated 2026-05-19:
[GHSA-4g73-w726-53h3](https://github.com/advisories/GHSA-4g73-w726-53h3),
[GHSA-3jmg-p96m-m328](https://github.com/advisories/GHSA-3jmg-p96m-m328),
[GHSA-7hgr-7h44-33w2](https://github.com/advisories/GHSA-7hgr-7h44-33w2),
[GHSA-jfc2-q6qh-g5x8](https://github.com/advisories/GHSA-jfc2-q6qh-g5x8),
[GHSA-84f2-rp86-235p](https://github.com/advisories/GHSA-84f2-rp86-235p),
[GHSA-73jc-5mrq-prw7](https://github.com/advisories/GHSA-73jc-5mrq-prw7),
[GHSA-wmhf-fqc8-vxhh](https://github.com/advisories/GHSA-wmhf-fqc8-vxhh),
[GHSA-qg89-qwwh-5f3j](https://github.com/advisories/GHSA-qg89-qwwh-5f3j),
[GHSA-m6xr-fvfg-5g64](https://github.com/advisories/GHSA-m6xr-fvfg-5g64),
[GHSA-m5j3-4634-c2vq](https://github.com/advisories/GHSA-m5j3-4634-c2vq),
[GHSA-32mq-hpph-xfvr](https://github.com/advisories/GHSA-32mq-hpph-xfvr),
[GHSA-6x44-w3xg-hqqf](https://github.com/advisories/GHSA-6x44-w3xg-hqqf),
[GHSA-g8wj-3cr3-6w7v](https://github.com/advisories/GHSA-g8wj-3cr3-6w7v),
[GHSA-62q4-447f-wv8h](https://github.com/advisories/GHSA-62q4-447f-wv8h),
[GHSA-22qr-rp27-j9wm](https://github.com/advisories/GHSA-22qr-rp27-j9wm),
[GHSA-2mgw-7q6p-8grg](https://github.com/advisories/GHSA-2mgw-7q6p-8grg),
[GHSA-7xpr-hc2w-34m9](https://github.com/advisories/GHSA-7xpr-hc2w-34m9),
[GHSA-686c-7vgv-v3fx](https://github.com/advisories/GHSA-686c-7vgv-v3fx),
[GHSA-9r33-xhw8-4qqp](https://github.com/advisories/GHSA-9r33-xhw8-4qqp),
[GHSA-5qwm-7pvp-w988](https://github.com/advisories/GHSA-5qwm-7pvp-w988),
[GHSA-phqj-4mhp-q6mq](https://github.com/advisories/GHSA-phqj-4mhp-q6mq),
[GHSA-hcf7-66rw-9f5r](https://github.com/advisories/GHSA-hcf7-66rw-9f5r),
[GHSA-3qcw-2rhx-2726](https://github.com/advisories/GHSA-3qcw-2rhx-2726),
[GHSA-g53w-w6mj-hrpp](https://github.com/advisories/GHSA-g53w-w6mj-hrpp),
[GHSA-m9p2-fxp5-v3fp](https://github.com/advisories/GHSA-m9p2-fxp5-v3fp),
[GHSA-q8x8-jrhj-fh9p](https://github.com/advisories/GHSA-q8x8-jrhj-fh9p),
[GHSA-crc3-h8v6-qh57](https://github.com/advisories/GHSA-crc3-h8v6-qh57),
[GHSA-gx7w-56w6-g48x](https://github.com/advisories/GHSA-gx7w-56w6-g48x),
[GHSA-wwhq-w58m-w29c](https://github.com/advisories/GHSA-wwhq-w58m-w29c),
[GHSA-m23h-6mwm-39m8](https://github.com/advisories/GHSA-m23h-6mwm-39m8),
[GHSA-3278-c88v-xrh4](https://github.com/advisories/GHSA-3278-c88v-xrh4),
[GHSA-rf5q-vwxw-gmrf](https://github.com/advisories/GHSA-rf5q-vwxw-gmrf),
[GHSA-9q9q-324x-93r2](https://github.com/advisories/GHSA-9q9q-324x-93r2),
[GHSA-fhh6-4qxv-rpqj](https://github.com/advisories/GHSA-fhh6-4qxv-rpqj), and
[GHSA-2q4c-3mrw-63c3](https://github.com/advisories/GHSA-2q4c-3mrw-63c3).

This batch is durable because many unrelated products failed at the same control seam: high-trust helper surfaces treated network endpoints, browser-control routes, parser inputs, admin paths, Kubernetes cross-namespace references, or local command strings as if they were already constrained by a previous layer.

## What changed

- **Agent and MCP surfaces:** CamoFox MCP exposed unauthenticated HTTP browser control; PenPot MCP and 9router exposed unauthenticated code/plugin execution; MCP Gateway had router-key / host-header authority injection that could bypass JWT/session checks; SillyTavern allowed SSRF through an unvalidated SearXNG `baseUrl`.
- **Cloud metadata and instance identity:** Coder had Azure instance-identity SSRF plus PKCS#7 signature-bypass paths that could leak unauthenticated agent tokens. Treat all metadata-document fetch and signature validation as an authentication boundary, not as an implementation detail.
- **Admin, proxy, and gateway controls:** Caddy fixed remote-admin PKI authorization bypass and a prior fix bypass; Kong Ingress Controller fixed cross-namespace TLS Secret exfiltration and secret-backed plugin diagnostic leakage; FileBrowser Quantum exposed unauthenticated user-share metadata.
- **Parser and resource budgets:** Cowboy multipart headers, cowlib SPDY inflation, Bandit chunked transfer decoding, SQLFluff parsing, Dasel selector lexing, FPDI PDF parsing, Wire decoding, OpenMcdf CFB directories, HAX CMS import handling, and OpenStack Ironic checksum pre-validation all had crash, infinite-loop, stack, disk, CPU, or memory exhaustion modes.
- **Filesystem, cache, and path boundaries:** `pymdownx.snippets` reintroduced sibling-prefix path traversal despite `restrict_base_path`; Nuxt `__nuxt_island` responses were not bound to request props and could poison shared caches; libp2p Kademlia DHT server nodes accepted unvalidated `PUT_VALUE` records that could exhaust disk.
- **Local execution and terminal trust:** Kopia could inject `ssh` `ProxyCommand`, Diesel could inject shell commands through `COPY FROM` / `COPY TO`, Turbo could execute local code during Yarn Berry detection, and GitHub CLI `gh run view` rendered Actions log escape sequences into terminals.
- **Crypto and memory safety:** rust-openssl fixed an AES-KW-PAD `cipher_update_inplace` out-of-bounds write; Diesel also fixed possible unaligned access for `SqliteAggregate`; Trubo disclosed login-callback CSRF/session fixation.

## Operator triage

1. **Patch by boundary, not by product list.** Prioritize internet-facing MCP/agent tools, browser-control servers, admin APIs, ingress controllers, cloud metadata integrations, and parsers that accept tenant or anonymous input. Then close the resource-budget and local-command bugs in developer workstations and CI.
2. **Bind every agent tool to an authenticated principal and explicit origin.** MCP/agent HTTP servers should require auth, CSRF protection where browser-reachable, loopback-only or mTLS where possible, route-level authorization, and audit logs for tool execution. A tool named "local" is still remote if it listens on a socket.
3. **Treat metadata services as credential stores.** Block user-influenced fetches to IMDS and cloud identity endpoints, verify instance documents with strict issuer/audience/key pinning, and do not issue agent tokens until both document provenance and expected instance identity are proven.
4. **Put parsers on budgets before helper libraries run.** Add size, depth, header-count, chunk-count, decompression-ratio, record-count, and wall-clock limits at ingress; prefer killable workers for PDF, SQL, selector, archive, binary, and HTTP parsers.
5. **Make namespace boundaries explicit.** Gate Kubernetes Secret references by namespace and owner, require GatewayClass/route annotations that opt into cross-namespace behavior, and redact or split diagnostics endpoints that include plugin or TLS material.
6. **Harden local developer trust paths.** Terminal output, repository metadata, Yarn detection, database copy paths, and SSH proxy options can all cross from untrusted project data into local code execution. Render logs safely and pass arguments as structured arrays, never through shells.

## Replayable validation boundaries

- **MCP/browser-control boundary:** expose the service on a non-loopback interface in a test network and attempt unauthenticated initialize, tool-list, tool-call, browser navigation, and custom plugin execution. Expected result: no operation before auth and authorization.
- **Metadata SSRF boundary:** point every user-controlled URL, proxy, search, fetch, and model-tool path at `169.254.169.254`, IPv6 metadata aliases, DNS-rebinding hosts, redirects, and signed-but-wrong identity documents. Expected result: blocked fetch or rejected identity before token issuance.
- **Parser-resource boundary:** fuzz multipart headers, SPDY/zlib frames, chunked trailers, SQLFluff SQL, Dasel selectors, PDFs, Wire messages, CFB trees, JSON imports, and block-device checksum inputs with depth/size/time metrics. Expected result: bounded rejection, not process death or persistent disk growth.
- **Cache-key boundary:** vary Nuxt island props under shared-cache headers and confirm response bodies, ETags, and cache keys are bound to all user-controllable rendering inputs.
- **Kubernetes namespace boundary:** from an unprivileged namespace, reference TLS Secrets and plugin configs in another namespace and query diagnostics endpoints. Expected result: no read, no redacted leak, and an auditable authorization failure.
- **Terminal/log boundary:** print OSC, CSI, hyperlink, title-change, and clipboard escape sequences in CI logs and view them through `gh run view` or wrappers. Expected result: escaped rendering or stripping before terminal output.

## Durable controls

- Default MCP and local-agent servers to loopback, auth, and deny-by-default route policies; require explicit opt-in before any browser-control or shell-equivalent tool is reachable.
- Centralize URL fetch, metadata denial, hostname canonicalization, and cloud identity-document verification so each feature cannot invent its own partial SSRF defense.
- Add resource budgets at every parser ingress and record the rejected dimension in tests so future fixes cannot silently become "parse until crash" again.
- Model caches and diagnostics as data-exfiltration surfaces: key on every render input, redact by construction, and keep Secret reads namespace-scoped.
- Treat terminal output and local project metadata as attacker-controlled input in developer tools and CI viewers.
