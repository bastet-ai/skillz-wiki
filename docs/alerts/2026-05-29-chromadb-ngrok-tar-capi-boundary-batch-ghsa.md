# ChromaDB pre-auth model loading, GlobalProtect auth bypass, ngrok command injection, tar parser differential, and CAPI boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-f4j7-r4q5-qw2c](https://github.com/advisories/GHSA-f4j7-r4q5-qw2c) / CVE-2026-45829, [GHSA-qr28-p3wr-mxq3](https://github.com/advisories/GHSA-qr28-p3wr-mxq3) / CVE-2025-57282, [GHSA-3cv2-h65g-fgmm](https://github.com/advisories/GHSA-3cv2-h65g-fgmm), [GHSA-xg9x-h37w-h3r3](https://github.com/advisories/GHSA-xg9x-h37w-h3r3) / CVE-2026-38739, [GHSA-rf84-wr5g-m3rp](https://github.com/advisories/GHSA-rf84-wr5g-m3rp), and [GHSA-9g8x-92q2-p28f](https://github.com/advisories/GHSA-9g8x-92q2-p28f) / CVE-2026-47141. CISA KEV also added [CVE-2026-0257](https://security.paloaltonetworks.com/CVE-2026-0257) for Palo Alto Networks PAN-OS GlobalProtect authentication bypass exploitation.

This batch is durable because it captures reusable offensive validation patterns: unauthenticated AI runtime model-loading before auth, edge VPN authentication override bypass validation, package wrapper command construction, archive parser differentials that smuggle filesystem writes, local maintenance-script SQL injection, Kubernetes cross-namespace control-plane references, and sandbox observability modules leaking host request context.

## What changed

- **ChromaDB Python FastAPI pre-auth code execution** — `chromadb` Python server versions `>=1.0.0, <=1.5.9` can instantiate client-supplied embedding function configuration before the `/api/v2/tenants/{tenant}/databases/{db}/collections` authorization check. Supplying a Hugging Face model name with `trust_remote_code: true` can execute attacker-controlled model code even when the API request is later rejected.
- **PAN-OS GlobalProtect authentication bypass in active exploitation** — CVE-2026-0257 affects PAN-OS GlobalProtect portal or gateway deployments where authentication override cookies are enabled with a specific certificate configuration. Successful abuse can establish an unauthorized VPN connection. Palo Alto marks exploit maturity as `ATTACKED`; CISA added it to KEV on 2026-05-29. Panorama and Cloud NGFW are not affected.
- **ngrok npm wrapper command injection** — `ngrok` npm package versions `4.3.3` and `5.0.0-beta.2` pass caller-controlled `binPath` behavior into command execution paths such as `getVersion()`. This matters when build scripts, scaffolding tools, or agent workflows call ngrok with options derived from project-controlled configuration.
- **astral-tokio-tar PAX header desynchronization** — `astral-tokio-tar <=0.6.1` applies PAX headers to the next header entry instead of the next file entry in sequences such as `x -> L -> file`. Crafted archives can extract differently under astral-tokio-tar than GNU/BSD tar and smuggle unexpected files.
- **eZ Publish Legacy dfscleanup SQL injection** — `ezsystems/ezpublish-legacy` branch `2019.03` and likely older EOL lines concatenate the `dfscleanup.php --path` value into `_getFileList()` SQL without quoting. An attacker with local shell access and rights to run the script can perform in-band union SQL injection and potentially influence file-deletion behavior.
- **CAPM3 cross-namespace resource access** — Cluster API Provider Metal3 allowed namespace-scoped users who can create or modify CAPM3 resources to reference secrets, BareMetalHosts, and Metal3DataTemplates in other namespaces. This is strongest in shared management clusters where namespace RBAC is treated as a tenant boundary.
- **NodeVM observability builtin data exposure** — `vm2 <=3.11.3` did not classify `diagnostics_channel`, `async_hooks`, and `perf_hooks` as dangerous process-wide builtins. Sandboxed code with those builtins allowed can observe host HTTP request headers, async context data, or performance marks.

## Operator triage

1. **Find exposed ChromaDB Python servers:** prioritize internet-facing Chroma API docs, `/api/v2/tenants/.../collections` routes, Docker images or process names indicating the Python FastAPI server, and version evidence at or after `1.0.0`.
2. **Separate Python from Rust Chroma paths:** the advisory centers on the Python FastAPI server; record deployment mode before reporting impact.
3. **Map model-loading trust:** look for products that let users configure embedding functions, Hugging Face model IDs, or `trust_remote_code` kwargs through collection setup, RAG admin panels, or tenant self-service APIs.
4. **Triage GlobalProtect exposure:** identify PAN-OS GlobalProtect portals or gateways, confirm affected version families, and determine whether authentication override cookies are enabled. This is an edge-access finding, so prioritize explicit program scope and non-invasive version/config proof.
5. **Find ngrok wrapper reachability:** search CI scripts, CLIs, developer portals, agent sandboxes, and scaffolding tools that call `ngrok.getVersion()`, `connect()`, or wrapper helpers with user/project-controlled option objects.
6. **Trace tar extraction consumers:** flag Rust services, package managers, CI ingestion flows, upload processors, and artifact scanners that use `astral-tokio-tar` and then trust extracted paths or presence/absence of specific files.
7. **Assess local-maintenance escalation:** for eZ Publish Legacy, treat `dfscleanup.php` as a local post-compromise or low-privileged-shell escalation primitive into database reads and filesystem deletion, not a remote web SQLi.
8. **Identify CAPI shared-management clusters:** CAPM3 is most interesting where multiple teams or customers can create Metal3 resources in separate namespaces on one management cluster.
9. **Extend vm2 config review:** alongside the RCE-focused NodeVM checks, inspect whether `diagnostics_channel`, `async_hooks`, or `perf_hooks` are allowed in sandboxes that process untrusted plugin code near HTTP request handling.

## Replayable validation boundaries

### ChromaDB Python server model-loading check

- **Version and route proof first:** capture ChromaDB version, server mode, API docs exposure, and the target collection-create route before sending any payload.
- **Use a controlled benign model repo in a lab:** for authorized validation, host a minimal Hugging Face-compatible model repository that performs a harmless canary action such as requesting a tester-owned callback URL or writing a marker in a disposable container path.
- **Prove pre-auth ordering safely:** send an unauthenticated collection-create request that sets a controlled model name and `trust_remote_code: true`, then verify the benign canary fired even though the API response was rejected. Do not read environment variables, tokens, collection data, or mounted secrets on production systems.
- **Report deployment context:** include Python FastAPI evidence, route, auth state, request ID or timestamp, model-loading callback proof, and whether the target is a lab mirror or production authorization scope.

### PAN-OS GlobalProtect auth-bypass check

- **Stay non-invasive by default:** for bug-bounty or external recon, stop at version, product, and GlobalProtect portal/gateway exposure evidence unless the program explicitly authorizes VPN authentication-bypass testing.
- **Confirm configuration through authorized channels:** the vulnerable condition depends on authentication override cookie settings and certificate use. Prefer admin-export evidence, screenshots from an authorized operator, or lab reproduction over probing production login flows.
- **Use lab replay for exploit-path validation:** if proof is required, mirror the affected PAN-OS version and GlobalProtect configuration in a lab and demonstrate unauthorized tunnel establishment with synthetic accounts and networks only.
- **Report active-exploitation context:** include CISA KEV date, Palo Alto `ATTACKED` status, affected version train, GlobalProtect role, and whether the target is an internet-facing portal or gateway.

### ngrok npm wrapper command-boundary check

- **Confirm reachable option control:** only test when a user, repository, or tenant can influence the options object passed to the ngrok package.
- **Prefer inert command markers:** in a lab or disposable CI workspace, use a canary file in a temp directory or a tester-owned callback. Avoid payloads that modify application code or developer machines.
- **Differentiate library bug from application bug:** report the exact application path that lets untrusted input set `binPath` or equivalent options; a vulnerable package version alone is weaker if callers hard-code safe options.

### astral-tokio-tar parser-differential check

- **Build a two-parser harness:** compare extraction manifests from `astral-tokio-tar <=0.6.1` and a reference tar implementation using a crafted `PAX -> GNU longname -> file` sequence.
- **Use canary filenames only:** prove differential extraction with harmless files such as `expected.txt` versus `smuggled-canary.txt`; do not overwrite real application paths.
- **Tie to trust boundary:** show how the target uses extracted output: package installation, build execution, config loading, signature verification, allowlist checks, or artifact publishing.

### eZ Publish Legacy dfscleanup SQLi check

- **Keep it local and authorized:** this requires shell access and permission to run `bin/php/dfscleanup.php`; treat it as a post-auth local privilege boundary.
- **Use read-only union probes first:** validate with a harmless constant or current database/user marker, not credential extraction.
- **Avoid deletion impact:** if testing deletion behavior, use a disposable lab instance and synthetic filesystem entries.

### CAPM3 cross-namespace reference check

- **Create two isolated test namespaces:** one attacker namespace with CAPM3 resource creation rights and one target namespace with a synthetic secret, BareMetalHost, or Metal3DataTemplate.
- **Validate one primitive at a time:** test cross-namespace `userData`, `metaData`, `networkData`, BareMetalHost annotation, ConsumerRef validation, and Metal3DataClaim template references separately.
- **Stop at synthetic data:** use canary secrets and dummy hosts; do not claim real bare-metal assets or read operational bootstrap data.

### NodeVM observability data-leak check

- **Confirm builtin allowance:** show that the sandbox allows `diagnostics_channel`, `async_hooks`, or `perf_hooks` while treating NodeVM as a security boundary.
- **Use synthetic request secrets:** send a request containing a canary header such as `X-Canary-Token` and verify whether sandbox code can observe it through diagnostics channels or async resource state.
- **Avoid live token capture:** never harvest real authorization headers or session cookies; a synthetic marker is sufficient.

## Reporting heuristics

- For ChromaDB, highlight the **pre-auth side effect**: code executes before auth rejection. Include the exact endpoint, embedding-function configuration field, model-loading evidence, and deployment mode.
- For GlobalProtect, distinguish exposed portal/gateway presence from proven authentication bypass. Include version train, auth-override cookie configuration evidence, certificate configuration evidence if available, and a scoped lab proof if production testing is not authorized.
- For ngrok, impact depends on who controls the options object. Include caller path, project-controlled input source, vulnerable package version, and benign command marker.
- For tar parser issues, include both extraction manifests and explain the parser differential rather than only naming a package version.
- For eZ Publish Legacy, be explicit about prerequisites: local shell access, script execution rights, MySQL backend, and EOL/no-fix status.
- For CAPM3, frame findings around namespace isolation in shared management clusters. Single-team clusters may be defense-in-depth rather than bug-bounty-grade escalation.
- For NodeVM observability, report the exact builtin, host context object observed, synthetic token proof, and the product feature that allowed untrusted JavaScript execution.

## Notes on skipped items from this scan

- IPAM controller excessive Secret permissions (GHSA-49pm-43hf-6xfq / CVE-2026-47190) was tracked as a useful hardening signal but not promoted as standalone operator guidance because exploitation requires a separate controller-pod compromise.
- Ironic Standalone Operator resource-modification and metrics-exposure advisories were reviewed as low-detail or defensive control-plane hardening items for this taxonomy.
- unbounded-spsc race-triggered memory unsafety was reviewed as implementation-hardening context without a clear replayable offensive workflow for Skillz.
- CISA KEV advanced to catalog `2026.05.29` with CVE-2026-0257 reflected above; PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.
