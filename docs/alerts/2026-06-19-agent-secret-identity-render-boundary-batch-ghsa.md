# Agent, secret-store, identity-token, and renderer boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-jvcm-f35g-w78p](https://github.com/advisories/GHSA-jvcm-f35g-w78p), [GHSA-2fmp-9rvw-hc96](https://github.com/advisories/GHSA-2fmp-9rvw-hc96), [GHSA-9c83-rr99-vfwj](https://github.com/advisories/GHSA-9c83-rr99-vfwj), [GHSA-h5jc-78hr-3pc9](https://github.com/advisories/GHSA-h5jc-78hr-3pc9), [GHSA-p9xj-fpr2-jf2q](https://github.com/advisories/GHSA-p9xj-fpr2-jf2q) / CVE-2026-55878, [GHSA-6v8j-33hc-mv84](https://github.com/advisories/GHSA-6v8j-33hc-mv84) / CVE-2026-55877, [GHSA-4vrg-r928-h5vv](https://github.com/advisories/GHSA-4vrg-r928-h5vv) / CVE-2026-55866, [GHSA-mwr2-wmgp-crj6](https://github.com/advisories/GHSA-mwr2-wmgp-crj6) / CVE-2026-55775, [GHSA-6mwx-4547-5vc9](https://github.com/advisories/GHSA-6mwx-4547-5vc9) / CVE-2026-55770, [GHSA-c36x-h252-g9x2](https://github.com/advisories/GHSA-c36x-h252-g9x2) / CVE-2026-55774, [GHSA-5c7p-g73q-rpg5](https://github.com/advisories/GHSA-5c7p-g73q-rpg5) / CVE-2026-55692, [GHSA-766v-q9x3-g744](https://github.com/advisories/GHSA-766v-q9x3-g744) / CVE-2026-56078, [GHSA-ffp3-3562-8cv3](https://github.com/advisories/GHSA-ffp3-3562-8cv3) / CVE-2026-56074, [GHSA-6hw7-j4jw-wpff](https://github.com/advisories/GHSA-6hw7-j4jw-wpff) / CVE-2026-12398, [GHSA-2jqp-f4gr-44fr](https://github.com/advisories/GHSA-2jqp-f4gr-44fr) / CVE-2026-30120, [GHSA-g6pc-6676-c23j](https://github.com/advisories/GHSA-g6pc-6676-c23j) / CVE-2026-30121, [GHSA-v52w-28xh-v562](https://github.com/advisories/GHSA-v52w-28xh-v562), [GHSA-2288-8h3r-cqgg](https://github.com/advisories/GHSA-2288-8h3r-cqgg) / CVE-2026-54784, [GHSA-gqv6-pwcg-87r8](https://github.com/advisories/GHSA-gqv6-pwcg-87r8) / CVE-2026-54783, [GHSA-xjr9-gg9q-jx3v](https://github.com/advisories/GHSA-xjr9-gg9q-jx3v) / CVE-2026-54782, [GHSA-48pq-2xq3-c2m4](https://github.com/advisories/GHSA-48pq-2xq3-c2m4) / CVE-2026-54781, [GHSA-4v55-cpmv-3vcm](https://github.com/advisories/GHSA-4v55-cpmv-3vcm) / CVE-2026-54780, and [GHSA-9jr3-rj99-8jq3](https://github.com/advisories/GHSA-9jr3-rj99-8jq3) / CVE-2026-54779.

This batch is durable because the advisories share repeatable offensive validation patterns: agent sandboxes and backup manifests crossing filesystem boundaries, vault path filters that only protect root-level directory names, CMS previewers and icon loaders rendering trusted same-origin markup from untrusted content, recipe manifests writing outside intended roots, authorization engines turning conditional decisions into unconditional grants, secret-store namespace and LDAP query boundaries, agent approval caches that reuse consent too broadly, server-side renderers and package portals executing attacker-controlled project material, unauthenticated MCP servers reachable through HTTP, and WS-Security/SAML token validators accepting replayed, unsigned, or weakly bound identity material.

June 20 update: [GHSA-4xgf-cpjx-pc3j](https://github.com/advisories/GHSA-4xgf-cpjx-pc3j) adds the same operator pattern for Python application secret loaders: `pydantic-settings` `NestedSecretsSettingsSource` could follow symlinked directories outside `secrets_dir` when `secrets_nested_subdir=True`, loading out-of-tree files while bypassing `secrets_dir_max_size` accounting. A follow-on CoreWCF wave adds SOAP identity and local transport boundary checks: [GHSA-rpj7-hr7h-w6p9](https://github.com/advisories/GHSA-rpj7-hr7h-w6p9) / CVE-2026-54774, [GHSA-jc6x-rj79-w4mx](https://github.com/advisories/GHSA-jc6x-rj79-w4mx) / CVE-2026-54773, [GHSA-wjpq-6766-7f5j](https://github.com/advisories/GHSA-wjpq-6766-7f5j) / CVE-2026-54776, [GHSA-6jj2-4q5c-x8g6](https://github.com/advisories/GHSA-6jj2-4q5c-x8g6) / CVE-2026-54777, and [GHSA-q6v9-43v5-jv9q](https://github.com/advisories/GHSA-q6v9-43v5-jv9q) / CVE-2026-54778.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-jvcm-f35g-w78p | Network-AI `AgentRuntime` sandbox | path-prefix checks allowed file access outside the configured base directory | Treat agent runtime file APIs as filesystem sandboxes; prove only with disposable outside-root canaries and compare canonical path decisions with the final open/read sink. |
| GHSA-2fmp-9rvw-hc96 | Network-AI environment backup pruning | a poisoned backup manifest could steer recursive deletion outside the intended backup set | Backup/prune jobs are destructive control planes; validate in a throwaway workspace with marker directories only, never production homes, repos, or caches. |
| GHSA-9c83-rr99-vfwj | MCPVault `PathFilter` | restricted directory names such as `.git`, `.obsidian`, and `node_modules` were denied only at the vault root, not nested paths | Test vault and MCP file filters with nested deny-name matrices, symlinks, and path normalization before trusting repository or notes boundaries. |
| GHSA-h5jc-78hr-3pc9 | Sveltia CMS Markdown/RichText preview | stored preview content rendered in an unsandboxed same-origin iframe | CMS preview panes are privileged render origins; use inert DOM markers to prove same-origin script reachability against lab content only. |
| GHSA-p9xj-fpr2-jf2q / CVE-2026-55878 | Symfony UX Toolkit recipe manifests | crafted recipes could read or write paths outside the expected install root | Treat starter/recipe manifests like archive extractors and code generators; validate path traversal with synthetic files and a disposable app. |
| GHSA-6v8j-33hc-mv84 / CVE-2026-55877 | Symfony UX Icons | local SVG files and Iconify on-demand responses could carry unsanitized scriptable content | Icon loaders cross from package or remote metadata into app DOM; prove with harmless SVG markers and mocked Iconify responses. |
| GHSA-4vrg-r928-h5vv / CVE-2026-55866 | SpiceDB caveated relations | conditional permissions could be evaluated as unconditional grants | Authorization-engine tests need caveat-positive, caveat-negative, and missing-context cases, not just allow/deny tuples. |
| GHSA-mwr2-wmgp-crj6 / CVE-2026-55775 | OpenBao system backend | namespace management crossed into the containing namespace | Secret-store APIs require parent/child namespace route matrices with disposable namespaces and canary policies. |
| GHSA-6mwx-4547-5vc9 / CVE-2026-55770 | OpenBao LDAP auth utility | LDAP filters used the wrong escaping boundary | For LDAP-backed auth, test username/group strings through the actual filter builder and bind/search flow with a lab directory. |
| GHSA-c36x-h252-g9x2 / CVE-2026-55774 | OpenBao lease routes | canonical lease revoke/renew paths crossed namespace boundaries | Lease and token maintenance routes need the same namespace scoping checks as normal secret reads. |
| GHSA-5c7p-g73q-rpg5 / CVE-2026-55692 | StarCitizenWiki Embed Video extension | malformed video source URLs became stored HTML/script when consent mode was enabled | Extension embed renderers need protocol, attribute, and consent-wrapper DOM canaries in a lab wiki. |
| GHSA-766v-q9x3-g744 / CVE-2026-56078 | PraisonAI multi-agent context | memory state and path traversal crossed between multi-agent contexts | Multi-agent memory stores need two-agent labs, per-context markers, and outside-root canaries before accepting isolation claims. |
| GHSA-ffp3-3562-8cv3 / CVE-2026-56074 | PraisonAI tool approval cache | coarse-grained approval reuse bypassed per-invocation shell-command consent | Agent consent systems must bind approval to command, arguments, workspace, principal, and time; prove with inert command markers only. |
| GHSA-6hw7-j4jw-wpff / CVE-2026-12398 | Galaxy NG | package/import data reached command execution | Package portal import and scanning workers should be tested as command sinks using throwaway packages and marker-only commands. |
| GHSA-2jqp-f4gr-44fr / CVE-2026-30120 | Remotion renderer | project-controlled render inputs could reach server-side code execution | Rendering services that execute user projects require isolated workspaces, no host secrets, and canary-only proof of code execution. |
| GHSA-g6pc-6676-c23j / CVE-2026-30121 | Remotion renderer | render inputs could write arbitrary files | Pair renderer RCE checks with filesystem write-boundary canaries outside the expected output directory. |
| GHSA-v52w-28xh-v562 | Kozou MCP HTTP server | unauthenticated HTTP MCP exposure and dev-stack defaults enabled local-network/browser-adjacent tool access | MCP dev servers need bind-address, Host, Origin, DNS-rebinding, request-size, and read-only/read-write tool checks from browser and direct clients. |
| GHSA-2288-8h3r-cqgg / CVE-2026-54784 | CoreWCF SPNEGO security context | proof keys could be wrapped without the confidentiality expected by the binding | Include negotiated security-context token proof-key handling in SOAP auth tests, using disposable identities and lab keys. |
| GHSA-gqv6-pwcg-87r8 / CVE-2026-54783 | CoreWCF WS-Security | XML Signature Wrapping allowed replay of captured signed messages | SOAP/WS-Security tests should mutate signed-token placement and body references in a lab service to prove parser-vs-policy mismatch. |
| GHSA-xjr9-gg9q-jx3v / CVE-2026-54782 | CoreWCF SAML token validation | SAML 1.1/2.0 signature validation could be bypassed | Validate SAML token signatures against the exact CoreWCF binding path, not only an external IdP library. |
| GHSA-48pq-2xq3-c2m4 / CVE-2026-54781 | CoreWCF SAML subject confirmation | bearer/holder-of-key confirmation methods and proof keys were not enforced | Include subject-confirmation and proof-of-possession negative controls in SOAP identity tests. |
| GHSA-4v55-cpmv-3vcm / CVE-2026-54780 | CoreWCF WS-Security algorithms | weak or unexpected digest methods could bypass the configured algorithm suite | Algorithm-suite policies need token-level and reference-level downgrade attempts with lab messages only. |
| GHSA-9jr3-rj99-8jq3 / CVE-2026-54779 | CoreWCF SAML replay protection | token replay protection was inoperative | Replay testing should use disposable signed tokens and record whether nonce/timestamp/cache controls reject reuse. |
| GHSA-4xgf-cpjx-pc3j | `pydantic-settings` `NestedSecretsSettingsSource` | symlinked nested secret directories could resolve outside `secrets_dir` and bypass `secrets_dir_max_size` | Python secret loaders need canonical path and size-accounting tests with disposable secret trees, symlinked canary directories, and no real secret files. |
| GHSA-rpj7-hr7h-w6p9 / CVE-2026-54774 | CoreWCF SAML serializer | `SignatureValue` verification could be skipped when the SAML signing token was not an X.509 certificate | Include non-X.509 signed-token variants in SOAP identity negative controls; evidence should be authorization decisions for synthetic claims only. |
| GHSA-jc6x-rj79-w4mx / CVE-2026-54773 | CoreWCF WS-Security signature lookup | document-wide signature lookup enabled signature substitution | Add duplicate/moved signature and body-reference variants to wrapper tests so parser lookup and policy-bound reference validation are both exercised. |
| GHSA-wjpq-6766-7f5j / CVE-2026-54776 | CoreWCF Unix domain socket transport | `PosixIdentity` transport accepted connections that skipped the security upgrade | Treat local IPC transports as identity boundaries; prove with disposable sockets and principals, not production service endpoints. |
| GHSA-6jj2-4q5c-x8g6 / CVE-2026-54777 | CoreWCF NetNamedPipe transport | clients could attach to a pre-existing named pipe instance | Named-pipe tests need ownership, creation-order, and pre-existing-listener controls to prove whether the endpoint is bound to the intended server. |
| GHSA-q6v9-43v5-jv9q / CVE-2026-54778 | CoreWCF Unix domain socket identity resolver | non-reentrant POSIX identity resolution could mix local peer identity decisions | Exercise concurrent connection identity checks in a lab and record whether peer UID/GID decisions remain bound to the correct socket. |

## Operator triage

1. **Classify the trust boundary before payloads.** Is the input a repository file, agent memory key, recipe manifest, CMS preview body, SVG/icon response, LDAP principal string, package artifact, MCP HTTP request, or SOAP identity token?
2. **Build two-principal or two-context labs.** SpiceDB caveats, OpenBao namespaces, PraisonAI contexts, and CoreWCF identities need positive and negative principals to distinguish real authorization drift from expected access.
3. **Use canaries for file and command evidence.** Create temp roots, outside-root marker files, fake packages, and inert commands. Do not read real `.git`, vault notes, secrets, home directories, package credentials, or service-account material.
4. **Separate browser, direct client, and SSRF-reachable paths.** CMS previews and MCP HTTP servers may be exploitable only from a browser origin, only from a direct client, or through a same-host/server-side relay. Capture `Host`, `Origin`, bind address, and route auth.
5. **Replay identity controls carefully.** For CoreWCF and SAML/WS-Security issues, use a lab service, disposable keys, and synthetic claims. Never replay production tokens or capture customer SOAP bodies. For `net.pipe` and Unix domain socket transports, use disposable sockets, users, and services only.
6. **Skip pure crash-only findings unless they unlock a workflow.** Nearby OpenBao transit crash and parser/memory-safety entries were not promoted because they lacked a reusable authorized exploit path beyond availability testing.
7. **Treat application secret loaders as filesystem boundaries.** When a framework maps files into configuration values, test whether symlinked subdirectories, nested paths, and size limits are enforced by the same canonical iterator that performs the final read.

## Replayable validation boundaries

### Agent filesystem, memory, and consent boundaries

- Create a disposable workspace with a temp base directory and a separate outside-root marker file/directory.
- Exercise agent file APIs, memory/context IDs, backup/restore manifests, and prune jobs using benign markers only.
- For approval caches, submit two commands that share the same coarse category but differ in arguments and effect; the second command should write only a temp marker if wrongly approved.
- Record the requested path/context/command, the policy decision, the resolved filesystem target or executor call, and the marker result.
- Negative controls: canonical path resolution before authorization, symlink rejection, per-context memory scoping, and approval bound to full command plus principal/workspace/session.

### CMS, icon, and renderer DOM boundaries

- Seed a lab CMS/wiki/app with content that is safe but visibly unique: harmless SVG attributes, Markdown markers, malformed embed URLs, and RichText preview markers.
- Test preview pane origin, iframe sandbox flags, Content Security Policy behavior, Iconify/local icon sanitization, and consent-wrapper rendering.
- Positive evidence is marker execution or unsafe DOM insertion in the privileged application origin. Do not target real editors, stored customer pages, or administrator sessions.
- Negative controls: sandboxed preview iframes without same-origin privileges, strict protocol allowlists, SVG sanitization, and escaped attribute output.

### Recipe, package, and render-worker boundaries

- Use isolated throwaway packages/projects with no credentials, no mounted home directory, and no shared package caches.
- For recipe manifests and render outputs, attempt only synthetic traversal paths to marker files outside the app/output root.
- For package portal workers, replace command execution with an inert marker command in a lab worker or mock sink.
- Record worker identity, mounted paths, output root, and whether the marker crossed the intended boundary.

### Secret-store and authorization-engine route matrices

- Create disposable OpenBao namespaces, leases, users, and policies; create SpiceDB relations with caveat-true, caveat-false, and missing-context variants.
- Exercise both canonical and alternate routes: parent/child namespace management, lease renew/revoke aliases, LDAP search filters, and check APIs.
- Positive evidence is a canary permission, namespace mutation, lease operation, or LDAP search result that contradicts the expected principal or caveat state.
- Do not test against production secret engines, identity stores, or real policy names.

### Python settings secret-directory harness

- Use a disposable app profile that opts into `NestedSecretsSettingsSource` with `secrets_nested_subdir=True`; never point the harness at a production `secrets_dir`.
- Create a temporary `secrets_dir`, a separate outside-root directory, and a synthetic canary file such as `outside/db/passwd` containing non-sensitive marker text.
- Place a symlinked directory inside `secrets_dir` that targets the outside-root canary directory, then instantiate the settings class with a deliberately small `secrets_dir_max_size`.
- Positive evidence is limited to the synthetic marker loading into the expected settings field, or the size cap being bypassed for that marker. Do not target `/etc`, home directories, cloud credentials, Kubernetes service-account mounts, or real secret stores.
- Negative controls: resolved path stays within `secrets_dir` before read, symlinked directories pointing outside are skipped, cyclic symlinks are not re-traversed, and size accounting uses the same path walk as the loader.

### MCP HTTP and localhost/dev-server checks

- Inventory listener address, advertised MCP transport, route authentication, request-size limits, `Host` handling, and `Origin` handling.
- Test direct HTTP clients and owned browser pages separately; include DNS-rebinding-style `Host` variants only in a lab.
- Exercise harmless `tools/list`, `resources/list`, echo, or read-only canary routes.
- Negative controls: loopback-only binding, authenticated sessions, strict `Origin`/`Host`, DNS-rebinding defenses, read-only mode that cannot reach sensitive files, and request-body limits.

### CoreWCF SAML and WS-Security proof harness

- Stand up a lab CoreWCF service with disposable signing keys and synthetic claims.
- Build message variants for valid token, unsigned token, moved signed assertion, duplicated body/reference, wrong digest algorithm, unsupported subject-confirmation method, missing proof key, and replayed timestamp/nonce.
- Compare the service authorization decision for each variant against the configured binding and algorithm suite.
- Capture only decision tables and synthetic claim IDs. Do not replay real identity-provider assertions or customer SOAP messages.

### CoreWCF local transport identity harness

- Stand up disposable CoreWCF `net.pipe` and Unix domain socket services under lab-only users; never point tests at production Windows services, local agents, or privileged daemons.
- For named pipes, test normal server-created pipe startup and a pre-existing listener/control pipe with the same endpoint name; record which process owns the pipe and whether clients attach to the intended service.
- For Unix domain sockets, test the expected `PosixIdentity` security-upgrade path, a connection path that skips upgrade negotiation, and a small concurrent-connection matrix with distinct lab users.
- Positive evidence is limited to route reachability or synthetic identity decisions showing that a connection was accepted under the wrong local peer identity. Do not access real service methods beyond harmless echo/canary operations.
- Negative controls: endpoint creation refuses pre-existing pipes, upgrade negotiation is mandatory before authorization, peer credentials are fetched per connection, and identity state is not shared across concurrent sockets.

## Reporting notes

- State the crossed boundary precisely: **agent sandbox prefix to outside-root file access**, **backup manifest to recursive deletion**, **nested vault path to restricted directory bypass**, **same-origin preview to stored DOM execution**, **recipe manifest to outside-root read/write**, **icon response to trusted SVG markup**, **caveated relation to unconditional authorization**, **secret-store namespace route to parent scope**, **LDAP principal to filter injection**, **lease alias to cross-namespace control**, **framework secret-directory symlink to out-of-tree config read**, **multi-agent memory to context leakage**, **coarse approval cache to shell-command consent bypass**, **package/render input to worker command execution**, **HTTP MCP exposure to unauthenticated tool access**, **SAML signature validation to auth bypass**, **WS-Security signature lookup to substitution**, **local IPC transport to peer-identity confusion**, **subject confirmation to proof-key bypass**, **algorithm-suite downgrade**, or **SAML replay acceptance**.
- Evidence should be boring: route matrices, synthetic claims, redacted headers, fake packages, harmless DOM markers, temp files, and disposable namespaces.
- Avoid mitigation-first framing; lead with reachability, preconditions, exact trust boundary, canary evidence, and authorized impact.
