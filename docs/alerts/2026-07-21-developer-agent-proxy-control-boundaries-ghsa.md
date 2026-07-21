# PKI, MCP, proxy-auth, updater, and cryptographic boundary checks

Sources: hourly offensive-security scan, 2026-07-21 GitHub Security Advisory wave. Primary entries: [GHSA-8r5m-3f66-qpr3](https://github.com/advisories/GHSA-8r5m-3f66-qpr3), [GHSA-c4hg-6933-x62x](https://github.com/advisories/GHSA-c4hg-6933-x62x), [GHSA-7x63-xv5r-3p2x](https://github.com/advisories/GHSA-7x63-xv5r-3p2x), [GHSA-hg88-v3cw-3qrh](https://github.com/advisories/GHSA-hg88-v3cw-3qrh), [GHSA-3pvj-jv98-qhjq](https://github.com/advisories/GHSA-3pvj-jv98-qhjq), [GHSA-8qwj-4jxw-m8jw](https://github.com/advisories/GHSA-8qwj-4jxw-m8jw), [GHSA-5jx8-q4cp-rhh6](https://github.com/advisories/GHSA-5jx8-q4cp-rhh6), and [GHSA-7g92-g4vh-hp84](https://github.com/advisories/GHSA-7g92-g4vh-hp84).

This batch is durable because it exposes reusable operator boundaries: DNS-controlled certificate-validation fetches, caller-controlled MCP routing, forwarded-path trust before authentication, signed updater archives gaining a broader filesystem primitive, predictable temporary runtime paths followed by developer tools, broken big-integer edge cases crossing into signature acceptance or signing-key recovery, and API-vs-UI authorization drift around protected integration destinations.

!!! warning "Authorized validation only"
    Use disposable PKI mounts, DNS zones, MCP servers, proxies, updater keys, filesystem trees, cryptographic keys, Grafana instances, and webhook listeners. Keep callbacks owned, commands inert, credentials fake, files synthetic, and proofs marker-only. Never target metadata/internal production services, overwrite real user/system files, sign a malicious production update, recover or use production private keys, change production notification endpoints, or capture live webhook payloads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-8r5m-3f66-qpr3](https://github.com/advisories/GHSA-8r5m-3f66-qpr3) / CVE-2026-5052 | HashiCorp Vault PKI ACME validation | Attacker-controlled DNS can make HTTP-01 or TLS-ALPN-01 validation requests reach local targets | Treat certificate challenge resolvers as DNS-rebinding and final-destination SSRF surfaces. |
| [GHSA-c4hg-6933-x62x](https://github.com/advisories/GHSA-c4hg-6933-x62x) / CVE-2026-34476 | Apache SkyWalking MCP 0.1.0 | Caller-controlled `SW-URL` steers server-side requests | Inventory MCP headers as tool-routing inputs, not merely metadata. |
| [GHSA-7x63-xv5r-3p2x](https://github.com/advisories/GHSA-7x63-xv5r-3p2x) / CVE-2026-40575 | OAuth2 Proxy in reverse-proxy mode | Client-supplied `X-Forwarded-Uri` can steer `skip_auth_routes` evaluation away from the upstream path | Compare edge, auth proxy, and backend path decisions with direct-vs-trusted-proxy controls. |
| [GHSA-hg88-v3cw-3qrh](https://github.com/advisories/GHSA-hg88-v3cw-3qrh) | Sparkle binary delta updater | Signed archive content can create an intermediate symlink and make a later extraction escape the update tree | Model compromised signing-key impact against updater filesystem privileges, not only bundle replacement. |
| [GHSA-3pvj-jv98-qhjq](https://github.com/advisories/GHSA-3pvj-jv98-qhjq) / CVE-2026-53765 | `chrome-devtools-mcp` daemon fallback under `/tmp` | Predictable runtime directory and symlink-following PID write let another local user redirect a victim-writable file write/truncation | Add parent-directory ownership and final-component symlink checks to local agent daemons. |
| [GHSA-8qwj-4jxw-m8jw](https://github.com/advisories/GHSA-8qwj-4jxw-m8jw) / CVE-2026-4602 | `jsrsasign` before 11.1.1 | Negative exponent handling can produce incorrect modular inverses and break signature verification | Add invalid-domain integer fixtures to crypto verifier assessments and prove accept/reject drift with disposable keys. |
| [GHSA-5jx8-q4cp-rhh6](https://github.com/advisories/GHSA-5jx8-q4cp-rhh6) / CVE-2026-4599 | `jsrsasign` 7.0.0 through before 11.1.1 | Incomplete range comparison biases DSA signing nonces enough for private-key recovery | Assess signer-generated signature corpora offline for nonce bias before any key-recovery proof. |
| [GHSA-7g92-g4vh-hp84](https://github.com/advisories/GHSA-7g92-g4vh-hp84) / CVE-2026-21724 | Grafana OSS provisioning contact-points API | Editor role can modify protected webhook URLs without the protected-receiver write permission | Test API/UI and protected/unprotected receiver authorization as a role-route matrix. |

## Replayable validation boundaries

### ACME challenge final-destination checks

1. Use a disposable Vault PKI mount, an owned DNS zone with short TTLs, and two lab listeners representing public and synthetic local destinations.
2. Request only canary certificates for the owned zone and record DNS answers plus connection destinations for HTTP-01 and TLS-ALPN-01.
3. If rebinding or time-of-check/time-of-use testing is approved, switch only between owned lab addresses and compare the validated address with the address actually dialed.
4. Add controls for patched Vault, stable public DNS, non-local final addresses, redirects if the challenge client follows them, and failed challenge tokens.

Report **attacker-controlled ACME identifier/DNS -> challenge validation -> request reaches a synthetic local destination**. Do not query metadata, loopback admin services, Kubernetes APIs, or third-party private hosts.

### MCP upstream-header routing checks

Run SkyWalking MCP 0.1.0 against an owned mock SkyWalking API. Vary `SW-URL` between the configured mock, another owned listener, loopback syntax variants, an owned redirector, malformed values, and patched 0.2.0. Evidence should identify whether the header overrides the server's expected upstream, which process makes the request, and which final owned destination receives it. Report **MCP caller header -> upstream base URL selection -> server-origin fetch to caller-selected canary**. Never point it at production monitoring systems or internal services.

### Forwarded-path authentication matrices

1. Put an owned edge proxy, OAuth2 Proxy, and marker backend in sequence. Enable reverse-proxy mode and define one harmless skip-auth route plus one protected marker route.
2. Test the protected and public routes with no forwarded header, a truthful edge-overwritten `X-Forwarded-Uri`, and a client-supplied value naming the public route.
3. Repeat from direct-client and trusted-edge source addresses. On 7.15.2 or later, compare unset and explicitly scoped `--trusted-proxy-ip`; upgrading alone preserves broad trust when the flag remains unset.
4. Record the wire request URI, forwarded URI, source class, skip-auth decision, backend path, session state, and status/body marker.

Report **client-controlled forwarded path -> skip-auth rule evaluates a different route -> protected marker backend reached without a canary session**. Stop at the synthetic route; do not access real user or admin data.

### Signed updater symlink-boundary checks

Use a disposable Sparkle app, throwaway EdDSA key, non-root updater process, temporary extraction root, and sibling marker directory. Create a signed delta that contains an intermediate symlink followed by a benign file under that path. Prove only whether the file lands in the sibling canary directory. Compare immediate-parent and deeper intermediate-symlink cases and a fixed build. State the signing-key-compromise precondition explicitly: this expands the filesystem effect available to a signing-key holder and is not an unsigned-update bypass. Do not overwrite bundles, startup files, or system paths.

### Predictable runtime-directory symlink checks

On a two-user disposable macOS/Linux lab where `XDG_RUNTIME_DIR` is unset, pre-create only the expected `/tmp/chrome-devtools-mcp-<uid>` path for the victim test user and redirect `daemon.pid` to a victim-owned temporary marker file. Start daemon mode as the victim and record directory ownership, symlink resolution, target size/content, and process result. Compare a private runtime directory and a fixed build using secure parent ownership plus no-follow/exclusive creation. Never target shell profiles, SSH files, browser profiles, or real configuration.

### `jsrsasign` verification and nonce-bias checks

For negative-exponent verification behavior, create disposable RSA/DSA keys and a local harness that invokes the exact affected verification path. Start with valid signatures and ordinary invalid signatures, then add only the malformed mathematical-domain fixture from the upstream advisory/reproducer. Compare vulnerable and 11.1.1-or-later accept/reject/error decisions. Keep all tokens and keys offline and synthetic.

For DSA nonce bias, generate a bounded corpus of signatures over known synthetic messages with one disposable key. Record `(r, s)`, message hashes, library version, and sampling configuration; then run the upstream statistical/key-recovery reproducer offline. A strong proof first demonstrates distribution bias, then—only in the disposable harness—confirms whether a recovered candidate matches the throwaway public key. Do not collect signatures from production signers, brute-force real keys, or use a recovered key for token or document forgery.

Report either **malformed integer domain -> verifier accepts a signature the fixed implementation rejects** or **biased signer nonce distribution -> disposable DSA private key recovered offline**. Do not generalize to application authentication without proving the target uses the affected library and algorithm path.

### Grafana protected-contact-point authorization checks

1. Create a disposable Grafana OSS instance, one Editor user, one contact point whose webhook URL is marked protected, and two owned marker-only webhook listeners.
2. Establish controls: the Editor can view/use only the actions intended by the configured role and cannot change the protected URL through the normal UI path.
3. Through the provisioning contact-points API, attempt to replace only the synthetic protected webhook URL with the second owned listener while preserving all unrelated fields.
4. Trigger one harmless test notification containing no dashboard, alert, label, or tenant data and record which owned listener receives the marker.
5. Compare Grafana 12.3.6 or later, a user holding the explicit protected-receiver write permission, an unprotected receiver, and a Viewer role.

Report **Editor provisioning API access -> protected field write check omitted -> synthetic notification destination changes**. Restore/delete the disposable receiver and never redirect production alerts or capture real alert payloads.

## Late July 21 parser, tenant, MCP, and token follow-up

The updated advisory feed added six adjacent developer-control boundaries: [GHSA-8whx-365g-h9vv](https://github.com/advisories/GHSA-8whx-365g-h9vv), [GHSA-339r-cjv9-x78g](https://github.com/advisories/GHSA-339r-cjv9-x78g), [GHSA-wvqx-v3f6-w8rh](https://github.com/advisories/GHSA-wvqx-v3f6-w8rh), [GHSA-xpg8-3hhp-p7w8](https://github.com/advisories/GHSA-xpg8-3hhp-p7w8), [GHSA-xw59-hvm2-8pj6](https://github.com/advisories/GHSA-xw59-hvm2-8pj6), and [GHSA-72gw-fmmr-c4r4](https://github.com/advisories/GHSA-72gw-fmmr-c4r4).

| Advisory | Component | Boundary worth testing |
| --- | --- | --- |
| GHSA-8whx-365g-h9vv | Loofah `allowed_uri?`, 2.25.0 through 2.25.1 | String-level entity decoding and browser URL parsing disagree for named `&Tab;` and `&NewLine;` references inside a scheme. Loofah's normal `sanitize()` parser path is not affected. |
| GHSA-339r-cjv9-x78g / CVE-2024-11958 | LlamaIndex DuckDB retriever before 0.4.0 | Retriever input reaches SQL construction without prepared statements; DuckDB extension capabilities can turn a query boundary into a larger runtime boundary. |
| GHSA-wvqx-v3f6-w8rh / CVE-2026-4600 | `jsrsasign` before 11.1.1 | Caller-supplied DSA domain parameters such as degenerate `g` and `y` values can make the verification equation accept a forged signature or certificate. |
| GHSA-xpg8-3hhp-p7w8 / CVE-2026-5199 | Temporal Server before 1.29.5, or 1.30 prereleases before 1.30.3 | A batch activity validates a namespace ID but trusts a caller-controlled namespace name, letting a namespace writer borrow an internal worker's cross-namespace authority in affected deployments. |
| GHSA-xw59-hvm2-8pj6 / CVE-2026-34742 | MCP Go SDK before 1.4.0 | Local unauthenticated `StreamableHTTPHandler` or `SSEHandler` servers lack default DNS-rebinding protection; stdio transport is not affected. |
| GHSA-72gw-fmmr-c4r4 / CVE-2026-4525 | Vault through 1.19.15, 1.20.9, or 1.21.4 | When an auth mount passes through `Authorization`, the Vault token used on the outer request can reach the auth plugin backend. |

### Canonicalization and query-construction harnesses

For Loofah, call the public `allowed_uri?` helper directly with a matrix containing a normal HTTPS URL, a literal disallowed scheme, numeric whitespace references, named `&Tab;`/`&NewLine;` references, and a non-stripped named reference such as `&nbsp;`. Render only inert URI markers in a disposable browser page and record helper decision, parsed DOM attribute, and browser-normalized scheme. Keep the claim narrow: **string helper approves an encoded value that the browser interprets as a disallowed scheme**. Do not report Loofah's default `sanitize()` path unless the same differential is independently reproduced there.

For LlamaIndex, seed a disposable DuckDB database with a public row and a distinct canary row. Capture the SQL or bound-parameter trace produced by ordinary retriever input, a quote canary, a boolean differential, and a patched 0.4.0 control. Stop once the synthetic row boundary or query structure changes. Do not install extensions, invoke shell-capable DuckDB features, read host files, or connect the harness to a production database. Report **retriever input -> unparameterized SQL structure -> synthetic result-set change**; RCE is a separate claim requiring an explicitly approved isolated lab.

### DSA domain-parameter validation

Extend the disposable `jsrsasign` harness above with malformed DSA public-domain fixtures. Compare a valid throwaway certificate/signature, an ordinary invalid signature, and the upstream degenerate-domain reproducer on a vulnerable release and 11.1.1 or later. Record `p`, `q`, `g`, and `y` validity checks plus only the final accept/reject decision; never use a forged certificate outside the harness. Report **unvalidated DSA domain parameters -> verifier accepts a synthetic signature or X.509 certificate rejected by the fixed build**.

### Temporal namespace ID/name binding

Use two disposable namespaces on one lab cluster, a writer identity in namespace A, synthetic workflow IDs in each namespace, and marker-only workflows. First establish that A cannot directly signal, reset, or delete B's marker. Then submit only a harmless batch signal while varying namespace ID and namespace name independently. Capture the caller role, worker-bound namespace, supplied ID/name pair, internal identity, and resulting marker state. The vulnerable configuration requires internal components with cross-namespace authorization; show that precondition rather than generalizing to every Temporal deployment. Do not delete real workflows or brute-force IDs.

### Local MCP browser-origin and Vault plugin token relays

For the MCP Go SDK, run one no-auth loopback server exposing a canary read-only tool and no secrets. From an owned browser origin, test direct cross-origin requests, rebinding between two owned addresses, `Host`/`Origin` mismatches, patched 1.4.0, and stdio as a non-HTTP control. Positive evidence is one inert tool invocation or synthetic resource read. Never expose command, file, credential, or network tools for this test.

For Vault, create a disposable auth mount and a mock auth plugin that records header names and a redacted fixed token marker. Compare plugin passthrough disabled, a non-`Authorization` header, `Authorization` used for Vault authentication, and fixed releases 1.19.16, 1.20.10, 1.21.5, or 2.0.0. Report **outer Vault bearer token -> configured auth-header passthrough -> plugin receives the marker**. Never log or replay a live Vault token.

## Late July 21 .NET build, authentication, and XAML boundaries

The next reviewed-advisory batch added three durable operator surfaces: [GHSA-55jh-fwmh-39m4](https://github.com/advisories/GHSA-55jh-fwmh-39m4), [GHSA-8prm-248r-h957](https://github.com/advisories/GHSA-8prm-248r-h957), [GHSA-2p3q-h3hg-jcqq](https://github.com/advisories/GHSA-2p3q-h3hg-jcqq), and [GHSA-2969-4q4w-w5h3](https://github.com/advisories/GHSA-2969-4q4w-w5h3). The adjacent SignalR stateful-reconnect and encrypted-XML entries are availability-only and are intentionally not promoted into operator guidance.

| Advisory | Component | Confirmed boundary |
| --- | --- | --- |
| GHSA-55jh-fwmh-39m4 / CVE-2026-50526 | `Microsoft.NET.Build.Containers` | A low-privilege local user can exploit link following to inject resources into container images built by another user on the same host. Affected package lines are 8.0.0–8.0.28, 9.0.0–9.0.17, and 10.0.0–10.0.9. |
| GHSA-8prm-248r-h957 / CVE-2026-47300 | ASP.NET Core Negotiate authentication | Improper validation can elevate an authenticated remote user when Negotiate authentication uses LDAP to retrieve role information. |
| GHSA-2p3q-h3hg-jcqq / CVE-2026-47303 | ASP.NET Core Negotiate authentication | Improper parsing, including an LDAP-query injection boundary, can alter authorization. The affected package lines match CVE-2026-47300. |
| GHSA-2969-4q4w-w5h3 / CVE-2026-50650 | WPF XAML parser | Specially crafted XAML can cross into local code execution/elevation on Windows when an application parses attacker-reachable XAML. Affected desktop-runtime lines are 8.0.0–8.0.28, 9.0.0–9.0.17, and 10.0.0–10.0.9. |

### Cross-user container-build injection

Use a disposable multi-user build host, an unprivileged attacker account, a separate builder account, a synthetic .NET project, and an isolated local OCI output. First record every shared temporary/cache/staging path touched by `Microsoft.NET.Build.Containers`; package presence alone does not prove a cross-user path is reachable. In the vulnerable build only, place an inert marker through the upstream link-following regression fixture or a semantically equivalent symlink fixture inside the disposable shared tree. Build as the second user and inspect the resulting OCI manifest/layer **without running the image**.

Positive evidence is **attacker-writable shared build path -> link resolution by another user's container build -> inert marker incorporated into that user's image**. Compare the fixed 8.0.29, 9.0.18, or 10.0.10 package, a private per-user staging root, a regular-file control, and a symlink whose destination is not readable by the builder. Capture path ownership, link targets, build-user identity, and layer diff. Never target a real build agent, shared registry, source tree, credential path, or production image.

### Negotiate-to-LDAP role binding

Build a lab realm/directory with two disposable users and two harmless roles, then run the same minimal ASP.NET Core app on an affected and fixed package. Confirm the application actually enables Negotiate and LDAP role retrieval. Record the authenticated principal emitted by Negotiate, the exact escaped LDAP filter shape, matched synthetic directory objects, resulting role claims, and access to one marker-only role route.

Exercise ordinary usernames, directory metacharacter canaries, alternate name forms/aliases, duplicated synthetic attributes, and the vendor regression fixture if Microsoft publishes one. Vary one field at a time; do not spray LDAP syntax or enumerate a real directory. Report CVE-2026-47300 only when a validated authenticated identity receives a role it was not assigned. Report CVE-2026-47303 only when attacker-influenced principal text changes LDAP query interpretation or selected synthetic entries. A strong result is **authenticated canary principal -> validation/parsing drift in LDAP role lookup -> unauthorized synthetic role claim -> marker route reached**, with fixed 8.0.29, 9.0.18, or 10.0.10 rejecting the same transition.

### Attacker-reachable WPF XAML sinks

Start with reachability rather than a code-execution payload. Inventory only applications that import, preview, deserialize, or otherwise parse XAML from files, plugins, IPC, downloads, or user-controlled fields. In a disposable Windows VM, trace the exact parser API and process token using benign XAML that creates only expected UI objects and writes no files. Then use Microsoft's regression test if it becomes public, substituting an inert in-process marker for any dangerous action.

The public advisory confirms crafted-XAML code injection but does not identify a universal remote ingestion path or public reproducer. Keep conclusions narrow: **attacker-controlled XAML reaches the affected WPF parser under a more privileged process and the fixed runtime changes the marker decision**. Do not invent gadget chains, open untrusted samples on a workstation, spawn processes, or touch user/system files. Compare fixed desktop runtimes 8.0.29, 9.0.18, or 10.0.10 and an application path that never parses external XAML.

## Late July 21 JDBC and TOML parser boundaries

Two updated-feed entries add reusable client and configuration-parser checks: [GHSA-j92g-9f8w-j867](https://github.com/advisories/GHSA-j92g-9f8w-j867) and [GHSA-m34p-749j-x6m6](https://github.com/advisories/GHSA-m34p-749j-x6m6). The adjacent Excon redirect-header update is already covered on the [July 10 HTTP client boundary page](2026-07-10-http-client-package-cache-identity-boundaries-ghsa.md#excon-redirect-follower-sensitive-header-relay).

| Advisory | Component | Confirmed boundary |
| --- | --- | --- |
| GHSA-j92g-9f8w-j867 / CVE-2026-54291 | PostgreSQL JDBC Driver 42.7.4 through 42.7.11 | `channelBinding=require` can silently negotiate plain `SCRAM-SHA-256` when the TLS certificate uses an unsupported channel-binding hash algorithm, including Ed25519 or Ed448. The required `-PLUS` mechanism is not enforced after negotiation. |
| GHSA-m34p-749j-x6m6 / CVE-2026-50029 | `js-toml` through 1.1.1 | A falsy scalar followed by a same-name table, dotted table, or array-of-tables bypasses duplicate-key rejection and turns the scalar into a truthy structured value. This is per-object type confusion, not global prototype pollution. |

### pgJDBC channel-binding downgrade matrix

Use a disposable PostgreSQL service, a throwaway database role, a lab CA, and an intercepting TLS endpoint that you own. Configure the client explicitly with `channelBinding=require`; the default `prefer` behavior permits fallback and is not a positive control. Present otherwise valid lab certificates using a conventional supported signature algorithm, Ed25519, and—only if the harness supports it—another algorithm for which `tls-server-end-point` cannot be derived. Record the server's advertised SASL mechanisms, certificate signature algorithm, extracted binding-data length, negotiated SCRAM mechanism, connection result, and driver version.

Positive evidence is **required channel binding + unsupported certificate algorithm -> successful connection using non-PLUS `SCRAM-SHA-256`** on 42.7.4–42.7.11 while 42.7.12 fails closed. Add `channelBinding=prefer` as an expected-fallback control, a direct connection, and `sslmode=verify-full` with the lab CA as an independent certificate-verification control. Do not intercept production database traffic, capture real credentials, weaken a deployed truststore, or describe ordinary `prefer` fallback as a bypass.

### TOML falsy-scalar structural confusion

Feed a minimal, synthetic TOML document through the application's real `js-toml` ingestion path. For each security-relevant candidate key, establish its expected schema and sink before testing. Compare `false`, `0`, and an empty string followed by a same-name standard table, dotted-key child, or array-of-tables. Add truthy-scalar duplicates, ordinary unique keys, another TOML parser, and `js-toml` 1.1.2 as controls. Capture the source text, parsed value type, own-key structure, schema-validation result, and final marker-only policy decision.

A safe fixture is a disabled synthetic feature becoming an object that reaches only an inert test branch. Report **falsy scalar -> duplicate table accepted -> parsed type changes from scalar to truthy object -> marker policy branch changes**. Do not claim prototype pollution, administrator access, or code execution unless a separate reachable application sink proves it. Never feed the fixture to production deployment, package-manager, CI, or infrastructure configuration.

## Reporting checklist

- [ ] Did the report prove the caller can reach the exact PKI, MCP, proxy, updater, daemon, cryptographic, or provisioning path?
- [ ] Are DNS answers, final destinations, forwarded paths, archive entries, filesystem resolution, signature decisions, and role-route outcomes shown as decision tables or diffs?
- [ ] Are keys disposable, callbacks owned, credentials fake, payloads inert, and files synthetic?
- [ ] Does each finding include a patched or policy-negative control?
- [ ] Are configuration-dependent preconditions explicit, especially ACME challenge type, reverse-proxy/skip-auth settings, signing-key control, `/tmp` fallback, algorithm path, and Grafana role/permission state?
- [ ] For late follow-ups, are helper-vs-browser parsing, SQL binding, DSA parameter validity, namespace ID/name binding, localhost HTTP transport, and auth-header passthrough shown separately?
- [ ] For .NET follow-ups, is the exact shared build path, Negotiate-to-LDAP role lookup, or attacker-reachable XAML parser proven before claiming impact?
- [ ] For JDBC and TOML follow-ups, are the negotiated SASL mechanism and parsed type/policy decision captured separately with fixed-version controls?
