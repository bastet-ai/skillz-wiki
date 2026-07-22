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

## Late July 21 package-build and URI authority boundaries

Four reviewed advisories add reusable repository-to-build and string-parser-to-network checks: [GHSA-h35f-9h28-mq5c](https://github.com/advisories/GHSA-h35f-9h28-mq5c), [GHSA-vcrf-j523-4mrf](https://github.com/advisories/GHSA-vcrf-j523-4mrf), [GHSA-4c8g-83qw-93j6](https://github.com/advisories/GHSA-4c8g-83qw-93j6), and [GHSA-c2w2-prh8-qm98](https://github.com/advisories/GHSA-c2w2-prh8-qm98).

| Advisory | Component | Confirmed boundary |
| --- | --- | --- |
| GHSA-h35f-9h28-mq5c / CVE-2026-59890 | `setuptools` before 83.0.0 | On normalization-preserving macOS filesystems, an NFD filename does not byte-match the visually identical NFC `MANIFEST.in` exclusion, so the excluded file enters the source distribution. |
| GHSA-vcrf-j523-4mrf / CVE-2026-13760 | `aws-cdk-lib` before 2.260.0 | A dependency version string for a module named in `NodejsFunction.nodeModules` is interpolated into a Docker-bundling shell command; the container has read/write host bind mounts. |
| GHSA-4c8g-83qw-93j6 / CVE-2026-13676 | `fast-uri` 2.3.1 through 2.4.1, 3.x before 3.1.3, and 4.0.0 | Failed IDN conversion leaves Unicode host text in the policy parser while Node `URL` or `fetch()` canonicalizes the same text to a different destination. |
| GHSA-c2w2-prh8-qm98 / CVE-2026-59882 | `guzzlehttp/psr7` before 2.12.3 | Delimiters, embedded ports, and malformed IPv6 brackets can make `Uri::getHost()` disagree with the URI authority or downstream connection target. |

### Source-distribution normalization collision

Use a disposable Python package on macOS APFS/HFS+ with two synthetic non-ASCII files whose names are written in NFD. Add an NFC `global-exclude`, `recursive-exclude`, or `prune` rule for one marker and an ASCII exclusion as a control. Build only a local sdist, list the archive without installing or uploading it, and record filename code points/UTF-8 bytes, filesystem form, manifest rule bytes, `SOURCES.txt`, and archive entries. Compare setuptools 82.0.1 or another affected release with 83.0.0.

Positive evidence is **visually identical NFC rule and NFD path -> byte-level manifest mismatch -> synthetic excluded marker present in the sdist**, while the ASCII control is absent and the fixed build excludes both. Never place secrets in the fixture or upload the test artifact to PyPI. This is a packaging disclosure boundary, not proof that every non-ASCII file is included.

### CDK dependency metadata to bundling command

Create a scratch CDK app, a local throwaway npm package, a synthetic `NodejsFunction`, and Docker-based bundling with that package named in `nodeModules`. Use the upstream regression shape with a version-string metacharacter canary that can only create a marker inside the disposable bind-mounted output tree. Capture `package.json`, installed package metadata, generated bundling argv/shell text, container mounts, process identity, and marker path. Compare local bundling, Docker bundling without `nodeModules`, a normal version string, and `aws-cdk-lib` 2.260.0.

Report **repository/package-controlled dependency version -> `OsCommand` shell interpolation -> inert write through the bundling container's host mount**. Do not run `cdk deploy`, use cloud credentials, mount a real source/home directory, invoke a network callback, or substitute a shell payload that reads environment variables. Package presence alone is insufficient: the exact dependency must enter the Docker `nodeModules` path.

### IDN and PSR-7 authority decision matrices

For `fast-uri`, use owned loopback listeners with no sensitive routes. Feed the same URL strings to `fast-uri.parse()`/`normalize()`/`equal()`, Node's WHATWG `URL`, and an instrumented `fetch()` that records only the owned destination. Include ordinary DNS names, an ASCII loopback control, the advisory's ideographic-full-stop form `127。0。0。1`, other IDN separator forms, parse-error state, and fixed versions 2.4.2, 3.1.3, or 4.0.1. Report **policy parser retains Unicode host -> network consumer canonicalizes it -> host rule and final owned destination disagree**. Do not probe metadata or internal services.

For PSR-7, construct disposable URI objects through `new Uri()`, `withHost()`, raw absolute-form `Message::parseRequest()`, and synthetic `ServerRequest::fromGlobals()` values. Test one authority delimiter at a time, an embedded port, balanced and unbalanced IPv6 brackets, and 2.12.3. Record input, `getHost()`, `getAuthority()`, serialized request target/`Host`, cookie-domain decision, `no_proxy` decision if reached, and the mock transport's selected host. A strong finding proves the application's attacker-controlled source reaches both a security decision and a downstream serializer/transport; do not infer standard Guzzle client exploitation from a malformed `Uri` object alone.

Report the narrow transition: **untrusted host text -> parser representation differs from authority/wire target -> canary allowlist, cookie, proxy, or routing decision changes**. Use fake cookies and proxies, owned hosts, and no real credentials.

## Late July 21 Git, pipeline, and render-policy boundaries

The next reviewed-advisory wave adds seven reusable checks across repository wrappers, CI attestations, browser test runners, SVG/HTML sanitizers, and Java request binding:

| Advisory | Component | Confirmed boundary |
| --- | --- | --- |
| [GHSA-956x-8gvw-wg5v](https://github.com/advisories/GHSA-956x-8gvw-wg5v), [GHSA-2f96-g7mh-g2hx](https://github.com/advisories/GHSA-2f96-g7mh-g2hx), [GHSA-v396-v7q4-x2qj](https://github.com/advisories/GHSA-v396-v7q4-x2qj) | GitPython through 3.1.50; fixed in 3.1.51 | `Repo.archive()`/dynamic `ls_remote()` omit unsafe-option guards, `iter_commits()`/`blame()` accept option-like revisions, and guarded clone/network paths miss Git's abbreviated long options or joined short options. Caller-controlled kwargs, revisions, or `multi_options` can therefore reach command helpers or file-clobber options. |
| [GHSA-pf56-329r-95rw](https://github.com/advisories/GHSA-pf56-329r-95rw) / CVE-2026-59891 | `@sigstore/oci` before 0.7.1 | Docker credentials are selected with substring matching, so an untrusted destination registry whose host is contained in a configured auth key can receive the wrong registry's credential. This includes attest actions only when an untrusted source controls `subject-name` and registry push is enabled. |
| [GHSA-p63j-vcc4-9vmv](https://github.com/advisories/GHSA-p63j-vcc4-9vmv) | `@vitest/browser` before 3.2.7, 4.1.10, or 5.0.0-beta.6 | Browser-provider commands such as upload, screenshot, and trace handling bypass `allowWrite` or project-root confinement and can read, create, overwrite, or delete process-accessible files when the Browser Mode API is reachable. |
| [GHSA-2p49-hgcm-8545](https://github.com/advisories/GHSA-2p49-hgcm-8545) | SVGO `removeScripts`/`removeScriptElement`; fixed in 2.8.3, 3.3.4, and 4.0.2 | Namespace-prefixed executable SVG elements and case variants of script URIs survive the optional plugin. SVGO is an optimizer, not a general sanitizer, and the plugin is disabled by default. |
| [GHSA-c2j3-45gr-mqc4](https://github.com/advisories/GHSA-c2j3-45gr-mqc4) | DOMPurify through 3.4.11; fixed in 3.4.12 | Elements admitted by `CUSTOM_ELEMENT_HANDLING.tagNameCheck` can skip `afterSanitizeElements`; an application hook may remove a canary attribute from normal elements but leave it on an allowed custom element. This is not direct DOMPurify XSS without a later custom-element sink. |
| [GHSA-3pjw-73gf-8qr5](https://github.com/advisories/GHSA-3pjw-73gf-8qr5) / CVE-2026-59888 | `jackson-databind` affected 2.x/3.x lines before 2.18.8, 2.21.4, or 3.1.4 | A Java Record component renamed by `PropertyNamingStrategy` can escape the stale original-name `@JsonIgnore` set and be populated from its renamed wire key. |
| [GHSA-mhm7-754m-9p8w](https://github.com/advisories/GHSA-mhm7-754m-9p8w) | `jackson-databind` 2.18.0–2.18.8 and 2.21.0–2.21.4; fixed in 2.18.9 and 2.21.5 | A creator property combining restricted `@JsonView` with `@JsonTypeInfo(include=As.EXTERNAL_PROPERTY)` misses the active-view check and can accept a restricted synthetic subtype/value. |

### Git wrapper and registry-credential harnesses

For GitPython, start from an application source-to-sink map: prove which untrusted field reaches `archive` kwargs, dynamic Git kwargs, a revision argument, or clone `multi_options`. In a temporary repository with no remotes or credentials, use a fake helper that writes one marker inside the temp tree and an option-like revision aimed only at a disposable marker. Compare exact blocked options with an unambiguous long-option prefix, a joined `-uVALUE`, ordinary refs/options, and 3.1.51. Record the final argv and guard decision. Report **caller option/revision -> wrapper guard/parser mismatch -> inert helper execution or temp-file clobber**. Never target hooks, startup files, lockfiles, SSH material, developer homes, or network repositories.

For `@sigstore/oci`, create a temporary Docker config containing one fake credential for an owned registry and two owned mock registries whose hostnames have the advisory's substring relationship. Invoke only the affected credential-selection/authentication path with a synthetic image/attestation; capture selected config key, canonical target host, and a redacted fixed-token marker received by the mocks. Compare 0.7.1, exact-host, no-match, Docker Hub alias, and `push-to-registry: false` controls. Never place live registry tokens in the fixture or push an artifact to a real registry.

### Browser-runner filesystem matrix

Expose a no-secret Vitest Browser Mode fixture only on loopback or an isolated lab network. Set `allowWrite: false`, create in-root and adjacent synthetic files, and invoke one provider command per operation class: upload/attachment read, screenshot/trace write, and deletion. Prove only whether the adjacent marker is read, changed, or removed; restore it between cases. Compare a direct trusted test, an unreachable API, project-root paths, and a fixed release. Do not read environment files, source, browser profiles, keys, or user data.

### SVG, custom-element, and Jackson policy harnesses

For SVGO, pass inert SVG fixtures through the exact enabled plugin and then parse the output in a disposable browser origin. Compare ordinary and namespace-prefixed script-element names plus lower/mixed-case URI schemes, but replace executable bodies with harmless DOM marker assignments and disable outbound requests. Record input namespace, plugin name, optimized XML, parsed namespace/local name, and marker result. Package use or optimization alone is not enough: prove untrusted SVG is served in a script-capable context and the application relied on this plugin as sanitization.

For DOMPurify, register an `afterSanitizeElements` hook that removes only a synthetic `data-policy` attribute. Sanitize an ordinary allowed element and a custom element admitted through both regex and function `tagNameCheck`, then record hook calls and retained attributes on 3.4.11 and 3.4.12. If the application has a custom-element implementation, make its downstream sink render only a visible marker. Report **custom-element allow path -> hook skipped -> inert policy attribute retained**; do not call it XSS without independently proving executable reinsertion.

For Jackson, use a minimal local REST/deserialization harness with marker-only fields. One fixture should combine a Record, `@JsonIgnore`, and a naming strategy; the other should combine a property-based creator, restricted `@JsonView`, and external type ID. Compare original and renamed keys, normal properties, public/admin views, external vs ordinary type inclusion, and fixed releases. Positive evidence is a restricted synthetic role/flag/object being populated under the public reader. Do not bind the canary to a real administrator action, polymorphic gadget, filesystem operation, or production API.

The adjacent Apache Thrift resource-allocation entry and Dosage stored output-handler XSS were processed without promotion: one is availability-only, while the other does not add a stronger bounded workflow than the render-context checks above.

## Final July 21 URL, schema-generation, sanitizer, and authorization boundaries

The next reviewed-advisory wave adds durable parser-to-consumer, schema-to-generated-code, sanitizer-to-browser, and policy-to-runtime checks:

| Advisory | Component | Confirmed boundary |
| --- | --- | --- |
| [GHSA-v2hh-gcrm-f6hx](https://github.com/advisories/GHSA-v2hh-gcrm-f6hx) / CVE-2026-16221 | `fast-uri` 2.3.1–2.4.2, 3.0.0–3.1.3, and 4.0.0–4.1.0 | A literal backslash in an HTTP-family authority is treated as userinfo/path text by one parser and as a slash delimiter by Node's WHATWG URL/network stack, so the policy host and dialed host can differ. |
| [GHSA-rwj8-pgh3-r573](https://github.com/advisories/GHSA-rwj8-pgh3-r573) | GitPython through 3.1.51 | `Repo.clone_from()` expands `$NAME`, `${NAME}`, and on Windows `%NAME%` inside an untrusted clone URL before invoking Git, placing process-environment values into the request sent to the URL's host. |
| [GHSA-2rp8-mm9q-fp49](https://github.com/advisories/GHSA-2rp8-mm9q-fp49) | TypeORM before 0.3.31 and the 1.0.x line before 1.1.0 | `migration:generate` places introspected comments, defaults, checks, and view definitions into JavaScript/TypeScript template literals without escaping `${...}`; loading the generated migration evaluates the interpolation. |
| [GHSA-5qhf-9phg-95m2](https://github.com/advisories/GHSA-5qhf-9phg-95m2) | Loofah 2.25.0–2.25.1 | Direct callers of `allowed_uri?` can approve a disallowed browser scheme split by semicolonless numeric character references. Loofah's normal `sanitize()` parser path is not affected. |
| [GHSA-9wjq-cp2p-hrgf](https://github.com/advisories/GHSA-9wjq-cp2p-hrgf), [GHSA-cj75-f6xr-r4g7](https://github.com/advisories/GHSA-cj75-f6xr-r4g7) | Loofah before 2.25.2; `rails-html-sanitizer` 1.0.3–1.7.0 when custom SVG reference tags are allowed | Local-reference checks cover `xlink:href` but miss SVG 2's plain `href`, allowing `<use>` or `<feImage>` to reference another same-origin document or image. Rails defaults do not allow these SVG tags. |
| [GHSA-5gvw-p9qm-jgwh](https://github.com/advisories/GHSA-5gvw-p9qm-jgwh) / CVE-2026-59889 | affected Jackson Databind 2.18, 2.21, 2.22, 3.0, and 3.2 lines | During deserialization, a container property combining restricted `@JsonView` with `@JsonUnwrapped` can be populated under a less-privileged active view because the regular unwrapped-property path omits the container visibility gate. |
| [GHSA-hrxh-6v49-42gf](https://github.com/advisories/GHSA-hrxh-6v49-42gf) | gRPC-Go before 1.82.1 | xDS RBAC translation silently drops unsupported `Metadata` or `RequestedServerName` matchers, changing `AND`/`OR`/`NOT` policy logic and potentially failing open. The same advisory includes HTTP/2 and malformed-policy availability issues, which are not promoted here. |

### Backslash authority and clone-environment decision matrices

For `fast-uri`, extend the IDN matrix above with ordinary allowed and denied owned hosts, then the advisory's literal-backslash authority form. Record raw input, `fast-uri` host/userinfo/path, WHATWG `URL` host/path, allowlist or proxy decision, and the destination seen by an owned listener. Compare 2.4.3, 3.1.4, or 4.1.1. Report **string policy parser approves host A -> network parser normalizes backslash -> owned host B receives the canary**. Never substitute metadata, loopback administration, or a production internal host.

For GitPython, use a disposable process containing only a fake environment marker and an owned HTTP listener. Submit a clone URL containing the marker variable's *name*, not its value, through the application's real repository-import path and capture the sanitized request path at the owned listener. Add an unset variable, literal percent/dollar text, direct `git clone`, and GitPython 3.1.52 controls. Do not put real tokens in the process, log full URLs in shared CI, or clone from third-party hosts. Report **untrusted clone URL -> wrapper expands process variable -> fake marker appears in an outbound request**.

### Generated migration and sanitizer/browser harnesses

For TypeORM, seed a disposable Postgres/MySQL-compatible schema with one ordinary comment and one `${...}` canary whose only possible effect is setting an in-process marker when the generated migration is imported. Run `migration:generate`, inspect the generated source before execution, and load it only in a no-credential sandbox. Preserve database role, metadata write authority, generated source diff, import path, and marker result. Compare patched TypeORM, escaped `${`, and a generated migration that is reviewed but not loaded. Report **schema metadata controlled by role A -> migration generator emits live template interpolation -> developer/CI process B evaluates an inert marker**. Never write shell files, access environment secrets, or run the fixture against production migrations.

For semicolonless numeric references, extend the earlier Loofah helper matrix with `&#58`, `&#9`, and semicolon-terminated controls. Record helper decision, parsed DOM property, and browser-normalized scheme using only a visible marker. For SVG references, enable `<use>`/`<feImage>` only in a disposable sanitizer configuration and reference an owned same-origin SVG/image that contains a harmless render marker. Compare plain `href`, `xlink:href`, cross-origin, default Rails allowlists, and patched versions. Keep claims separate: helper-level URI approval, same-origin SVG content inclusion, tracking fetch, and script execution are different outcomes.

### Jackson and xDS policy-binding harnesses

For Jackson, add a minimal bean whose *container* property is both `@JsonView(AdminView.class)` and `@JsonUnwrapped`, with inert `role`/`approved` fields beneath it. Deserialize paired JSON under public and admin readers, comparing an ordinary nested restricted property, an unwrapped restricted container, fixed versions 2.18.9/2.21.5/2.22.1/3.1.5/3.2.1, and `DEFAULT_VIEW_INCLUSION` settings. Report **public active view -> unchecked unwrapped container replay -> restricted marker fields populated**; do not turn the marker into a real account or billing change.

For gRPC-Go, run a disposable xDS management server, one marker-only protected RPC, and two synthetic client identities. Apply policies that vary one matcher at a time: supported identity, unsupported `Metadata`, unsupported `RequestedServerName`, and those fields nested under `AND`, `OR`, and `NOT`. Record delivered policy, translated matcher tree or logs, client identity, and RPC decision on vulnerable and 1.82.1 builds. A positive finding is **policy requires unsupported matcher -> translator drops it -> unauthorized canary RPC succeeds**. Do not deliver malformed policies or rapid-reset traffic to shared services.

The adjacent Sharp/libvips bundle, repeated-DOCTYPE expansion-limit reset, Hono aborted-WebSocket leak, and Jackson chunked-number limit bypass were processed without publication because their disclosed value is memory safety or availability rather than a bounded cross-privilege operator workflow.

## July 22 Wagtail TableBlock attribute-rendering follow-up

[GHSA-p5cm-246w-84jm](https://github.com/advisories/GHSA-p5cm-246w-84jm) adds a focused CMS author-to-viewer render boundary. In affected Wagtail releases, a user who can create or edit a page containing a `TableBlock` inside a `StreamField` can persist a specially crafted table `class` attribute that is emitted into the rendered page as executable browser content. This is not an unauthenticated visitor finding: the site must use `TableBlock`, the tester needs page-authoring authority, and impact beyond the author's own session requires a higher-privileged user to view the affected page.

Affected lines are Wagtail before 6.3.8; 6.4rc1 and later before 7.0.6; 7.1rc1 and later before 7.2.3; and 7.3rc1 and later before 7.3.1. The corresponding fixed releases are 6.3.8, 7.0.6, 7.2.3, and 7.3.1.

### TableBlock class-attribute render matrix

1. Use a disposable Wagtail site with one low-privilege page author, one separate viewer account, and a page type whose `StreamField` explicitly contains `TableBlock`. Confirm that an ordinary visitor without authoring access cannot set the table configuration.
2. Create a baseline table with an ordinary CSS class and capture the saved block value, rendered HTML attribute, and browser DOM property.
3. Through the same authoring path, use a harmless class-attribute breakout canary whose only effect is setting an unmistakable in-page marker. Disable outbound requests and do not read cookies, storage, page content, or CSRF material.
4. Compare four states: author preview, a separate viewer opening the published page, the same fixture on a fixed Wagtail release, and a custom `TableBlock(template=...)` that does not emit the configurable class attributes.
5. Preserve the Wagtail version, page/block definition, author role, stored block fragment, rendered HTML, DOM event/marker result, and fixed-version decision. Remove the page and test users when the lab is complete.

Report **page-author-controlled TableBlock class metadata -> trusted Wagtail page rendering -> harmless script marker executes in a separate viewer origin**. Do not claim visitor-to-admin XSS, account takeover, or arbitrary site-wide impact unless the target's actual authoring roles, publication workflow, and viewer path prove those transitions. Never exfiltrate a real session or induce a production administrator to open the canary.

## Reporting checklist

- [ ] Did the report prove the caller can reach the exact PKI, MCP, proxy, updater, daemon, cryptographic, or provisioning path?
- [ ] Are DNS answers, final destinations, forwarded paths, archive entries, filesystem resolution, signature decisions, and role-route outcomes shown as decision tables or diffs?
- [ ] Are keys disposable, callbacks owned, credentials fake, payloads inert, and files synthetic?
- [ ] Does each finding include a patched or policy-negative control?
- [ ] Are configuration-dependent preconditions explicit, especially ACME challenge type, reverse-proxy/skip-auth settings, signing-key control, `/tmp` fallback, algorithm path, and Grafana role/permission state?
- [ ] For late follow-ups, are helper-vs-browser parsing, SQL binding, DSA parameter validity, namespace ID/name binding, localhost HTTP transport, and auth-header passthrough shown separately?
- [ ] For .NET follow-ups, is the exact shared build path, Negotiate-to-LDAP role lookup, or attacker-reachable XAML parser proven before claiming impact?
- [ ] For JDBC and TOML follow-ups, are the negotiated SASL mechanism and parsed type/policy decision captured separately with fixed-version controls?
- [ ] For package-build and URI follow-ups, are Unicode forms, archive entries, generated command context, parser hosts, URI authority, and final owned destination captured independently?
- [ ] For the late Git/pipeline/render wave, are wrapper argv, credential-host selection, provider-command file effects, sanitizer hook/plugin decisions, and Jackson field/view binding shown separately with fixed controls?
- [ ] For the final URL/schema/sanitizer/policy wave, are raw and normalized hosts, expanded fake variables, generated source, browser DOM properties, active views, and translated xDS matchers captured independently?
- [ ] For Wagtail, is `TableBlock` actually present, is authoring permission proven, and does the evidence stop at a harmless marker in a separate disposable viewer session?
