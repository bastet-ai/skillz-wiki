# HTTP client, identity, router, CI, and RDP boundary checks

Sources: hourly offensive-security scan, 2026-08-01 GitHub Security Advisory feed. Primary entries: [GHSA-mjrx-74jh-7xgw](https://github.com/advisories/GHSA-mjrx-74jh-7xgw), [GHSA-mqq9-gxg5-m58g](https://github.com/advisories/GHSA-mqq9-gxg5-m58g), [GHSA-32rq-jhr7-m3hh](https://github.com/advisories/GHSA-32rq-jhr7-m3hh), [GHSA-g2jv-pgqw-qxhv](https://github.com/advisories/GHSA-g2jv-pgqw-qxhv), [GHSA-rf63-989x-x4x8](https://github.com/advisories/GHSA-rf63-989x-x4x8), [GHSA-7qf5-7ppr-87v8](https://github.com/advisories/GHSA-7qf5-7ppr-87v8), [GHSA-4f8w-fmh5-hcxr](https://github.com/advisories/GHSA-4f8w-fmh5-hcxr), [GHSA-9chj-cp8j-3c5f](https://github.com/advisories/GHSA-9chj-cp8j-3c5f), [GHSA-mx9v-6x7q-rjc2](https://github.com/advisories/GHSA-mx9v-6x7q-rjc2), [GHSA-v6mf-3jqv-cgr7](https://github.com/advisories/GHSA-v6mf-3jqv-cgr7), [GHSA-wc6m-wggm-hjr8](https://github.com/advisories/GHSA-wc6m-wggm-hjr8), [GHSA-3x8f-6ffv-v2wc](https://github.com/advisories/GHSA-3x8f-6ffv-v2wc), and [GHSA-759r-h698-g7xj](https://github.com/advisories/GHSA-759r-h698-g7xj).

These advisories preserve five durable assessment questions:

1. Does an HTTP client preserve cookie, fragment, and proxy-credential authority across redirects and reused client state?
2. Does an identity framework authenticate callback origins and session side effects before redirecting or deleting state?
3. Does router or tenant-object authorization survive rewriting, normalization, and multi-object input?
4. Can pull-request-controlled metadata reach a privileged CI shell?
5. Does a remote-desktop client confine shared files and authenticate the server/proxy destination after redirection?

!!! warning "Authorized validation only"
    Use owned hosts, fake credentials, disposable users/tenants, inert CI markers, synthetic certificate authorities, and temporary shared directories. Never collect real cookies, proxy credentials, billing or tenant data, CI secrets, RDP files, or certificate material. Do not run these checks against production CI runners, remote desktops, proxies, or protected routes without explicit written approval.

## Confirmed boundaries

| Advisory | Component | Confirmed boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-mjrx-74jh-7xgw](https://github.com/advisories/GHSA-mjrx-74jh-7xgw) / CVE-2026-67355 | `guzzlehttp/guzzle` before 7.15.1 | host-only cookies are stored as domain cookies, so a reused jar can send a parent-host cookie to a child host | Test integration workers that reuse one jar across sibling hosts or tenant-controlled subdomains. |
| [GHSA-mqq9-gxg5-m58g](https://github.com/advisories/GHSA-mqq9-gxg5-m58g) / CVE-2026-67354 | Guzzle before 7.15.1 with `allow_redirects.referer` enabled | a same-scheme redirect can copy the source URI fragment into the generated `Referer` header | Prove fragment-to-header disclosure with a fake marker and an owned redirect destination. |
| [GHSA-32rq-jhr7-m3hh](https://github.com/advisories/GHSA-32rq-jhr7-m3hh) / CVE-2026-67339 | Guzzle before 7.14.2 using cURL handlers | `Proxy-Authorization` can reach an origin after redirect, bypass, or SOCKS proxy classification drift | Test proxy-vs-origin header isolation with a fake proxy credential and local recorders. |
| [GHSA-g2jv-pgqw-qxhv](https://github.com/advisories/GHSA-g2jv-pgqw-qxhv) / CVE-2025-71403 | Better Auth before 1.1.20 | absolute/wildcard callback origin checks can approve an attacker-controlled destination | Add DNS-label, scheme, port, and absolute-URL controls to callback matrices. |
| [GHSA-rf63-989x-x4x8](https://github.com/advisories/GHSA-rf63-989x-x4x8) / CVE-2025-71402 | Better Auth multi-session plugin after 1.3.34 and before 1.4.0 | the sign-out hook consumes unsigned raw multi-session cookie values before deleting sessions | Test whether a forged cookie can select another synthetic session for deletion without first validating its signature. |
| [GHSA-7qf5-7ppr-87v8](https://github.com/advisories/GHSA-7qf5-7ppr-87v8) / CVE-2026-67309 | Traefik 3.7.0-3.7.7 Kubernetes Ingress NGINX provider | regex capture plus `rewrite-target` can create a traversal path that the backend normalizes into a separately protected route | Compare router match, rewritten path, backend-normalized path, and auth decision. |
| [GHSA-4f8w-fmh5-hcxr](https://github.com/advisories/GHSA-4f8w-fmh5-hcxr) / CVE-2026-67310 | OpenRemote through 1.26.2 `setAssetLinks` | only one realm from a caller-supplied `HashSet` is checked, so mixed-realm links can pass non-deterministically | Use two synthetic realms and repeated no-op link attempts to expose order-dependent authorization. |
| [GHSA-9chj-cp8j-3c5f](https://github.com/advisories/GHSA-9chj-cp8j-3c5f) / CVE-2026-67308 | Wazuh workflows before commit `44bf114` | pull-request-controlled `VERSION.json` values are interpolated into shell steps | Validate repository metadata-to-shell data flow with an argv recorder or inert marker on a no-secret runner. |
| [GHSA-mx9v-6x7q-rjc2](https://github.com/advisories/GHSA-mx9v-6x7q-rjc2) / CVE-2026-67295 | FreeRDP before 3.29.0 drive redirection | prefix-based path validation permits access to sibling directories outside the shared root | Prove confinement with sibling canaries in a disposable client filesystem. |
| [GHSA-v6mf-3jqv-cgr7](https://github.com/advisories/GHSA-v6mf-3jqv-cgr7) / CVE-2026-67294 | FreeRDP before 3.29.0 TLS verification | failed server-purpose EKU validation falls back to client/any-purpose acceptance | Test a trusted, hostname-matching client-only certificate as a negative server-auth control. |
| [GHSA-wc6m-wggm-hjr8](https://github.com/advisories/GHSA-wc6m-wggm-hjr8) / CVE-2026-67293 | FreeRDP before 3.29.0 wildcard matching | `*.example.test` can match multiple labels such as `a.b.example.test` | Compare FreeRDP and a standards-based hostname verifier against the same synthetic chain. |
| [GHSA-3x8f-6ffv-v2wc](https://github.com/advisories/GHSA-3x8f-6ffv-v2wc) / CVE-2026-67289 | FreeRDP before 3.29.0 redirection through an HTTP proxy | server-controlled `TargetNetAddress` reaches the proxy `CONNECT` request without control-character rejection | Record raw proxy bytes with a harmless injected header marker in an isolated harness. |
| [GHSA-759r-h698-g7xj](https://github.com/advisories/GHSA-759r-h698-g7xj) / CVE-2026-66402 | FreeRDP before 3.29.0 certificate identity checks | embedded NUL, CN-over-SAN precedence, and IP-literal handling can disagree with length-aware identity verification | Build a certificate decision table; never use misissued real certificates. |

## HTTP client state and redirect harness

Run the application integration path where possible; a package-only reproduction does not prove reachability.

1. Create two owned HTTPS origins under sibling names, an owned redirector, and a local fake HTTP/SOCKS proxy. Use one reusable Guzzle cookie jar.
2. Seed only a fake host-only cookie from the parent host. Request the child host through the same application flow and record whether the cookie is sent.
3. Send a source URL containing a fragment marker through a same-scheme redirect with `allow_redirects.referer` first disabled, then enabled. Record only the destination's `Referer` header.
4. Configure a fake `Proxy-Authorization` value. Exercise direct, HTTP-proxy, SOCKS-proxy, `NO_PROXY`, and redirect transitions while recording header presence independently at proxy and origin.
5. Repeat on Guzzle 7.15.1 for cookie/fragment cases and 7.14.2 for proxy isolation. Include a fresh-jar control and cross-scheme redirect control.

Report the smallest proven transition: **host-only cookie -> reused jar -> sibling host**, **URI fragment -> generated Referer -> redirect origin**, or **proxy credential -> handler classification drift -> origin header**. Never seed a real session or proxy secret.

## Better Auth callback and sign-out matrices

### Callback origin parsing

Use one disposable Better Auth deployment and owned callback hosts. Vary one property at a time:

- exact trusted origin;
- sibling or suffix hostname without a DNS-label boundary;
- wildcard single-label and multi-label hosts;
- scheme and port changes;
- absolute URL, network-path, userinfo, and backslash-normalized forms;
- patched version and an explicit deny control.

Capture the raw callback value, validator's parsed origin, emitted `Location`, and final browser destination. Stop at an owned landing-page marker. Do not collect tokens or involve another user.

### Signed-cookie-before-side-effect check

1. Create two disposable sessions for the same lab user and record redacted session identifiers.
2. Submit a correctly signed multi-session cookie to establish the expected sign-out behavior.
3. Change only the selected session token while leaving the cookie signature invalid. Invoke the sign-out route and record which synthetic sessions remain.
4. Repeat with a malformed cookie, an unknown token, a different test user, and Better Auth 1.4.0.

Positive evidence is **invalid cookie signature -> attacker-selected synthetic token reaches deletion -> unrelated test session is removed**. Do not race or delete production sessions.

## Router and tenant-object authorization checks

### Traefik rewrite-to-protected-route differential

Build a lab with one public router and one auth-protected router that terminate at a backend exposing only harmless marker routes.

1. Configure the affected Kubernetes Ingress NGINX provider with a public regex path such as `/api(.*)` and rewrite target `/$1`.
2. Record four values for each request: raw path, matched router, rewritten path, and the path after backend normalization.
3. Compare an ordinary public marker, a literal protected route, encoded and unencoded dot segments, a capture that requires a slash, and Traefik 3.7.8.
4. A positive result is a request matched as public that the backend resolves to the protected marker without the protected router's auth middleware.

Do not point the fixture at a production admin route or use another user's session. Report **public regex capture -> traversal-bearing rewrite -> backend normalization -> protected canary reached without expected middleware**.

### OpenRemote mixed-realm object binding

1. Create realms A and B, an authenticated user authorized only for A, one disposable alarm in A, and one marker asset in each realm.
2. Submit `setAssetLinks` requests containing only A, only B, then both A and B in varied insertion orders.
3. Repeat the mixed request enough times to determine whether `HashSet` iteration changes the authorization result. Reset links after each accepted attempt.
4. Read back only the test alarm and synthetic asset names; do not enumerate real realm assets.
5. Repeat on OpenRemote 1.27.0.

Evidence should be a realm/object matrix showing **one checked realm -> mixed-realm collection accepted -> foreign synthetic link or name becomes visible**. Preserve iteration order and attempt count; do not overstate one intermittent response as deterministic bypass.

## Pull-request metadata to CI shell

Use a fork or local clone of the affected workflow on a disposable runner with no secrets and no cloud permissions.

1. Map every `VERSION.json` field into workflow expressions, environment variables, generated scripts, and shell `run` steps.
2. Replace the real shell command with an argv recorder where feasible. Otherwise, use a metacharacter canary whose only effect is creating one marker beneath the runner's temporary directory.
3. Compare an ordinary version, shell metacharacters, newline/control characters, an untrusted pull-request event, and the fixed workflow.
4. Record event type, trust boundary, workflow permissions, interpolation stage, final argv/script, marker result, and whether the runner had any secrets mounted.

The report should prove **pull-request-controlled version metadata -> unquoted/interpreted shell context -> inert runner marker**. Never run the proof on a secret-bearing or self-hosted production runner, and never attempt token or credential exfiltration.

## FreeRDP filesystem, certificate, and proxy-redirection harness

Use a malicious-server simulation only in an isolated RDP lab. The client must have no real home-directory share, credentials, clipboard data, or production proxy configuration.

### Shared-drive confinement

1. Create `/tmp/rdp-lab/share/inside.txt` and `/tmp/rdp-lab/share-sibling/outside.txt` with different non-sensitive markers.
2. Share only `share` with the disposable FreeRDP client.
3. Instrument or patch the filesystem sink so initial testing records requested and resolved paths without performing writes or deletes.
4. Send ordinary in-root paths, `..` traversal, absolute paths, and prefix-sibling forms from the lab server.
5. If a read proof is required, return only `outside.txt`; do not test write/delete until the customer explicitly approves a disposable fixture.
6. Compare FreeRDP 3.29.0.

Report **server RDPDR path -> lexical/prefix confinement -> resolved sibling canary outside shared root**.

### TLS identity decision table

Generate a private throwaway CA and leaf certificates covering:

- correct hostname plus `serverAuth` EKU;
- correct hostname plus `clientAuth` only;
- single-label wildcard used for one and multiple labels;
- non-matching SAN plus matching CN;
- IP target with DNS SAN versus `iPAddress` SAN;
- a synthetic embedded-NUL SAN, only if the certificate toolchain and isolated harness permit it.

For each chain, record FreeRDP's decision, a reference `X509_check_host`/equivalent decision, target hostname/IP, SAN/CN, EKU, and patched behavior. A trusted synthetic CA is a test precondition, not evidence that public PKI normally issues these certificates.

### Redirected proxy request bytes

1. Place a local recording HTTP proxy between the disposable client and lab RDP server.
2. Have the server issue a redirection whose `TargetNetAddress` contains only a harmless control-character/header marker.
3. Capture the exact `CONNECT` request bytes and confirm whether the marker becomes a separate header or request component.
4. Compare ordinary redirection, direct connection without a proxy, rejected controls, and FreeRDP 3.29.0.

Report **server-controlled RDP redirection -> unvalidated target address -> proxy request-line/header boundary changes**. Do not target shared proxies, smuggle a second operational request, or use credential-bearing proxy sessions.

## August 2 FreeRDP server-to-client media and clipboard follow-up

Two additional FreeRDP advisories turn server-controlled channel metadata into client memory-safety fixtures:

| Advisory | Affected boundary | Safe validation target |
| --- | --- | --- |
| [GHSA-mj63-24h6-p8wq](https://github.com/advisories/GHSA-mj63-24h6-p8wq) / CVE-2026-68580 | before `3.29.0`, audio-input `FramesPerPacket` arithmetic can wrap allocation sizing across ALSA, sndio, WinMM, and OpenSL ES backends | sanitizer finding or rejected-frame decision from a synthetic audio packet; never weaponized heap data |
| [GHSA-m4j8-6wj9-56fg](https://github.com/advisories/GHSA-m4j8-6wj9-56fg) / CVE-2026-68579 | through `3.29.0`, Windows clipboard file-content responses can copy the server-supplied length into an OLE consumer buffer sized by the caller | recorder showing response length exceeds requested `cb`, or a sanitizer abort in an isolated Windows VM |

### Sanitizer-first channel harness

1. Build the affected FreeRDP revision with AddressSanitizer and integer/undefined-behavior checks where the platform supports them. Run it in a disposable VM with no shared clipboard contents, drives, credentials, or host integration.
2. Use a lab RDP server that records channel state and emits only deterministic synthetic frames. For audio input, vary `FramesPerPacket` around ordinary values and arithmetic boundaries while keeping sample data inert and minimal.
3. Capture negotiated format, frame count, bytes-per-frame, computed allocation size, backend, rejection decision, and sanitizer output. Stop after the first reproducible sanitizer finding; do not tune layout or pursue code execution.
4. For clipboard testing, offer one synthetic file marker. Instrument `CliprdrStream_Read` or the file-content response handler to record caller `cb`, requested range, server response length, and proposed copy length before copying.
5. If dynamic proof is required, use an isolated Windows VM and a throwaway OLE consumer under a memory debugger. Trigger only a paste of the synthetic marker and stop at the first controlled exception or sanitizer report.
6. Compare audio handling on `3.29.0` and clipboard handling on `3.30.0`. Preserve backend/platform distinctions: the advisory describes heap overflow on ALSA and availability effects on other audio backends, while the clipboard issue is Windows-client specific.

Report **server audio metadata -> unchecked size arithmetic -> undersized allocation/sanitizer finding** or **OLE caller buffer length -> oversized server clipboard response -> proposed copy exceeds `cb`**. A malformed channel packet, disconnect, or generic crash is not enough without the size relationship and affected call path.

## Evidence and reporting checklist

- [ ] Is the application feature or deployment configuration that reaches the affected component proven?
- [ ] Are all hosts, users, tenants, cookies, sessions, proxy credentials, runners, files, and certificates synthetic?
- [ ] Does the evidence separate policy input, parsed/canonical form, selected authority/object/path, and final side effect?
- [ ] Is there a patched-version or policy-negative control for every claimed boundary?
- [ ] Are intermittent collection-order results reported with attempt counts rather than certainty?
- [ ] Are duplicate advisory aliases already represented by existing GitPython, Axios, ArcadeDB, Budibase, and Better Auth workflows excluded from inflated claims?
- [ ] Does the report stop at a marker rather than collecting secrets, user data, host files, or production route content?

Lead with the narrow boundary that failed. A dependency match, malformed certificate, redirected request, or accepted object collection is not enough unless the real application or lab topology demonstrates a policy-relevant decision difference.