---
title: Directory, cluster, agent-fetch, and signed-document boundaries from July 27 GHSA updates
---

# Directory, cluster, agent-fetch, and signed-document boundaries from July 27 GHSA updates

A July 27 GitHub advisory wave yields four durable operator workflows: directory objects crossing into host authorization, Kubernetes subresource permissions authorizing cross-namespace storage clones, an auto-approved agent fetcher validating only URL text instead of the connected destination, and signed-document metadata crossing into native URI handlers or an XXE-capable preview parser. An adjacent Apache Thrift group adds a reusable TLS hostname-verification matrix across language bindings.

Sources:

- [GHSA-2vq9-j58h-2qj3 / CVE-2026-14474: SSSD LDAP sudo search-base scope](https://github.com/advisories/GHSA-2vq9-j58h-2qj3)
- [Red Hat CVE-2026-14474 record](https://access.redhat.com/security/cve/CVE-2026-14474)
- [GHSA-v6qh-pm8g-3c5w / CVE-2026-14476: SSSD AD GPO path traversal](https://github.com/advisories/GHSA-v6qh-pm8g-3c5w)
- [Red Hat CVE-2026-14476 record](https://access.redhat.com/security/cve/CVE-2026-14476)
- [GHSA-2cmm-29f6-xcpx / CVE-2026-17527: CDI view-role PVC clone authorization](https://github.com/advisories/GHSA-2cmm-29f6-xcpx)
- [Red Hat CVE-2026-17527 record](https://access.redhat.com/security/cve/CVE-2026-17527)
- [GHSA-28vq-345c-25gg / CVE-2026-17534: Kimi Code FetchURL SSRF](https://github.com/advisories/GHSA-28vq-345c-25gg)
- [Kimi Code fix and regression fixtures](https://github.com/MoonshotAI/kimi-code/commit/31449728b72df94e22bcb2de350a1e7624895e30)
- [Kimi Code 0.27.0 release](https://github.com/MoonshotAI/kimi-code/releases/tag/%40moonshot-ai%2Fkimi-code%400.27.0)
- [GHSA-434r-7c99-hwf3 / CVE-2026-49138: Nanobot `web_fetch` redirect SSRF](https://github.com/advisories/GHSA-434r-7c99-hwf3)
- [Nanobot per-hop redirect validation fix and regression fixtures](https://github.com/HKUDS/nanobot/commit/545294c62c0947da40eb5b65288aaf02b5fdf632)
- [Nanobot 0.2.1 release](https://github.com/HKUDS/nanobot/releases/tag/v0.2.1)
- [GHSA-g4fw-p4hw-gq39 / CVE-2026-19246: Nanobot provider-returned image URL SSRF](https://github.com/advisories/GHSA-g4fw-p4hw-gq39)
- [Nanobot merged image-downloader fix #5095](https://github.com/HKUDS/nanobot/pull/5095)
- [GHSA-m7cq-h27p-hwp4 / CVE-2026-57916: proCertum SmartSign CPS URI handling](https://github.com/advisories/GHSA-m7cq-h27p-hwp4)
- [GHSA-fqfw-hf3f-2q4c / CVE-2026-57917: proCertum SmartSign preview-time XXE](https://github.com/advisories/GHSA-fqfw-hf3f-2q4c)
- [CERT Polska coordinated disclosure for both SmartSign issues](https://cert.pl/posts/2026/07/CVE-2026-57916)
- [GHSA-p2c7-c4gw-678h / CVE-2026-48145: Apache Thrift C++ hostname verification](https://github.com/advisories/GHSA-p2c7-c4gw-678h)
- [GHSA-367h-9jj5-w29f / CVE-2026-48144: Apache Thrift C/GLib hostname verification](https://github.com/advisories/GHSA-367h-9jj5-w29f)
- [GHSA-hwrj-9rr4-24xh / CVE-2026-66053: Apache Thrift Python hostname verification](https://github.com/advisories/GHSA-hwrj-9rr4-24xh)
- [Apache Thrift 0.24.0 security announcement index](https://lists.apache.org/thread/7v3jhgwfbmhx42424phydlnzb109g8b9)

The GitHub records are unreviewed. Confirm the affected product, binding, version, configuration, and fixed-build behavior from the linked primary source before reporting. The SSSD and CDI records describe meaningful privileges that the test principal must already hold; do not erase those preconditions from the finding.

!!! warning "Authorized validation only"
    Use disposable directory trees, synthetic GPOs, lab hosts, temporary Kubernetes namespaces and PVCs, owned callback services, a local canary HTTP service, generated test certificates, inert executables, and synthetic signature files. Never alter production sudo policy, write host authentication configuration, clone customer volumes, query metadata or internal production services, open live documents, read local secrets, or intercept real TLS credentials.

## Build a boundary matrix first

| Surface | Attacker-controlled representation | Authority or policy that should bind it | Safe proof |
| --- | --- | --- | --- |
| SSSD LDAP sudo | `sudoRole` object location and attributes | explicitly scoped sudo search base plus directory ACLs | command-free rule matching a synthetic user/host |
| SSSD AD GPO | `gPCFileSysPath` components | normalized path confined to the GPO cache | marker-only write into a disposable sibling directory |
| CDI clone | source namespace/PVC and `datavolumes/source` create | explicit source-data permission, not destination-only write | one text-marker PVC cloned between lab namespaces |
| Agent FetchURL | URL, DNS answers, redirects, prompt-derived tool args | resolved destination checked and pinned at every hop | owned redirector or split-answer DNS to a local canary |
| SmartSign CPS | certificate CPS URI | allowed scheme and explicit user-mediated destination | inert local marker handler or owned HTTPS page |
| SmartSign preview | signature-file XML entities | external entities disabled before preview parsing | owned callback only; no local-file entity |
| Thrift TLS | requested host, certificate names, binding options | chain trust **and** endpoint identity | local CA with valid-chain/wrong-host certificate |

For every row, capture the affected build, fixed build, configuration, principal, submitted representation, normalized representation, policy decision, and marker result. Stop after the first harmless boundary crossing.

## SSSD: directory scope is part of host authorization

### LDAP sudo provider search-base drift

The CVE-2026-14474 record says that when `ldap_sudo_search_base` is not explicitly configured, SSSD can search the whole LDAP tree for `sudoRole` objects. A directory principal with write access to an otherwise unrelated subtree may therefore introduce a role that influences enrolled hosts.

1. Build a disposable LDAP directory with a designated sudo-policy subtree and a separate application subtree writable by a synthetic low-privilege principal.
2. Enroll one lab host through SSSD and create a synthetic user that has no sudo grant in the designated subtree.
3. Test both configurations: an explicit `ldap_sudo_search_base` and the affected implicit/default state.
4. In the writable application subtree, create a `sudoRole` that matches only the synthetic host and user and permits a harmless identity command or an instrumented no-op wrapper.
5. Refresh SSSD policy in the lab and use policy-listing or dry-run instrumentation before executing anything.
6. Record the LDAP DN returned by the provider, the configured search base, and whether the out-of-scope role entered the host's effective sudo policy.
7. Repeat on the fixed package with identical directory ACLs.

A positive result is **write access to a non-policy LDAP subtree -> out-of-scope `sudoRole` discovered by the provider -> synthetic host authorization changes**. The prerequisite is authenticated directory write access to some searched subtree; this is not anonymous LDAP injection.

### AD GPO path confinement

CVE-2026-14476 describes `..` components in the GPO `gPCFileSysPath` crossing from directory metadata into root-owned cache writes. The record notes that an authentication-impact chain may exist on default RHEL/SELinux configurations, but a safe proof should stop at path escape.

1. Use a disposable AD domain, one lab client, and a synthetic principal delegated to manage only a test GPO.
2. Place unique marker directories inside the intended GPO cache and in a temporary sibling path owned by the lab.
3. Set a test `gPCFileSysPath` containing a traversal form that resolves only to the sibling marker directory; do not target `/etc`, Kerberos files, PAM files, SSH configuration, or startup paths.
4. Trigger one GPO refresh and trace the final resolved destination with filesystem auditing.
5. Verify only that a benign marker crossed the cache root, then remove the synthetic GPO and marker.
6. Repeat with encoded/mixed separators only if the affected platform parser supports them, and keep all destinations under the disposable parent.
7. Confirm that the fixed build rejects or confines the same path.

Report **directory attribute -> parser normalization -> root-owned resolved path -> marker write**. Do not claim authentication bypass unless that separate configuration-dependent edge is reproduced in a throwaway host; never demonstrate it against a real login stack.

## September 21 follow-up: ADSys AD CS CA fetch over plaintext HTTP poisons the system trust store

[GHSA-crm4-q7v4-c2r2 / CVE-2026-12249](https://github.com/advisories/GHSA-crm4-q7v4-c2r2) — Canonical ADSys through v0.16.2 performs Active Directory Certificate Services (AD CS) certificate auto-enrollment through the vendored Samba client script (`internal/policies/certificate/python/vendor_samba/gp/gp_cert_auto_enroll_ext.py`), which requests the CA certificate from the configured CA hostname via `GetCACert` over **plaintext `http://`** instead of `https://`. An **unauthenticated network-position attacker** between the managed Ubuntu host and the CA hostname intercepts that fetch and returns an arbitrary attacker-controlled root CA, which ADSys **accepts unconditionally and installs into the local trust store via `update-ca-certificates`**. Result: every OS-trust-store TLS client on the host accepts rogue certificates for arbitrary domains — persistent, host-wide TLS interception from one network position. Fixed in v0.16.3.

Why this is the same page as the SSSD rows: it is another **directory-adjacent enrollment artifact crossing into host authorization state** — here the artifact is CA material fetched during group-policy processing, and the "authorization" it changes is the host's TLS trust anchor set. The preconditions are weaker than the SSSD sudo/GPO rows (network position, no credentials), which makes it the strongest pivot in this cluster on hybrid AD + Ubuntu fleets.

### Operator axes

1. **Enrollment daemons fetch trust material over unauthenticated channels.** Any agent that runs during join/GPO processing to download CA certs, CRLs, or policy blobs is a trust-anchor injection target if the scheme is `http://` and the response is installed without pinning. Grep deployed agent source (Python, Samba vendor trees, shell hooks) for `http://` + `GetCACert`/`caCert`/`update-ca-certificates`/`update-ca-trust`.
2. **GPO/sysvol configuration carries the fetch target.** The CA hostname arrives via group policy; in an authorized lab where you control a GPO or DNS answer for the CA hostname, you control where the plaintext fetch goes. Test only on lab hosts you own.
3. **Trust-store poisoning is persistence, not just interception.** The injected root survives reboots and outlives the network position; detection is a trust-store diff, so the operator-relevant validation is: enumerate installed anchors (`/usr/local/share/ca-certificates`, `update-ca-certificates` output), timestamp drift, and which anchor was *not* issued by the enterprise CA.
4. **Fingerprint-then-pivot recon on internal Linux fleets:** unpatched ADSys (< 0.16.3) on AD-joined Ubuntu hosts means a single on-path position (ARP/NDP, switched-port attack, rogue AP, compromised neighbor) yields interception of *all* subsequent TLS from that host — backup sessions, package pulls, web apps, LDAP-over-TLS, anything using the OS store.

### Bounded validation (owned lab only)

| Step | Input | Record | Stop condition |
| --- | --- | --- | --- |
| Fingerprint | ADSys version on lab host (`dpkg -l adsys`) + CA fetch scheme in policy | version, scheme (`http` vs `https`), CA hostname source | plaintext scheme + < 0.16.3 = precondition positive |
| MITM proof | Disposable AD domain, lab Ubuntu host, owned fake CA hostname (lab DNS); attacker listener on the host's network segment | whether `GetCACert` request is visible, whether lab-generated test root lands in `/usr/local/share/ca-certificates` / `update-ca-certificates --fresh` output | test root present in store = boundary crossing proven |
| Impact bound | One `curl` from the lab host to an owned HTTPS canary through the fake root | chain accepted with fake CA | **stop there** — never intercept real user traffic, real enterprise CAs, or production sessions |

Prove with a **self-generated lab root CA and a synthetic canary service only**. Never poison a real host's trust store, never present a forged certificate for a live domain, and redact CA hostnames and policy paths from reports. Report shape: **network position (no credentials) -> plaintext CA fetch -> unvalidated root installed -> OS-trust TLS clients accept lab-issued anchor for synthetic domain**, with the fixed-build (0.16.3) negative control showing HTTPS scheme or rejected install.

## CDI: do not treat subresource creation as source-data read authority

CVE-2026-17527 says the aggregated `cdi.kubevirt.io:view` role grants `create` on `datavolumes/source`, and CDI clone authorization accepts that permission as sufficient to clone a named PVC. A principal also needs ordinary write access to a destination namespace. The reusable bug class is a control-plane subresource permission standing in for authorization to the source data.

### Two-namespace clone matrix

1. Deploy the affected CDI build in a disposable cluster with namespaces `source-a` and `dest-b`.
2. Put a unique, non-sensitive text marker in one small PVC in `source-a`.
3. Bind a synthetic service account to the affected view role and grant it edit rights only in `dest-b`; verify it cannot directly `get`, mount, or read the source PVC through ordinary APIs.
4. Record `kubectl auth can-i` results for the source PVC, the clone/source subresource, and destination DataVolume creation.
5. Request one DataVolume clone from the named marker PVC into `dest-b`.
6. If the request succeeds, mount the destination only in `dest-b`, read the single marker, and delete both destination workload and cloned volume.
7. Add controls for a random source name, a principal without destination write, a principal without the aggregated view role, and the fixed CDI build.

The decisive evidence is **no direct source-data permission + view-role subresource permission + destination write -> successful clone of the synthetic marker**. Do not enumerate PVC names, clone Secrets-backed application volumes, or retain volume snapshots.

## Kimi Code: validate and pin the destination of every fetch hop

The pre-0.27.0 `FetchURL` guard reportedly checked static hostname/IP-literal rules but did not resolve hostnames or revalidate redirects. The tool is in the default auto-approve set, making prompt-influenced fetch arguments especially important. The linked fix resolves all addresses, rejects private/loopback/link-local/CGNAT/ULA and mapped forms, follows redirects manually with per-hop checks, caps hops, and pins connections to the validated DNS answer to close the check/connect rebinding window.

### Owned-destination decision table

Use only a local lab with:

- an owned public-looking test hostname;
- an owned redirector;
- a synthetic local HTTP canary that returns a random marker and no environmental data;
- controlled DNS or a mocked resolver/connect layer.

Test these rows independently:

| Case | Validation answer | Connect/final destination | Expected fixed behavior |
| --- | --- | --- | --- |
| direct private literal | n/a | local canary | reject before request |
| hostname resolves local | local canary address | local canary | reject after resolution |
| public first hop redirects local | public | local canary | reject redirect target |
| split answer | public during check | local during connect | use pinned public answer or fail |
| mixed answers | public + local | any | reject if any answer is disallowed |
| resolution failure | error | none | fail closed |

1. Start with a direct fetch initiated by the operator, then repeat through a benign prompt that asks the agent to retrieve the owned URL.
2. Record whether approval is requested, the exact tool arguments, each redirect `Location`, resolver answers, the actual peer address, and whether the canary marker returns.
3. Keep responses tiny and cap redirect depth; do not test cloud metadata addresses or arbitrary RFC1918 services.
4. Compare the affected build with 0.27.0 using the same mocked resolver and canary fixtures.

A positive result is **allowed URL text -> unchecked resolution/redirect or check-connect answer change -> FetchURL reaches the synthetic local canary without approval**. Separate SSRF reachability from response disclosure: seeing a callback proves a request, while the marker in agent output proves readback.

### July 27 follow-up: Nanobot image preflight redirect validation

GHSA-434r-7c99-hwf3 describes a parallel redirect-boundary failure in `nanobot-ai` before `0.2.1`. The linked fix is narrower than the Kimi Code change: Nanobot's image-detection preflight used an HTTP client path that could follow a `3xx Location` after validating only the initial URL. Version `0.2.1` adds a streamed, manual redirect loop with `follow_redirects=False`, validates each resolved `Location` before the next request, and closes every intermediate stream.

Reuse the owned redirector and synthetic local canary above, but keep the media branch explicit:

1. Serve an allowed first-hop URL that redirects to the local canary and vary the final response among `text/html`, `image/png`, and a missing `Content-Type`.
2. Record the initial validation, image-preflight request, redirect status and raw `Location`, resolved next URL, whether readability/Jina fallback runs, actual peer, and whether any response body is read.
3. Add relative, scheme-relative, multi-hop, missing-`Location`, and redirect-limit controls; every hop must remain owned and every response tiny.
4. Compare the affected package with `0.2.1`. The fixed build should stop before dialing the synthetic local destination for every content-type branch.
5. Separately exercise any later readability or external-reader fetch path that the deployment enables. A safe image preflight does not prove that another fetch backend applies the same policy.

The positive edge is **validated public-looking URL -> automatic image-preflight redirect -> synthetic local canary receives the request**. A callback proves reachability; returning the canary nonce in tool output proves readback. Do not query metadata endpoints, arbitrary private services, or production agent sessions.

### August 7 follow-up: provider-returned image URLs are a separate fetch authority

GHSA-g4fw-p4hw-gq39 describes Nanobot's image-generation path accepting a URL returned by the configured model/provider and downloading it outside the hardened user-supplied fetch path. This matters even when users cannot type a URL directly: provider output, a compatible API, or a compromised upstream can still select the downloader's destination. Merged pull request #5095 routes direct downloads through the shared DNS-pinning transport, checks each redirect, ignores ambient process proxy variables, caps streamed bodies at 32 MiB, and validates image bytes. An explicitly configured provider proxy remains a distinct trusted egress boundary and owns final DNS resolution.

Extend the existing two-peer fixture:

1. Mock the image provider so its response contains one owned public URL; do not send a prompt to a live provider.
2. Vary direct allowed URL, hostname resolving to the local canary, allowed-to-local redirect, mixed DNS answers, oversized body, non-image bytes, and process-wide proxy environment variables.
3. Run a second matrix with an explicitly configured test proxy and capture initial URL policy, redirect checks, proxy selection, final peer, byte count, and image validation.
4. Compare user-supplied `web_fetch`, image preflight, and provider-returned image download traces. Passing one route is not evidence that its siblings share policy.

A bounded positive is **mock provider response -> unchecked returned URL -> downloader selects the owned denied peer**. Treat an explicitly configured proxy as an operator-selected trust boundary and report that precondition; never target metadata or private services, and never return downloaded bytes to a live model.

## SmartSign: signed metadata is still untrusted input

CERT Polska reports two issues in proCertum SmartSign versions below 9.4.3.90:

- a certificate's CPS URI may launch a local executable or arbitrary URL when the signed document is opened;
- external XML entities in signature files may resolve during file-picker preview, before the user clicks **Open**.

These are separate parser/handler edges and should not be combined without reproducing both.

### CPS URI handler proof

1. Use an isolated desktop VM with SmartSign below 9.4.3.90 and no production certificates or documents.
2. Generate a disposable test certificate whose CPS URI points first to an owned HTTPS marker page.
3. Sign a harmless text document and open it while tracing process and URL-handler activity.
4. For the local-handler control, register or select only an inert test executable that writes a marker inside the VM; do not reference system binaries or pass arguments.
5. Record whether the URI is displayed, requires confirmation, opens automatically, and which process launches it.
6. Repeat with unsupported schemes, an empty URI, and version 9.4.3.90.

The proof is **attacker-authored certificate metadata -> document-open workflow -> unvalidated URI dispatched to an OS handler**. An owned web page proves arbitrary navigation; a disposable no-argument marker handler proves local execution without shell payloads.

### Preview-time XXE proof

1. Run an owned HTTP callback listener with a unique path and no sensitive query data.
2. Create a synthetic signature file whose external entity references that listener and whose expanded value is an inert marker.
3. Navigate to the containing directory in SmartSign's file picker without clicking **Open**.
4. Record whether the callback occurs at directory listing, selection, preview, or explicit open.
5. Add controls with external entities disabled, a plain signature, a nonexistent entity, and version 9.4.3.90.
6. Do not use `file:` entities, UNC paths, metadata destinations, internal hostnames, or recursive/entity-expansion payloads.

A positive result is **merely rendering the attacker-supplied signature preview -> parser resolves the owned external entity**. This proves preview-time XXE/SSRF reachability without reading a local file.

## Apache Thrift: separate CA trust from hostname identity

The C++, C/GLib, and Python binding records say versions before 0.24.0 can accept a validly signed certificate for the wrong host. Package presence is not enough: identify a client path that enables TLS, supplies a server name, and reaches the affected binding's verification code.

1. Create a local CA and two server certificates: one valid for the requested canary hostname and one valid for a different owned hostname.
2. Run a mock Thrift service with no application data and trust only the local CA in the client fixture.
3. Test trusted/right-host, trusted/wrong-host, untrusted/right-host, expired/right-host, and no-SAN controls in each actually used binding.
4. Capture the requested hostname, SNI, certificate SAN/CN, chain result, hostname result, and whether any marker RPC is sent.
5. Repeat on 0.24.0 or the vendor's fixed package.

The vulnerable result is **trusted chain + hostname mismatch -> TLS session accepted and marker RPC reaches the mock service**. Do not use real service certificates, credentials, or transparent interception. Report the exact binding and TLS constructor/options because secure behavior may differ across language implementations.

## Reporting checklist

Include:

- exact package, version, platform, feature path, configuration, and prerequisite principal;
- directory DN/search base, normalized filesystem destination, Kubernetes RBAC decision, resolved/connected peer, parser stage, or TLS identity tuple as applicable;
- affected and fixed-build decision tables with negative controls;
- marker-only evidence and cleanup steps;
- redaction of directory credentials, kubeconfigs, tokens, certificates' private keys, document contents, and raw agent transcripts;
- a bounded impact statement that distinguishes policy injection, path escape, source-volume authorization, SSRF callback/readback, URI dispatch, XXE resolution, and hostname-verification failure.

Do not inflate prerequisites. Directory subtree write is not directory-admin access; destination-namespace edit plus a view role is not cluster-admin; an SSRF callback is not secret theft; a preview callback is not local-file disclosure; and a valid-chain/wrong-host TLS acceptance is not proof that a production credential was intercepted.