# Workflow-platform internal deputies and presigned-URL operation confusion

Source: hourly offensive-security scan, 2026-09-21 (12:32Z GitHub advisory wave). Primary entries: [CVE-2026-87858 / GHSA-vrgw-vghm-5p74](https://github.com/advisories/GHSA-vrgw-vghm-5p74) (Temporal Server, high), [CVE-2026-89139 / GHSA-w8cx-4cf2-9hvr](https://github.com/advisories/GHSA-w8cx-4cf2-9hvr) (Temporal Server, high), and [CVE-2026-94368 / GHSA-5p5f-qvx9-whpj](https://github.com/advisories/GHSA-5p5f-qvx9-whpj) (NooBaa, CVSS 7.1).

This wave is durable because all three items are the same reusable class: **a request parameter that looks like data to the caller is interpreted as trust, configuration, or intent by an internal component that the caller never touches directly**. One namespace-write role, or one valid presigned URL, becomes a server-side deputy acting with privileges the caller does not hold.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| CVE-2026-87858 / GHSA-vrgw-vghm-5p74 | Temporal Server workflow-completion callbacks | "internal vs external callback" decided by a **caller-supplied HTTP header**; a non-empty `source` header makes History re-target the request at the **internal frontend client**, rewriting only scheme+host and preserving the caller's path, query, and body | Header-named internal trust flag; SSRF where the server (not you) reaches an admin API |
| CVE-2026-89139 / GHSA-w8cx-4cf2-9hvr | Temporal Server Worker Controller Instance | a registered `subprocess` compute provider takes **program name + argv from the caller's request**, and the enable-allowlist check is **skipped when the config value is unset** (the default) | Configuration-in-request + fail-open allowlist = write-role → host RCE under the server account |
| CVE-2026-94368 / GHSA-5p5f-qvx9-whpj | noobaa-core S3 presigned URLs (SigV4) | unsigned `x-amz-` headers are **dropped from the signature calculation instead of rejected**; adding an unsigned `x-amz-copy-source` to a presigned PUT converts it into a CopyObject | Presigned URL scope ≠ granted operation; signature-scope asymmetry at header level |

## Temporal: the completion-callback internal deputy (CVE-2026-87858)

An authenticated caller with **write permission in a single namespace** attaches a completion callback to a Workflow where:

1. The callback URL **host matches the configured allowlist** (`component.callbacks.allowedAddresses`, per-namespace dynamic config).
2. The callback URL **path is any Temporal HTTP API route** — the allowlist checks host, not path.
3. The callback **header map contains a non-empty header named `source`**.

On delivery, the History service sees the `source` header, classifies the callback as *internal*, re-targets it at the local frontend client, and rewrites **only scheme and host** — your path, query, and body ride along. Where the deployment runs the internal frontend with its HTTP API enabled (`services.internal-frontend.rpc.httpPort` non-zero), that client **authorizes every request as a system administrator with no authentication**. The server then performs your chosen state-changing POST against its own admin API in namespaces you have no access to. Confirmed effects: terminating Workflows in other namespaces, registering namespaces, modifying another namespace's configuration, deleting a namespace and its Workflows. You never need network access to the internal frontend — History makes the request for you.

Version split matters for precondition work: **1.30.0+** any non-empty `source` header suffices; **1.25.0–1.29.7** requires the header to exactly match the cluster ID (a UUID a namespace-scoped caller cannot read through the API) — same consequence, materially harder attack. The routing defect is present in both the HSM and CHASM callback-delivery implementations.

Precondition probes for authorized assessments (both must hold):

```text
1. Static server config: services.internal-frontend.rpc.httpPort != 0
2. Effective per-namespace dynamic config: component.callbacks.allowedAddresses non-empty
```

Validation boundary: lab Temporal cluster only. Prove with a canary Workflow **in a second disposable namespace** that you terminate/canary-annotate via the deputy, never against shared or production clusters; capture the callback spec, delivered request (from a lab-side listener on the allowlisted host), and the admin-API action outcome.

### Reusable axes

- **A caller-supplied header that selects internal vs external handling is an auth boundary.** Sweep every header/parameter named `source`, `internal`, `system`, `origin`, or product-jargon that changes which client or credential the server uses on the next hop. Compare delivered-request shapes with and without the flag.
- **Allowlists that check host but not path make the internal service the destination and your input the command.** Once re-targeted, the entire remaining URL + body is yours — the allowlist check was for the wrong dimension.
- **The SSRF leg never leaves the product.** When the internal hop is a first-party admin client (not a raw HTTP dial), classic SSRF defenses (loopback blocks, egress policy) prove nothing — check what *authorization context* the internal client carries.
- Version-conditional exploits are normal in callback/relay code: fingerprint the exact server version first; the same payload may need a readable UUID (cluster ID) on older releases.

## Temporal: the `subprocess` compute provider is caller-configured and on by default (CVE-2026-89139)

The Worker Controller Instance module compiles into the Worker Service and registers a compute provider named **`subprocess`** whose job is to launch workers by running a command on the Worker Service host. The **program name and argv come from the compute-provider configuration in the caller's request**, not from operator configuration. Configuring a worker deployment version with `subprocess` makes the Worker Service execute your chosen command, as the server process account, **immediately** — the config handler invokes every provider using the invoke strategy directly after validating the spec, so no scaling decision, task arrival, or unusual sequence is required.

The blast radius: the Worker Service process holds **persistence credentials for every namespace in the cluster plus the cluster TLS material**. One namespace write role → code execution as the server → cluster-wide credential access.

The only guardrail is the per-namespace dynamic config `workercontroller.compute_providers.enabled`, and it **fails open**: its default is an unset list, and the allowlist check is **skipped entirely when unset**, so every registered provider (including `subprocess`) is permitted. The provider ships in official Temporal Server binaries and container images.

Affected window: **1.31.0 ≤ version < 1.31.3**, Worker Service running (it is in the default service set — stock deployments), `workercontroller.compute_providers.enabled` unset or containing `subprocess`, and a real authorizer/claim-mapper configured (a no-authorizer deployment already grants more).

Validation boundary: lab cluster only; prove with an inert marker command (`id > /tmp/…`) in a disposable namespace and record config state before/after. Never register a deployment version with `subprocess` on shared or production infrastructure.

### Reusable axes

- **Default-unset allowlist = no allowlist.** When auditing any provider/plugin/backend registry pattern, ask what happens when the enable-list is *empty* vs *explicitly empty*. Fail-open on unset is the same bug class as the Sept 18 Obot default-allow authorizer — grep the check for an `if len(list) > 0` guard around enforcement.
- **Config-in-request is code-in-request when the executor trusts the config shape.** Enumerate registered provider/handler families and diff which fields come from the request vs operator config. A field you can set in an API call that names a program, path, URL, or class is a sink.
- **Execution-on-save (eager invoke) removes the waiting window.** The provider was invoked immediately after validation "as a test" — anything that *probes* configuration by executing it is a same-request RCE primitive.
- Sweep adjacent registered provider names for the same request-sourced-fields pattern before stopping at the named one.

## NooBaa: a presigned PUT becomes CopyObject of anything the signer can read (CVE-2026-94368)

S3 SigV4 presigned URLs sign a canonical request that includes only *signed* headers. NooBaa's validation **dropped unsigned `x-amz-` headers from the signature calculation instead of rejecting the request**. An attacker holding a valid presigned **PUT** URL adds an unsigned `x-amz-copy-source` header, and the gateway's operation dispatch converts the upload into a **CopyObject** — server-side copy of any object the original signer is permitted to reach, across the entire storage system. The signature still verifies (the injected header was never in the canonical form); the operation semantics changed underneath it.

### Reusable axes

- **Presigned URL = capability scoped to one (method, bucket/key) tuple — test whether adjacent operations inherit it.** From any captured presigned PUT, replay with: `x-amz-copy-source` (CopyObject), `x-amz-copy-source-if-match`, version-id/retention headers, and alternate API routes. The finding class is *operation confusion at the signature boundary*: signature valid, intent changed.
- **Validator shape: reject-vs-strip.** When your added header disappears from the signature calc but the request still passes, ask what the *dispatcher* still reads. Dropping for signing while honoring for behavior is the exact desync between two components parsing the same request (sibling of the Sept 17 transport-parity and grammar-desync axes).
- Applies to any S3-compatible gateway (NooBaa/Ceph RGW/MinIO-style stacks): fingerprint the gateway first (error XML shapes), then run the presigned-scope battery on owned buckets with synthetic objects — never on customer data.

## Adjacent wave items (tracked, not published)

- CRI-O [CVE-2026-92574 / GHSA-mhq8-392f-7m6m](https://github.com/advisories/GHSA-mhq8-392f-7m6m) (8.8) checkpoint-restore security-context retention — folded onto the [June 19 container/checkpoint boundary page](2026-06-19-jupyterlab-stanza-containerd-parse-symfony-archive-boundaries-ghsa.md#september-21-second-follow-up-restored-processes-keep-checkpoint-security-state-ignoring-the-destination-pod-spec).
- Temporal DoS set (tracked, availability-only): sqlparser deep-unary stack overflow reachable by namespace-read callers ([CVE-2026-65651](https://github.com/advisories/GHSA-7vcf-7m3r-v7x3)), Schedule next-action unbounded search ([CVE-2026-16652](https://github.com/advisories/GHSA-pv35-7w89-v65c)), tchannel-go malformed fragment panic ([CVE-2026-65653](https://github.com/advisories/GHSA-vg3p-fxfm-m684)) + checksum-type validation ([CVE-2026-65652](https://github.com/advisories/GHSA-2mhp-wpjp-pjr8)), ringpop-go SWIM label-limit ([CVE-2026-65654](https://github.com/advisories/GHSA-2cw5-f255-55f8)).
- Apache Neethi WS-Policy five-pack (nesting-depth bypass, re-expansion, intersection blowup, assertion content limit, per-read vs whole-doc timeout) — parser memory-safety/DoS, tracked per parser precedent.
- Checkmk push-mode zlib amplification ([CVE-2026-77021](https://github.com/advisories/GHSA-5q8h-fhcg-2395)) — DoS, tracked. iceoryx2 safe-Rust `&str` UB ([CVE-2026-92612](https://github.com/advisories/GHSA-gm83-3hcx-j6jj)) — memory-safety, tracked.
- MISP galaxy-name stored XSS into the statistics view ([CVE-2026-94277](https://github.com/advisories/GHSA-8mcv-mp35-55rc)) and Leantime Kanban XSS ([CVE-2026-94210](https://github.com/advisories/GHSA-j9vw-9527-3hx6)) — generic unescaped-render stored XSS, tracked.
- 1millionbot self-session Markdown XSS ([CVE-2026-91921](https://github.com/advisories/GHSA-rf8x-cp2v-q2fg)) — self-only impact, not promotable.

## Reporting heuristics

- For the Temporal pair, the report language is **which credential the server used for your request**: the callback finding = "system-administrator internal client resolved from your header flag"; the subprocess finding = "server process account, immediate execution, cluster-wide persistence creds." Name the privilege, not the HTTP detail.
- Separate *precondition found* from *exploit proven*: both Temporal findings need config state (`httpPort`, `allowedAddresses`, `compute_providers.enabled`) recorded verbatim before any proof step.
- For NooBaa, prove with **owned signer + owned source bucket + synthetic canary object**, showing the copy landing where the presigned PUT alone could never write; a passing signature plus changed semantics is the whole finding.
