# NVIDIA OpenShell wave (13 GHSAs): L7 proxy policy bypasses and cross-sandbox SSH secret reuse

Source: hourly offensive-security scan, 2026-11-17 (unreviewed wave published 2026-11-17T18:31Z, GHSA package version fields empty, vendor advisory banding). Product: **NVIDIA OpenShell for Linux**, the sandboxed inference/agent execution platform (Kubernetes sandboxes, a gateway control plane, and a layer-7 policy proxy sitting on the egress path). Thirteen legs, several critical-tier, clustered around one theme: **the sandbox boundary is enforced by parsers and caches, and every parser or cache leg fails open.**

## Advisory table

| Advisory | Component | Boundary |
| --- | --- | --- |
| [GHSA-9m2f-cpxf-5hpj](https://github.com/advisories/GHSA-9m2f-cpxf-5hpj) / CVE-2026-100971 (high) | L7 path allowlist | Semicolon-dot path sequences (`;.`, path parameters) bypass the allowlist |
| [GHSA-29vc-ggrm-xf8q](https://github.com/advisories/GHSA-29vc-ggrm-xf8q) / CVE-2026-100977 (high) | L7 REST policy | Cleartext **h2c over an HTTP CONNECT tunnel** evades policy: proxy inspects the HTTP/1 CONNECT, never the h2c frames inside |
| [GHSA-qpwc-624r-xfj9](https://github.com/advisories/GHSA-qpwc-624r-xfj9) / CVE-2026-100981 | L7 REST proxy | Body framing interpreted differently by proxy vs upstream, second request **smuggled past policy checks** |
| [GHSA-h367-5r6j-9pvv](https://github.com/advisories/GHSA-h367-5r6j-9pvv) / CVE-2026-100973 | L7 CONNECT policy | **Nonstandard HTTP methods** bypass restriction (method the policy matcher does not enumerate falls through) |
| [GHSA-x7jc-f46q-jh85](https://github.com/advisories/GHSA-x7jc-f46q-jh85) / CVE-2026-100970 | Policy hot-reload | Existing L7-inspected tunnels keep the **previous policy** after reload |
| [GHSA-r39c-3vg8-wchj](https://github.com/advisories/GHSA-r39c-3vg8-wchj) / CVE-2026-100976 | K8s network policy | TCP **source-port identity confusion**: proxy attributes traffic to the wrong process, process-based policy bypassed |
| [GHSA-w58c-ffgx-6c3x](https://github.com/advisories/GHSA-w58c-ffgx-6c3x) / CVE-2026-100979 | Gateway connection-proxy | Sandbox **status metadata steers control-plane connections to arbitrary internal hosts** (no address-range validation) |
| [GHSA-mg46-jffw-6j27](https://github.com/advisories/GHSA-mg46-jffw-6j27) / CVE-2026-100978 | Gateway-to-sandbox transport | Accepts **any host key without verification**, on-path MITM impersonates the sandbox endpoint, captures credentials, tampering with commands |
| [GHSA-gqww-m5rr-m2rg](https://github.com/advisories/GHSA-gqww-m5rr-m2rg) / CVE-2026-100975 (high) | Sandbox SSH auth | SSH handshake secret in a **plaintext environment variable**, reuse it to reach other sandboxes |
| [GHSA-mxf6-2f88-j9v5](https://github.com/advisories/GHSA-mxf6-2f88-j9v5) / CVE-2026-100974 | Sandbox SSH auth | The same handshake secret is **shared across sandboxes**, lateral tenant traversal from a high-priv position |
| [GHSA-hg3h-3f9h-87wr](https://github.com/advisories/GHSA-hg3h-3f9h-87wr) / CVE-2026-100972 (high) | Resource authorization | CRUD operations reachable **without resource-level authorization checks** |
| [GHSA-rmvg-c84h-mp7q](https://github.com/advisories/GHSA-rmvg-c84h-mp7q) / CVE-2026-100980 (high) | CLI diagnostic interface | Command injection: values pass through **two successive shell layers while escaped for only one** |
| [GHSA-35x8-vvh9-x73g](https://github.com/advisories/GHSA-35x8-vvh9-x73g) / CVE-2026-100982 | Inference-interception parser | Chunked request with no body-size or chunk-count limit exhausts the parser (DoS) |

## Why this wave is durable guidance

OpenShell is an AI-inference sandbox platform, so its threat model is the same one every agent-runtime vendor is converging on: untrusted code in a sandbox, a policy proxy policing egress, a gateway control plane holding credentials. These thirteen advisories are a checklist of where that architecture leaks.

1. **The egress policy proxy is a second HTTP parser, so the full desync suite applies to it.** Three legs (h2c-in-CONNECT, CL/TE body-framing disagreement, nonstandard methods) are the request-smuggling battery re-expressed as *policy bypass*: you are not poisoning a cache, you are getting a request the policy engine never saw. Rule: on any product with an L7 policy proxy, re-run the smuggling/method/transport-negotiation battery against the proxy itself and treat every parser differential as an allowlist escape. h2c-upgrade-after-CONNECT is the newest classic: the inspector parses the request it can see, the tunnel carries the request the policy matters about (transport-parity rule, sibling of the Oct 14 NGINX HTTP/3 leg).
2. **Policy-at-connection-setup is not policy-at-request.** The hot-reload leg proves enforcement is cached per tunnel: tighten the policy, existing inspected tunnels keep the old one. Operator test: open a long-lived tunnel, change (or have admin change) the policy, verify whether the live tunnel obeys the new rule. Same shape as session-state-as-authorization (Oct 14 NGINX `ssl_session_cache` leg): security state that lives longer than the config that authorized it is attack surface.
3. **`;.`, `;`, and post-validation stripping is a same-day two-product pattern.** OpenShell's path allowlist falls to semicolon-dot sequences the *validator* saw as path parameters but the *dispatcher* strips (Crucible CVE-2026-21592 in the same 18:31Z wave has the identical shape: crafted segment passes validation, Jetty removes the path parameter during dispatch and resolves to a protected path). Add `;`, `;.`, `%3B`, and trailing-parameter spellings to the canonical traversal battery next to `..%2f`: any allowlist matcher that runs before a framework-level parameter strip is decorative.
4. **Metadata that names a destination is an SSRF, even when the metadata is attacker-owned.** The gateway initiates connections to addresses taken from sandbox status metadata without range checks. Audit rule for any control plane: enumerate every field the control plane *reads from its own clients* that ends up as a connect target; a sandbox you can write status into is a pivot into the internal network (FQDN/metadata-as-endpoint family, Sept 21 automation-platform page).
5. **Shared handshake secrets erase tenant isolation in one grep.** A plaintext env var holding the SSH handshake secret, identical across sandboxes, turns one sandbox's process env into a passport to every other sandbox. Standard sweep: diff every secret in the sandbox process environment across two lab sandboxes; anything byte-identical across tenants is a lateral-movement credential (per-sandbox uniqueness is the assertion to test, not to trust). Accept-any host key on the gateway-to-sandbox leg adds the position rule: an on-path attacker on the internal segment becomes the sandbox, capturing credentials and injecting commands.
6. **Escape-layer-count mismatch is a grep-able bug class.** The CLI diagnostic leg is: value interpolated into a command run under `sh -c` twice, escaped once. Audit your own wrappers and vendor diagnostics: count shell layers the string passes through vs the number of escaping passes applied; mismatch = injection. Newline/`;`/backtick battery at every field that reaches the diagnostic path.
7. **Process identity by source port is fragile.** The network-policy leg is the classic proxy-attributes-traffic-to-wrong-process failure: if policy decides by ephemeral source port mapping, race the mapping. Validate in a lab by making a low-priv process reuse the port an authorized process just released.

## Validation boundaries

- Lab OpenShell/K8s namespace only, two disposable sandboxes you own; prove cross-sandbox access with an SSH probe from sandbox A to sandbox B using an extracted shared env secret.
- Egress-policy proofs via owned listeners (callback host + your own h2c server); never proxy into customer internal ranges through the bypass.
- No production inference tenants, no reading other tenants' sandboxes or secrets; file-read legs prove with synthetic marker files.
- Version banding: GHSA package fields are empty; fingerprint from vendor advisory and the deployment image tag, do not infer patch state from the release line.

## Related pages

- [Sept 21 automation-platform FQDN-endpoint metadata SSRF](2026-09-21-automation-platform-credential-test-exfil-and-fqdn-endpoint-metadata-ssrf-ghsa.md) (metadata-as-destination family)
- [Sept 15 parser/header/route boundaries](2026-09-15-http4s-ember-traefik-parser-header-route-boundaries-ghsa.md) (proxy-vs-origin parser differentials)
- [Oct 14 NGINX coordinated wave](2026-10-14-nginx-coordinated-wave-ssi-aio-uaf-map-alias-overflows-http3-injection-mtls-session-forgery-and-ingress-header-relay-ghsa.md) (HTTP/3 transport parity, session state as authorization)
- [Sept 16 OT server-response-trust fold](2026-09-16-secret-server-identity-crypto-boundaries-and-ot-hardcoded-update-keys-ghsa.md) (accept-any host key / TOFU disarm)

*Source: hourly offensive-security scan, 2026-11-17 (18:31Z unreviewed wave).*
