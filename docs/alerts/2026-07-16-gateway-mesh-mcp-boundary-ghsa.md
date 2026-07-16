# Gateway, service-mesh, and local MCP boundary checks

Sources: hourly offensive-security scan, 2026-07-16 GitHub Security Advisory updates. Primary entries: [GHSA-fcrp-7gc2-93g7](https://github.com/advisories/GHSA-fcrp-7gc2-93g7), [GHSA-v95x-xhq5-4929](https://github.com/advisories/GHSA-v95x-xhq5-4929), and the updated [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f).

This batch is durable for operators because all three advisories expose reusable control-plane trust boundaries: namespace-owned Gateway API backends referenced without target-namespace consent, mesh CLI profiles sending bearer tokens over unverified HTTPS, and unauthenticated local MCP HTTP transports reachable through browser DNS rebinding.

!!! warning "Authorized validation only"
    Keep proofs to disposable Kubernetes namespaces, lab mesh control planes, owned browser origins, local MCP canaries, fake tokens, and route/decision tables. Do not route production traffic through another tenant's backend, intercept real operator tokens, invoke dangerous MCP tools, read local user files, or use DNS rebinding against systems outside written scope.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-fcrp-7gc2-93g7](https://github.com/advisories/GHSA-fcrp-7gc2-93g7) | Envoy Gateway before `1.7.4` and `1.8.0-rc.0` through `1.8.0` | `HTTPRoute` extension-managed custom `backendRef` can target another namespace without a matching `ReferenceGrant` | Test whether route authors can bind traffic to backend resources whose owner never granted cross-namespace consent. |
| [GHSA-v95x-xhq5-4929](https://github.com/advisories/GHSA-v95x-xhq5-4929) | Kuma / `kumactl` profile setup across vulnerable 1.x and 2.x lines | HTTPS control-plane profile without a CA certificate disables TLS verification and sends API tokens over the unverified channel | Validate mesh-admin workstation trust assumptions with fake control-plane profiles and token canaries, not live credential capture. |
| [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f) | MCP Python SDK `mcp` before `1.23.0` | `FastMCP` streamable HTTP or SSE servers on `localhost`/`127.0.0.1` lacked default DNS-rebinding protection | Reuse the existing local-service DNS-rebinding workflow against agent/MCP tools that expose unauthenticated local HTTP transports. |

## Replayable validation boundaries

### Envoy Gateway cross-namespace backend consent

1. Use a disposable cluster or explicitly approved tenant lab with at least two namespaces:
   - `route-ns` controlled by the route author;
   - `backend-ns` controlled by the backend owner.
2. Deploy an inert backend in `backend-ns` that returns a unique marker string and no sensitive data.
3. Confirm the negative control: a standard Gateway API cross-namespace reference should require a `ReferenceGrant` in `backend-ns` before `route-ns` can route to it.
4. Create only extension-managed custom backend references that match the advisory precondition. Do not test with production Services, Secrets, or customer traffic.
5. Record whether Envoy Gateway accepts the route and forwards traffic to the backend marker without a matching `ReferenceGrant`.
6. Add controls for:
   - patched Envoy Gateway versions;
   - a valid `ReferenceGrant` present versus absent;
   - same-namespace backend references;
   - standard backend references that still enforce the consent model.

Report this as **route namespace control -> extension-managed backendRef -> target namespace backend use without ReferenceGrant consent**. Evidence should include object manifests with non-sensitive names, route status, gateway logs with markers only, and version data.

### Kuma `kumactl` unverified control-plane profile

1. Build a lab profile with a fake or low-privilege token. Never use a real admin token for interception evidence.
2. Stand up an owned HTTPS endpoint with a certificate that should fail verification for the configured hostname.
3. Add a vulnerable-style `kumactl` HTTPS control-plane profile without `--ca-cert-file`.
4. Run a harmless read-only `kumactl` command against the owned endpoint and capture whether the fake token is sent despite certificate mismatch.
5. Repeat with patched `kumactl` and with an explicit CA certificate to show the corrected trust decision.

Report this as **mesh CLI HTTPS profile without CA -> certificate verification disabled -> bearer token exposed to attacker-controlled control-plane endpoint**. Keep the captured token synthetic and redact hostnames if they reveal customer topology.

### MCP Python SDK local DNS-rebinding probe

Use the existing [DNS rebinding local-service testing](../methodology/dns-rebinding-local-service-testing.md) workflow, constrained to MCP-specific preconditions:

1. Launch a disposable `FastMCP` server with streamable HTTP or SSE transport on `localhost`/`127.0.0.1` and no authentication.
2. Expose only harmless canary tools/resources, such as `whoami_canary`, `echo_canary`, or a static resource named `public-marker`.
3. From an owned browser origin and rebinding domain, test whether browser JavaScript can reach the local MCP endpoint after DNS answers rotate from public IP to loopback.
4. Capture only request/response markers, origin headers, and tool names. Do not expose file-reading, shell, cloud, credential, or browser-control tools during the test.
5. Repeat against `mcp` `1.23.0` or an explicit `TransportSecuritySettings` configuration as a negative control.

Report this as **browser-origin DNS rebinding -> unauthenticated local MCP HTTP transport -> canary tool/resource invocation**.

## Operator checklist

- [ ] Does the Gateway API route cross a namespace boundary, and is a target-namespace `ReferenceGrant` absent?
- [ ] Is the backend reference standard Gateway API behavior or extension-managed custom behavior?
- [ ] Can all Kubernetes evidence be reduced to synthetic namespaces, marker Services, and route status tables?
- [ ] Does any `kumactl` profile point at HTTPS without an explicit CA or publicly trusted serving certificate?
- [ ] Are mesh CLI token proofs synthetic, low-privilege, and captured only on owned infrastructure?
- [ ] Are local MCP HTTP/SSE servers unauthenticated, loopback-bound, and reachable from a browser rebinding origin?
- [ ] Are dangerous MCP tools disabled during validation?

## Reporting notes

- Lead with the trust invariant that failed: namespace consent, TLS server identity, or browser-to-localhost origin isolation.
- Avoid publishing reusable exploit manifests for shared clusters; use minimal object snippets or redacted route tables.
- For MCP findings, include the SDK version, transport, bind host, authentication state, and the exact canary tool/resource invoked.
- For Kuma findings, do not claim production compromise unless a real profile, network path, and token exposure were approved and observed. Prefer synthetic-token proof.
