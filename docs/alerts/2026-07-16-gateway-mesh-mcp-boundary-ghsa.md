# Gateway, service-mesh, and local MCP boundary checks

Sources: hourly offensive-security scan, 2026-07-16 GitHub Security Advisory updates. Primary entries: [GHSA-fcrp-7gc2-93g7](https://github.com/advisories/GHSA-fcrp-7gc2-93g7), [GHSA-wcrf-9vrr-854f](https://github.com/advisories/GHSA-wcrf-9vrr-854f), [GHSA-22xc-xg2r-9j7v](https://github.com/advisories/GHSA-22xc-xg2r-9j7v), [GHSA-v95x-xhq5-4929](https://github.com/advisories/GHSA-v95x-xhq5-4929), [GHSA-wvmp-6r4v-j6cv](https://github.com/advisories/GHSA-wvmp-6r4v-j6cv), the updated [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f), [GHSA-vj7q-gjh5-988w](https://github.com/advisories/GHSA-vj7q-gjh5-988w), [GHSA-jpw9-pfvf-9f58](https://github.com/advisories/GHSA-jpw9-pfvf-9f58), and [GHSA-hvrp-rf83-w775](https://github.com/advisories/GHSA-hvrp-rf83-w775).

This batch is durable for operators because the advisories expose reusable control-plane trust boundaries: namespace-owned Gateway API backends referenced without target-namespace consent, gateway extension validation reading controller-local files, xDS authentication gaps exposing control-plane resources, mesh clients sending bearer tokens over unverified HTTPS, browser-reachable MCP transports without origin/host controls, and MCP session/task identifiers used without principal or owner binding.

!!! warning "Authorized validation only"
    Keep proofs to disposable Kubernetes namespaces, lab mesh control planes, owned browser origins, local MCP canaries, fake tokens, and route/decision tables. Do not route production traffic through another tenant's backend, intercept real operator tokens, invoke dangerous MCP tools, read local user files, or use DNS rebinding against systems outside written scope.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-fcrp-7gc2-93g7](https://github.com/advisories/GHSA-fcrp-7gc2-93g7) | Envoy Gateway before `1.7.4` and `1.8.0-rc.0` through `1.8.0` | `HTTPRoute` extension-managed custom `backendRef` can target another namespace without a matching `ReferenceGrant` | Test whether route authors can bind traffic to backend resources whose owner never granted cross-namespace consent. |
| [GHSA-wcrf-9vrr-854f](https://github.com/advisories/GHSA-wcrf-9vrr-854f) | Envoy Gateway before `1.7.4` and `1.8.0-rc.0` through `1.8.0` | `EnvoyExtensionPolicy` Lua validation path-normalization gaps can disclose controller-pod local files | Validate extension-policy author boundaries with synthetic files and redacted decision tables, not service-account token capture. |
| [GHSA-22xc-xg2r-9j7v](https://github.com/advisories/GHSA-22xc-xg2r-9j7v) | Envoy Gateway in `GatewayNamespaceMode` before `1.7.4` / `1.8.1` | xDS unary and SotW paths can bypass intended JWT checks | Check whether in-cluster pods can fetch xDS resources with unauthenticated canary clients. |
| [GHSA-v95x-xhq5-4929](https://github.com/advisories/GHSA-v95x-xhq5-4929) | Kuma / `kumactl` profile setup across vulnerable 1.x and 2.x lines | HTTPS control-plane profile without a CA certificate disables TLS verification and sends API tokens over the unverified channel | Validate mesh-admin workstation trust assumptions with fake control-plane profiles and token canaries, not live credential capture. |
| [GHSA-wvmp-6r4v-j6cv](https://github.com/advisories/GHSA-wvmp-6r4v-j6cv) | Kuma / `kuma-dp` Universal mode across vulnerable 1.x and 2.x lines | Data-plane HTTPS control-plane connection without CA disables peer verification and sends dataplane auth tokens | Test Universal-mode data-plane bootstrap trust with synthetic tokens and owned control-plane endpoints. |
| [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f) | MCP Python SDK `mcp` before `1.23.0` | `FastMCP` streamable HTTP or SSE servers on `localhost`/`127.0.0.1` lacked default DNS-rebinding protection | Reuse the existing local-service DNS-rebinding workflow against agent/MCP tools that expose unauthenticated local HTTP transports. |
| [GHSA-vj7q-gjh5-988w](https://github.com/advisories/GHSA-vj7q-gjh5-988w) | MCP Python SDK WebSocket server transport before `1.28.1` | Deprecated WebSocket transport accepted browser upgrades without SDK-level `Host`/`Origin` validation | Validate browser-to-local MCP WebSocket reachability with canary tools only. |
| [GHSA-jpw9-pfvf-9f58](https://github.com/advisories/GHSA-jpw9-pfvf-9f58) | MCP Python SDK SSE and stateful Streamable HTTP transports through `1.27.1` | Session requests were routed by session ID without binding to the authenticated principal | Test two-client session fixation/injection only with fake OAuth clients and canary JSON-RPC calls. |
| [GHSA-hvrp-rf83-w775](https://github.com/advisories/GHSA-hvrp-rf83-w775) | MCP Python SDK experimental tasks `1.23.0` through `1.27.1` | Default task handlers used task IDs without enforcing session ownership | Validate cross-client task listing, result access, and cancellation with synthetic tasks. |

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

Report this as **route namespace control -> extension-managed backendRef -> target namespace backend use without ReferenceGrant consent**, **extension policy author -> controller validation path -> synthetic local file disclosure**, or **in-cluster pod -> xDS Fetch/SotW path -> canary xDS resource access without expected JWT binding**. Evidence should include object manifests with non-sensitive names, route status, gateway logs with markers only, xDS client decisions, and version data.

### Kuma `kumactl` and `kuma-dp` unverified control-plane profiles

1. Build a lab profile with a fake or low-privilege token. Never use a real admin token or dataplane auth token for interception evidence.
2. Stand up an owned HTTPS endpoint with a certificate that should fail verification for the configured hostname.
3. Add a vulnerable-style `kumactl` HTTPS control-plane profile without `--ca-cert-file`, or start a Universal-mode `kuma-dp` lab process without `KUMA_CONTROL_PLANE_CA_CERT`.
4. Run a harmless read-only `kumactl` command or data-plane bootstrap attempt against the owned endpoint and capture whether the fake token is sent despite certificate mismatch.
5. Repeat with patched Kuma and with an explicit CA certificate to show the corrected trust decision.

Report this as **mesh CLI or data plane HTTPS profile without CA -> certificate verification disabled -> bearer/dataplane token exposed to attacker-controlled control-plane endpoint**. Keep the captured token synthetic and redact hostnames if they reveal customer topology.

### MCP Python SDK local transport and session-boundary probes

Use the existing [DNS rebinding local-service testing](../methodology/dns-rebinding-local-service-testing.md) workflow, constrained to MCP-specific preconditions:

1. Launch a disposable `FastMCP` server with streamable HTTP or SSE transport on `localhost`/`127.0.0.1`, or a deprecated WebSocket transport only if the application explicitly wires it into an ASGI server.
2. Expose only harmless canary tools/resources, such as `whoami_canary`, `echo_canary`, or a static resource named `public-marker`.
3. From an owned browser origin and rebinding domain, test whether browser JavaScript can reach the local MCP endpoint after DNS answers rotate from public IP to loopback, or whether a cross-origin WebSocket can complete the MCP initialize flow.
4. For authenticated SSE or stateful Streamable HTTP servers, use two fake OAuth clients and verify whether a request bearing one principal can inject canary JSON-RPC messages into a session created by another principal when only the session ID is known.
5. If `server.experimental.enable_tasks()` is present, use two synthetic clients to test whether task listing, result retrieval, or cancellation is scoped to the creating session.
6. Capture only request/response markers, origin headers, session/task IDs, and tool names. Do not expose file-reading, shell, cloud, credential, or browser-control tools during the test.
7. Repeat against fixed versions (`mcp` `1.23.0` for DNS-rebinding defaults, `1.27.2` for task ownership, `1.28.1` for WebSocket origin/host validation, or the relevant patched HTTP transport) or an explicit `TransportSecuritySettings` configuration as a negative control.

Report this as **browser-origin DNS rebinding or WebSocket reachability -> local MCP transport -> canary tool/resource invocation**, **session ID without principal binding -> cross-client JSON-RPC injection**, or **task ID without owner binding -> cross-client task read/cancel**.

## Operator checklist

- [ ] Does the Gateway API route cross a namespace boundary, and is a target-namespace `ReferenceGrant` absent?
- [ ] Is the backend reference standard Gateway API behavior or extension-managed custom behavior?
- [ ] Can extension-policy and xDS evidence be reduced to synthetic files/resources and route/auth decision tables?
- [ ] Can all Kubernetes evidence be reduced to synthetic namespaces, marker Services, and route status tables?
- [ ] Does any `kumactl` or Universal-mode `kuma-dp` profile point at HTTPS without an explicit CA or publicly trusted serving certificate?
- [ ] Are mesh CLI and dataplane token proofs synthetic, low-privilege, and captured only on owned infrastructure?
- [ ] Are local MCP HTTP/SSE/WebSocket servers unauthenticated or weakly authenticated, loopback/LAN-bound, and reachable from a browser origin?
- [ ] Are MCP session and task IDs bound to the authenticated principal and creating session?
- [ ] Are dangerous MCP tools disabled during validation?

## Reporting notes

- Lead with the trust invariant that failed: namespace consent, TLS server identity, or browser-to-localhost origin isolation.
- Avoid publishing reusable exploit manifests for shared clusters; use minimal object snippets or redacted route tables.
- For MCP findings, include the SDK version, transport, bind host, authentication state, session/task owner model, and the exact canary tool/resource invoked.
- For Kuma findings, do not claim production compromise unless a real profile, network path, and token exposure were approved and observed. Prefer synthetic-token proof.
- For Envoy Gateway findings, avoid collecting service-account tokens or TLS private keys; use mounted marker files, fake Secrets, and xDS canary resources to prove the parser/auth boundary.
