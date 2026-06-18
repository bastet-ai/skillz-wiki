# Agent, proxy, Kubernetes, document-render, and AI service boundary checks

Source: hourly offensive-security scan, 2026-06-18. Primary entries: GitHub advisories [GHSA-r2xf-7jw5-pjg6](https://github.com/advisories/GHSA-r2xf-7jw5-pjg6) / CVE-2026-55887, [GHSA-f397-5vjw-v2c2](https://github.com/advisories/GHSA-f397-5vjw-v2c2) / CVE-2026-53866, [GHSA-fq9j-vw4w-fr6v](https://github.com/advisories/GHSA-fq9j-vw4w-fr6v) / CVE-2026-53842, [GHSA-ccwh-wwpp-6wg5](https://github.com/advisories/GHSA-ccwh-wwpp-6wg5) / CVE-2026-53864, [GHSA-q99w-vh6v-q3v7](https://github.com/advisories/GHSA-q99w-vh6v-q3v7) / CVE-2026-53843, [GHSA-985f-72mj-8gf7](https://github.com/advisories/GHSA-985f-72mj-8gf7) / CVE-2026-53863, [GHSA-gcq2-9pq2-cxqm](https://github.com/advisories/GHSA-gcq2-9pq2-cxqm) / CVE-2026-55603, [GHSA-64mm-vxmg-q3vj](https://github.com/advisories/GHSA-64mm-vxmg-q3vj) / CVE-2026-55602, [GHSA-2c85-rfcc-g74j](https://github.com/advisories/GHSA-2c85-rfcc-g74j), [GHSA-x9g3-xrwr-cwfg](https://github.com/advisories/GHSA-x9g3-xrwr-cwfg) / CVE-2026-55388, [GHSA-2mrg-35hw-x3x9](https://github.com/advisories/GHSA-2mrg-35hw-x3x9) / CVE-2026-55229, [GHSA-mw9r-p8xp-wx96](https://github.com/advisories/GHSA-mw9r-p8xp-wx96) / CVE-2026-55225, [GHSA-r427-j2h7-wv3m](https://github.com/advisories/GHSA-r427-j2h7-wv3m) / CVE-2026-55226, [GHSA-6x8v-2fq5-2229](https://github.com/advisories/GHSA-6x8v-2fq5-2229) / CVE-2026-55670, and [GHSA-29jh-8cfq-rr8x](https://github.com/advisories/GHSA-29jh-8cfq-rr8x) / CVE-2026-55671.

This batch is durable because the advisories map to reusable offensive validation boundaries: agent catalog metadata crossing into container launch flags, agent shell/environment/session policy checks that can be bypassed by lower-trust workspace input, unauthenticated AI service APIs invoking tools, approval and webhook gates that fail open, file tools crossing workspace/artifact roots, SSE/MCP transports exposed without origin or authentication controls, reverse-proxy helpers that transform request bodies or route by attacker-controlled host material, mock servers that recursively evaluate request-derived template expressions, prototype-pollution gadgets that turn inherited worker options into code loading, document converters that fetch embedded resources, Kubernetes operators that mint cross-namespace secret permissions from custom resources, and identity providers where recycled identifiers, client binding, token lifetime checks, or user-managed callback URLs cross tenant, OAuth, or network trust boundaries.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-r2xf-7jw5-pjg6 / CVE-2026-55887 | Docker MCP Gateway | attacker-controlled `io.docker.server.metadata` OCI label YAML mass-assigned runtime fields that became `docker run` flags | Test agent/MCP catalogs where descriptive image metadata can become mounts, users, commands, hosts, secrets, or network policy. |
| GHSA-f397-5vjw-v2c2 / CVE-2026-53866 | OpenClaw shell inline commands | one parser path could route inline shell content without the intended allowlist decision | Validate every command syntax family against the same approval boundary, especially compact inline forms. |
| GHSA-fq9j-vw4w-fr6v / CVE-2026-53842 | OpenClaw Gmail setup | repository-local `.env` could influence `gcloud` execution through `CLOUDSDK_PYTHON` | Treat workspace environment loading as code-execution-adjacent when setup helpers launch cloud CLIs. |
| GHSA-ccwh-wwpp-6wg5 / CVE-2026-53864 | OpenClaw environment sanitizer | lower-trust env sources could pass Node.js control variables into later child processes | Build env-sanitizer tests around runtime control variables, not just obvious credential names. |
| GHSA-q99w-vh6v-q3v7 / CVE-2026-53843 | OpenClaw device sessions | a pairing-scoped session could regain node WebSocket authority after node-token revocation | Verify revocation boundaries with live session reuse and reconnect attempts, not only token deletion. |
| GHSA-985f-72mj-8gf7 / CVE-2026-53863 | OpenClaw tool policy groups | policy callers could resolve decisions for unvalidated group ids | Test tool-policy routing when a caller can supply group, role, workspace, or channel identifiers. |
| GHSA-gcq2-9pq2-cxqm / CVE-2026-55603 | http-proxy-middleware `fixRequestBody()` | multipart reconstruction interpolated `req.body` keys/values without neutralizing CRLF | Compare gateway-side parsed body validation with the exact wire body re-emitted to the backend. |
| GHSA-64mm-vxmg-q3vj / CVE-2026-55602 | http-proxy-middleware `router` | host+path proxy-table entries used substring matching over attacker-controlled `Host` plus URL | Test host-header superstrings that steer traffic to unintended backends despite apparent route tables. |
| GHSA-2c85-rfcc-g74j | Karate Mock Server | request body, headers, or parameters assigned to variables could be recursively processed as Karate embedded expressions | Treat mock/test servers as reachable execution surfaces when untrusted HTTP data crosses into expression evaluation. |
| GHSA-x9g3-xrwr-cwfg / CVE-2026-55388 | Piscina worker pool | inherited `options.filename` from polluted prototypes flowed into worker thread code loading | Link prototype-pollution sources to downstream worker/import gadgets instead of stopping at object mutation. |
| GHSA-2mrg-35hw-x3x9 / CVE-2026-55229 | Gotenberg LibreOffice conversion | uploaded documents could trigger outbound resource fetches, and may reference local file resources during conversion | Add document-converter SSRF/file-resource checks to render pipelines that accept DOCX/ODT/HTML-like inputs. |
| GHSA-mw9r-p8xp-wx96 / CVE-2026-55225 | Strimzi Cluster Operator | attacker-controlled `Kafka.spec.entityOperator.*.watchedNamespace` could create roles allowing secret CRUD in target namespaces | Validate Kubernetes operators that convert custom-resource fields into RBAC in other namespaces. |
| GHSA-r427-j2h7-wv3m / CVE-2026-55226 | Strimzi Entity Operator | single-operator deployments still granted rights corresponding to the absent counterpart operator | Check least-privilege assumptions when optional controllers are disabled but shared service accounts remain broad. |
| GHSA-6x8v-2fq5-2229 / CVE-2026-55670 | ZITADEL user lifecycle | recreating a deleted user id under another org could route events to the original org | Probe tenant isolation where externally supplied or recycled object ids meet event-sourced ownership history. |
| GHSA-29jh-8cfq-rr8x / CVE-2026-55671 | ZITADEL outbound HTTP components | notification channels, OIDC backchannel logout, and SAML metadata fetches accepted user-defined URLs with redirect/rebinding/protocol denylist bypasses | Treat IdP-admin URL fields as high-value SSRF sinks and validate redirect, DNS rebinding, and scheme downgrade controls with canaries. |

## Late PraisonAI and ZITADEL additions

Source: GitHub advisories published later in the same hourly window: [GHSA-gcq3-mfvh-3x25](https://github.com/advisories/GHSA-gcq3-mfvh-3x25), [GHSA-p75f-6fp4-p57w](https://github.com/advisories/GHSA-p75f-6fp4-p57w), [GHSA-x92v-rpx6-p6cw](https://github.com/advisories/GHSA-x92v-rpx6-p6cw), [GHSA-rh39-9c67-59mh](https://github.com/advisories/GHSA-rh39-9c67-59mh), [GHSA-892r-p3jq-jp24](https://github.com/advisories/GHSA-892r-p3jq-jp24), [GHSA-x8cv-xmq7-p8xp](https://github.com/advisories/GHSA-x8cv-xmq7-p8xp), [GHSA-rjvw-7vvw-549v](https://github.com/advisories/GHSA-rjvw-7vvw-549v), [GHSA-fq2m-6wqh-x44g](https://github.com/advisories/GHSA-fq2m-6wqh-x44g), [GHSA-2rcg-mm5h-xchx](https://github.com/advisories/GHSA-2rcg-mm5h-xchx), [GHSA-j4hj-7hfh-g2f4](https://github.com/advisories/GHSA-j4hj-7hfh-g2f4), [GHSA-vxgj-xg5c-p4h7](https://github.com/advisories/GHSA-vxgj-xg5c-p4h7), [GHSA-4869-x4pr-q22x](https://github.com/advisories/GHSA-4869-x4pr-q22x), [GHSA-p4pj-vh7h-6cqh](https://github.com/advisories/GHSA-p4pj-vh7h-6cqh), [GHSA-x227-pf99-vffg](https://github.com/advisories/GHSA-x227-pf99-vffg), [GHSA-pv2j-rghr-v5r9](https://github.com/advisories/GHSA-pv2j-rghr-v5r9), [GHSA-6h9p-93hq-q7h6](https://github.com/advisories/GHSA-6h9p-93hq-q7h6), [GHSA-w6h2-fr4q-xvxv](https://github.com/advisories/GHSA-w6h2-fr4q-xvxv), [GHSA-v847-hxxw-3pxg](https://github.com/advisories/GHSA-v847-hxxw-3pxg), [GHSA-63v4-w882-g4x2](https://github.com/advisories/GHSA-63v4-w882-g4x2), [GHSA-fc26-m9pf-v56q](https://github.com/advisories/GHSA-fc26-m9pf-v56q), [GHSA-j7qx-p75m-wp7g](https://github.com/advisories/GHSA-j7qx-p75m-wp7g), [GHSA-qvpf-j64c-jmhr](https://github.com/advisories/GHSA-qvpf-j64c-jmhr), [GHSA-5qw8-f2g9-ff29](https://github.com/advisories/GHSA-5qw8-f2g9-ff29), [GHSA-vmf9-xx9w-86wx](https://github.com/advisories/GHSA-vmf9-xx9w-86wx), [GHSA-22cj-m4wf-fv2c](https://github.com/advisories/GHSA-22cj-m4wf-fv2c), [GHSA-8579-rgg5-ph2m](https://github.com/advisories/GHSA-8579-rgg5-ph2m), [GHSA-35w5-pcw4-jx94](https://github.com/advisories/GHSA-35w5-pcw4-jx94), [GHSA-g5h5-m4hm-xjrr](https://github.com/advisories/GHSA-g5h5-m4hm-xjrr) / CVE-2026-55669, [GHSA-wxg7-w2v3-w38g](https://github.com/advisories/GHSA-wxg7-w2v3-w38g), and [GHSA-xqxv-4jc2-x56x](https://github.com/advisories/GHSA-xqxv-4jc2-x56x) / CVE-2026-55672.

| Advisory cluster | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-p75f-6fp4-p57w, GHSA-4869-x4pr-q22x, GHSA-fq2m-6wqh-x44g, GHSA-892r-p3jq-jp24, GHSA-x8cv-xmq7-p8xp, GHSA-j4hj-7hfh-g2f4, GHSA-5qw8-f2g9-ff29 | PraisonAI UI, Jobs API, AgentOS, AgentTeam, and recipe servers | unauthenticated routes could connect MCP stdio commands, submit agent workflows, list/invoke agents, or expose recipe service functions | Enumerate AI agent service routes for unauthenticated tool invocation before testing individual tool impact. |
| GHSA-v847-hxxw-3pxg, GHSA-63v4-w882-g4x2, GHSA-8579-rgg5-ph2m | PraisonAI dangerous-tool approval paths | policy enforcement could be skipped, approval pages rendered tool arguments as raw HTML, or unrelated Discord channel messages could approve dangerous tools | Treat approval UX and chat-mediated approvals as privileged state machines; verify request binding, origin, and negative approval controls. |
| GHSA-gcq3-mfvh-3x25, GHSA-2rcg-mm5h-xchx, GHSA-p4pj-vh7h-6cqh, GHSA-j7qx-p75m-wp7g, GHSA-22cj-m4wf-fv2c | PraisonAI code, file, dynamic-context, and artifact tools | workspace roots, `@file:` mentions, `agent_file`, artifact storage, history, or terminal helpers could read or modify paths outside intended roots | Build file-boundary tests around every agent-visible path abstraction, not only obvious upload/download endpoints. |
| GHSA-x227-pf99-vffg, GHSA-vmf9-xx9w-86wx, GHSA-35w5-pcw4-jx94 | PraisonAI MCP/SSE transports | SSE MCP servers or publish endpoints could bind broadly without auth/origin validation and expose registered tools or event injection | Probe MCP transports as web attack surfaces: bind address, unauthenticated list/invoke, browser origin relay, and event-channel authorization. |
| GHSA-x92v-rpx6-p6cw, GHSA-fc26-m9pf-v56q, GHSA-qvpf-j64c-jmhr, GHSA-rh39-9c67-59mh | PraisonAI webhook, bot, and platform API flows | missing webhook secrets, Slack authorization bypasses, or ownership checks let lower-trust messages or users trigger trusted bot/platform actions | Validate bot integrations with forged canary events, wrong-channel users, and cross-owner object ids before asserting command execution impact. |
| GHSA-rjvw-7vvw-549v, GHSA-vxgj-xg5c-p4h7, GHSA-6h9p-93hq-q7h6 | PraisonAI Jobs, praisonaiagents, and SpiderTools outbound fetches | SSRF guards could validate literal IPs or initial URLs but miss DNS rebinding, DNS resolution, or redirect targets | Use owned redirector/DNS-rebind canaries and synthetic internal listeners; do not probe real internal services. |
| GHSA-pv2j-rghr-v5r9, GHSA-w6h2-fr4q-xvxv | PraisonAI code execution and compute-bridged file tools | sandbox/blocklist and compute bridge boundaries could be bypassed into attribute access or shell command construction | Keep proofs to inert markers in isolated workers and avoid publishing payloads that are directly reusable against production hosts. |
| GHSA-g5h5-m4hm-xjrr / CVE-2026-55669, GHSA-wxg7-w2v3-w38g, GHSA-xqxv-4jc2-x56x / CVE-2026-55672 | ZITADEL JWT IdP and OAuth/OIDC flows | token audience/lifetime validation or authorization-code/refresh-token client binding could be missing under specific flow preconditions | Add positive/negative OAuth canaries for `aud`, `exp`, `iat`, authorization-code client binding, and refresh-token client binding in multi-client IdP assessments. |

## Operator triage

1. **Start with control-plane composition.** MCP gateways, agent workspaces, Kubernetes operators, identity providers, and proxy layers are high-value because a small parsing or routing mistake can cross into host execution, cross-tenant access, or backend trust.
2. **Confirm reachability before impact.** The strongest cases require a lower-trust actor controlling an OCI label, repository workspace file, request body, `Host` header, document upload, custom resource, or IdP URL setting that is actually consumed by the vulnerable code path.
3. **Use synthetic canaries only.** Prove with disposable images, workspaces, request fields, backend route markers, mock server variables, prototype-pollution lab objects, document URLs, Kubernetes namespaces, and identity-provider test users. Do not mount real host secrets, exfiltrate tokens, collect tenant data, or query internal production services.
4. **Keep negative controls explicit.** Pair every positive with a patched build, rejected route, absent outbound callback, denied RBAC, sanitized environment, or revocation reconnect failure.

## Replayable validation boundaries

### MCP image metadata to container-launch flags

- Build a disposable OCI image in a lab registry with an inert `io.docker.server.metadata` label that attempts only harmless runtime shaping, such as adding a canary environment variable or mounting an empty temp directory.
- Reference the image through the affected gateway path (`docker://` or catalog snapshot) in a lab gateway with no production credentials loaded.
- Positive proof is that label-controlled YAML changes the constructed container launch arguments beyond descriptive metadata.
- Do not mount `/`, home directories, Docker sockets, SSH keys, cloud credentials, or production workspaces.

### Agent workspace environment and command-policy boundaries

- Seed a disposable repository with `.env` markers for environment variables that should not cross into cloud CLI or Node.js child-process launches.
- Exercise the affected setup/helper path and record only whether a benign marker runtime or output path was selected.
- Test all command syntaxes separately: long-form commands, inline shell forms, plugin-dispatched commands, and any grouped tool route.
- For revocation, keep an already paired lab device session alive, revoke the node token, and verify whether reconnect or WebSocket authority returns without a fresh approval.

### PraisonAI service, MCP, and approval boundaries

- Inventory every exposed PraisonAI web surface in scope: UI API, Jobs API, AgentOS, AgentTeam launch endpoints, recipe servers, MCP stdio-connect routes, MCP/SSE transports, webhook receivers, bot adapters, and approval dashboards.
- For unauthenticated invocation checks, use only inert tools or commands that write a lab marker under a disposable temp directory. Capture route, request id, authenticated/unauthenticated state, and whether the tool invocation reached the server-side runner.
- For approval flows, submit a harmless dangerous-tool request with a canary argument. Verify whether HTML rendering, unrelated chat messages, or skipped policy paths can flip the approval state without the intended reviewer decision.
- For file tools, seed a synthetic workspace/artifact root and a separate canary file outside it. Positive proof is only path-resolution evidence or reading a disposable marker, never real host files, keys, project secrets, shell history, cloud credentials, or user data.
- For MCP/SSE and event channels, test bind address, `Origin`, `Host`, unauthenticated `list`/`invoke`, and publish semantics from a lab browser and a direct HTTP client. Keep all registered tools inert.
- For webhook and bot adapters, send forged canary events from owned accounts/channels with and without configured secrets; verify only whether the event enters the trusted workflow.

### Agent SSRF and outbound-fetch guard boundaries

- Use owned callback infrastructure plus an optional lab-only DNS rebinding host to test whether guards validate the final resolved address and post-redirect target, not only the initial literal URL.
- Pair each positive callback with negative controls for blocked literal private IPs, blocked redirected private targets, and denied rebinding targets on patched builds.
- Do not request cloud metadata, service-discovery endpoints, RFC1918 production ranges, admin panels, or customer internal services.

### Multipart body re-emission and proxy router boundary

- Put a controlled backend behind `http-proxy-middleware` and enable the exact `fixRequestBody()` or `router` configuration under test.
- For multipart re-emission, send a value containing CRLF plus a harmless extra field marker. Compare what the gateway parsed and validated with what the backend received on the wire.
- For router matching, configure a host+path proxy-table entry and send `Host` superstrings that include the configured key inside a longer attacker-controlled host.
- Evidence should be backend route/field canaries only. Do not target real upstream admin, payment, identity, or metadata services.

### Mock-server expression evaluation

- Confirm the Karate Mock Server feature file assigns request-derived values such as `request`, `requestHeaders`, or `requestParams` into variables that undergo embedded-expression processing.
- Use a harmless expression canary in a header, query parameter, or body field that returns a fixed marker; do not execute OS commands in shared environments.
- Positive proof is server-side evaluation of data that arrived over HTTP and was not present in the feature file.
- Scope impact to the mock server process privileges and lab configuration.

### Prototype-pollution source to Piscina worker gadget

- In a local harness, use a known prototype-pollution source to set only `Object.prototype.filename` to an inert `.mjs` canary under a temp directory.
- Call the affected Piscina constructor or `run()` path with options that lack an own `filename` property.
- Positive proof is loading of the inherited canary worker filename; negative proof is patched own-property validation or null-prototype option handling.
- Do not chain this against production services or load untrusted code.

### Document converter outbound and local-resource boundary

- Upload a synthetic DOCX/ODT to a lab Gotenberg `/forms/libreoffice/convert` endpoint containing an image/resource URL on infrastructure you own.
- Capture only the outbound canary request and conversion metadata. If local resource behavior is in scope, use a disposable file created inside the lab container.
- Do not probe cloud metadata, RFC1918 ranges, admin panels, service discovery endpoints, real local files, or shared document stores.

### Kubernetes operator custom-resource to RBAC boundary

- Use a disposable cluster or namespace pair. Confirm the service account running the operator has permissions only in the intended test namespaces.
- Create a Kafka custom resource with `entityOperator` watched namespace fields pointing at a canary namespace and inspect the resulting Role/RoleBinding and service account token capabilities.
- Positive proof is unexpected Secret CRUD or cross-namespace access to synthetic secrets created for the test.
- Never read production Secrets, service-account tokens, cluster credentials, or tenant namespaces.

### Identity-provider tenant and outbound URL boundary

- For recycled identifiers, create and delete only synthetic users, then recreate the same id under a second lab org and observe whether ownership/events route to the original org.
- For outbound URL sinks, configure notification, OIDC backchannel logout, or SAML metadata URL fields with owned callback URLs that test redirect, DNS rebinding, and HTTPS-to-HTTP downgrade behavior.
- For JWT IdP/OIDC client binding, use disposable clients and users. Attempt only synthetic token/code/refresh-token swaps across two lab clients and record whether `aud`, `exp`, `iat`, authorization-code client id, and refresh-token client id are enforced.
- Positive proof is a cross-org canary association, a denied-network bypass callback to infrastructure you control, or a token/code accepted by the wrong lab client under documented preconditions.
- Do not target internal hosts, metadata services, real users, or production tenant objects.

## Reporting heuristics

- Title findings around the crossed boundary: **OCI label to host container flags**, **workspace env to cloud CLI execution**, **inline shell parser to skipped allowlist**, **unauthenticated agent API to tool invocation**, **approval-page input to dangerous-tool approval**, **chat message to approval-state confusion**, **workspace path abstraction to out-of-root file read**, **MCP SSE transport to unauthenticated tool invoke**, **agent URL guard to redirected/rebound SSRF**, **revoked pairing session to restored node authority**, **parsed body to backend multipart injection**, **Host superstring to backend route bypass**, **HTTP request data to mock expression execution**, **prototype-polluted filename to worker import**, **document resource to converter SSRF**, **custom resource to cross-namespace Secret RBAC**, **IdP URL setting to denylist bypass SSRF**, or **OIDC code/token accepted by wrong client**.
- Keep impact bounded by observed canaries. Avoid claiming host compromise, cluster takeover, tenant breach, or credential theft unless the customer explicitly approved that proof and the synthetic evidence demonstrates the same path.
- Include exact versions, route/config snippets, the lower-trust input, the privileged consumer, positive and negative controls, and redacted request/response or Kubernetes object evidence.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. JLine Telnet resource exhaustion, NCalc factorial DoS, Jodit generic prototype pollution, Hydro session-expiration behavior, TinaCMS/Jodit rich-text XSS, and ZITADEL low-severity object leakage were tracked in state but not promoted separately because the page above focuses on stronger replayable agent, proxy, render, Kubernetes, and identity-provider trust boundaries. The ProjectDiscovery RSS body hash changed without a new item in the top feed entries, and CISA KEV remained unchanged.
