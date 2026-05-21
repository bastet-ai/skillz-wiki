# Tekton git resolver and Network-AI MCP boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-21.

This batch is durable because it turns two fresh advisories into replayable operator checks for CI/CD resolver argument injection, resolver service-account blast radius, localhost MCP cross-origin tool invocation, and default-secret drift in agent tooling.

## What changed

- **Tekton Pipelines git resolver argument injection to pod RCE** — [GHSA-94jr-7pqp-xhcq](https://github.com/advisories/GHSA-94jr-7pqp-xhcq) / CVE-2026-40938: the git resolver passed the user-controlled `revision` parameter directly to `git fetch origin <revision> --depth=1`. Because Git parses flag-looking refspecs, a tenant who can create `ResolutionRequest` objects could supply values such as `--upload-pack=<binary>`. The advisory also notes that repository URL validation allowed local filesystem paths, which makes the primitive more practical inside the resolver pod. The vulnerable resolver service account commonly has cluster-wide `get/list/watch` on Secrets, so pod execution becomes a cluster-secret exposure path.
- **Network-AI unauthenticated cross-origin MCP tool invocation** — [GHSA-j3vx-cx2r-pvg8](https://github.com/advisories/GHSA-j3vx-cx2r-pvg8) / CVE-2026-46701: `network-ai` MCP SSE server defaulted `NETWORK_AI_MCP_SECRET` to an empty string, and the authorization guard treated an empty secret as authorized. The same transport returned `Access-Control-Allow-Origin: *`, so a malicious web page could invoke localhost MCP tools when a user had the default server running. Exposed tools include configuration writes, agent spawning, and blackboard writes.

## Operator triage

1. Search target inventories for Tekton Pipelines resolver deployments using the git resolver, especially multi-tenant clusters where users can submit `ResolutionRequest`, `TaskRun`, or `PipelineRun` resources.
2. For Tekton, collect the resolver controller image/version, resolver feature flags, tenant RBAC for resolver-backed runs, allowed resolver parameters, egress controls, mounted binaries, and the resolver service-account permissions. Pay special attention to cluster-wide Secret read permissions.
3. Search developer workstations, internal agent platforms, and localhost MCP launch scripts for `network-ai <= 5.4.4`, `NETWORK_AI_MCP_SECRET` unset/empty, SSE transport enabled, or browser-accessible localhost ports.
4. For Network-AI, enumerate exposed MCP tools and classify which tools can mutate config, start agents, write files/state, call network targets, or persist attacker-controlled instructions.

## Replayable validation boundaries

- **Tekton argument-injection proof:** in an explicitly authorized lab namespace, submit a disposable resolver request whose `revision` begins with a benign Git option that produces an observable non-sensitive effect, or points `--upload-pack` at a harmless owned binary in a lab resolver image. Vulnerable result: `git fetch` interprets the revision as an option rather than a ref. Do not execute arbitrary production binaries or access production Secrets.
- **Tekton blast-radius proof:** after proving argument control in a lab, document resolver service-account permissions with Kubernetes authorization checks or redacted RBAC manifests. If token exposure validation is authorized, use a throwaway secret and capture only the minimum proof that the resolver pod could read it.
- **Network-AI localhost proof:** with a lab browser profile and a default-configured local server, host a benign HTML page that performs a cross-origin request to the MCP SSE endpoint for a harmless read-only or marker-write tool. Vulnerable result: the browser can read the response or trigger the tool without an `Authorization` header.
- **Network-AI tool-control proof:** prefer low-impact actions such as writing a marker to a test blackboard or toggling a disposable config key. Do not spawn agents, run shell-capable tools, or modify real user configuration unless the scope explicitly allows it.

## Reporting heuristics

- Frame Tekton findings as a tenant-controlled resolver parameter crossing into Git process arguments, then into resolver-pod execution and shared service-account privilege.
- Include exact resolver versions, tenant role needed, resolver parameters accepted, service-account permissions, pod security context, egress assumptions, and a redacted proof artifact.
- Frame Network-AI findings as browser-origin to localhost MCP tool-control caused by empty-secret defaults plus wildcard CORS, not merely as “missing auth.”
- Include the local bind address/port, server launch path, whether the secret was unset or empty, tool list, and one harmless cross-origin invocation proof.
- Keep proofs scoped to marker writes, controlled callbacks, or authorization checks; avoid collecting real cluster Secrets, production tokens, or personal workstation data.
