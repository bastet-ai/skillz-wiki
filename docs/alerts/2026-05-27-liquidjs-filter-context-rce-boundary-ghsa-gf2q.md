# LiquidJS filter-context RCE boundary (GHSA, 2026-05-27)

**Signal:** GitHub Advisory Database published a critical LiquidJS advisory for `GHSA-gf2q-c269-pqgc` / `CVE-2026-45618`: crafted templates can recover engine/context internals through filter evaluation, pivot through comparable-function gadgets, mutate scope/prototype state, and reach arbitrary code execution in Node.js render processes.

Promoted item:

- `GHSA-gf2q-c269-pqgc` / `CVE-2026-45618`: LiquidJS `< 10.26.0` allows attacker-controlled templates to turn `valueOf` / filter-comparison behavior into access to the Liquid context and parser internals. The public advisory demonstrates escalation from context disclosure to function access and process-level command execution.

Use this only in authorized tests. Treat template-RCE validation as high impact: prefer local reproduction, tenant-owned preview environments, or agreed staging systems. Do not run arbitrary commands on production infrastructure; collect reachability/version evidence first and escalate proof only with explicit program approval.

## Operator checklist

### 1. Find reachable untrusted LiquidJS template surfaces

Where to look:

- Applications using `liquidjs < 10.26.0` in Node.js.
- Theme editors, email/SMS template builders, CMS personalization fields, storefront theme previews, workflow-notification templates, and documentation generators that render user-supplied Liquid.
- Products that expose only “safe” Liquid expressions but still evaluate attacker-controlled filters or assignments server-side.
- Existing LiquidJS findings from the May 26-27 batch: `ownPropertyOnly` drift, `strip_html` bypasses, date-filter resource-limit bypasses, and render-limit gaps are useful signals that Liquid is reachable and security-sensitive.

Recon steps:

1. Confirm the package and version from `package-lock.json`, SBOMs, vendor docs, stack traces, JavaScript bundle comments, dependency manifests, or an approved authenticated admin view.
2. Identify whether the attacker controls a full template, a partial, or a stored field that is embedded into a server-rendered Liquid template.
3. Test harmless Liquid evaluation first, for example arithmetic/string markers or a benign `{% assign %}` + echo sequence that proves server-side evaluation without touching host internals.
4. Map privilege and isolation: user role required, tenant boundary, whether the renderer runs in the main web process, worker queue, build job, or sandboxed container.

Reporting heuristic: strong reports show **untrusted template control plus vulnerable LiquidJS version plus server-side render reachability**. Do not lead with a production command-execution attempt when version and reachability already establish high likelihood.

### 2. Validate the context-escape primitive safely

The advisory’s first durable operator lesson is that filter evaluation can expose the Liquid context despite expected property restrictions. For a safe validation path:

1. In a local clone or approved staging environment, render a tiny template that assigns `1|valueOf` and inspects whether the result exposes context-like fields.
2. Confirm whether `ownPropertyOnly: true` or other hardening options are configured globally and per-render; this bug is meaningful because expected property-boundary assumptions can still fail.
3. Capture proof as a redacted object-shape or a boolean marker such as “context object was reachable,” not a dump of environment variables, secrets, files, or process state.
4. If the application strips `inspect` or other helpers, test equivalent low-impact signals that prove the object boundary has been crossed without enumerating sensitive data.

Evidence to capture:

- LiquidJS version and render options.
- The exact user-controlled template field or API request.
- A minimal rendered marker proving context access.
- Whether the render path is unauthenticated, authenticated low-privilege, tenant-scoped, or admin-only.

### 3. Escalate to RCE proof only with explicit scope

For authorized lab or staging validation, the advisory shows that context access can be chained through comparable-function gadgets and parser/loader internals to obtain a JavaScript `Function` constructor and execute Node.js code. Keep escalation proof bounded:

1. Use a disposable environment that mirrors the target’s LiquidJS version and render options.
2. Use a harmless command marker such as writing a UUID to a temporary test file or printing a fixed value to renderer logs. Avoid network callbacks, persistence, credential access, shell history reads, and filesystem enumeration unless explicitly authorized.
3. If the target program allows only non-destructive proof, stop at context escape + vulnerable version + reachable template surface and explain the public RCE chain as impact justification.
4. If a SaaS tenant boundary is involved, verify only inside your tenant-owned template/render surface. Do not test cross-tenant effects or privileged worker context without written approval.

Reporting heuristic: frame the bug as **untrusted Liquid template input reaches Node.js process execution through LiquidJS filter-context escape**. The highest-signal report includes a minimal safe marker, dependency evidence, render-path privilege, worker/container isolation notes, and the concrete business impact of code execution in that render process.

## Non-signal this hour

Reviewed but not promoted as new standalone Skillz guidance:

- CISA KEV advanced to catalog `2026.05.27` with `CVE-2026-48027` Nx Console embedded malicious code, `CVE-2026-45321` TanStack unspecified vulnerability, and `CVE-2026-8398` Daemon Tools Lite embedded malicious code. These are high-signal threat/supply-chain items, but this pass did not turn them into new offensive operator guidance beyond existing Mini Shai-Hulud / TeamPCP / supply-chain coverage.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis hardening article.
- ProjectDiscovery stayed on already-covered Neo / Nuclei / DAST proof-loop material.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [LiquidJS remote code execution (`GHSA-gf2q-c269-pqgc`)](https://github.com/advisories/GHSA-gf2q-c269-pqgc)
- [LiquidJS upstream advisory (`GHSA-gf2q-c269-pqgc`)](https://github.com/harttle/liquidjs/security/advisories/GHSA-gf2q-c269-pqgc)
- [LiquidJS `v10.26.0` release](https://github.com/harttle/liquidjs/releases/tag/v10.26.0)
