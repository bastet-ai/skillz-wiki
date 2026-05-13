# Template, render, CMS, and execution-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

Renderer, CMS, and documentation/tooling advisories keep showing the same failure mode: helper APIs cross from data into executable, file-system, or browser contexts unless the boundary is explicit and regression-tested.

## Advisories covered

- **Kyverno policy-reporter-ui stored property XSS** — [GHSA-q98m-7w8c-w388](https://github.com/advisories/GHSA-q98m-7w8c-w388): stored property values reached the PropertyCard component as executable browser content.
- **Sandboxed Thymeleaf expression bypass** — [GHSA-c9ph-gxww-7744](https://github.com/advisories/GHSA-c9ph-gxww-7744): unauthorized syntax patterns were not recognized by the sandbox boundary.
- **Mako TemplateLookup Windows traversal** — [GHSA-2h4p-vjrc-8xpq](https://github.com/advisories/GHSA-2h4p-vjrc-8xpq): backslash URI handling could escape intended template roots on Windows.
- **Hugo Node tool execution outside project** — [GHSA-x597-9fr4-5857](https://github.com/advisories/GHSA-x597-9fr4-5857): Node-based tooling could access files outside the site project directory.
- **Statamic forgot-password enumeration** — [GHSA-m24v-f7g5-gq67](https://github.com/advisories/GHSA-m24v-f7g5-gq67): account existence leaked through the reset flow.
- **Scramble validation-rule evaluation RCE** — [GHSA-4rm2-28vj-fj39](https://github.com/advisories/GHSA-4rm2-28vj-fj39): user-controlled validation rules reached evaluation paths.
- **Low-privileged Grav API super-admin creation** — [GHSA-6xx2-m8wv-756h](https://github.com/advisories/GHSA-6xx2-m8wv-756h): blueprint upload let a low-privileged API user cross into super-admin account creation.
- **Craft CMS AssetsController permission miss** — [GHSA-33m5-hqp9-97pw](https://github.com/advisories/GHSA-33m5-hqp9-97pw): missing volume checks exposed asset information.
- **Craft CMS attached-behavior RCE** — [GHSA-qrgm-p9w5-rrfw](https://github.com/advisories/GHSA-qrgm-p9w5-rrfw): malicious attached behavior could become authenticated remote code execution.
- **Craft CMS GraphQL address resolver PII disclosure** — [GHSA-gj2p-p9m4-c8gw](https://github.com/advisories/GHSA-gj2p-p9m4-c8gw): authorization was missing across address-resolution scopes.
- **LobeHub XSS to RCE** — [GHSA-xq4x-622m-q8fq](https://github.com/advisories/GHSA-xq4x-622m-q8fq): browser script execution could escalate into local/desktop execution impact.
- **YAFNET thread stored XSS** — [GHSA-8rq5-wwpp-fmj2](https://github.com/advisories/GHSA-8rq5-wwpp-fmj2): forum posts and replies could execute JavaScript for all viewers.
- **YAFNET event-log second-order XSS** — [GHSA-33gv-fc78-qgf5](https://github.com/advisories/GHSA-33gv-fc78-qgf5): the User-Agent header became stored script content in admin event logs.

## Operator triage

1. Patch affected packages and hosted services first where the vulnerable component is internet-facing, tenant-facing, or reachable by untrusted project data.
2. Inventory transitive exposure; many of these bugs live in helpers, plugins, middleware, scanner images, or framework defaults rather than application code.
3. Search logs for boundary probes: encoded paths, unusual headers, oversized bodies, duplicate auth attempts, symlinked project files, private-network URLs, and stored HTML/script payloads.
4. Add regression tests at the trust boundary, not only at the direct vulnerable function. Exercise canonicalized paths, redirects, alternate address syntax, concurrent auth, and malformed protocol inputs.

## Durable controls

- Canonicalize once, authorize after canonicalization, and execute/use only the canonicalized object.
- Give every parser, helper, cache, upload, range handler, and HTTP client explicit byte, item, time, and recursion budgets.
- Treat user-controlled templates, package metadata, project files, identity headers, event fields, and backup archives as untrusted code-adjacent inputs.
- Prefer positive allowlists tied to resolved identities/resources over deny-lists tied to raw input strings.

