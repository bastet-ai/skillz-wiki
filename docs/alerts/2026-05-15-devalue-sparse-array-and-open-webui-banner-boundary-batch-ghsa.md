# devalue sparse-array and Open WebUI banner-boundary batch

**Signal:** The **2026-05-15 02:15 UTC** advisory scan surfaced two high-severity JavaScript render/resource issues: Svelte `devalue` sparse-array deserialization could exhaust memory, and Open WebUI banner Markdown sanitization could let an admin plant XSS that targets higher-privilege admins.

## Advisory cluster

- **Svelte `devalue` sparse-array resource exhaustion** — [GHSA-77vg-94rm-hx3p / CVE-2026-42570](https://github.com/advisories/GHSA-77vg-94rm-hx3p): npm `devalue >=5.6.3, <=5.8.0`, fixed in `5.8.1`, allowed `devalue.parse()` to allocate far more memory than needed when deserializing sparse arrays on some JavaScript engines. The durable boundary is not just parser correctness; serialized data must be bounded before it can force server, worker, or hydration runtimes to materialize attacker-shaped structures.
- **Open WebUI banner stored XSS via sanitize-before-Markdown order** — [GHSA-cqp4-qqvg-3787 / CVE-2026-45665](https://github.com/advisories/GHSA-cqp4-qqvg-3787): `open-webui <=0.7.2`, fixed in `0.8.0`, sanitized banner text with DOMPurify before converting Markdown with `marked`. A malicious or compromised admin could store a banner such as a `javascript:` Markdown link, which was then rendered for other admins, including primary/super-admin users.

## Why this matters

Both advisories are source-to-sink ordering failures. `devalue` accepted compact serialized input that could expand into expensive runtime objects, while Open WebUI sanitized one representation and then transformed it into a different representation before rendering. Security checks need to happen at the representation that reaches the dangerous sink: allocation, merge, hydration, or HTML insertion.

## Triage

1. Upgrade `devalue` to `5.8.1+`; prioritize SSR, server actions, cache hydration, session-state, and worker paths where unauthenticated or cross-tenant data can reach `devalue.parse()`.
2. Add size, depth, array-index, and post-parse allocation budgets around serialized state before accepting it into request, cache, or job-processing paths.
3. Upgrade Open WebUI to `0.8.0+`; if that cannot happen immediately, disable configurable global banners or strip Markdown links until sanitization-after-rendering is verified.
4. Review Open WebUI banner/admin-setting history for Markdown links, `javascript:`, `data:`, event-handler-like content, or suspicious “security update”/login prompts. Rotate admin sessions if malicious banner content may have been displayed.

## Durable controls

- Treat parser output as an allocation boundary: test sparse arrays, deep nesting, huge indexes, cyclic-like shapes, and high fan-out objects under realistic memory limits.
- Sanitize rendered HTML after Markdown or template expansion, not only the raw source text. If a renderer can introduce links, attributes, or HTML, validate the rendered tree before insertion.
- For admin-to-admin content, assume stored XSS can become privilege escalation. Primary admins are high-value victims, not trusted render targets.
- Prefer safe renderer configurations that block raw HTML and dangerous URL schemes, backed by CSP that disables inline script and rejects `javascript:` navigations where possible.
