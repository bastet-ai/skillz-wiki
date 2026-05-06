# App secret, auth, agent, and render-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced application and agent-runtime advisories updated on **2026-05-06** across Lemur, Kimai, LiteLLM, MetaGPT, Pimcore, Grafana, MCP URL fetchers, mkdocs-mcp-plugin, kaggle-mcp, and auto-favicon.

## Advisories covered

- **Lemur LDAP TLS verification disabled globally** — [GHSA-vr7c-r5gj-j3w5](https://github.com/advisories/GHSA-vr7c-r5gj-j3w5): enabling LDAP TLS disabled certificate verification, exposing LDAP credentials and identity assertions to interception.
- **Kimai template secret exposure** — [GHSA-vrqv-52x7-rm4v](https://github.com/advisories/GHSA-vrqv-52x7-rm4v): invoice/export Twig templates could call `config()` and leak server-wide secrets such as LDAP bind passwords or SAML SP private keys.
- **Kimai missing voter check** — [GHSA-9g2q-w3w2-vf7q](https://github.com/advisories/GHSA-9g2q-w3w2-vf7q): cross-team timesheet manipulation due to missing authorization checks.
- **LiteLLM unrestricted proxy config endpoint** — [GHSA-53mr-6c8q-9789](https://github.com/advisories/GHSA-53mr-6c8q-9789): proxy configuration changes could enable privilege escalation.
- **MetaGPT injection** — [GHSA-g977-h85w-h2xj](https://github.com/advisories/GHSA-g977-h85w-h2xj): agent/runtime injection risk.
- **Pimcore authenticated XSS and SQL injection** — [GHSA-7gxw-q9j5-mrj4](https://github.com/advisories/GHSA-7gxw-q9j5-mrj4), [GHSA-c8g3-x47w-8q7p](https://github.com/advisories/GHSA-c8g3-x47w-8q7p).
- **Grafana custom frontend plugin XSS** — [GHSA-q53q-gxq9-mgrj](https://github.com/advisories/GHSA-q53q-gxq9-mgrj).
- **MCP and helper path/SSRF issues** — [mkdocs-mcp-plugin path traversal GHSA-wfr3-hf93-qgg3](https://github.com/advisories/GHSA-wfr3-hf93-qgg3), [kaggle-mcp path traversal GHSA-q882-jc55-6343](https://github.com/advisories/GHSA-q882-jc55-6343), [mcp-url-downloader SSRF GHSA-h7xc-4mv8-59fj](https://github.com/advisories/GHSA-h7xc-4mv8-59fj), and [auto-favicon SSRF GHSA-vmh7-9c7h-2pgg](https://github.com/advisories/GHSA-vmh7-9c7h-2pgg).

## Why this is durable

Admin templates, plugin frontends, agent tools, and proxy configuration endpoints are all extensibility surfaces. If they can read global config, fetch URLs, traverse files, or mutate routing without narrow policy, they become privilege-escalation paths even when only authenticated users can reach them.

## Immediate triage

1. Patch affected products and review exposure of admin/template/plugin/agent endpoints.
2. Rotate LDAP, SAML, API, model-provider, and database secrets if templates, plugins, logs, or agent outputs could have disclosed them.
3. Search logs for template calls to configuration helpers, proxy-config mutations, MCP file reads, SSRF attempts to metadata/loopback, and suspicious plugin asset loads.
4. Add authorization checks at object/team scope for Kimai/Pimcore-like multi-tenant actions; do not rely on route-level authentication only.
5. Disable or sandbox untrusted plugins and MCP tools until path, egress, and argument policies are explicit.

## Durable controls

- Separate admin customization from global secret access: templates and plugins should receive a narrow data model, not process config.
- Put agent tools behind capability descriptors: explicit roots for file access, positive egress allowlists, and audited config mutation verbs.
- Treat authenticated XSS in admin panels as credential and server-side action compromise; pair CSP with strict output encoding and plugin signing.
- Require per-object authorization voters/checks on every mutating endpoint, export, and background job.
