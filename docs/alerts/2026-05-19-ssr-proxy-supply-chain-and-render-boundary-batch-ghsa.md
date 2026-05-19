# SSR, proxy, supply-chain, and render-boundary batch

Source: GitHub Security Advisories, updated 2026-05-19:
[GHSA-rfh7-fxqc-q52v](https://github.com/advisories/GHSA-rfh7-fxqc-q52v),
[GHSA-3h23-rrpc-3p87](https://github.com/advisories/GHSA-3h23-rrpc-3p87),
[GHSA-6xwp-cp5h-q856](https://github.com/advisories/GHSA-6xwp-cp5h-q856),
[GHSA-rwhr-h69g-8qmq](https://github.com/advisories/GHSA-rwhr-h69g-8qmq),
[GHSA-xxvj-8g5m-4qgw](https://github.com/advisories/GHSA-xxvj-8g5m-4qgw),
[GHSA-9f66-54xg-pc2c](https://github.com/advisories/GHSA-9f66-54xg-pc2c),
[GHSA-w832-gg5g-x44m](https://github.com/advisories/GHSA-w832-gg5g-x44m),
[GHSA-wjw6-95h5-4jpx](https://github.com/advisories/GHSA-wjw6-95h5-4jpx),
[GHSA-hxwh-jpp2-84pm](https://github.com/advisories/GHSA-hxwh-jpp2-84pm),
[GHSA-f3h9-8phc-6gvh](https://github.com/advisories/GHSA-f3h9-8phc-6gvh),
[GHSA-xrf4-39fm-j5f2](https://github.com/advisories/GHSA-xrf4-39fm-j5f2),
[GHSA-fxmx-pfm2-85m2](https://github.com/advisories/GHSA-fxmx-pfm2-85m2),
[GHSA-fwr5-q9rx-294f](https://github.com/advisories/GHSA-fwr5-q9rx-294f), and
[GHSA-429q-fhh4-r6hj](https://github.com/advisories/GHSA-429q-fhh4-r6hj).

This batch is durable because it crosses the same handful of trust seams in different stacks: server-side rendering adopts attacker-controlled host context, proxy defenses read the wrong client IP, package installation runs hostile code, old storage/control-plane identities leak across tenants, and render/template helpers turn data into authority.

## What changed

- **SSR and server-side fetch context:** `@angular/platform-server` could treat an absolute-form request URL as the current hostname, causing relative `HttpClient` requests or `PlatformLocation.hostname` use to target attacker-controlled origins. Angular added an `allowedHosts` control in render APIs; SSR entrypoints should not inherit host authority from raw request URLs.
- **Proxy and CORS policy gaps:** Caddy Defender evaluated `RemoteAddr` instead of Caddy's trusted-proxy-resolved `client_ip`, allowing blocked clients through a CDN/load balancer. Flask-CORS could emit `Access-Control-Allow-Private-Network: true` by default, expanding browser reach into private-network resources.
- **Supply-chain compromise:** malicious `@beproduct/nestjs-auth` versions `0.1.2` through `0.1.19` carried Mini Shai-Hulud-style postinstall payloads that attempted to harvest npm/GitHub/cloud/SSH secrets and persist via developer tooling. Treat any install during the May 11 window as host and token compromise.
- **Storage and control-plane identity:** OpenStack Nova libvirt/LVM backed instances could expose previous logical-volume contents; Salt minion ID validation allowed directory traversal during minion authentication; Anchor `InterfaceAccount` in `anchor-lang 1.0.0-rc.1` could accept unexpected account types after discriminator checking was disabled.
- **Redirect and URL normalization:** Jupyter Server, Datasette, and other apps had open redirect paths where apparently trusted application URLs could bounce users to attacker-controlled origins. These are most dangerous when combined with token links, auth flows, or trusted-host assumptions.
- **Template, render, and query helpers:** Nautobot Jinja2 computed fields/custom links could expose secrets or mutate data; Gradio accepted user-controlled JSON into a remotely triggerable local file include; Fava and CodeChecker had reflected/stored XSS; legacy Django admin query-string filtering could expose sensitive fields via regex filters.

## Operator triage

1. **Patch the exposed SSR/proxy path first.** Upgrade Angular SSR users in the affected `22.0.0-next.*` range and configure explicit `allowedHosts`; upgrade Caddy Defender to the fixed release and confirm it evaluates the resolved client IP after trusted-proxy processing.
2. **Treat the npm event as compromise, not a version bump.** For any environment that installed affected `@beproduct/nestjs-auth` versions, rotate npm tokens, GitHub tokens, SSH keys, cloud credentials, CI secrets, and check for unexpected workflow/package changes before restoring trust.
3. **Audit private-network browser exposure.** Disable default private-network CORS exposure, review Flask-CORS configurations, and test browser-origin requests against internal admin, metadata, and RFC1918 services.
4. **Recheck render/template sandboxes.** Inventory Nautobot computed fields/custom links, Jinja2 filters, Gradio API file paths, CodeChecker comments, Fava error rendering, and admin query helpers that can reflect or evaluate user input.
5. **Close legacy control-plane cleanup gaps.** Scrub reused LVM-backed images/volumes, reject path separators and traversal in Salt minion IDs before auth, and ensure Anchor programs relying on `InterfaceAccount` are on `1.0.0-rc.2+` with account-type expectations tested.

## Replayable validation boundaries

- **SSR host-boundary test:** send absolute-form and poisoned `Host`/`X-Forwarded-Host` requests through SSR and confirm all server-side relative fetches stay within an allowlisted origin or fail closed.
- **Trusted-proxy client-IP test:** place the app behind the real CDN/load balancer chain, spoof `X-Forwarded-For`, and verify block/allow decisions use only the framework-resolved client IP after trusted proxy rules.
- **Private-network CORS test:** from an untrusted public origin, attempt private-network preflights and internal fetches; expected result is no permissive private-network CORS unless explicitly justified per origin.
- **Package-install incident test:** rebuild a disposable host with the affected npm versions and compare observed filesystem/network/token access patterns against production endpoint telemetry to hunt for matching behavior.
- **Template/render test:** execute template fields, comments, filter parameters, and JSON path inputs with secret-reading, mutation, traversal, and XSS payloads; expected result is sandboxed read-only data rendering with context-specific escaping.

## Durable controls

- Treat SSR request URLs as untrusted input; pass canonical origin/host data into renderers through explicit allowlists rather than deriving authority from raw request lines.
- Enforce proxy-aware client identity in one shared middleware path and make security plugins consume that canonical value.
- Keep install-time code execution out of high-trust environments where possible; pin and verify packages, use isolated builders, and rotate credentials after any postinstall compromise.
- Model redirects, template helpers, and admin query builders as policy surfaces: bind them to allowlisted hosts, read-only sandboxes, typed field maps, and context-aware encoders.
- Scrub storage before reuse and validate node/account identifiers before they reach filesystem paths, authentication decisions, or account-type dispatch.
