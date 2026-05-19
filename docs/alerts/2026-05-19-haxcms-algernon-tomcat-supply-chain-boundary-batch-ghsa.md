# HAXcms, Algernon, Tomcat, and supply-chain boundary batch

Source: GitHub Security Advisories, updated 2026-05-19:
[GHSA-x3x5-7h4h-gwxg](https://github.com/advisories/GHSA-x3x5-7h4h-gwxg),
[GHSA-jh3h-rpxg-fr36](https://github.com/advisories/GHSA-jh3h-rpxg-fr36),
[GHSA-6c8g-9hfh-pq5h](https://github.com/advisories/GHSA-6c8g-9hfh-pq5h),
[GHSA-4fg7-f244-3j49](https://github.com/advisories/GHSA-4fg7-f244-3j49),
[GHSA-2m6p-hm3w-6jm3](https://github.com/advisories/GHSA-2m6p-hm3w-6jm3),
[GHSA-q862-gcgq-5m6g](https://github.com/advisories/GHSA-q862-gcgq-5m6g),
[GHSA-9v4j-7g44-qcqw](https://github.com/advisories/GHSA-9v4j-7g44-qcqw),
[GHSA-xwcr-wm99-g9jc](https://github.com/advisories/GHSA-xwcr-wm99-g9jc),
[GHSA-fwqx-8365-9983](https://github.com/advisories/GHSA-fwqx-8365-9983),
[GHSA-24c8-4792-22hx](https://github.com/advisories/GHSA-24c8-4792-22hx),
[GHSA-27f5-xjrr-q9ff](https://github.com/advisories/GHSA-27f5-xjrr-q9ff),
[GHSA-65pc-fj4g-8rjx](https://github.com/advisories/GHSA-65pc-fj4g-8rjx),
[GHSA-5m62-pw8w-7w9f](https://github.com/advisories/GHSA-5m62-pw8w-7w9f), and
[GHSA-9m89-8frq-c98c](https://github.com/advisories/GHSA-9m89-8frq-c98c).

This batch is durable because the same defensive pattern spans CMS editors, static-file helpers, template engines, dependency feeds, hostname validation, and app servers: code that bridges trust boundaries must not expose secrets to browser script, walk above its root, forward credentials on partial host matches, or process attacker-sized strings before limits are enforced.

## What changed

- **HAXcms / HAX open-apis** fixed a cluster of high-impact web boundary issues in `26.0.0`: stored XSS through `<iframe>` and `<video-player>` attributes, client-side exposure of JWT/session/site/appstore tokens through `window.appSettings`, a broken Node.js HMAC helper that appended the private signing key to generated tokens, authenticated `createSite` SSRF/local-file import, and substring-only hostname checks that could forward Basic credentials to attacker-controlled domains.
- **Algernon** fixed three server-root and debug-mode boundary flaws in `1.17.7`: `handler.lua` discovery could walk above the configured server root and execute a parent-directory handler pre-auth; single-file mode forced debug error pages that dump server-side source; and auto-refresh Server-Sent Events could bind broadly and stream filesystem event names without authentication.
- **Scriban** fixed `array.insert_at` unbounded fill allocation in `7.2.0`. A template author could bypass `LoopLimit` and string/recursion limits with a huge insert index, driving host-process memory exhaustion.
- **OpenSearch JavaScript client** disclosed malicious npm releases of `@opensearch-project/opensearch` versions `3.5.3`, `3.6.2`, `3.7.0`, and `3.8.0` after an external actor gained force-push capability in project CI. Hosts that installed those versions during the compromise window should be treated as fully compromised.
- **Python `idna`** fixed an incomplete CVE-2024-3651 remediation in `3.15`; oversized crafted contextual-codepoint inputs could consume significant CPU before length rejection.
- **Apache Tomcat** fixed security-constraint and AJP-secret handling issues in `9.0.118`, `10.1.55`, and `11.0.22`. The critical item is extension-pattern method constraints where only the first matching method constraint was applied; the lower-severity AJP issue used non-constant-time secret comparison.

## Operator triage

1. Upgrade HAXcms / HAX packages to `26.0.0` or later. Treat pre-upgrade browser tokens, site tokens, appstore tokens, and signing keys as exposed if untrusted authors could create content or hit `/system/api/connectionSettings`.
2. Search HAX content for dangerous component attributes and schemes: `<iframe src=...>`, `srcdoc`, `<video-player source=...>`, `source-data`, `javascript:`, `data:`, and unexpected external URLs. Remove suspect pages before relying on patching alone.
3. Audit HAX/open-apis server-side fetches and import workflows for loopback, metadata, `file://`, internal CIDR, and attacker-controlled hostnames. Rebuild allowlists with canonical URL parsing and exact host/suffix matching, not substring checks.
4. Upgrade Algernon to `1.17.7` or later. Until patched, avoid single-file serving for anything reachable by others, disable auto-refresh listeners, and ensure no writable parent directory of the served root contains `handler.lua`.
5. Upgrade Scriban to `7.2.0` or later anywhere users, tenants, plugins, or CMS authors can submit templates. Add request-level memory/time limits around template rendering even after upgrading.
6. For `@opensearch-project/opensearch`, identify installs of `3.5.3`, `3.6.2`, `3.7.0`, or `3.8.0` between 2026-05-12 00:00-10:00 UTC. Rotate secrets from a clean system, rebuild affected hosts, and pin to a known-good package version rather than only uninstalling the package.
7. Upgrade Python `idna` to `3.15` or later, and reject domain names longer than 253 characters before calling IDNA conversion.
8. Patch Tomcat to `9.0.118`, `10.1.55`, or `11.0.22`. Prioritize apps using extension-pattern security constraints, method-specific constraints, AJP, or shared app-server configs across tenants.

## Replayable validation boundaries

- **Browser-token boundary:** stored editor content must not be able to execute script in a victim origin or read live bootstrap tokens. Regression-test component attributes and embedded frames against scheme allowlists, sanitizer output, and HttpOnly/SameSite cookie posture.
- **Signing-key boundary:** token-generation endpoints must never return signing material or reusable secrets. Decode representative tokens in tests and assert they contain only MAC/signature bytes plus expected claims, not key material.
- **Server-side fetch boundary:** importers and API helpers should parse URLs once, canonicalize host/IP after DNS resolution, reject local files and internal ranges by default, and attach credentials only for exact, trusted destinations.
- **Server-root boundary:** request routing must resolve handlers from a trusted root descriptor and stop at the configured root. Parent directories and process working directories are not part of the web app.
- **Debug-output boundary:** demo and single-file modes must not silently enable production-reachable source dumps. Errors should redact paths, source, environment, cookies, and template context unless explicitly running in a local-only debug profile.
- **Template resource boundary:** loop counters are not enough; helper functions that allocate, pad, repeat, insert, or join need independent size caps before allocation.
- **Supply-chain compromise boundary:** malicious package advisories are incident-response events. Package removal is cleanup, not containment, when install scripts or loaded code may already have run.

## Durable controls

- Keep secrets out of browser-readable bootstrap objects. If frontend code needs a capability, scope it to one purpose, one tenant, and one short lifetime.
- Use exact-origin credential rules for outbound requests; never decide whether to attach secrets with substring tests.
- Treat CMS authors, template authors, plugins, and imported site files as untrusted code-adjacent input.
- Put root containment, symlink rejection, and parent-walk stopping rules in reusable filesystem helpers instead of each handler.
- Patch web servers and templating engines as boundary infrastructure. Their bugs silently invalidate application-level assumptions above them.
