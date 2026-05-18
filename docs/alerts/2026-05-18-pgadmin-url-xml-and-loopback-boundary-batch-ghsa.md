# pgAdmin, URL, XML, and loopback-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-4rhg-h8f2-v4jm](https://github.com/advisories/GHSA-4rhg-h8f2-v4jm),
[GHSA-hv9p-2pqf-r5w3](https://github.com/advisories/GHSA-hv9p-2pqf-r5w3),
[GHSA-hr4r-fwpv-c95j](https://github.com/advisories/GHSA-hr4r-fwpv-c95j),
[GHSA-p58c-q354-6c4f](https://github.com/advisories/GHSA-p58c-q354-6c4f),
[GHSA-6p2c-69cv-3fxq](https://github.com/advisories/GHSA-6p2c-69cv-3fxq),
[GHSA-j74f-g7vx-fh4x](https://github.com/advisories/GHSA-j74f-g7vx-fh4x),
[GHSA-hp84-p2gq-6fvr](https://github.com/advisories/GHSA-hp84-p2gq-6fvr),
[GHSA-5rv5-xj5j-3484](https://github.com/advisories/GHSA-5rv5-xj5j-3484),
[GHSA-cr42-rg2m-mq4q](https://github.com/advisories/GHSA-cr42-rg2m-mq4q),
[GHSA-5cvp-p7p4-mcx9](https://github.com/advisories/GHSA-5cvp-p7p4-mcx9), and
[GHSA-q2pj-8v84-9mh5](https://github.com/advisories/GHSA-q2pj-8v84-9mh5).

This batch is durable because it clusters around admin tools and parsers that cross boundaries on behalf of trusted operators: session stores deserialize server-side data, file managers follow links, import/export helpers reach shells or SQL, URL clients mis-scope destinations, XML backends expand entities, and reverse proxies accidentally turn loopback-only trust into public API access.

## What changed

- pgAdmin 4 advisories covered FileBackedSessionManager deserialization, weak authentication throttling, symbolic-link path traversal in File Manager, LFI/SSRF, stored XSS in Browser Tree and Explain Visualizer, command injection in Import/Export query export, and SQL injection in the Maintenance Tool.
- Faraday's prior fix for host scoping was incomplete for protocol-relative URI objects, so URL policy code could still treat attacker-controlled destinations as in-scope.
- Docling's JATS XML backend was vulnerable to XML entity expansion/XXE-style attacks when parsing hostile journal XML.
- Neotoma exposed Inspector/API access through a reverse-proxy loopback-auth bypass when deployments trusted loopback headers or routing assumptions too broadly.
- Arcane added a reflected SVG color-parameter XSS path that can become admin account takeover when an administrator views the crafted route.

## Operator triage

1. Inventory exposed admin consoles and helper features:
   - pgAdmin 4 deployments with File Manager, Import/Export, Maintenance Tool, saved sessions, or externally reachable login.
   - Faraday consumers that enforce `allowed_hosts`, webhook allowlists, proxy scoping, or SSRF guardrails around user-supplied URI objects.
   - Docling pipelines that ingest JATS/XML from uploads, feeds, papers, tickets, or untrusted storage.
   - Neotoma/Arcane deployments behind reverse proxies, especially when admin users browse untrusted links.
2. Treat pgAdmin findings as a single admin-tool boundary review, not isolated CVEs. A low-privileged database user who can reach file, export, or maintenance helpers may chain read, write, command, and SQL primitives.
3. For pgAdmin session deserialization, rotate Flask/session secrets and invalidate existing server-side session files if untrusted users could influence session storage or after a suspected compromise.
4. For Faraday and similar URL clients, test protocol-relative values (`//host/path`), mixed URI object/string flows, redirects, DNS rebinding, IPv4-mapped IPv6, link-local, loopback, and RFC1918 targets.
5. For Docling, disable external entities and DTDs at the parser factory, then bound entity expansion, input size, nesting depth, and fetch behavior in a regression fixture.
6. For loopback-auth designs, make the reverse proxy inject a signed internal identity header only after authentication, strip all inbound copies, and reject direct backend exposure.

## Replayable validation boundaries

- **Admin file boundary:** create symlinks, nested escapes, absolute paths, and encoded traversal paths in a disposable workspace; file managers must stay under the configured root after final path resolution.
- **Shell/SQL boundary:** pass metacharacters and stacked-query probes through export and maintenance helpers; command execution must use argv arrays and database APIs must preserve parameterization.
- **URL boundary:** normalize scheme-relative and object-wrapped URLs before policy checks; enforce policy on the final socket address after DNS and redirects.
- **XML boundary:** include a harmless local entity and exponential-entity fixture; parsing must fail closed without outbound network fetches or excessive expansion.
- **Reverse-proxy boundary:** send forged loopback, forwarded, and internal-auth headers from the public side; the backend must not infer trust from client-controlled headers.
- **Admin XSS boundary:** render untrusted labels, colors, summaries, and SVG parameters as text or sanitize after all decoding and transformation steps.

## Durable controls

- Keep admin helper surfaces behind explicit role checks and separate high-risk file, import, export, and maintenance permissions from ordinary database access.
- Never deserialize session or cache contents unless the storage path, format, signer, and object types are strictly controlled.
- Resolve filesystem and URL targets to canonical final destinations before authorization or allowlist decisions.
- Disable XML external entities by default and add parser-level resource caps for every document-ingestion backend.
- Make reverse-proxy trust cryptographic or mTLS-backed, not source-IP or loopback-header based.
- Add adversarial regression tests for every bug class fixed here; most of these were bypasses of controls that looked present but were applied at the wrong boundary.
