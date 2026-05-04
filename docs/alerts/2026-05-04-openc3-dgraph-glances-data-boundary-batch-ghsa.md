# OpenC3, Dgraph, and Glances data-boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST fallback surfaced a 2026-05-04 batch where observability, graph database, and monitoring interfaces exposed or modified sensitive operational data through incomplete query, CORS, debug, and session boundaries.

## Advisories in this batch

- **OpenC3 COSMOS QuestDB SQL injection** — `openc3` `>= 6.7.0, < 7.0.0-rc3` builds TSDB SQL with unsanitized input, allowing authenticated remote telemetry disclosure or deletion. Fixed in **7.0.0-rc3**. References: <https://github.com/advisories/GHSA-v529-vhwc-wfc5>, CVE-2026-42087.
- **OpenC3 COSMOS self-XSS in Command Sender** — `openc3 < 7.0.0` uses unsafe `eval()` on array-like command parameters, allowing script execution in the authenticated browser context if an attacker can influence command input. Fixed in **7.0.0**. References: <https://github.com/advisories/GHSA-ffq5-qpvf-xq7x>, CVE-2026-42086.
- **OpenC3 COSMOS plugin config arbitrary writes within shared plugin tree** — `openc3 < 6.10.5` and `>= 7.0.0.pre.rc1, < 7.0.0-rc3` allow crafted config filenames to create or overwrite files under the shared `/plugins` root. Fixed in **6.10.5** and **7.0.0-rc3**. References: <https://github.com/advisories/GHSA-4jvx-93h3-f45h>, CVE-2026-42085.
- **OpenC3 COSMOS session-token password reset persistence** — `openc3 < 6.10.5` and `>= 7.0.0.pre.rc1, < 7.0.0-rc3` allow a valid hijacked session token to reset the account password without the old password, turning token theft into persistent account takeover. Fixed in **6.10.5** and **7.0.0-rc3**. References: <https://github.com/advisories/GHSA-wgx6-g857-jjf7>, CVE-2026-42084.
- **Dgraph admin token disclosure via `/debug/vars`** — `github.com/dgraph-io/dgraph/v25 < 25.3.3`, older v24 lines, and legacy `github.com/dgraph-io/dgraph` expose command-line arguments through unauthenticated expvar, leaking admin tokens commonly passed via startup flags. Fixed in **25.3.3** for v25. References: <https://github.com/advisories/GHSA-vvf7-6rmr-m29q>, CVE-2026-41492.
- **Dgraph pre-auth DQL injection through NQuad language tags** — affected Dgraph default configurations without ACL can allow unauthenticated database exfiltration through crafted `/alter` and `/mutate?commitNow=true` requests. Fixed in **25.3.3** for v25. References: <https://github.com/advisories/GHSA-x92x-px7w-4gx4>, CVE-2026-41328.
- **Dgraph pre-auth DQL injection through upsert condition fields** — affected Dgraph default configurations without ACL can allow unauthenticated full database read through crafted upsert `cond` injection. Fixed in **25.3.3** for v25. References: <https://github.com/advisories/GHSA-mrxx-39g5-ph77>, CVE-2026-41327.
- **Glances REST API permissive CORS information disclosure** — `Glances < 4.5.4` exposes unauthenticated `/api/4/*` data cross-origin with `Access-Control-Allow-Origin: *`, allowing a malicious website to read local or internal Glances data through a victim browser. Fixed in **4.5.4**. References: <https://github.com/advisories/GHSA-gfc2-9qmw-w7vh>, CVE-2026-34839.

## Why this is durable

Operational interfaces are often deployed “inside” trusted networks, but browsers, debug handlers, session tokens, and query builders ignore that comfort boundary.

- Monitoring APIs leak sensitive topology when CORS and auth are permissive.
- Debug endpoints leak secrets when command-line flags are treated as safe runtime metadata.
- Query languages need structural parameterization, not string concatenation with cosmetic filtering.
- A session token is not proof the user knows the current password or should gain durable persistence.
- Shared plugin trees are cross-tenant write surfaces unless file ownership and namespace boundaries are explicit.

## Immediate triage

1. **Patch exposed systems:** upgrade OpenC3 to fixed 6.10.5/7.0.0-rc3/7.0.0 lines as applicable, Dgraph v25 to **25.3.3+**, and Glances to **4.5.4+**.
2. **Block debug and monitoring endpoints:** deny public access to Dgraph `/debug/*`, `/alter`, `/mutate`, and Glances `/api/4/*`; require authentication even on internal networks.
3. **Rotate Dgraph admin tokens:** if tokens were passed on the command line or debug handlers were reachable, rotate them and remove token values from process args where possible.
4. **Review OpenC3 account integrity:** invalidate sessions after patching; investigate password resets that occurred without normal old-password verification.
5. **Constrain plugin writes:** review OpenC3 `/plugins` tree changes for unexpected config paths, overwrites, or cross-plugin writes.

## Hunt ideas

- Search Dgraph access logs for `/debug/vars`, `/debug/pprof/cmdline`, `/alter`, `/mutate?commitNow=true`, suspicious `@lang` fields, and upsert `cond` payloads.
- Query reverse-proxy and browser telemetry for Glances `/api/4/` reads with unexpected `Origin` or `Referer` headers.
- Inspect OpenC3 QuestDB logs for unusual statements, stacked query markers, telemetry table deletion, or broad data reads.
- Review OpenC3 authentication logs for session-token reuse, password changes shortly after suspicious browser activity, and Command Sender payloads containing script syntax.
- Compare plugin config mtimes and paths against expected plugin ownership.

## Durable controls

- Never expose debug muxes by default. Bind them to localhost or an admin-only listener, and scrub command-line secrets from runtime metadata.
- Treat unauthenticated database mutation endpoints as critical findings even when documentation says “development” or “default.”
- Use parameterized query builders or AST-level allowlists for DQL/SQL-like languages.
- Apply CORS as a data exfiltration control: wildcard origins are unsafe for APIs that can reveal host, process, network, or user data.
- Require old-password proof, fresh MFA, or equivalent step-up auth for password changes, even when a session token is valid.
- Give plugin/config namespaces explicit ownership; canonicalization alone does not stop cross-plugin overwrites inside a shared root.

## Operator lesson

When auditing admin or monitoring products, test from three positions: unauthenticated network client, malicious webpage in an authenticated user's browser, and low-privileged authenticated user. Many “internal-only” data-boundary bugs appear only when those three views are combined.
