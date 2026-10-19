# Upload, vector-store, JDBC, and NiFi execution-boundary batch

Source: GitHub Security Advisories updated 2026-05-14.

This batch links four different routes to the same durable lesson: helper APIs that look like data plumbing often cross into execution, storage, or policy enforcement. MIME checks, vector-store filters, JDBC URL parameters, and optional service components need the same explicit trust boundary as a shell, SQL query, or plugin loader.

## Advisories covered

- **Strapi Upload Plugin MIME validation bypass via Content API** — [GHSA-pcw7-5633-82vv](https://github.com/advisories/GHSA-pcw7-5633-82vv): Content API uploads bypassed administrator-configured upload MIME allow/deny rules that were enforced on the Admin Panel upload path. Affected `@strapi/upload <=5.33.2`; update to Strapi `>=5.33.3`.
- **Spring AI vector-store filter-expression injection** — [GHSA-v632-2m87-7469](https://github.com/advisories/GHSA-v632-2m87-7469): `MilvusVectorStore#doDelete(List)` and related vector-store packages built filter expressions from unsanitized document IDs. Affected Spring AI 1.0.x before 1.0.7 and 1.1.x before 1.1.6.
- **Amazon Redshift JDBC unsafe class loading RCE** — [GHSA-wmmv-vvg5-993q](https://github.com/advisories/GHSA-wmmv-vvg5-993q): Redshift JDBC driver versions before 2.2.2 could load arbitrary classes while processing certain connection URL parameters, allowing code execution when an attacker can influence JDBC URLs.
- **Apache NiFi TinkerpopClientService missing execute-code restriction** — [GHSA-2j9m-25xv-mp6r](https://github.com/advisories/GHSA-2j9m-25xv-mp6r): the optional graph service component lacked the Restricted annotation requiring Execute Code permission, allowing users without that permission to configure Groovy bytecode submission when the extension was installed.

## Operator triage

1. Patch exposed Strapi, Spring AI, Redshift JDBC, and NiFi installations on internet-facing, tenant-facing, or data-pipeline paths first.
2. Search for alternate upload routes, API-only upload clients, custom vector-store delete helpers, user-editable JDBC connection strings, and NiFi optional NARs that were deployed but treated as low-risk utilities.
3. Review audit logs for disallowed MIME uploads through Content API routes, suspicious vector delete filters, unusual Redshift JDBC URL parameters, and NiFi service configuration changes by users lacking execute-code authority.
4. For NiFi, remove unused optional extension bundles where possible; for JDBC, make connection descriptors operator-owned configuration rather than tenant/project input.

## Durable controls

- Enforce upload policy in one shared server-side path used by every route, not only in the admin UI path.
- Build vector/database filters with structured parameters or escaped identifiers; never interpolate user-controlled IDs into expression languages.
- Treat JDBC URLs and driver parameters as code-adjacent configuration. Do not let untrusted users supply arbitrary connection properties.
- Permission-gate components by their maximum capability. A service that can run Groovy is an execute-code surface even if its everyday use looks like graph querying.

## October 19 07:1xZ follow-up: openGauss-connector-jdbc — `logger` connection property instantiates any class before the type check (4fmq/CVE-2026-111440 high, 1.1.0 through 6.0.6 + 7.0.0-RC1–RC3, fixed 7.0.0-LTS)

`LogFactory` in openGauss's pgjdbc fork takes the `logger` class name straight from the JDBC URL / connection properties, calls `Class.forName` on it, and **immediately reflectively invokes any `String`-argument constructor** — the `asSubclass(Log.class)` check lands only *after* construction, so a non-`Log` class still runs its constructor side effects before the cast rejects it. With attacker-controlled connection properties plus a loadable gadget-ish class on the client classpath, this is unintended client-side class loading and constructor execution. Fix PR #423 just moves `asSubclass` before instantiation.

This is the **third independent GHSA on this page's class** (Redshift JDBC connection-URL class loading RCE, this logger-property leg, plus the Avatica `Class.forName` plugin leg tracked on the September 22 Lantronix page) — the JDBC connection-property class-loading family keeps producing hits, which validates it as a standing scan class rather than three coincidences.

Durable axes:

- **Every connection property whose value is a class name is a code-loading sink.** Fingerprint by grepping driver/tooling sources for `Class.forName(` fed from `Properties`/URL parameters: `logger`, `sslfactory`, `socketFactory`, `sslhostnameverifier`, `authenticationPluginClassName`, `loadBalancePlugin`, `handler`-style plugin properties are the standard set inherited from the Postgres/mysql drivers. `asSubclass` *after* the constructor runs is a real, repeatable defect shape — check not just whether a type check exists, but whether it precedes the first side-effecting call (`newInstance`, static initializer, `String`-ctor reflection).
- **Who supplies the connection string is the trust question.** App-server datasource registration UIs, workflow/BI tools that let tenants paste JDBC URLs, shared-notebook datasource configs, and connection-string relays in managed-data platforms all put this property within reach of low-priv users. The vulnerable runtime is the *client* (app server, notebook kernel, CI runner) — pivot value is high because those processes usually hold the network credentials.
- **Fleet fingerprint:** openGauss deployments pinning `opengauss-jdbc` ≤ 6.0.6 (vendor band includes 2.x/3.x/5.x/6.x since 1.1.0); the fork's `org.postgresql` package namespace means scanner greps matching `org.postgresql` alone will conflate it with upstream pgjdbc — check the artifact groupId.
- **Bounded proof:** lab datasource, point `logger=` at an inert class outside `Log` whose constructor only writes a marker file or prints; positive = marker reached, negative = fixed build rejects before ctor; never construct a class with real side effects on shared systems.
