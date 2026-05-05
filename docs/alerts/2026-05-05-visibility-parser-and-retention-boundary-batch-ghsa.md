# Visibility, parser, and retention-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because the fixes are all reusable boundary lessons: viewer authorization must be applied to embedded graph/detail data, browser form defenses must understand Fetch Metadata correctly, parser recursion needs explicit limits, unsafe string assumptions break memory safety, and retention policy must reject invalid lifetime inputs.

## Advisories covered

- **Apache Airflow < 3.2.1** — fixed in **3.2.1**:
  - [GHSA-w7rc-q6cm-f5gm](https://github.com/advisories/GHSA-w7rc-q6cm-f5gm): asset dependency graph exposed DAG and asset names outside the viewer's DAG read permissions.
  - [GHSA-p3v3-229h-mc63](https://github.com/advisories/GHSA-p3v3-229h-mc63): authenticated `/ui/dags` endpoint exposed embedded HITL prompts and TaskInstance details for DAGs outside the viewer's per-DAG authorization scope.
- **JupyterHub >= 4.1.0, < 5.4.5** — [GHSA-m68r-v472-jgq9](https://github.com/advisories/GHSA-m68r-v472-jgq9): XSRF protection treated `Sec-Fetch-Mode: no-cors` as same-origin for HTTP form endpoints such as `/hub/spawn` and `/hub/accept-share`. Fixed in **5.4.5**.
- **Diesel < 2.3.8** — [GHSA-h5x4-m2qf-r4f2](https://github.com/advisories/GHSA-h5x4-m2qf-r4f2): SQLite string deserialization used unchecked UTF-8 assumptions for values that can contain arbitrary bytes, violating Rust string safety contracts. Fixed in **2.3.8**.
- **webonyx/graphql-php <= 15.32.2** — [GHSA-r7cg-qjjm-xhqq](https://github.com/advisories/GHSA-r7cg-qjjm-xhqq): recursive descent parser allowed crafted nested GraphQL documents to trigger stack overflow / worker crash. Fixed in **15.32.3**.
- **ots <= 1.21.4** — [GHSA-h5fq-653g-gxrm](https://github.com/advisories/GHSA-h5fq-653g-gxrm): negative `expire` values on `/api/create` could bypass memory-backend secret expiry expectations. Fixed in **1.21.5**.

## Operator triage

### Airflow authorization leaks

1. Upgrade Airflow to **3.2.1+**.
2. Treat graph/detail APIs as authorization-sensitive even when they look read-only or UI-only.
3. Review users with access to at least one DAG and assume they may have learned names, asset topology, HITL prompt parameters, or TaskInstance context for other DAGs.
4. Hunt access logs for asset graph browsing and `/ui/dags` requests by users with narrow DAG scopes.
5. Remove secrets from DAG names, asset names, prompt parameters, and TaskInstance free-form context; these surfaces are often copied into UI/API payloads.

### JupyterHub XSRF bypass

1. Upgrade to **5.4.5+**.
2. If a reverse proxy is in front of JupyterHub, drop requests with `Sec-Fetch-Mode: no-cors` to Hub form endpoints until every Hub is patched.
3. Hunt for cross-origin form POSTs to `/hub/spawn`, `/hub/accept-share`, and other non-JSON form actions.
4. Review unexpected server spawns or accepted shares. The advisory notes attackers could trigger actions but not directly read the victim's server through this path.

### Parser and type-contract failures

1. Upgrade Diesel to **2.3.8+** and webonyx/graphql-php to **15.32.3+**.
2. For Diesel/SQLite, search for code paths that deserialize untrusted or attacker-controlled SQLite `BLOB` data as Rust `str`/`String` and add explicit UTF-8 validation tests.
3. For GraphQL, add maximum nesting depth, token count, document size, and parse-time budgets at the GraphQL boundary, independent of library patches.
4. Hunt for repeated GraphQL requests near 50-100 KB containing deeply nested lists/objects/selection sets followed by PHP-FPM, Swoole, RoadRunner, or CLI worker crashes.

### Secret retention bypass in ots

1. Upgrade to **1.21.5+**.
2. Until patched, set `disableExpiryOverride: true` where possible.
3. Search logs for `/api/create?expire=-` or unusually large/invalid expiry values.
4. If memory backend is used, enumerate and purge secrets whose lifetime exceeds policy; rotate any downstream credentials that may have been shared through retained one-time secrets.

## Durable controls

- Apply object-level authorization to every node in a graph and every embedded record in a compound response.
- Do not rely on UI route access as proof that nested API data is safe for that viewer.
- Treat browser Fetch Metadata as a policy input with deny-by-default semantics for ambiguous or cross-site modes; do not classify `no-cors` as same-origin.
- Validate byte/string contracts at FFI and database boundaries. Documentation promises are not a substitute for runtime validation when unsafe constructors are involved.
- Put explicit depth and work limits in recursive parsers before accepting untrusted documents.
- Parse retention lifetimes as bounded, positive values; reject negative, overflow, and sentinel-like values instead of normalizing them into "forever".
