# Apache, observability, and MCP boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced a **2026-05-05** batch affecting workflow schedulers, message brokers, observability query limits, and MCP package release hygiene. The common theme is trusted operational tooling exposing too much authority to authenticated users, internal RPC callers, query parameters, or published source archives.

## Advisories in this batch

- **Apache DolphinScheduler tenant authorization bypass** — `org.apache.dolphinscheduler:dolphinscheduler < 3.4.1` lets authenticated users with login permissions execute workflows using tenants not defined on the platform. Fixed in 3.4.1. Reference: <https://github.com/advisories/GHSA-72mv-wwvm-vgp5>.
- **Apache DolphinScheduler RPC deserialization** — `org.apache.dolphinscheduler:dolphinscheduler` and `dolphinscheduler-rpc >= 3.2.0, < 3.3.1` allow attackers who can reach Master or Worker RPC nodes to send crafted `StandardRpcRequest` messages with malicious class types. Fixed in 3.3.1. Reference: <https://github.com/advisories/GHSA-f786-9c63-8xr8>.
- **Apache ActiveMQ admin-console broker-name code injection** — `org.apache.activemq:apache-activemq`, `activemq-all`, and `activemq-broker < 5.19.6` and `>= 6.0.0, < 6.2.5` can let an authenticated admin-console attacker craft broker names that later trigger remote Spring XML loading through VM transport creation. Fixed in 5.19.6 and 6.2.5. Reference: <https://github.com/advisories/GHSA-mr6m-xj7v-3cv3>.
- **Apache ActiveMQ HTTP Discovery / Jolokia code-injection bypass** — the same ActiveMQ version ranges can bypass prior validation when `activemq-http` is on the classpath and connector management is exposed through `BrokerView`/Jolokia, allowing a malicious HTTP Discovery endpoint to redirect into VM transport Spring XML loading. Fixed in 5.19.6 and 6.2.5. Reference: <https://github.com/advisories/GHSA-w3w2-mpp5-92gm>.
- **Apache ActiveMQ web-console XSS** — the same ActiveMQ version ranges can render attacker-supplied HTML while browsing queues when content type and JMS selector fields are abused. Fixed in 5.19.6 and 6.2.5. Reference: <https://github.com/advisories/GHSA-2jp3-2923-9h52>.
- **Grafana Tempo query memory exhaustion** — `github.com/grafana/tempo >= 1.3.0, < 2.8.4`, `>= 2.9.0, < 2.9.2`, and `>= 2.10.0, < 2.10.2` can allocate excessive memory for large-limit queries. Fixed in 2.8.4, 2.9.2, and 2.10.2; set `max_result_limit` as a mitigation. Reference: <https://github.com/advisories/GHSA-p4r4-xvrq-gvmc>.
- **`ogham-mcp` credentials embedded in PyPI sdists** — `ogham-mcp >= 0.6.3, < 0.11.1` published source distributions containing Neon PostgreSQL development URLs/passwords and a Voyage API key. Credentials were rotated; upgrade to 0.11.1 for a clean release. Reference: <https://github.com/advisories/GHSA-8pqq-224h-x875>.

## Why this is durable

Operational platforms are often treated as internal and trusted, but they concentrate authority:

- Workflow schedulers can impersonate tenants, run jobs, and reach worker nodes.
- Message brokers expose management APIs that can instantiate connectors, transports, MBeans, and web-console rendering paths.
- Observability systems sit on large datasets where one query limit can become a memory-pressure primitive.
- MCP/tool packages may publish test fixtures, Makefiles, or source archives that never pass through runtime secret scanners.

## Immediate triage

1. Patch DolphinScheduler to **3.4.1** for tenant authorization and at least **3.3.1** for RPC deserialization exposure; if both apply, use the newest supported release.
2. Patch ActiveMQ to **5.19.6** or **6.2.5**. Restrict admin console, Jolokia, JMX/MBeans, and connector-management surfaces to trusted operators only.
3. Patch Tempo to **2.8.4**, **2.9.2**, or **2.10.2** as appropriate, and set a conservative `max_result_limit` immediately.
4. Upgrade `ogham-mcp` to **0.11.1** and verify no affected sdist was mirrored into internal package registries, build caches, or golden images.
5. Rotate any credentials that may have been copied from vulnerable `ogham-mcp` archives, even if the upstream advisory says known credentials were already rotated.

## Hunt ideas

- DolphinScheduler: audit workflow executions for tenant names not present in the platform tenant table; review Master/Worker RPC access from unexpected hosts.
- ActiveMQ: review admin-console changes to broker names, connectors, network connectors, Jolokia calls, and HTTP Discovery URLs; look for `brokerConfig`, `xbean`, remote XML URLs, or unexpected VM transport creation.
- ActiveMQ web console: search access logs for queue browsing with unusual selectors, overridden content types, or script-like payloads.
- Tempo: alert on large `limit` query parameters, memory spikes tied to search endpoints, querier OOM restarts, and tenants exceeding normal trace-search budgets.
- MCP/package hygiene: scan internal PyPI mirrors and source archives for Neon connection strings, `postgres://`, `postgresql://`, `VOYAGE`, and API-key patterns in tests, Makefiles, and sdists.

## Durable controls

- Treat “authenticated admin” surfaces as privileged code-execution boundaries; require MFA, network isolation, audit logging, and change approval for connector or transport changes.
- Keep scheduler tenant identity server-side and immutable during execution; never accept tenant context only from user-controlled workflow metadata.
- Segment scheduler RPC planes from user networks, CI runners, and general cluster workloads; require mutual auth where supported.
- Put resource budgets at the query-planner and API edge for observability tools: max result count, max bytes, max wall time, per-tenant concurrency, and circuit breakers.
- Run secret scanning against release artifacts, not only source repositories. Include sdists, wheels, npm tarballs, container layers, docs, tests, fixtures, and generated examples.

## Operator lesson

Internal tooling is still production attack surface. Restrict management planes, budget expensive queries, and scan the exact artifacts users install—not just the repo you meant to publish.
