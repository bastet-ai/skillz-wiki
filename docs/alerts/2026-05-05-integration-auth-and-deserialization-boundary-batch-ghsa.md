# Integration auth and deserialization boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because integration frameworks and service control planes often inherit authority from adjacent channels: TLS client certs, HTTP alternate paths, message headers, database namespaces, templates, and package-index behavior. Each channel needs its own authentication, type, and deserialization guard.

## Advisories covered

- **ArcadeDB cross-database authorization bypass** — [GHSA-fxc7-fm93-6q77](https://github.com/advisories/GHSA-fxc7-fm93-6q77): authorization can cross database boundaries and newly created databases may be unsecured.
- **Apache Camel Mail header injection** — [GHSA-2vqf-x7g4-7c2g](https://github.com/advisories/GHSA-2vqf-x7g4-7c2g): Camel-Mail headers can be injected across message boundaries.
- **Apache Camel platform HTTP alternate-path auth bypass** — [GHSA-27vm-5vpj-rp5g](https://github.com/advisories/GHSA-27vm-5vpj-rp5g): alternate path/channel handling can bypass authentication.
- **Apache Camel Infinispan deserialization** — [GHSA-4xwx-hvv7-7prj](https://github.com/advisories/GHSA-4xwx-hvv7-7prj): untrusted data reaches deserialization in the Infinispan component.
- **Apache Camel Consul deserialization** — [GHSA-5rc6-9qfp-8vwg](https://github.com/advisories/GHSA-5rc6-9qfp-8vwg): untrusted data reaches deserialization in the Consul component.
- **Apache MINA incomplete deserialization fix** — [GHSA-f2wh-grmh-r6jm](https://github.com/advisories/GHSA-f2wh-grmh-r6jm): CVE-2024-52046 incomplete fix leaves deserialization exposure.
- **Apache Storm TLS client auth failure** — [GHSA-j2q8-xx3q-8fqh](https://github.com/advisories/GHSA-j2q8-xx3q-8fqh): TLS client-auth failure can assign an anonymous principal.
- **Apache Storm Prometheus Reporter SSL downgrade** — [GHSA-82fm-wpc2-5pmp](https://github.com/advisories/GHSA-82fm-wpc2-5pmp): global SSL context behavior can disable expected certificate validation.
- **jdbi3-freemarker template injection** — [GHSA-mggx-p7jf-jgw4](https://github.com/advisories/GHSA-mggx-p7jf-jgw4): FreeMarker special elements are not neutralized before SQL/template construction.
- **authd primary group confusion** — [GHSA-fg3j-5w9g-hmg7](https://github.com/advisories/GHSA-fg3j-5w9g-hmg7): primary group ID is set to UID value, creating identity/authorization drift.
- **Kubewarden `can_i` host capability reconnaissance** — [GHSA-wqcw-g35j-j578](https://github.com/advisories/GHSA-wqcw-g35j-j578): unchecked host capability calls can expose RBAC reconnaissance.
- **pip untrusted control sphere inclusion** — [GHSA-jp4c-xjxw-mgf9](https://github.com/advisories/GHSA-jp4c-xjxw-mgf9): package-install behavior can include functionality from an untrusted control sphere.

## Operator triage

1. Inventory Camel routes using Mail, platform-http, Infinispan, Consul, MINA, and any component that accepts serialized payloads or maps transport headers into application state.
2. Verify TLS-client-auth failure handling in Storm and related services: failed certificate validation must fail closed, not downgrade to anonymous or global insecure contexts.
3. Audit database and namespace creation workflows for default grants, cross-database session reuse, inherited admin tokens, and newly created resources with open ACLs.
4. Search templates, query builders, and package/install hooks for user-controlled values crossing into FreeMarker, SQL, shell, or package-index configuration.
5. Review identity providers and admission/policy engines for UID/GID confusion and host-capability calls that leak authorization topology to low-trust users.

## Durable controls

- Treat transport channels, route aliases, and message headers as untrusted until authenticated and normalized by the exact endpoint.
- Disable native deserialization for network payloads unless a narrow class allowlist, size limit, and signed envelope are enforced.
- New databases, tenants, namespaces, and queues must start closed and require explicit grants after creation.
- TLS validation should be local to the client/server component; avoid mutable global SSL contexts that one integration can downgrade for another.
- Package managers and template-backed query builders need provenance locks, escaping by target language, and deny-by-default plugin/install behavior.
