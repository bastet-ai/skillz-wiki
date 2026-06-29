# Graph, web-service, and OAuth integration boundary checks

Source: hourly offensive-security scan, 2026-06-29. Primary entries: GitHub Advisory Database [GHSA-q2m9-6jp9-c6mc](https://github.com/advisories/GHSA-q2m9-6jp9-c6mc) / CVE-2026-44840, [GHSA-r5vf-grcx-5vqp](https://github.com/advisories/GHSA-r5vf-grcx-5vqp) / CVE-2026-28735, [GHSA-2hvc-5c6v-f533](https://github.com/advisories/GHSA-2hvc-5c6v-f533) / CVE-2026-44417, [GHSA-pg32-686q-qh6x](https://github.com/advisories/GHSA-pg32-686q-qh6x) / CVE-2026-44930, and [GHSA-vmm5-fjgx-2jhp](https://github.com/advisories/GHSA-vmm5-fjgx-2jhp) / CVE-2026-44618.

These advisories are useful for operators because they expose reusable integration boundaries: GraphQL password-check inputs crossing into Dgraph DQL string construction, OAuth callback parameters widening repository scopes, user-controlled JMS endpoint configuration crossing into Apache CXF runtime code paths, certificate lookup fields crossing into LDAP filters, and WS-Transfer XML bodies crossing into XXE-capable parsers.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-q2m9-6jp9-c6mc](https://github.com/advisories/GHSA-q2m9-6jp9-c6mc) / CVE-2026-44840 | Dgraph `checkUserPassword` GraphQL query | password input was interpolated into a DQL `checkpwd()` expression with `fmt.Sprintf` before DQL serialization | Treat GraphQL helper queries as query-language translators; test string-literal breakouts with synthetic graph canaries. |
| [GHSA-r5vf-grcx-5vqp](https://github.com/advisories/GHSA-r5vf-grcx-5vqp) / CVE-2026-28735 | Mattermost GitHub plugin OAuth callback | callback handling failed to validate requested OAuth token scope after the user modified the GitHub authorization URL | Add scope-tightening and callback reconciliation checks to SaaS/chat integrations that broker GitHub, GitLab, or cloud tokens. |
| [GHSA-2hvc-5c6v-f533](https://github.com/advisories/GHSA-2hvc-5c6v-f533) / CVE-2026-44417 | Apache CXF JMS configuration | another untrusted JMS-configuration path could reach code-execution capability after an incomplete prior fix | Treat admin/self-service integration endpoints that accept JMS/JNDI-style configuration as runtime execution boundaries. |
| [GHSA-pg32-686q-qh6x](https://github.com/advisories/GHSA-pg32-686q-qh6x) / CVE-2026-44930 | Apache CXF XKMS LDAP certificate repository | certificate lookup input could alter LDAP query shape and retrieve unintended certificates | Test certificate repositories and identity lookup helpers for LDAP-filter construction with seeded certificate canaries. |
| [GHSA-vmm5-fjgx-2jhp](https://github.com/advisories/GHSA-vmm5-fjgx-2jhp) / CVE-2026-44618 | Apache CXF WS-Transfer module | insecure XML parser configuration could allow XXE | Include WS-* utility modules in XML parser reviews; prove only with owned callbacks or synthetic local files in labs. |

## Operator triage

1. **Translator layers deserve direct injection tests.** Dgraph's issue is not generic GraphQL injection; it is GraphQL input crossing into a second query language. Review resolvers, auth helpers, search helpers, and password-check wrappers that build DQL, SQL, LDAP, Gremlin, Cypher, or search DSL strings.
2. **OAuth callbacks must bind requested scope to approved scope.** If a user can edit the authorization URL before returning to the integration, the callback should reject widened scopes, changed resource owners, mismatched `state`, and unexpected provider parameters.
3. **Integration configuration can be code.** CXF JMS findings are strongest when non-admin tenants, project maintainers, or support users can save endpoint factories, connection strings, JNDI names, provider classes, or broker URLs.
4. **Certificate and directory helpers are data-exposure sinks.** XKMS/LDAP issues may not need shell execution to be reportable; a scoped certificate canary returned across a boundary is durable evidence.
5. **WS-* modules often parse XML outside main API routes.** Inventory legacy SOAP, WS-Transfer, XKMS, SAML, and management endpoints separately from REST and GraphQL surfaces.

## Replayable validation boundaries

### Dgraph GraphQL-to-DQL injection harness

- Preconditions: Dgraph lab or explicitly scoped environment, affected version before the fixed release, a disposable GraphQL schema with a `User.password` predicate, and seeded graph records containing unique canary values.
- Exercise only the `checkUserPassword` query with benign password canaries that test whether a double quote changes DQL query shape or returns a synthetic marker record.
- Capture the GraphQL request, Dgraph version, schema fragment, canary record ID, response difference, and fixed-version negative control.
- Do not dump production graph data, enumerate users, brute-force passwords, or publish payloads that target sensitive predicates.

### OAuth scope callback harness

- Preconditions: Mattermost lab through the affected GitHub plugin versions, disposable Mattermost user, disposable GitHub organization/repository, and no real code or secrets in the test repository.
- Start the normal GitHub integration flow, then alter only the requested `scope` parameter in the provider authorization URL before callback completion.
- Evidence should show the originally intended scope, modified scope, callback result, repository access decision, plugin version, and a patched or scope-rejected negative control.
- Stop at access to a synthetic private repository marker. Do not access real private repositories, clone source code, collect tokens, or retain elevated OAuth grants after testing.

### Apache CXF JMS, XKMS, and WS-Transfer harness

- Preconditions: isolated CXF lab, affected version, disposable service endpoints, seeded LDAP certificate entries, owned XML callback endpoint, and explicit approval to change integration configuration.
- For JMS configuration, verify who can write JMS endpoint settings and use only inert provider/class/broker canaries that prove whether untrusted configuration is loaded or instantiated.
- For XKMS LDAP, seed allowed and disallowed certificate canaries, then submit lookup fields that show LDAP-filter shape changes through returned canary certificates only.
- For WS-Transfer XXE, send a SOAP/XML body that references an owned callback URL or lab-only temporary marker file and record only callback reachability or parser error behavior.
- Do not load gadget chains, run commands on production services, query real directories, retrieve private keys, contact internal services, or read sensitive local files.

## Reporting notes

- Lead with the exact boundary: **GraphQL password input to DQL string**, **authorization URL scope to OAuth callback token grant**, **untrusted JMS configuration to runtime object loading**, **certificate lookup field to LDAP filter**, or **WS-Transfer XML to external entity resolution**.
- Include product version, package/plugin/module version, role required to reach the boundary, request/route, canary value, observed decision, and fixed-version negative control.
- Keep artifacts synthetic: graph marker records, throwaway repositories, fake OAuth tokens, seeded LDAP certificates, owned callback domains, and lab XML markers.
