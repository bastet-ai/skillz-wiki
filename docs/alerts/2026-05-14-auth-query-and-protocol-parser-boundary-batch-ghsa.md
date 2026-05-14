# Auth, query, and protocol-parser boundary batch

**Signal:** The **2026-05-14 21:15 UTC** advisory scan added a second durable batch around deceptively small boundary mistakes: empty shared secrets accepted as valid signatures, full-text search configuration crossing into SQL, and protocol parser integer coercion in Bettercap service emulation paths.

## Advisory cluster

- **`slack-go` empty signing secret accepted** — [GHSA-gxhx-2686-5h9g](https://github.com/advisories/GHSA-gxhx-2686-5h9g): `SecretsVerifier` accepted an empty signing secret without a precondition, making webhook authenticity checks meaningless when configuration was missing or blank.
- **Marten full-text search `regConfig` injection** — [GHSA-vmw2-qwm8-x84c](https://github.com/advisories/GHSA-vmw2-qwm8-x84c): attacker-controlled full-text search configuration could cross into query construction and become injection in affected Marten deployments.
- **Bettercap MySQL server integer coercion** — [GHSA-jcqv-2g3v-gm88](https://github.com/advisories/GHSA-jcqv-2g3v-gm88): integer coercion in `modules/mysql_server/mysql_server.go` created parser-state risk in the service-emulation path.
- **Bettercap IPP chunked-body integer coercion** — [GHSA-322p-rrj6-j44g](https://github.com/advisories/GHSA-322p-rrj6-j44g): integer coercion in `ippReadChunkedBody` affected chunked request parsing in Bettercap’s IPP handling.

## Why this matters

Security checks fail open when configuration is missing unless the code explicitly refuses empty secrets. Query helpers fail open when “configuration” values such as text-search dictionaries are treated as safe identifiers. Parser emulation code fails open when wire-length fields are coerced into smaller or signed integer types before bounds checks.

## Triage

1. Search for Slack webhook verification configured with empty or missing signing secrets. Fail startup if any signing secret is blank, and add tests for this exact condition.
2. Review Marten full-text search entry points where users can influence `regConfig`, language, dictionary, or search configuration names. Restrict to a fixed enum of known-good values.
3. For Bettercap or similar service-emulation tooling exposed in labs, CI, or shared networks, patch promptly and avoid running parsers with elevated privileges or access to sensitive capture material.
4. Add negative tests for blank auth secrets, identifier-like query parameters, overlarge length fields, negative values, and integer wrap/coercion around protocol boundaries.

## Durable controls

- Authentication middleware should distinguish “not configured” from “configured and verified”; blank secrets must be fatal at process start.
- SQL and full-text search helpers should bind values and whitelist identifiers separately. Anything that changes query grammar is not a bind parameter.
- Protocol parsers should parse length fields into wide unsigned types, validate before allocation/copy, and reject impossible chunk or frame sizes before conversion.
- Service-emulation and testing tools still deserve sandboxing: run them as unprivileged users, constrain filesystem/network access, and treat captured protocol bytes as hostile input.
