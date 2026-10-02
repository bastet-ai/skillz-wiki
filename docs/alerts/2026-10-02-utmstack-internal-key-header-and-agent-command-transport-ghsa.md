---
title: "UTMStack SIEM — static internal-key header bypass and unauthenticated agent-command transport (Oct 2 21:32Z)"
---

# UTMStack: static internal-key header auth bypass + any-user agent command transport (Oct 2 21:32Z)

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-10-02. Six GHSAs published 21:32Z for **UTMStack before 11.2.16**, an open-source SIEM/UTM management platform with a microservice backend and an agent fleet. Two of the six are near-critical and carry durable axes the wiki hasn't catalogued in this shape; the rest land on existing canonical classes and are folded here as one wave.

Why this matters to an operator: a SIEM/UTM manager is a credential-dense, agent-riddled target class (same reasoning as the Oct 2 Zammad helpdesk KEV page): it stores integrations credentials, indexes the whole estate, and runs root/SYSTEM agents on monitored endpoints. Fixing one login page proves nothing about the service-to-service auth side door or the WebSocket command bus next to it.

## 1. `Utm-Internal-Key`: the static env-var header that *is* the admin API (CVE-2026-82042 / [GHSA-phx4-fx7q-vfw9](https://github.com/advisories/GHSA-phx4-fx7q-vfw9), 9.8)

`InternalApiKeyFilter` accepts a valid `Utm-Internal-Key` header matching the **`INTERNAL_KEY` environment variable** for **any endpoint**, with no path restriction, no constant-time comparison, no rate limiting, and no audit logging. An attacker who learns the key value authenticates with **no user account and no JWT** — then creates accounts, manages users, exfiltrates data, and edits security rules.

Operator axes:

1. **Internal-service header families are a standing probe list.** Microservice backends routinely ship an "internal" auth header (`X-Internal-Key`, `X-Internal-Token`, `X-API-Key`, service-name variants) whose secret is an env var or a committed compose/manifest default. For any multi-service app, sweep known/internal header names against the public API edge with plausible values: committed defaults, the product name, and values leaked from any sibling disclosure (`.env` reads, debug endpoints, error bodies, source). A 200 where the browser flow needs a JWT = the side door is public.
2. **The bypass is invisible by design.** The filter logs nothing, so the strongest post-exploitation signal is *absence* of expected auth events. On authorized engagements, the detection-resistance property is itself report-grade detail.
3. **Non-constant-time comparison of a header secret is a timing-oracle candidate** — the advisory states the comparison is not constant-time; lab-position timing against a wrong-but-same-length key is a legit proof shape where network noise allows.
4. **Fingerprint the key's blast radius**: the filter gates *every* endpoint, so once held, enumerate the full route tree (this platform exposes asset groups, network scans, identity providers, incident commands — see legs below) rather than the handful the UI uses.

## 2. Any authenticated user can run OS commands on every agent via the STOMP command bus (CVE-2026-82041 / [GHSA-q995-ggc5-8fmx](https://github.com/advisories/GHSA-q995-ggc5-8fmx), CVSS 9.9)

`UTMIncidentCommandWebsocket.processCommand()` — the handler mapped to the **`/command/{hostname}` STOMP destination** — applies **no role check and no command allowlist** before forwarding caller-supplied commands over gRPC to any connected agent, where agent processes commonly run **as root or SYSTEM**. Read literally from the description: *any authenticated user, regardless of role*, sends arbitrary OS commands to any monitored endpoint by hostname.

Operator axes:

1. **Authorization is enforced at the REST layer; the message transport beside it enforces nothing.** On any product with WebSocket/STOMP/SockJS/SignalR surfaces, enumerate destinations (`/command/*`, `/topic/*`, `/queue/*`, `/app/*` via CONNECT + subscribe/send probes) with a **lowest-privilege lab principal** and diff against the REST permission model. A destination a Viewer-role user can SEND on is the finding. This is the transport-parity sibling of the alternate-surface drift already canonized on the Sept 19 WP and Sept 21 precedence pages — the *transport* is the alternate surface.
2. **Hostname/enrollment identifiers are the target selector.** The destination embeds `{hostname}`, so a host inventory (from any enumeration leg, DHCP logs, or the asset-group search below) converts one beachhead credential into fleet-wide execution. On pentests, the agent-command destination + an asset inventory is an instant lateral-movement map.
3. **Command-allowlist absence**: test with an inert marker command (`id`, `hostname`) in a lab only; on customer-approved systems, prefer proving reachability (response shape on a benign verb) over execution.

## 3. Same wave, canonical-class legs (folded, no new axes)

- **Native-query SQLi via `String.format()`** — `UtmAssetGroupService.searchQueryBuilder()` interpolates `assetType`/`groupName` into a native PostgreSQL query reachable at `GET /api/utm-asset-groups/searchGroupsByFilter` with DBA privileges (CVE-2026-82039 / [GHSA-2c66-2qvh-84xr](https://github.com/advisories/GHSA-2c66-2qvh-84xr), 8.8), and the **JPQL twin** `searchPropertyValues()` builds JPQL with `String.format()` + `em.createQuery()`, letting an authenticated user exfiltrate entity tables incl. `jhi_user` credentials (CVE-2026-82045 / [GHSA-ggxr-hwjj-pgmj](https://github.com/advisories/GHSA-ggxr-hwjj-pgmj)). String-concatenation-into-native-query and JPQL-injection classes are canonical (Sept 18 ORM query-grammar page; YesWiki deferred-SQLi page). One fingerprint takeaway: the Spring Boot scaffold (`jhi_user` table name) marks this as a JHipster-generated app — **JHipster-shaped apps inherit this scaffold's route families**; grep-scan generated-codebases for `String.format` near `createQuery`/native queries during white-box reviews.
- **SSRF pair with two render/scan channels**: `PdfService.downloadPdf()` fetches an unvalidated `url` and **renders the fetched content into the returned PDF** — internal backend endpoints, the OpenSearch cluster, or cloud instance metadata readable in the artifact (CVE-2026-82044 / [GHSA-hg4r-wjvj-4cww](https://github.com/advisories/GHSA-hg4r-wjvj-4cww)); `IdentityProviderService.validateMetadataUrl()` fetches caller-supplied IdP metadata URLs with no host/IP/scheme validation = internal port-scan + metadata access (CVE-2026-82040 / [GHSA-w93c-mfp3-35p4](https://github.com/advisories/GHSA-w93c-mfp3-35p4)). "Report/PDF generator SSRF = response read-back through the generated document" is the final-destination-proof pattern already on the SSRF pages; the *metadata-URL validator that fetches before validating* is the SAML/OIDC metadata class from the Oct 1 Authlib fold. Proof stays bounded to owned callbacks and lab-internal canaries.

## Validation workflow (lab scope only)

!!! warning "SIEM = the estate's data lake"
    UTMStack-class platforms index real credentials and endpoint telemetry. All proofs run against a disposable instance with synthetic assets/users/agents. Never send commands through a customer's production agent fleet; the STOMP leg proof is a lab agent + `id`-class marker, and the internal-key leg is a single request with a lab-set value plus the negative control (no header → 401).

1. **Internal-header probe matrix:** public edge × {`X-Internal-Key`, `Utm-Internal-Key`, `X-Internal-Token`, `X-API-Key`} × {absent, empty, product-name default, env-leaked value}; compare against a JWT-authenticated positive control on one harmless GET route.
2. **Transport parity sweep:** CONNECT a STOMP session as the lowest-privilege lab user, `SEND /command/<lab-agent>` with an inert marker, table accept/reject per role.
3. **Route-vs-transport diff:** replay three representative REST actions (read asset group, write config, generate report) through both transports and diff the authz decision.

## Tracked without publication (same 21:32Z wave)

- Digi appliance CVE-2026-75937 unauth root POST → cmdi (critical, zero sink detail; revisit when the vendor advisory lands).
- Microsoft Exchange CVE-2026-96940 weak-authorization privilege escalation (8.8, description-free vendor text).
- H3C CVM CVE-2023-54405 / Weaver e-Bridge CVE-2020-37278 late-backfill publications (old classes, no new axis).
- Trivy CVE-2026-104994 Terraform filesystem-function traversal above scan root during misconf scans of untrusted PRs (low; scanner-reads-outside-root class noted, revisit if a leak-channel pattern generalizes).
- Canonical MAAS CVE-2026-12392 info exposure; postgresql-operator charm CVE-2026-104055 exporter logging the monitoring password in cleartext on connection errors (log-credential-leak class).
- Phproject CVE-2026-104991 REST API never calls its own `allowAccess()` (missing-call class canonical on the Sept 21 pages); Wallstreet WP CSRF + AIO SEO shortcode-processing single.
- Detail-free six-pack of same-product advisories (CVE-2026-90452–90457: reverse-proxy→IdP calls without cert verification, Referer-driven upload redirect, weak admin hash + world-readable hash file, shipped default admin password, read-only-mode tag-route deny-list gap, reverted HTTP-client bump) — vendor unnamed in summaries; the no-cert-verify leg and shipped-default leg land on existing classes; revisit when the product identifies itself.
