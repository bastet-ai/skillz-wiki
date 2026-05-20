# Tomcat parser, client-certificate, and session-boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-20.

This batch is durable for operators because it ties together three Tomcat surfaces that often sit behind load balancers and WAFs: byte-level HTTP parsing, TLS/client-certificate identity handoff, and session persistence. Treat it as an edge-stack validation checklist for authorized testing, not as a generic patch advisory.

## What changed

- **Invalid chunk-extension request/response smuggling** — [GHSA-563x-q5rq-57qp](https://github.com/advisories/GHSA-563x-q5rq-57qp) / CVE-2026-24880: Tomcat `11.0.0-M1..11.0.18`, `10.1.0-M1..10.1.51`, `9.0.0.M1..9.0.115`, `8.5.0..8.5.100`, and `7.0.0..7.0.109` could parse invalid chunk extensions inconsistently. The operator-relevant signal is a proxy/backend parser differential: a frontend may believe one request ended while Tomcat consumes bytes differently.
- **CLIENT_CERT soft-fail authentication confusion** — [GHSA-95jq-rwvf-vjx4](https://github.com/advisories/GHSA-95jq-rwvf-vjx4) / CVE-2026-29145: Tomcat `11.0.0-M1..11.0.18`, `10.1.0-M7..10.1.52`, `9.0.83..9.0.115`, and Tomcat Native `1.1.23..1.1.34`, `1.2.0..1.2.39`, `1.3.0..1.3.6`, `2.0.0..2.0.13` could continue in scenarios where `CLIENT_CERT` authentication should have failed. This overlaps but is distinct from the earlier Tomcat CLIENT_CERT item already tracked in the wiki.
- **Session `PersistenceManager` + `FileStore` deserialization RCE preconditions** — [GHSA-344f-f5vg-2jfj](https://github.com/advisories/GHSA-344f-f5vg-2jfj) / CVE-2020-9484: legacy Tomcat lines can deserialize attacker-controlled session files when all required conditions line up: attacker-controlled file name/content on the server, `PersistenceManager` with `FileStore`, permissive `sessionAttributeValueClassNameFilter`, and knowledge of the relative path from the store location to the controlled file.
- **Configured cipher preference order not preserved** — [GHSA-69cc-cv78-qc8g](https://github.com/advisories/GHSA-69cc-cv78-qc8g) / CVE-2026-29129: Tomcat `11.0.16..11.0.18`, `10.1.51..10.1.52`, and `9.0.114..9.0.115` did not preserve configured cipher preference order. Offensive value is mostly in fingerprinting brittle TLS policy assumptions around edge identity and downgrade-sensitive environments.
- **Examples webapp resource consumption** — [GHSA-653p-vg55-5652](https://github.com/advisories/GHSA-653p-vg55-5652) / CVE-2024-54677: Tomcat example applications could be abused for resource consumption. This is only durable when `webapps/examples/` is reachable in a real environment; it does not affect Tomcat core components.

## Operator triage

1. Inventory direct and embedded Tomcat exposure, including Spring Boot `tomcat-embed-core`, appliance bundles, CI preview stacks, and internal admin apps that bypass the public CDN/WAF path.
2. Record the full request path for each target: client → CDN/WAF/load balancer → reverse proxy → Tomcat connector. Parser-differential issues matter most when different components make independent decisions about chunk extensions, transfer encoding, connection reuse, or request boundaries.
3. For mutual-TLS deployments, map where certificate verification actually happens. Distinguish frontend-terminated mTLS with trusted headers from Tomcat-native `CLIENT_CERT`; then test failure modes for missing, expired, malformed, revoked, and untrusted client certificates.
4. Check for session persistence settings before spending exploit time on CVE-2020-9484. The high-signal combination is `PersistenceManager` + `FileStore` + permissive session deserialization + an upload/write primitive that lets the tester control both file content and an addressable path.
5. Treat `webapps/examples/` and default Tomcat assets as recon signals. If examples are exposed, capture that in the report even when the resource-consumption CVE itself is low impact, because it often predicts weak deployment hygiene.

## Replayable validation boundaries

- **Chunk-extension differential test:** in staging or an explicitly authorized target, send malformed chunk-extension cases through the approved frontend path and compare frontend logs, backend logs, and response ordering. Expected safe result: the edge and Tomcat reject the same request at the same boundary and do not process a hidden follow-up request.
- **mTLS failure matrix:** exercise certificate-present/certificate-absent and valid/invalid certificate states against endpoints that require `CLIENT_CERT`. Expected safe result: every invalid certificate path fails closed before application identity is established, with no fallback authenticated principal.
- **Session-store precondition check:** verify whether Tomcat uses `PersistenceManager` with a filesystem `FileStore`; if yes, confirm whether uploaded files can be placed where the session loader can reach them by relative path. Expected safe result: no attacker-controlled path is loadable as a session object and deserialization filters are narrow.
- **TLS policy fingerprint:** compare configured cipher order with the observed negotiated cipher under controlled client preference lists. Expected safe result: operator-observed negotiation matches the intended server policy where cipher ordering is security-relevant.
- **Examples exposure check:** request known examples paths such as `/examples/` only within scope. Expected safe result: examples are absent, blocked, or isolated from production worker pools.

## Reporting heuristics

- For request smuggling, report the parser differential and the security impact of the backend action you can safely demonstrate. A log-only mismatch is weaker than a bounded demonstration that a hidden request reaches a different route, cache key, or authenticated context.
- For `CLIENT_CERT`, show the exact failure state that should deny access and the principal or authorization decision that still succeeds.
- For CVE-2020-9484, do not overclaim RCE from version alone. The finding becomes strong only when you prove the file-write/control, `FileStore`, and deserialization-filter preconditions align.
- For examples/resource exhaustion, frame the issue around exposed default attack surface and bounded resource impact, not generic DoS speculation.

## Durable controls to verify

- One canonical HTTP parser decision per request path; reject malformed transfer framing at the first edge and disable backend reuse after parse errors.
- Private Tomcat backends behind a single hardened edge, with direct connector access blocked from untrusted networks.
- Explicit mTLS failure behavior tested in CI and pre-production, especially after Tomcat Native or connector changes.
- No production `PersistenceManager` filesystem session deserialization unless filters and storage paths are deliberately constrained.
- No default `webapps/examples/` exposure on production or shared staging hosts.
