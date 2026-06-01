# Apache Airflow Variable, event-log, and JWT cookie boundary batch

Sources: GitHub Security Advisories / NVD entries published or updated 2026-06-01: [GHSA-33g2-gx67-c2h3](https://github.com/advisories/GHSA-33g2-gx67-c2h3) / CVE-2026-42358, [GHSA-qphr-3mvq-v466](https://github.com/advisories/GHSA-qphr-3mvq-v466) / CVE-2026-46764, and [GHSA-95v7-h9j5-gvjr](https://github.com/advisories/GHSA-95v7-h9j5-gvjr) / CVE-2026-41017.

This batch is durable because the issues map to reusable Airflow operator checks: JSON secret masking that fails at nested depth, ID-based API detail endpoints that skip per-DAG scoping, and auth cookies that become replayable when TLS terminates before the API server.

## What changed

- **Variable redaction depth bypass** — Airflow Variable responses could return plaintext values under sensitive key names such as `password`, `token`, `secret`, or `api_key` when the JSON value is nested deeper than the shared secrets masker's recursion limit. The affected precondition is an authenticated UI/API user with Variable read permission.
- **Event-log detail IDOR across DAG scope** — `GET /api/v2/eventLogs/{event_log_id}` fetched audit-log rows by numeric ID after only a generic Audit Log permission check, while the list endpoint applied per-DAG scoping. A user authorized for one DAG's audit logs could enumerate numeric IDs and retrieve logs for other DAGs.
- **JWT refresh cookie without `Secure`** — `JWTRefreshMiddleware` set the JWT auth cookie without the `Secure` flag. In the common topology where HTTPS terminates at nginx, Envoy, or a managed load balancer and cleartext HTTP reaches the Airflow API server, a network-positioned attacker could induce a browser request over HTTP and capture the session JWT.

## Operator triage

1. **Start with role and topology, not the CVE string:** these findings only become high signal when you can prove the tested Airflow role should not see the secret/log boundary, or when the deployment exposes an HTTP downgrade path for the same hostname.
2. **Use canary data:** create disposable Variables, DAG names, and audit events in a lab or authorized tenant. Never use real production secrets as proof.
3. **Separate API behavior from UI labels:** Airflow roles often look constrained in the UI while API detail endpoints still accept numeric identifiers. Test both collection and detail routes.
4. **Keep cookie testing passive unless authorized:** header inspection is safe; network interception, captive-portal tricks, and active downgrade tests require explicit authorization.

## Recon and validation boundaries

### Airflow surface discovery

Use this only against systems in scope.

```bash
# Identify likely Airflow web/API surfaces.
httpx -silent -status-code -title \
  -path /,/login/,/api/v2/version,/api/v2/dags,/api/v2/eventLogs \
  -l airflow-candidates.txt

# If credentials are authorized, capture version and principal context.
curl -sk -H 'Authorization: Bearer ***' \
  'https://airflow.example.test/api/v2/version'
```

High-signal evidence:

- Airflow API is reachable from a role or network zone in scope.
- The tested account has narrowly scoped DAG or Variable permissions.
- Version or response behavior matches the advisory's affected boundary.

### Variable redaction depth check

Run this in a disposable Airflow deployment or an explicitly authorized test tenant.

1. Create a canary Variable whose value is JSON with a sensitive leaf key nested deeply enough to test the masker boundary, for example a value that eventually contains `{ "api_key": "skillz_canary_<case_id>" }`.
2. Retrieve the Variable through the same UI/API path available to a low-privilege user with Variable read permission.
3. A vulnerable result is plaintext return of `skillz_canary_<case_id>` under a sensitive key where the application policy or UI promises masking.

Example shape for a lab-only canary value:

```json
{
  "level1": {
    "level2": {
      "level3": {
        "level4": {
          "api_key": "skillz_canary_CASEID"
        }
      }
    }
  }
}
```

Report the tested role, Variable key name, nesting depth, response path, and whether the same value is masked at shallower depths. Do not include real Variable values in screenshots or tickets.

### Event-log detail scoping check

Prerequisite: two DAGs or tenants where the tested user is allowed to view audit logs for one DAG but not the other.

```bash
# Collection route should be scoped to the user's authorized DAG visibility.
curl -sk -H 'Authorization: Bearer ***' \
  'https://airflow.example.test/api/v2/eventLogs?limit=20'

# Lab-only: compare detail IDs from authorized and unauthorized DAG events.
curl -sk -H 'Authorization: Bearer ***' \
  'https://airflow.example.test/api/v2/eventLogs/12345'
```

A vulnerable result is a detail response for another DAG's event log when the collection route does not expose that event to the same principal. Avoid broad ID brute forcing; use seeded lab events or a tiny adjacent-ID window only if explicitly permitted.

Evidence to capture: tested principal, authorized DAG, unauthorized DAG, collection response omission, detail endpoint response status/body fields, and numeric ID derivation method.

### JWT cookie `Secure` flag check

Safe first pass: inspect `Set-Cookie` headers from normal login or refresh flows.

```bash
curl -sk -D - -o /dev/null \
  'https://airflow.example.test/login/' | grep -i '^set-cookie:'
```

Look for the JWT/session cookie relevant to Airflow API auth. A high-signal finding requires all of these:

- the auth cookie lacks `Secure`;
- the same hostname or parent domain can be reached over cleartext HTTP, or HSTS does not prevent downgrade in the tested browser context;
- the deployment uses TLS termination before the Airflow API server or otherwise permits a plaintext hop where the browser would send the cookie;
- the captured cookie would authenticate API access.

Do not attempt live credential capture or MITM against users. If active proof is required, use a lab browser profile and a canary account you control.

## Reporting heuristics

- For Variable redaction, frame the invariant as “low-privilege reader can recover masked nested secret values,” not just “Airflow is outdated.”
- For event logs, show the collection/detail authorization mismatch with the minimum number of IDs needed.
- For cookie flags, distinguish missing header hardening from exploitable session replay. The report is stronger when you prove cleartext reachability and canary-token reuse in a lab account.
- Include remediation references only after the operator evidence: affected endpoint, role, canary value/event, response status, and scope boundary crossed.

## Notes on skipped and unchanged sources

- GitHub Advisory Database also listed generic SourceCodester XSS, GPAC parser crashes, and FlexRIC SCTP disconnect DoS items. They were processed but not promoted because they did not add durable Skillz Wiki operator guidance beyond existing XSS/parser-crash/resource-boundary patterns.
- CISA KEV stayed on catalog `2026.06.01` with CVE-2024-21182 already reflected in the previous middleware boundary update.
- ProjectDiscovery published a Neo agent-architecture engineering post; it reinforces existing agentic DAST planning/execution/verification guidance but did not require a new wiki page this hour.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025; GitHub Security Blog stayed GHES signing-key rotation / IR-oriented; Trail of Bits stayed on older zizmor material; Disclosed stayed lander-only.
