# Fleet MDM identity and rate-limit boundary batch

Source: GitHub Security Advisories updated 2026-05-14.

Fleet's May 14 advisories are a clean reminder that management-plane identity is not just "a signed token exists" or "a request has a familiar device identifier." The verifier has to bind the credential to the expected tenant, audience, issuer, certificate, and proxy chain before any device-management or brute-force protection decision is made.

## Advisories covered

- **Fleet Windows MDM Azure AD JWT authentication bypass** — [GHSA-ffg9-j72f-j6xm](https://github.com/advisories/GHSA-ffg9-j72f-j6xm): Windows MDM accepted Microsoft-signed Azure AD tokens without enforcing the expected `aud` and `iss` claims, allowing tokens from unrelated tenants to authenticate to MDM endpoints.
- **Fleet Windows MDM management endpoint authentication bypass** — [GHSA-2rc4-7jc6-qffh](https://github.com/advisories/GHSA-2rc4-7jc6-qffh): device-management requests could be processed without proper client-certificate validation, letting an attacker with a valid device identifier impersonate an enrolled Windows device in some circumstances.
- **Fleet rate-limit bypass via untrusted client IP headers** — [GHSA-j8h8-75h3-jg53](https://github.com/advisories/GHSA-j8h8-75h3-jg53): per-IP rate limits trusted client-supplied `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` values instead of only trusted proxy-injected address metadata.

## Operator triage

1. Patch Fleet deployments using Windows MDM to fixed versions (`>=4.82.0` for the Azure AD JWT issue, `>=4.81.0` for the mTLS endpoint issue, and `>=4.80.1` for the rate-limit bypass).
2. Treat MDM as a privileged control plane: review enrollment events, device identifiers, and configuration-payload access for unexpected Azure AD tenants, missing client certificates, or anomalous enrollment attempts.
3. Check ingress/proxy configuration and application logs for attacker-controlled forwarding headers. Only the final trusted proxy hop should be allowed to set the effective client address.
4. Rotate or reissue sensitive enrollment material if logs show unknown tenants, devices, or repeated rate-limit evasion around Fleet auth routes.

## Durable controls

- Validate all token binding fields: signature, issuer, audience, tenant, scopes, expiry, and the local enrollment context.
- Fail closed on absent or invalid client certificates for device-management endpoints; never substitute a user-supplied device identifier for possession proof.
- Make rate limits depend on transport/proxy-trusted attributes, not raw request headers supplied by the client.
- Add regression tests for wrong-tenant JWTs, missing-client-cert requests, and spoofed forwarding headers at every exposed control-plane route.

## September 7 follow-up: observer-class field-masking differential on target search (GHSA-88p2-jj8w-j8qg / CVE-2026-48786)

Source: GitHub Security Advisories updated 2026-09-06 (published 2026-08-12, `fleet/v4 < 4.87.0`, medium 6.5, CWE-639/200). This extends the May 14 batch with a different boundary class: **per-role response sanitization is a per-route property, and search/list endpoints routinely skip it.**

The target search endpoint (`POST /api/latest/fleet/targets`) returned unmasked team enroll secrets and full team configuration — including credential-bearing agent options (AWS secret access keys, proxy passwords, session tokens) — to users with Observer, Observer+, or Technician roles (global or team-scoped). Other team-facing endpoints mask these same fields for the same principals; the target search path did not apply the sanitization step. A leaked enroll secret is directly usable to enroll unauthorized hosts into the team, so the read-only differential collapses into an enrollment primitive plus credential theft.

Durable axes:

1. **Field-masking is a per-route decision, not a global one.** When a platform supports read-only/observer roles, the masking of sensitive fields is applied at each handler, not at the object layer. The reusable test: pick one sensitive field class (enroll tokens, API keys, stored credentials, customer PII), request the same object through every reachable read path (list, search, export, detail, dashboard endpoints), and diff the response schemas. One endpoint that returns the field unmasked is the finding.
2. **Search/aggregate endpoints are the weak ones.** Search, filter, and aggregate handlers (Fleet's `targets`, Kibana-style saved searches, Jira search, SAML user search) build responses from different code paths than the primary detail view. They frequently serialize the whole stored object instead of the role-projected view. Prioritize them when auditing role-scoped platforms.
3. **Role-scoped "read-only" still implies write capability.** Observer/Technician roles in MDM fleets are meant to be non-mutating, but the secrets they can read (enroll tokens, agent-option credentials) are mintable/enrollable. For any read-only role, inventory what each readable field *enables* (enroll, proxy, API call) — the read is the exploit.

Replayable validation boundary:

- Disposable Fleet < 4.87.0 lab instance; synthetic team with a marker enroll secret and marker agent-option credentials (e.g., `FAKE_AWS_KEY` values you generated); a synthetic Observer-class user account.
- Call `POST /api/latest/fleet/targets` with an observer-runnable synthetic query and compare the returned team object field-for-field against a known-masked team endpoint for the same role. A positive is the target-search response containing the unmasked enroll-secret field and agent-option credential fields.
- Do not enroll real hosts with the marker secret, do not use the marker credentials against real services, and do not repeat the differential against non-synthetic tenants or real enroll tokens.
