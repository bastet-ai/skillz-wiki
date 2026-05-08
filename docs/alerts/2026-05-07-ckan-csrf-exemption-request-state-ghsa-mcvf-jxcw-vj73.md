# CKAN CSRF exemption request-state boundary (GHSA-mcvf-jxcw-vj73 / CVE-2026-41255)

**Signal:** GitHub Security Advisories updated **2026-05-08**. CKAN fixed a request-state bug where anonymous or token-authenticated access could mark an endpoint as CSRF-exempt for the lifetime of a worker process.

## What it is
CKAN used Flask-WTF's `CSRFProtect` exemption API as if it could safely vary per request. The exemption state was stored on a shared object in middleware, so a request that reached a protected endpoint through an unauthenticated or token path could prime that server worker to skip CSRF checks for later browser-session requests.

Affected package: pip `ckan`.

- Affected: `>= 2.10.0, < 2.10.10`
- Affected: `>= 2.11.0, <= 2.11.4`
- Fixed: `2.10.10`, `2.11.5`

References: <https://github.com/advisories/GHSA-mcvf-jxcw-vj73>, <https://github.com/ckan/ckan/security/advisories/GHSA-mcvf-jxcw-vj73>

## Triage
1. Inventory public CKAN portals and identify instances running `2.10.x` before `2.10.10` or `2.11.x` before `2.11.5`.
2. Prioritize deployments with authenticated admin/editor workflows exposed to ordinary browsers, because exploitation pairs naturally with XSS or user-driven navigation.
3. Review whether any custom extensions call CSRF exemption APIs dynamically during request handling; treat process-global request-state mutation as suspicious.

## Mitigation
- Upgrade CKAN to `2.10.10`, `2.11.5`, or later.
- Keep CSRF exemptions static and route-scoped. Do not use decorator-style exemption mechanisms for per-request decisions.
- Put state-changing CKAN endpoints behind SameSite cookies, explicit origin/referrer checks, and server-side CSRF validation even when API token paths exist.

## Detection ideas
- Look for anonymous or token-authenticated requests to endpoints immediately before state-changing browser-session requests on the same worker or host.
- Correlate CKAN admin/editor mutations with preceding XSS, suspicious referrers, or missing CSRF tokens.
- Add regression tests that send an unauthenticated/token request first, then verify a separate cookie-authenticated request still requires CSRF.

## Durable lesson
Request-specific authorization and CSRF decisions must not be stored in shared middleware state. If a control is process-global, treat it as configuration, not as a per-request switch.
