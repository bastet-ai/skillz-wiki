# CAST Imaging wave (8 GHSAs): one issuer header enrolls your own IdP for admin takeover

Source: hourly offensive-security scan of GitHub Security Advisories, wave published 2026-11-18T15:34Z. Vendor banding only: all eight advisories have empty GHSA package version fields, confirmed in CAST Imaging 3.6.2, vendor says fixed "in newer versions" without a range. Treat version fingerprinting as an open item and verify from the app's own build banner before reporting.

**Wave in one line:** an enterprise code-analysis appliance trusts a request header to choose which OpenID Connect issuer to trust, ships a hardcoded auth-service token, and reads `/proc/self/environ` through its own file-management API, so an unauthenticated attacker can walk in via a fake IdP or enumerate users and credential hashes before ever authenticating.

## Advisory table

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-32fr-8jh3-mcch](https://github.com/advisories/GHSA-32fr-8jh3-mcch) | CVE-2026-109857 | critical | `TenantFilter` processes the `X-ISSUER-LOCATION` HTTP header and **dynamically registers an OIDC issuer from its value**. Point it at an IdP you operate, create users matching existing administrative usernames, mint JWTs the application accepts. Unauthenticated auth bypass straight to administrative access. |
| [GHSA-cpr5-vpq9-7vq5](https://github.com/advisories/GHSA-cpr5-vpq9-7vq5) | CVE-2026-109859 | medium | `/api/auth/keycloak/users/{username}` has **no authentication at all**: an unauthenticated attacker can modify an arbitrary Keycloak user's email address and read sensitive account data including the API authentication token hash. Account takeover and user enumeration without credentials. |
| [GHSA-3rm5-vmc4-7vm6](https://github.com/advisories/GHSA-3rm5-vmc4-7vm6) | CVE-2026-109861 | high | Hardcoded authentication token in the `KeyCloakController` class of `auth-service.jar`. Anyone who extracts it from source, the application package, logs, or config files can call auth-service endpoints unauthenticated, enumerate users across Keycloak realms via `/api/auth/keycloak/users`, and pull user attributes containing API token hashes. |
| [GHSA-8mm7-8r6p-9pxc](https://github.com/advisories/GHSA-8mm7-8r6p-9pxc) | CVE-2026-109858 | high | Path traversal in various endpoints via `../`; reading `/proc/self/environ` yields environment variables with Keycloak and PostgreSQL passwords, chaining to full server compromise. |
| [GHSA-53q7-59m7-64fv](https://github.com/advisories/GHSA-53q7-59m7-64fv) | CVE-2026-109860 | high | `/api/server-folders` and `/api/server-folders/download` accept user-supplied filesystem paths and **execute a whitelist of system commands (`ls` etc.) at the supplied location** with no authorization boundary; enumerate directories and pull arbitrary files like `/etc/passwd` outside the app workspace. |
| [GHSA-mjhq-6xrq-9jfp](https://github.com/advisories/GHSA-mjhq-6xrq-9jfp) | CVE-2026-109863 | medium | A wildcard route redirects **any unrecognized URL path** to `/admin/applications`; low-privileged users then reach admin-restricted actions: app-to-app link generation, regex configuration, searchable-object property changes. |
| [GHSA-chwp-f842-7v55](https://github.com/advisories/GHSA-chwp-f842-7v55) | CVE-2026-109862 | medium | `/api/admin/user/update-subscriber` lets a low-privileged user toggle **another user's** email notifications, a silent security-alert suppression primitive. |
| [GHSA-hhwv-9jvp-hh2w](https://github.com/advisories/GHSA-hhwv-9jvp-hh2w) | CVE-2026-109864 | low | `/api/jobs/<uuid>/logs/download` authorizes on UUID knowledge only: any authenticated low-priv user downloads any job's log archive if they know or guess the identifier. |

## Why this earns a page

This is a compact museum of five boundaries an operator hits on every appliance engagement, all in one product:

1. **Header-selected trust anchor (the crown leg).** `X-ISSUER-LOCATION` turns an inbound header into a *trust decision input*: the server registers whichever OIDC issuer the header names. This is the header-as-identity family's most powerful variant yet, previous legs let you spoof *which user* you were claimed to be; this one lets you choose *who is allowed to say who you are*. One header, a Keycloak/authorization-server instance you control, and a username copied from any public source is a complete admin login. Same genealogy as the EGroupware `idp` parameter (Nov 17, this wiki's IdP-authority page, any `https://` URL becomes your IdP): **any request input that *selects* the identity provider is an authentication-destination control**, whether it arrives as a query param, a config field, or a header. Dynamic client/issuer registration APIs (RFC 7591-style, Spring Security OAuth2 `issuer-location` conventions) turn "we trust our IdP" into "we trust whoever the request says," and the attacker's registration is *self-service*, there is no admin to phish.
2. **`/proc/self/environ` as the canonical env-leak target.** The traversal leg does what half the container-escape writeups recommend: process environment holds Keycloak and PostgreSQL passwords. When probing *any* authenticated file-read primitive, `/proc/self/environ`, `/proc/self/cmdline`, and `/proc/self/status` should be the first reads, ahead of `/etc/passwd`, because they are product-shaped: modern deploys put secrets in env vars by design.
3. **Whitelisted-command execution at an attacker-chosen path.** `/api/server-folders` is the "safe command, unsafe location" pattern: `ls` is vetted, the path is not. The audit question for every admin file-manager, backup, or media endpoint is *which parameter reaches the argv and which reaches the cwd*, and whether the two are independently attacker-controlled.
4. **Hardcoded token in a shipped jar.** `auth-service.jar` is the practical target: decompile the product's own jars/asar/wheels before brute-forcing anything, grep for literal tokens, client secrets, and `Authorization:` literals. The token here opens cross-realm user enumeration plus token-hash attributes, recon worth a high rating on its own.
5. **Wildcard route into the admin panel.** The "unknown path redirects to `/admin/applications`" leg is an inverse route-family bug: instead of a hidden legacy route missing authz, the *fallback handler itself* lands inside the admin surface, and admin actions behind it check nothing. Always enumerate deliberately bogus paths (`/zzz`, `/../../admin`, random strings) and observe where the framework *redirects* you; the catch-all destination is an untested route family.

## Validation workflows (authorized scope only)

!!! warning "Lab instances, your own IdP, synthetic users only"
    Run every proof against a CAST Imaging instance you are explicitly authorized to test. The issuer-registration leg must target a Keycloak/auth-server *you operate*, and user creation happens only in your own realm. Never register attacker-controlled issuers against production IdPs, never read real credential material into report evidence, and redact any captured hashes.

### 1. Header-driven issuer decision table

Preconditions: authorized CAST Imaging target, your own OIDC provider (Keycloak container is fine) with a canary realm, one known application username from passive recon (login-page error text, docs, `/api/auth/keycloak/users` if the unauthenticated leg is present).

1. Baseline: normal login flow, capture how the app discovers its issuer (well-known URL, cookie, config) so you know what the legitimate value looks like.
2. Replay the login/SSO entry request with `X-ISSUER-LOCATION: https://idp.your-lab.example/realms/canary` and record the decision table: {absent, legitimate value, your URL, your URL with path traversal, non-HTTPS, empty} x {login page renders against your IdP, JWKS fetched from your host, JWT from your realm accepted}.
3. In your own realm, mint a token for a username that exists on the target (use a lab account whose username you own on both sides; on production targets test only with your own account name).
4. Positive: your realm's JWT yields an application session with elevated role. Confirm the negative on the patched build. Log which endpoint consumed the header (login initiator vs callback vs TenantFilter-time) since the report should name the exact consumption point.

### 2. Unauthenticated auth-service surface battery

1. `GET /api/auth/keycloak/users` and `GET /api/auth/keycloak/users/{username}` with no cookie or token: record response shapes, user enumeration breadth, and whether attribute payloads include token-hash fields.
2. `PATCH/PUT` the email field of a **lab-owned** user via the unauthenticated endpoint to prove write capability (never touch a real user's email; a successful write against your own canary account is sufficient proof).
3. Package-side: pull `auth-service.jar` from an eval/lab install (or the vendor package), grep `KeyCloakController` for literal strings, test any recovered token against auth-service endpoints from a lab install only.

### 3. File-reader and path battery (authenticated leg)

With any low-privilege lab account: hit `/api/server-folders` with `{path: "/etc"}` style payloads, then `/proc/self/environ`, `/proc/self/cmdline`, and the app config directory. Record which *commands* the endpoint honors at which paths; a per-command x per-location capability table is the report artifact. For proof in production-scope tests, read a known-marker file you planted yourself or a file whose existence you can state without quoting contents.

### 4. Route-fallback and object-authz probes

1. Request 10 random unrecognized paths; diff the redirect targets. Landing inside `/admin/*` from an unauthenticated or low-priv request is the finding; then check which admin actions (link generation, regex config) actually execute for the low-priv session.
2. Object-level battery: for every `/api/<resource>/<id>` verb, replay with a second lab user's resource id (job logs, notification settings). UUID-only authorization on log download and cross-user notification toggles are both cheap, high-signal reports because impact is concrete (log-borne secrets; security-alert suppression).

## Reporting heuristics

- The issuer-header leg should be reported as auth bypass + privilege escalation with the full chain written out (header -> dynamic issuer registration -> attacker realm user -> accepted JWT -> admin), CVSS-critical framing justified by the unauthenticated path. Include the decision table; it proves the header is consumed, not merely reflected.
- For the env-read and jar-token legs, report **field presence** with redacted evidence: name the variable keys exposed (`KEYCLOAK_PASSWORD`, `POSTGRES_PASSWORD`) and redact values. Never paste live credential material into the report.
- The notification-suppression leg is easy to understate; frame impact as security-controls tampering (an attacker mid-intrusion silences the victim's alerting), not just a settings write.
- Version banding is vendor-silent; anchor every finding to the 3.6.2 confirmed build and request the fixed version from the vendor before final severity claims.
