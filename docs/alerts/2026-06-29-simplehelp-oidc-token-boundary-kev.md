# SimpleHelp OIDC identity-token boundary check

Source: hourly offensive-security scan, 2026-06-29. Primary entries: CISA KEV [CVE-2026-48558](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), NVD [CVE-2026-48558](https://nvd.nist.gov/vuln/detail/CVE-2026-48558), and SimpleHelp [Security Update 2026-05](https://simple-help.com/security/simplehelp-security-update-2026-05).

This KEV is useful for operators because it exposes a durable identity boundary: a remote-support appliance can accept OIDC identity tokens during login without validating the token's cryptographic signature. In vulnerable configurations, a forged token with arbitrary identity claims can become a fully authenticated technician session, and may bypass MFA when MFA is delegated to the IdP.

## What changed

| Entry | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [CVE-2026-48558](https://nvd.nist.gov/vuln/detail/CVE-2026-48558) | SimpleHelp 5.5.15 and earlier, plus 6.0 pre-release builds before RC2 | OIDC login accepted submitted identity tokens without verifying their cryptographic signature | Treat remote-support SSO as an appliance control-plane boundary: prove token signature enforcement with signed and tampered canaries before any technician-action testing. |

Confirmed public details:

- Affected versions include SimpleHelp `5.5.0` through versions before `5.5.16`, and 6.0 pre-release builds before `6.0 RC2`.
- The vulnerable path requires OIDC authentication to be configured.
- The reported impact is remote unauthenticated technician-session creation through forged identity claims; no user interaction is required.
- CISA added the issue to KEV on 2026-06-29.

## Operator triage

1. **Confirm ownership and scope first.** SimpleHelp is a remote-support control plane; do not test customer or third-party support portals without explicit authorization.
2. **Fingerprint only what you need.** Capture product/version evidence and whether OIDC login is enabled. Avoid technician-console enumeration, customer-device listings, remote-control actions, file transfer, or command execution.
3. **Map the identity trust chain.** Record issuer, audience/client ID, redirect URI, expected signing algorithm, JWKS URL, and whether MFA is enforced by SimpleHelp or by the upstream IdP.
4. **Use a two-token decision table.** Compare one valid, signed canary token for a disposable lab user with altered-token negative controls. The finding is signature enforcement failure, not broad JWT fuzzing.
5. **Stop at session establishment.** If a forged canary identity reaches an authenticated technician landing page in an approved lab, that is sufficient. Do not initiate support sessions, deploy agents, collect device data, or access real users.

## Replayable validation boundary

### OIDC signature-enforcement harness

- Preconditions: SimpleHelp lab or customer-approved staging server, OIDC enabled, disposable IdP/client, disposable technician identity, no production customer devices, and permission to inspect authentication traffic.
- Establish a baseline login with a valid signed ID token for a canary technician account. Capture only non-sensitive token metadata: issuer, audience, subject marker, algorithm, key ID, and authentication result.
- Build negative controls that preserve the same claims shape but break cryptographic proof:
  - alter the subject or technician claim after signing;
  - replace the signature with a bogus value;
  - use an untrusted key ID or key not present in the configured JWKS;
  - test algorithm confusion only in a lab, and record whether unsigned or mismatched-algorithm tokens are rejected.
- Submit negative-control tokens only to the approved lab login flow and record the authentication decision: rejected before session, accepted but unprivileged, or accepted as a technician session.
- Evidence should be a decision table with token metadata, altered fields, expected result, observed result, server version, OIDC configuration state, and fixed-version behavior.
- Do not publish full tokens, signing keys, real user claims, session cookies, SimpleHelp license data, device inventories, logs containing customer names, or any remote-support action evidence.

## Reporting notes

- Lead with the crossed boundary: **OIDC ID-token signature verification to technician-session creation**.
- Include version, OIDC-enabled state, issuer/audience, canary identity, signed-vs-tampered decision table, and patched negative control.
- Keep proof synthetic and reversible: disposable IdP, fake users, redacted token headers/claims, and screenshots limited to authentication state.
- Avoid overclaiming reachability when OIDC is not configured or when the target is already on `5.5.16` / `6.0 RC2` or later.
