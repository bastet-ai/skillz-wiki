# Keycloak unauthenticated account takeover via reset-credentials flow bypass, operator validation

**Date reviewed:** 2026-08-29
**Advisory:** [GHSA-4gv3-mc9p-5wqc / CVE-2026-18963](https://github.com/advisories/GHSA-4gv3-mc9p-5wqc), critical, CVSS 9.1
**Affected:** `keycloak-services` (Red Hat Build of Keycloak) reset-credentials flow
**Boundary class:** identity-provider session/authz state confusion, the email-verification gate for password reset can be bypassed by unauthenticated callers, letting an attacker set new credentials for any account.

## The primitive

Keycloak's self-service password reset requires the target user to follow the email link before new credentials can be written. In the affected builds, the reset-credentials flow in `keycloak-services` does not reliably enforce that the caller has completed the email-verification step: an unauthenticated attacker can **force the password reset process for any user and set new credentials directly**, without ever clicking or possessing the verification link.

The durable pattern: **a multi-step identity workflow whose server-side state transition (verified → credential write) is keyed to caller-supplied or attacker-reproducible tokens rather than to a server-held, single-use, time-boxed verification receipt.** The email link is a UX detail if the server's final decision ("may I write credentials for user X?") does not depend on a secret only the user's mailbox produced.

This is the highest-impact Keycloak ATO shape because it is **unauthenticated**: no valid token, no prior session, no MFA step, just the target username (or a stable identifier that resolves to the account) and the reset-flow endpoints.

## Recon heuristics

- **Find the reset-flow surface.** Enumerate `/realms/<realm>/connect/...` and account-management reset routes: `forgot-password` initiation, the email-link target route, and the credential-change endpoint. Note which routes accept a `token`/`id`/`username` parameter and which of those parameters the server treats as authoritative.
- **Probe the state gate.** The decisive test is whether the credential-write endpoint requires the verification link's token to be consumed. Send the reset-initiation request, then call the credential-change endpoint **without** consuming the link token, and separately **with** a token from a *different* user's initiation. If either succeeds, the gate is broken.
- **Check token entropy and scope.** Reset-link tokens should be high-entropy, single-use, realm+user-scoped, and short-TTL. Low-entropy, guessable, user-id-keyed, or cross-realm-reusable tokens are independent findings even when the main flow is enforced.
- **Correlate with the account-API and feature-flag history.** This advisory joins a long line of Keycloak reset/account-boundary issues (forced-browsing `/account/v1alpha1`, backchannel-logout SSRF, token-exchange fallbacks). If a realm has the account API enabled or versioned route families reachable, test the reset flow *and* the alternate route family together.
- **Version evidence.** Record the exact `keycloak-services` build (Red Hat build number) because the fix is server-side in the services component.

## Replayable validation (lab realm only)

Preconditions: an isolated lab Keycloak deployment on the affected build, one disposable victim user, one disposable attacker client/user, and full authorization. Never test against real users or production realms.

1. **Baseline control.** As the victim user, complete the normal reset flow: initiate → receive the email link (capture the link token as a synthetic label, do not reuse real mail infrastructure) → consume it → set a synthetic password. Record every request/response pair, route, and state flag.
2. **Unauthenticated gate probe.** Without any session, initiate a reset for the victim username, then call the credential-change endpoint with:
   - no token,
   - the victim's initiation token without consuming the link,
   - a token minted for a *different* user.
   A positive result is credential write succeeding where the server should demand the consumed link. Stop at the first successful write of a **synthetic** password to a **disposable** account; capture route, token labels, and expected-vs-observed state.
3. **Single-use check.** Consume the link once, then repeat the write with the same token. The fixed behavior denies reuse; record the decision.
4. **TTL/binding check.** Record whether the token is bound to realm, user, and initiating IP/user-agent, and whether a stale token (beyond the TTL) is still honored.
5. **Negative control.** Repeat step 2 against the patched build; the expected result is denial on every unauthenticated or cross-user attempt.

Evidence to capture: exact routes and parameters, token labels (never token bytes or real mailbox data), expected vs observed state transitions, and the patched-build denial table.

## Safe boundaries

- Isolated lab realm, disposable users only. No production Keycloak, no real user accounts, no real email delivery.
- Proofs use synthetic credentials and synthetic users; report the boundary crossed (unauthenticated caller → credential write for another account) and the exact state gate that failed.
- Do not publish reset-link tokens, mailbox contents, or production realm identifiers.
- Frame as **reset-flow verification-gate bypass**, not as generic "password reset weakness", the finding is the missing server-side binding between link consumption and credential write.

## Sources

- [GitHub Advisory Database: Keycloak GHSA-4gv3-mc9p-5wqc / CVE-2026-18963](https://github.com/advisories/GHSA-4gv3-mc9p-5wqc)
