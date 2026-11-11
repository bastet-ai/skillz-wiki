# 2026-02-05, Devtron Attributes API leaks API token signing key (GHSA-8wpc-j9q9-j5m2)

**Product:** **Devtron** (Go)

## Impact (per advisory)
An authorization failure in Devtron’s Attributes API can allow a logged-in user to retrieve the global API token signing key (`apiTokenSecret`). With that key, an attacker can **forge JWTs** and potentially gain **full control** of Devtron and move laterally into the underlying Kubernetes cluster.

## Recommended actions
- Apply vendor fixes as available.
- Until patched:
  - Restrict network access to the orchestrator API (NetworkPolicy / ingress allowlists).
  - Treat `apiTokenSecret` as compromised: rotate it and invalidate existing tokens.
  - Review role assignments; minimize accounts that can access sensitive APIs.

## August 31 follow-up: `/orchestrator/api-token/webhook` returns plaintext super-admin JWTs to any authenticated user (GHSA-mrqp-7v92-wchj / CVE-2026-82882)

A second, distinct Devtron authorization failure on the same API-token surface: `GET /orchestrator/api-token/webhook` performs **no authorization check** beyond "is the caller authenticated at all." Any authenticated account, including a low-privilege user, can query the endpoint with arbitrary `project`, `environment`, and `application` parameters and receive **plaintext super-admin JWT tokens** in the response body, giving full platform control and a lateral-move credential into the managed Kubernetes clusters. This is a CWE-862 (missing authorization) on a token-issuance endpoint, and it pairs with the earlier `apiTokenSecret` signing-key leak: one path hands you the *key*, this one hands you a *forged-equivalent signed token directly*.

- **Affected:** Devtron through `2.2.0`.
- **Severity:** high.
- **Sink references:** `ApiTokenRestHandler.go` / `pkg/apiToken/ApiTokenService.go` (v2.2.0 tree), tracked at <https://github.com/devtron-labs/devtron/issues/7013>.

### Operator triage

1. Treat the Devtron orchestrator API as a **token-issuance surface**, not just a config API. Enumerate every `api-token*` route and check which ones gate on *role* rather than *authenticated*.
2. The reusable boundary: **a webhook/automation endpoint that exists to mint API tokens for machines must still carry the caller's permission context**, "this is a machine endpoint" is not a valid authorization check when humans can reach it.
3. If you can reach any Devtron route authenticated, probe the token-issuance family before anything else: the blast radius (super-admin JWT → cluster admin) dwarfs the individual route's intended function.

### Replayable validation (lab / owned cluster only)

Preconditions: an authorized lab Devtron `<= 2.2.0` with at least two lab accounts (one low-privilege, one admin) and disposable projects/environments/apps. No production Devtron instances, no real cluster credentials, no exfiltration of issued tokens outside the lab.

1. **Baseline:** with the low-privilege lab account, call the token routes the account legitimately owns; record that the webhook route is reachable (HTTP 200, not 403).
2. **Positive proof is the token's *scope*, not its content.** Query `GET /orchestrator/api-token/webhook` with a lab project/environment/app and confirm the response carries a JWT whose claims/permissions correspond to **super-admin**, not the calling low-privilege user. Decode claims locally to document the privilege mismatch. Do not use the token against any real cluster; in the lab you may verify the mismatch by calling a lab admin-only route with it and observing it succeeds.
3. **Parameter steering:** show that arbitrary `project`/`environment`/`application` values change the minted token's resource scope, the endpoint trusts caller-selected parameters for what a webhook should have pre-bound.
4. **Negative control:** patched build (or a build with the authorization check restored) must return 403 for the low-privilege account.
5. Capture: Devtron version, both accounts, the steered parameters, the decoded claim mismatch (redact any real signing keys or cluster secrets), and the negative control.

### Durable lesson

- **Token-issuance endpoints are authorization boundaries, not automation conveniences.** The moment an endpoint can mint a more-privileged token, its own authz check is the only thing standing between a low-privilege account and that higher privilege.
- **Pair this with the Feb 5 signing-key leak when reporting Devtron findings:** together they describe the full credential-extraction surface (key leak → self-forged tokens; webhook route → directly issued tokens). A report that stops at "one missing check" understates the platform-level impact.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-8wpc-j9q9-j5m2>
- GitHub advisory: [GHSA-mrqp-7v92-wchj / CVE-2026-82882](https://github.com/advisories/GHSA-mrqp-7v92-wchj)
- Devtron issue: <https://github.com/devtron-labs/devtron/issues/7013>
- VulnCheck advisory: <https://www.vulncheck.com/advisories/devtron-through-2.2.0-missing-authorization-via-webhook-api-token-endpoint>
