# Keycloak account-API feature-flag boundary

Source: hourly offensive-security scan, 2026-06-10. Primary entry: GitHub advisory [GHSA-hm32-hfmw-rhvg](https://github.com/advisories/GHSA-hm32-hfmw-rhvg) / CVE-2026-7500 for Keycloak account API forced browsing when `--features-disabled=account,account-api` leaves selected `/account/v1alpha1` endpoints reachable.

This is durable for operators because it gives a reusable bug-hunting pattern: **a product advertises a disabled feature or UI surface, but alternate versioned API routes still execute read/write account operations for authenticated users**.

## Why it matters for assessments

Feature flags and disabled modules are often treated as hard authorization boundaries during tenant hardening, appliance configuration, or managed-service rollout. The Keycloak advisory shows a common gap:

- older or canonical endpoints check whether a feature is enabled;
- newer, preview, or versioned endpoints implement the same capability but miss the feature gate;
- the UI appears unavailable, but direct HTTP requests can still reach account-profile or account-management operations.

For red-team and bug-bounty work, the useful lesson is not just Keycloak-specific path trivia. The repeatable test is to map every route family that represents the same business capability and verify that the disabling control is enforced consistently across each route.

## What to map

1. Confirm an explicitly scoped Keycloak instance where the customer expects account UI/API functionality to be disabled with `--features-disabled=account,account-api` or equivalent deployment configuration.
2. Record the Keycloak version, hostname, realm, and whether the test account is a normal authenticated user rather than an administrator.
3. Enumerate account route families exposed by the instance, including:
   - `/realms/<realm>/account/`
   - `/realms/<realm>/account/*`
   - `/realms/<realm>/account/v1alpha1/*`
   - any reverse-proxy rewritten equivalents.
4. Identify which endpoints should be blocked when the account feature is disabled and which still return authenticated read or write behavior.
5. Use only a disposable user profile, session, and canary fields. Do not alter real user MFA, credentials, recovery codes, or production identity settings.

## Safe validation boundary

Run this only against a lab, owned tenant, or program-approved Keycloak deployment.

Minimal proof shape:

```bash
BASE='https://keycloak.example.test'
REALM='demo'
TOKEN='redacted-test-user-access-token'

# Expected-disabled account surface. Redact TOKEN in notes and screenshots.
curl -i \
  -H "Authorization: Bearer <redacted-test-token>" \
  "$BASE/realms/$REALM/account/"

# Versioned account API family highlighted by the advisory.
curl -i \
  -H "Authorization: Bearer <redacted-test-token>" \
  "$BASE/realms/$REALM/account/v1alpha1/"
```

Then test only the smallest harmless operation the program allows, such as reading the current test account profile or updating a disposable profile attribute. Capture status codes, route, method, response shape, and whether the same action is blocked on a gated account route.

Strong evidence shows a contrast:

- disabled account route returns a disabled-feature, not-found, or forbidden response;
- a versioned account route under the same realm and same user token still performs an account read/write operation;
- the operation affects only the tester-controlled account or canary profile data.

## Route-family test heuristic

Use the same approach for other products with feature flags, disabled modules, or hidden UI:

1. Start from the disabled UI route and collect linked API calls from a lab instance where the feature is enabled.
2. Search docs, OpenAPI specs, generated clients, frontend bundles, and route tables for versioned or preview equivalents: `v1`, `v1alpha1`, `beta`, `internal`, `api`, `rest`, and legacy paths.
3. Replay equivalent read-only requests with a low-privilege authenticated user after the feature is disabled.
4. If a read endpoint still works, test one reversible canary write only after authorization is explicit.
5. Report the exact missing gate: feature-disabled configuration to still-reachable route family, not generic "forced browsing".

## Reporting heuristics

- Lead with the boundary: **disabled account feature did not disable all route families for authenticated users**.
- Include deployment flags, Keycloak version, realm, test user role, route family, HTTP method, and before/after behavior.
- Show the positive and negative control: one route blocked because the feature is disabled, one equivalent versioned route still functional.
- Keep evidence redacted. Do not include bearer tokens, cookies, real profile fields, or identity-provider secrets.
- Avoid overclaiming unauthenticated impact. The advisory states the user needs permission to use the API; prove privilege and scope precisely.

## Notes on skipped adjacent items

Sparse updated-feed PyTorch local memory-corruption entries from the same scan were marked processed without publication because they did not add a replayable web, identity, recon, supply-chain, or exploit-path workflow beyond generic local crash/memory-safety validation.
