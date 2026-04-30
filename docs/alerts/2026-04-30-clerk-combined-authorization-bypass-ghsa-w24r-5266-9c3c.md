# Clerk combined authorization predicate bypass (GHSA-w24r-5266-9c3c / CVE-2026-42349)

**Signal:** GitHub Security Advisories published **2026-04-30**. Clerk SDK authorization helpers could incorrectly allow requests when multiple authorization dimensions were combined in one predicate.

## What it is
`has()`, `auth.protect()`, and related Clerk authorization predicates could return `true` for combined checks that should fail. Authentication, sessions, impersonation, and token verification are not the issue; the risk is an application trusting a faulty authorization decision for a gated action.

Affected call shapes include:

- reverification combined with `role`, `permission`, `feature`, or `plan` in one `has()` / `auth.protect()` call;
- billing checks (`feature` or `plan`) combined with role or permission checks;
- an additional `@clerk/nextjs` path where `auth.protect()` discarded authorization params when the same object also included `unauthenticatedUrl`, `unauthorizedUrl`, or `token`.

Single-condition checks and callback forms that combine separate single-condition checks were not described as affected.

Affected packages include many Clerk npm packages, including `@clerk/shared`, `@clerk/backend`, `@clerk/nextjs`, `@clerk/clerk-js`, React/Vue/Astro/Nuxt/Expo/Express/Fastify/Hono integrations, and others across current major lines. Patched versions vary by package; upgrade each consuming Clerk framework package to its advisory-listed patch release.

Reference: <https://github.com/advisories/GHSA-w24r-5266-9c3c>

## Triage
1. Search application code for `has({ ... })`, `auth.protect({ ... })`, and direct `createCheckAuthorization` use.
2. Flag predicates that combine more than one dimension, especially `reverification` plus permission/role/plan/feature or billing plus role/permission.
3. Prioritize admin, billing, organization-management, destructive, and data-export routes.
4. Run `npm why @clerk/shared` or the package-manager equivalent to identify the installed shared package version pulled through framework packages.

## Mitigation
- Upgrade the Clerk framework package and any directly pinned Clerk packages to the patched advisory versions.
- If you cannot upgrade immediately, split combined checks into sequential single-condition checks and deny if any condition fails.
- Keep callback-form authorization explicit, for example `has({ permission: 'org:X' }) && has({ reverification: 'strict' })`, rather than one combined object.
- Add regression tests for routes where auth requirements combine identity, organization, billing, and reverification gates.

## Detection ideas
- Review access logs and audit events for successful sensitive actions by users lacking the expected role, permission, plan, feature, or recent reverification.
- Compare route-level authorization code to business rules for organization admin, billing, and account-security flows.
- Hunt recent deployments that introduced combined Clerk predicate objects.

## Durable lesson
Authorization helper APIs are policy compilers. When multiple dimensions are collapsed into one predicate, test the exact combined shape and keep high-risk gates fail-closed with independent checks.
