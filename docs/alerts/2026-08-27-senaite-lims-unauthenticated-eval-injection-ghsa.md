# Senaite LIMS unauthenticated eval injection, operator validation

**Date reviewed:** 2026-08-27  
**Advisory:** [GHSA-JRW6-7X4Q-W25J](https://github.com/advisories/GHSA-JRW6-7X4Q-W25J) / CVE-2026-54569  
**Severity:** Critical (CVSS 9.8)  
**Affected:** `senaite.core` (Zope-based LIMS) prior to the patch referenced by the advisory  
**Boundary class:** unauthenticated JSON API write route → Python `eval()` sink

## What is durable here

Senaite is a Zope-based Laboratory Information Management System that
frequently runs on public management subnets, DMZs, or behind a single
WAF rule. The advisory describes a two-request anonymous chain:

1. **Missing `AccessJSONAPI` gate on the JSON API write route.** The
   `/@@API/update` route runs an `eval()` on attacker-controlled input
   before any permission check fires. The sibling `create.py` route
   does enforce the permission; the `update.py` route does not.
2. **`eval()` sink on a write-accessible field.** Even after the
   permission gate is restored, an authenticated user with write access
   to a `RecordsField` can still reach the same `eval()` sink. Either
   fix alone does not close the unauthenticated chain.

The operator value is the **unauthenticated `eval()` on a JSON API
route**, a rare, high-yield primitive on a Zope stack. Most Zope
applications sit behind the same Zope instance as other products, so
a working chain here often gives a foothold on a host that also runs
lab data, sample management, and sometimes internal integrations.

## Validation workflow (authorized lab / customer-approved)

### Recon

- Enumerate Zope routes on the target host. Senaite LIMS typically
  exposes `/@@API/create`, `/@@API/update`, and a handful of other
  JSON API routes. The `update` route is the interesting one.
- Confirm the product is `senaite.core` (not a fork). The advisory's
  affected range is specific to `senaite.core`.
- Note the Zope instance version. Older Zope instances have additional
  unauthenticated management surfaces.

### Proof of unauth reachability (no code execution)

1. Send an authenticated request to `/@@API/update` with a valid
   session token and a benign field update. Confirm it works.
2. Repeat the same request **without** a session token (or with an
   anonymous cookie jar). If the route returns `200` and applies the
   update, the `AccessJSONAPI` gate is missing.
3. Do **not** attempt code execution. The proof is the route-level
   permission differential, not the `eval()` payload.

### If the gate is present

- An authenticated account with `RecordsField` write access can still
  reach the `eval()` sink. Validate by:
  1. Obtaining a low-privilege account with write access to a
     `RecordsField` (ask the customer for a throwaway account).
  2. Sending an update that sets the field to a benign string.
  3. Confirming the update is applied without an `AccessJSONAPI`
     permission error. The `eval()` sink is present but the chain
     requires both flaws; record this as a **conditional** finding.

### Negative evidence to record

- A `403` or `401` on the anonymous `/@@API/update` request means the
  gate is present.
- A `400` with a permission error means the gate is present but the
  `eval()` sink may still be reachable by authenticated users.

## Reporting heuristic

- Lead with the **unauthenticated `eval()`**, it is the critical
  finding. The authenticated variant is a secondary finding that
  requires two flaws to chain.
- State the Zope instance version and whether the `update.py` route
  is the one at `src/bika/lims/jsonapi/update.py` or a fork.
- Do not publish `eval()` payloads. The proof is the route-level
  permission differential.
- If the target is a fork of `senaite.core`, note the fork name and
  version; the advisory range may not apply.

## Safety constraints

- Do not execute arbitrary code on the target.
- Do not modify lab data, sample records, or workflow state.
- Use throwaway accounts only.
- Do not test against production LIMS data.
