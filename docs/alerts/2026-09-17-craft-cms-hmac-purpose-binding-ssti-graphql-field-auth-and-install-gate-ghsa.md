---
title: "Craft CMS wave: unbound HMAC signatures to unsandboxed Twig RCE, GraphQL field-auth gaps, and outage-triggered installer secret disclosure"
---

# Craft CMS wave: unbound HMAC signatures to unsandboxed Twig RCE, GraphQL field-auth gaps, and outage-triggered installer secret disclosure

The September 17 GitHub wave (published 2026-09-17T00:31Z) lands a six-advisory Craft CMS cluster that is unusually operator-valuable: **two signed-token authority breaks that chain low-privilege authenticated access to server-side template injection RCE**, a **GraphQL field-level authorization gap that turns a drafts-only scope into unauthenticated PII harvest**, a **fail-open install-state gate that leaks environment secrets during a database outage**, and a **read-only-view-to-write-authz drift** on a reorder endpoint.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-24f9-r76v-62p8](https://github.com/advisories/GHSA-24f9-r76v-62p8) / CVE-2026-92592 | Cookie HMAC not bound to its purpose: the `license-shun` cookie is signed with the **same key and format** (`cookieValidationKey` derived from `securityKey`) used to validate signed redirect parameters. A non-admin user signs an arbitrary payload into the cookie, transplants the envelope into the login redirect parameter, and on successful login Craft renders the authenticated bytes as an **unsandboxed Twig template** — the `map` filter accepts a string callback, reaching PHP `system()` as the web-server user (4.18.6 / 5.10.13) | Signature-domain confusion: any app that reuses one HMAC key across cookie validation, redirect signing, and parameter signing lets a low-privilege feature mint trusted tokens for a higher-trust parameter |
| [GHSA-9v9g-4j69-p6q5](https://github.com/advisories/GHSA-9v9g-4j69-p6q5) / CVE-2026-92593 | **Incomplete fix + new oracle**: the prior fix for CVE-2026-55794 left the `getPostedRedirectUrl() → View::renderObjectTemplate()` sink unsandboxed **and the fix commit itself added a self-signing oracle** (`Cp::elementLabelHtml()`). Because Craft/Yii HMAC tokens are not bound to a **parameter name**, a low-privilege CP user with edit rights on one element type mints a token over attacker-controlled Twig for `returnUrl` and replays it as the `redirect` POST parameter → SSTI → arbitrary PHP (5.10.13) | HMAC parameter tokens that sign *values* but not *names* are transplantable across parameters; always diff fix commits — they can introduce signing oracles alongside the patch |
| [GHSA-f53v-9r85-mf77](https://github.com/advisories/GHSA-f53v-9r85-mf77) / CVE-2026-92594 | GraphQL `draftCreator`/`revisionCreator` fields gated only on `elements.drafts:read`/`elements.revisions:read` instead of the `usergroups.*:read` user-data scope, and the resolver returns a raw `User` element (email, username, fullName, addresses) with **no per-field authorization**. With the public GraphQL schema enabled plus those scopes, this is **unauthenticated editor/admin PII harvest** (5.11.0) | GraphQL resolver authorization must be checked at both field-resolution level and consumer-scope level; relationship fields pointing at user models are the usual leak |
| [GHSA-fq6c-26cc-63cr](https://github.com/advisories/GHSA-fq6c-26cc-63cr) / CVE-2026-92591 | A database connection failure makes Craft conclude it is **not installed**, re-exposing anonymous installer actions (`install/validate-site`) on a production site. The action serializes a site name through `Site::getName()` and expands `${NAME}` via `App::env()` — a pre-obtained guest session/CSRF pair plus a predictable variable name (`CRAFT_SECURITY_KEY`) returns security keys, DB credentials, API keys, `$_SERVER` entries (5.10.13) | Feature-gating on "is the app configured" instead of explicit install-state flags is a time-of-check fail-open; enumerate installer/setup routes and re-probe them during any degraded-dependency window |
| [GHSA-mhr8-6rjx-8fjw](https://github.com/advisories/GHSA-mhr8-6rjx-8fjw) / CVE-2026-92589 | Opening another author's entry **read-only** unconditionally grants the session a `manageNestedElements::<ownerId>::field:<handle>` flag; unlike the delete endpoint, `actions/nested-elements/reorder` trusts the session flag alone and never rechecks the caller's save permission → view-only users rewrite Matrix/Address sort order they were denied (5.10.13) | Sibling-endpoint authz parity: build a per-endpoint matrix of "checks session flag only" vs "rechecks permission"; the read path granting a write flag is the bug |
| [GHSA-gjx7-qh8p-42m8](https://github.com/advisories/GHSA-gjx7-qh8p-42m8) / CVE-2026-92590 | Generated Fields feature disables Twig autoescaping and doesn't encode cached values → editor-to-admin stored XSS in the Control Panel element index (5.10.13) | Feature toggles that flip a global escaping default are stored-XSS islands; include generated/computed field features in CMS XSS matrices |

!!! warning "Lab-only validation"
    Use disposable Craft installs with synthetic users, synthetic security keys, and scratch content. Do not mint tokens or replay signed envelopes against third-party sites, and do not attempt installer actions against production deployments. Secret-disclosure proofs must use lab-configured fake values only.

## Operator patterns

### 1. Signature-purpose and signature-name binding audit (both RCEs)

The two RCE advisories are the same audit family: **an HMAC envelope proves integrity but not intent**.

1. Inventory every place the application emits an HMAC-signed value (cookies, redirect parameters, action tokens, email verification links, state params). Ask: does the signed payload include a *purpose/type* field, and is the verification site pinned to that purpose?
2. Same question for parameter names: if the signature covers only the value, a token minted for parameter A is replayable as parameter B. Craft's `returnUrl`→`redirect` transplant is the template.
3. In a lab, find any endpoint that signs attacker-influenced bytes for a low-trust feature (here: setting a `license-shun` cookie, element-label rendering), capture the signed output, and check whether a higher-trust consumer accepts the same envelope. Positive evidence is the downstream consumer *acting on* the transplanted bytes — stop at an inert marker in the signed value; don't build the Twig `system()` chain on anything but your own box.
4. **Diff fix commits.** CVE-2026-92593's patch introduced its own signing oracle. For any CMS/framework with a security history on a route, re-run the original attack matrix *and* inspect what the patch added, not just what it closed.

### 2. GraphQL field-authorization differential

1. Fetch the introspection schema (public schema endpoints are often unauthenticated). For every field whose return type is a user/identity type (`User`, `Author`, `Creator`), request it with the *minimum* plausible scope, or with no token at all on public schemas.
2. Two-scope differential: request `entries.author { email username }` with entries-read only, then with drafts-read, then with user-data scope. Any non-null identity field below the user-data scope is the finding.
3. Report field presence with synthetic users; redact any real PII immediately. This is a schema-level design bug — the report is the scope matrix, not harvested records.

### 3. Degraded-state feature gating

1. Enumerate installer/setup/onboarding routes (`install/*`, `setup/*`, `initialize`) and re-probe them with a pre-captured guest session + CSRF pair — they may be gated on *runtime connectivity* rather than a persisted install flag.
2. Where an action expands template expressions (`${VAR}`) against the process environment, request conventional variable names (`*_SECURITY_KEY`, `*_SECRET`, `DB_*`) and record whether values are returned. In the lab, configure fake env values first.
3. This class doesn't require you to cause the outage — it requires noticing that an availability incident flips an authz decision. During authorized engagements, ask whether setup routes were reachable during any degraded window.

### 4. Read-path grants write flag

1. For any CMS that grants *temporary/session-scoped* capability flags when rendering a record, enumerate every endpoint that trusts such a flag and check which ones also re-check the underlying permission (Craft's delete endpoint did; reorder didn't).
2. Two-disposable-author lab: author A creates content, view-only author B opens it read-only, then B POSTs to each sibling write endpoint (reorder, move, sort, replicate) using the parameters visible in the read-only page source. Positive = state change without the save permission.

## Reporting heuristics

- For signature-confusion RCEs, report the mint route, the consumer route, the parameter transplant path, and the exact binding that is missing (purpose vs name vs key). State preconditions precisely — CVE-2026-92592 needs password-auth accounts without active 2FA and PHP `system()` available; don't overclaim unauthenticated.
- For the incomplete-fix advisory, cite the prior CVE and show the fix commit introduced the oracle — that's a maintainer-trust finding as well as a vulnerability.
- GraphQL and reorder findings are authorization deltas; evidence is the request/response pair plus role/flag state, no data volume.

## October 7 follow-up: preview-token action re-dispatch to unauthenticated admin impersonation

[GHSA-cc7p-2j3x-x7xf](https://github.com/advisories/GHSA-cc7p-2j3x-x7xf) / CVE-2026-32267 (updated-feed enrichment landing 2026-10-07T06:59Z, original advisory March 16; fixed 4.17.6 / 5.9.12) completes this page's token-binding theme with a **full-privilege pre-auth takeover**: any holder of a valid Craft **preview token** — including an unauthenticated visitor sent a shared preview URL, or an editor who clicked Preview once on their own entry — can request `/?token=<preview>&action=users/impersonate-with-token&userId=1&prevUserId=1` and land in the admin dashboard as user 1. The advisory ships a working PoC, so this is a proven class, not inference.

Three defects compose it:

1. `actionPreview()` re-dispatches with `$skipSpecialHandling=true`, which bypasses all security guards on the re-dispatched request, and passes `$checkToken=false` to `checkIfActionRequest()` — so an attacker-controlled `action` query parameter **overrides the dispatch target** of a tokenized preview URL.
2. The `requireToken()` guard on `actionImpersonateWithToken()` only checks a boolean `_hadToken` set when *any* preview token resolved. The token is never bound to the impersonation action — the same purpose-binding gap as CVE-2026-92592/92593 above, now on the session-mint side instead of the HMAC side.
3. `actionImpersonateWithToken` sits in `$allowAnonymous` with no authorization beyond `requireToken()` — possession of any valid token from any route *is* the authentication.

Operator patterns for this class:

- **Action re-dispatch sweep.** Where a controller re-dispatches internally (`handleRequest`, forward, sub-request), diff the guard set of the outer request vs the inner one. Flags like `skipSpecialHandling`/`_inner` that suppress guards on the second pass, combined with a routable `action`/`_target` query parameter, give one valid token from a low-trust route as an envelope for any anonymous action.
- **`$hadToken`-style booleans are not bindings.** Grep guard code for boolean "a token was present" checks (`_hadToken`, `tokenValid=true`); compare against guards that re-derive the intended action/route from the token payload. Every impersonation, password-reset-completion, magic-link, and SSO-handoff action guarded only by presence-of-token is the same bug.
- **Anonymous allow-list inventory.** `$allowAnonymous` (or per-action anonymous lists in any Yii/Craft-lineage or Laravel app) plus a single weak guard = pre-auth surface. Enumerate the list from source or route dumps, then probe each entry with a token minted for a *different* purpose.
- **Shared URLs carry the token to unauthenticated parties.** Preview, live-preview, and share links embed tokens in iframe `src` values — a token you were "sent" is an attacker-reachable pre-auth trigger leg. Treat forwarded preview URLs as credential material in scope conversations.
- Fingerprint band: 4.x ≤ 4.17.5 and 5.x ≤ 5.9.11 are vulnerable; the PoC's expected 404-then-admin-landing behavior means a successful hit looks like a navigation error, not a redirect — verify by following up with `/admin` in the same session.

## October 24 follow-up — two more routes to the same `securityKey`: sandboxed element-search oracle and CRLF `.env` key replacement ([GHSA-gg4p-9c93-5hfp / CVE-2026-115938](https://github.com/advisories/GHSA-gg4p-9c93-5hfp), [GHSA-j6hf-w48h-c9f9 / CVE-2026-115935](https://github.com/advisories/GHSA-j6hf-w48h-c9f9), high)

A second Craft wave (published 2026-10-24T00:32Z) lands **two independent ways to obtain or replace `GeneralConfig::securityKey`** — after which this page's HMAC→unsandboxed-`renderObjectTemplate()` RCE chain applies unchanged. Each leg closes none of the others (the advisory says so explicitly: "fixing either source does not fix the other"), and both start from a low-privilege `accessCp`-only account.

1. **Sandboxed Twig becomes a character oracle via a delegated property lookup.** Any authenticated CP user can submit an element-search condition whose element selector is evaluated as a *sandboxed* Twig object template. The sandbox's empty property/method allowlists are bypassed because Craft's allowed `column` filter delegates property lookup to Yii `ArrayHelper` — **outside** Twig's `SecurityPolicy`. The condition value is eventually cast to an integer, but that's fine: the template returns author ID 1 when a guessed key character is correct and an impossible ID otherwise, and the JSON endpoint's entries-vs-empty-array response is a stable **remote character-by-character oracle** for the security key. ([GHSA-gg4p-9c93-5hfp](https://github.com/advisories/GHSA-gg4p-9c93-5hfp))
2. **Fake API response headers CRLF-inject the `.env` writer.** The `app/process-api-response-headers` action accepts Craft API response headers from any authenticated CP user; a `accessCp`-only user puts newlines into `X-Craft-Plugin-Licenses` and Craft writes the value to `.env` **without stripping them** — inserting an attacker-chosen `CRAFT_SECURITY_KEY`. Once Craft loads the replacement key, the user forges a signed login redirect containing a Twig `system()` callback. Key *replacement* beats key *theft*: no oracle needed, and it survives the fix for leg 1. ([GHSA-j6hf-w48h-c9f9](https://github.com/advisories/GHSA-j6hf-w48h-c9f9))

Operator rules from this wave:

- **A sandbox that delegates lookups to an unsandboxed helper is not a sandbox — and the delegation is usually one library call away from the "allowed" filter.** The fingerprint is any allowlist/whitelist filter whose member-check itself calls into a general-purpose accessor (`ArrayHelper::getValue`, `getattr`, map-path resolvers). Audit predicate: for every "allowed columns/fields/properties" filter, trace where the property *lookup* executes; if it's outside the policy object, repeated single-segment lookups probe anything. This is the same shape as the Aug 4 Flowise 38-regex deny-list bypass and the `ownPropertyOnly` LiquidJS family — the check and the read must run in the same enforced layer.
- **Any boolean-shaped response over attacker-guessable input is a key-recovery oracle.** JSON endpoints that return non-empty for a correct guess and empty otherwise turn the final integer cast (a "safe" sink) into a side channel. When hunting signed-token RCEs where the key isn't readable: enumerate *every* endpoint whose output shape depends on config material (search conditions, cache keys, ordering, error-vs-empty) and check for a stable two-state differential. The regression-proof discipline transfers: prove with `substr()`-style inert callbacks, never `system()`, outside your own box.
- **Response-header-shaped inputs that reach config-file writers need newline stripping at the writer, not the parser.** Grep every code path that persists a header/env/callback-provided value (`->write` into `.env`, `php_value`, ini files) for CRLF filtering; "this endpoint only accepts API responses" is moot when the *client* controls the response being parsed — a malicious/compromised upstream, or as here, a local action that trusts request-supplied headers as if they were upstream replies. Test decision table per writer: clean value / value with `\n` / value with `\r\n`, in the low-priv role.
- **Two independent secrets paths = report them as separate findings even when one fix ships.** Maintainer fix-scope drift on this product is already canonical on this page (CVE-2026-92593's fix added its own oracle); the same-day twin advisories explicitly warn the two key-exposure legs don't subsume each other. Post-fix verification must run BOTH the search-condition oracle and the fake-header `.env` probe before trusting a patch.
- Bands: confirm against the vendor advisory — GHSA package version fields were empty at scan time. Validation stays lab-only: disposable CP users, synthetic security keys, marker-only callbacks.

## Tracked without publication

- Craft `User` element adjacent hygiene items in the same wave without a new boundary.
- This wave's Nodemailer cluster is covered on its own page ([mail-parser differentials and sandbox-option drop](2026-09-17-nodemailer-addressparser-differentials-and-resolvecontent-sandbox-drop-ghsa.md)); n8n, AVideo, and misc siblings are folded into their existing pages.

---

*Source: hourly offensive-security scan, 2026-09-17 (00:31Z GitHub advisory wave); October 7 follow-up added 2026-10-07 from the enriched GHSA-cc7p landing. Tracked in the [source index](../notes/source-index.md).*
