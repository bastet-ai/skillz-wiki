# PostCSS, PhpSpreadsheet, and Auth.js trust-boundary checks

Source: hourly offensive-security scan, 2026-07-23 GitHub advisory publication wave. Primary entries: [GHSA-6g55-p6wh-862q](https://github.com/advisories/GHSA-6g55-p6wh-862q) / CVE-2026-45623, [GHSA-6hq5-7373-42rg](https://github.com/advisories/GHSA-6hq5-7373-42rg) / CVE-2026-59931, [GHSA-8fpg-xm3f-6cx3](https://github.com/advisories/GHSA-8fpg-xm3f-6cx3), [GHSA-7rqj-j65f-68wh](https://github.com/advisories/GHSA-7rqj-j65f-68wh), and [GHSA-x445-f3h2-j279](https://github.com/advisories/GHSA-x445-f3h2-j279).

This wave exposes reusable boundaries in developer-facing processors and identity integrations:

- metadata embedded in untrusted CSS can become a process-local file read;
- an approved spreadsheet fetch origin can redirect to a destination that was never approved;
- an authentication error object can satisfy an application-level existence check;
- an email address can change structure after downstream Unicode normalization; and
- OAuth anti-CSRF material can lose the provider identity of the flow that created it.

!!! warning "Authorized validation only"
    Use disposable applications, synthetic files, owned HTTP and mail endpoints, fake identity providers, and test-only accounts. Do not read host secrets, query metadata services, probe internal production services, intercept real sign-in links, or link accounts belonging to other users.

## Boundary map

| Advisory | Required reachability | Positive signal | Negative control |
| --- | --- | --- | --- |
| PostCSS source-map path | attacker-influenced CSS reaches `postcss().process()` with on-disk source-map handling enabled | an annotation aimed at a synthetic readable file causes a distinguishable parse error or instrumented read | `map: false`, a missing canary path, or PostCSS `8.5.12+` does not read it |
| PhpSpreadsheet redirect SSRF | uploaded workbook formulas are calculated after `setDomainWhiteList()` approves at least one origin | `WEBSERVICE()` starts at the approved owned origin and follows its redirect to an owned destination outside the allowlist | direct use of the destination is rejected; fixed releases reject or revalidate the redirect |
| Auth.js truthy error session | Auth.js v5 middleware or a route handler authorizes with `!!auth` or `if (req.auth)` | an unauthenticated request passes only while a controlled server-configuration error populates `auth` | the same request fails with valid config, a concrete `auth.user` check, or `next-auth` beta 32+
| Auth.js email canonicalization | magic-link provider uses the default identifier normalizer and a downstream mailer normalizes Unicode | pre-normalization and post-NFKC parsing disagree about separator count or recipient | ASCII-only controls and patched normalization reject the ambiguous test address |
| Auth.js provider confusion | multiple OAuth/OIDC providers, logged-in account linking, observable authorization request, and a target flow not requiring PKCE | a check cookie minted for provider A is accepted on a synthetic provider B callback | single-provider, provider-bound cookie, or PKCE-enforced flow rejects the swap |

A package version is reconnaissance only. Confirm the application-specific source-to-sink path and every listed precondition.

## 1. PostCSS source-map file boundary

### Recon

Look for attacker-controlled or tenant-controlled CSS entering:

- CMS theme and user-style processors;
- browser-extension style importers;
- package or template preview builders;
- multi-tenant build services; and
- application code that invokes `postcss().process(css, options)`.

Record the runtime package version, effective `map` option, `from` path, working directory, error handling, and whether processing occurs synchronously or asynchronously. The vulnerable default is important: the advisory states that an absent `map` option still parses a non-inline `sourceMappingURL` annotation.

The confirmed affected range is `postcss <= 8.5.11`; the first fixed release is `8.5.12`.

### Safe replay

1. Create a temporary test directory and a synthetic source-map target containing a non-secret marker such as `POSTCSS_CANARY_7F3A`.
2. Mirror the target's exact PostCSS call in a local harness.
3. Process ordinary CSS as the baseline.
4. Add a final `sourceMappingURL` comment that names the synthetic file. Test:
   - a relative path within the fixture;
   - a `..` path that reaches a separate synthetic sibling directory, only if the target supplies `from`; and
   - a nonexistent path.
5. Instrument `fs.readFileSync` or capture the thrown error. Do not point the annotation at `/etc`, `/proc`, home directories, credentials, or application configuration.
6. Repeat with `map: false` and PostCSS `8.5.12+`.

Expected vulnerable behavior is a three-state oracle: missing paths are ignored, existing non-JSON files produce a JSON parse error, and valid source-map JSON may parse successfully. Error text may contain only an initial fragment of a file; report exactly what the fixture shows rather than claiming full remote file disclosure.

Strong evidence is:

```text
untrusted CSS -> sourceMappingURL extraction -> resolved canary path -> readFileSync(canary) -> parse/error response
```

Also prove whether the application exposes the distinction to the submitting user. A process-local read that is visible only to trusted build logs has a different impact from a response-body oracle.

## 2. PhpSpreadsheet redirect revalidation

### Preconditions

The advisory's workflow requires all of these:

1. the application accepts attacker-influenced workbooks;
2. formulas are calculated with `getCalculatedValue()` or an equivalent evaluation path;
3. a nonempty domain whitelist is installed with `setDomainWhiteList()`; and
4. an approved domain can issue an attacker-steerable redirect.

Affected release lines and first fixes are:

- `<= 1.30.5` -> `1.30.6`;
- `2.0.0-2.1.17` -> `2.1.18`;
- `2.2.0-2.4.6` -> `2.4.7`;
- `3.3.0-3.10.6` -> `3.10.7`; and
- `4.0.0-5.8.0` -> `5.8.1`.

### Owned redirect matrix

Use two owned HTTP listeners:

- **A**: hostname present in the test application's allowlist;
- **B**: hostname absent from the allowlist, returning only `PHPSPREADSHEET_CANARY`.

Create a workbook whose `WEBSERVICE()` formula targets A. Configure A to return a single redirect to B. Capture requests at both listeners and the synthetic calculated cell value.

| Test | Initial URL | Redirect | Expected secure decision |
| --- | --- | --- | --- |
| direct negative | B | none | blocked before fetch |
| approved baseline | A | none | fetched |
| redirect boundary | A | A -> B | blocked or each hop revalidated |
| port control | A on unapproved test port | none | decision recorded separately |
| fixed version | A | A -> B | destination rejected or redirect disabled |

The report should prove **initial allowlist pass -> HTTP redirect -> unapproved final destination -> response returned to formula evaluation**. Do not substitute a blind timing difference if the application exposes a deterministic owned-callback or canary-body result.

Never use cloud metadata, loopback services, RFC1918 infrastructure, or third-party redirectors. An owned second listener demonstrates the final-destination policy failure without touching sensitive networks.

## 3. Auth.js authorization and identity-flow checks

### Truthy configuration-error object

Search middleware and route handlers for existence-only checks:

```text
!!req.auth
if (req.auth)
Boolean(auth)
authorized: ({ auth }) => !!auth
```

In a disposable Auth.js v5 fixture:

1. send an unauthenticated request to a harmless protected marker route with valid configuration;
2. introduce a controlled configuration error, such as a deliberately incomplete synthetic provider;
3. capture the shape of `req.auth` and repeat the request;
4. compare an existence check with `req.auth?.user` and an explicit role/permission decision; and
5. repeat on `next-auth 5.0.0-beta.32+`.

The affected range is `next-auth 5.0.0-beta.0` through `5.0.0-beta.31`. A valid finding shows an unauthenticated request accepted because an error object is truthy. Do not describe this as universally remotely triggerable: the advisory requires a server-side configuration error, so document who or what can cause that state.

### Email normalization order

This check applies only to passwordless email sign-in using the default identifier normalizer and a downstream mail component that performs Unicode normalization.

Use two owned test mailboxes and an instrumented mail sink. Compare the address at four stages:

1. original submitted code points;
2. Auth.js normalized identifier;
3. the mailer's post-NFKC recipient string; and
4. the mailbox selected by the test mail transport.

Use a synthetic address containing a Unicode code point that normalizes to the ASCII separator only inside the fixture; log code points rather than copying an account-targeting address into a report. The proof is a parser differential: **validated as one structure before canonicalization -> canonicalized into another structure -> magic-link recipient changes**.

Affected versions are `@auth/core 0.1.0-0.41.2`, `next-auth 4.10.3-4.24.14`, and `next-auth 5.0.0-beta.1-5.0.0-beta.31`. Fixed releases are `@auth/core 0.41.3`, `next-auth 4.24.15`, and `next-auth 5.0.0-beta.32`.

### Provider-bound OAuth checks

First prove every precondition with test providers and accounts. Capture cookie names and hashes, never raw state, nonce, verifier, authorization code, or session values.

| Sequence | Check-cookie creator | Callback provider | Linking enabled | PKCE required | Expected secure result |
| --- | --- | --- | --- | --- | --- |
| baseline A | A | A | yes | target setting | accepted |
| baseline B | B | B | yes | target setting | accepted |
| cross-provider | A | B | yes | no | rejected as wrong flow/provider |
| PKCE control | A | B | yes | yes | rejected |
| patched control | A | B | yes | same as vulnerable fixture | rejected |

Run the sequence only against fake providers or local OIDC fixtures and link disposable accounts. The issue is not ordinary OAuth CSRF: it is loss of provider identity when global check cookies are consumed. Exploitation also requires the victim to start a legitimate same-origin flow, according to the advisory.

Affected versions are `@auth/core <= 0.41.2`, `next-auth <= 4.24.14`, and `next-auth 5.0.0-beta.1-5.0.0-beta.31`. Fixed releases are `@auth/core 0.41.3`, `next-auth 4.24.15`, and `next-auth 5.0.0-beta.32`.

## Evidence and reporting

For all five boundaries, lead with reachability rather than package presence. Capture:

- dependency and deployed-bundle version;
- exact attacker-controlled input and processing entry point;
- effective options, whitelist, middleware condition, or provider configuration;
- a marker-only positive result;
- a missing-input, stricter-policy, or patched-version negative control; and
- the narrowest demonstrated impact.

Use wording such as:

- "synthetic file read reached and initial marker bytes surfaced," not "all server secrets stolen";
- "owned final redirect destination fetched," not "cloud metadata compromised";
- "configuration-error object passed an existence-only gate," not "authentication always bypassed";
- "owned test recipient changed after normalization," not "arbitrary account takeover"; and
- "provider-A check material was accepted by provider B in a disposable linking flow," not "all OAuth providers compromised."
