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

## July 24 follow-up: previous-map traversal to `.map` disclosure

[GHSA-r28c-9q8g-f849](https://github.com/advisories/GHSA-r28c-9q8g-f849) narrows an important limitation in the PostCSS check above. PostCSS 8.5.12 blocked loading non-`.map` files through the previous source-map path, but did not confine `.map` paths to the CSS source directory. Versions through 8.5.17 still allow parent traversal when `from` is set and absolute `.map` paths when it is absent. If the loaded map contains `sourcesContent`, PostCSS can merge that content into the generated `result.map`, giving a deterministic full-content disclosure path rather than only the earlier parse/error oracle. The traversal fix is in 8.5.18.

### Revised two-phase fixture

Use this layout under one disposable root:

```text
TEMP/
  uploads/user/input.css
  uploads/user/inside.js.map
  sibling/outside.js.map
```

Both map files should be valid synthetic source maps with distinct `sources` and `sourcesContent` canaries. Then test:

1. same-directory `inside.js.map` as the expected baseline;
2. `../../sibling/outside.js.map` with `from` set to `TEMP/uploads/user/input.css`;
3. the absolute path to `outside.js.map` with `from` omitted;
4. a sibling file with a non-`.map` extension to distinguish the 8.5.12 extension restriction from path confinement;
5. each case with `map: false`; and
6. each case on 8.5.11, 8.5.12-8.5.17, and 8.5.18 or later where practical.

Capture the annotation, `from`, resolved path, filesystem-open trace, whether `result.map` becomes truthy, and whether the outside canary appears in `result.map.toString()` or an emitted API/build artifact. The expected version matrix is:

| Version | Non-`.map` outside file | Outside `.map` file |
| --- | --- | --- |
| <= 8.5.11 | earlier arbitrary-extension behavior may be reachable | reachable if path resolves and application exposes result |
| 8.5.12-8.5.17 | blocked by extension check | still reachable by traversal/absolute path |
| >= 8.5.18 | blocked | confined/rejected |

Revise the earlier negative-control guidance accordingly: `8.5.12+` is not a valid fixed control for an outside file ending in `.map`; use 8.5.18 or later. A strong finding proves **untrusted CSS annotation -> out-of-source-directory synthetic `.map` read -> `sourcesContent` copied into an attacker-visible result map**. Do not read real build maps, bundled proprietary source, or other tenants' artifacts.

## August 3 follow-up: missing-`from` residual after path confinement

[GHSA-fxqj-rqcc-2cmp / CVE-2026-69153](https://github.com/advisories/GHSA-fxqj-rqcc-2cmp) shows that the previous-map boundary must be tested by option state, not only package version. The guard added after the earlier traversal reports was conditional on a truthy CSS filename. PostCSS 8.5.22 could therefore reject an outside `.map` when `from` was supplied yet read the same absolute or parent-traversing annotation when the caller processed a CSS string without `from`. The first fixed release listed for this residual is 8.5.23.

This makes **omitted**, **empty**, and **valid** base-path states separate security cases. A successful control with `from` set does not prove that a string-input minifier, linter, playground, or build API is confined.

### Revised option-state matrix

Use only valid synthetic source maps beneath a disposable root. Give the inside and sibling maps different `sources` and `sourcesContent` canaries.

| Case | `from` state | Annotation | Affected-build question |
| --- | --- | --- | --- |
| same-directory baseline | fixture CSS path | `inside.js.map` | Does ordinary previous-map loading work? |
| parent-path control | fixture CSS path | `../../sibling/outside.js.map` | Is the path rejected relative to the CSS file? |
| missing-base residual | omitted | absolute sibling `.map` path | Is the path read because the confinement branch lacks a base file? |
| traversal residual | omitted | a `..` path resolved from the fixture working directory | Does working-directory resolution escape the intended input root? |
| extension control | omitted | sibling file not ending in `.map` | Is the extension restriction distinct from confinement? |
| parser control | omitted | malformed synthetic `.map` | Does the file-open path occur even when parsing later fails? |
| corrected build | repeat all cases on 8.5.23+ | same values | Are all untrusted outside paths rejected? |

Instrument `fs.readFileSync` or an equivalent file-open boundary and capture the effective working directory, exact options object, resolved path, and whether the canary appears in `result.map`. Keep `map: false` as an independent reachability control. Do not infer disclosure from a package version or a file-open alone: prove that the caller exposes the generated map or a deterministic marker derived from it.

The narrow report chain is **attacker-influenced CSS -> external `sourceMappingURL` -> missing `from` skips path confinement -> synthetic outside `.map` is opened -> canary `sourcesContent` reaches an observable generated map**. Never target real source maps, source trees, credentials, or another tenant's build artifacts.

## October 27 16:1xZ follow-up: five-leg second wave — the redirect fix went to one file, and the DOCTYPE scanner has two more blind spots

October 27 wave fixed 5.10.0 (band ≥4.0.0–≤5.9.0):

- **[CVE-2026-108360 / GHSA-2phh-27fw-q4gc](https://github.com/advisories/GHSA-2phh-27fw-q4gc) (medium) — the §2 redirect-revalidation fix shipped to ONE call site.** `Worksheet\Drawing::setPath()` external-image loading validates against the operator `isWhitelisted` callback on the **initial URL only**, then fetches via `file_get_contents()` with a stream context that never sets `follow_location => 0` — PHP's default follows up to 20 redirects with no re-validation. This is explicitly the unfixed sibling of CVE-2026-59931 (`7ef7b25e` touched `Calculation/Web/Service.php` only). Operator rule: after any library ships a redirect-revalidation fix, **grep every other consumer of the same URL-fetching primitive** — formula engines, drawing/image loaders, hyperlink resolvers, custom-properties — and re-run the owned redirect matrix per consumer. One fixed fetcher ≠ fixed library; each fetch site is a separate allowlist-enforcement point. Precondition gate to fingerprint: `setAllowExternalImages(true)` is opt-in, so fingerprint apps that enable it (logo-rich workbooks) before testing.
- **[CVE-2026-108358 / GHSA-3x94-m842-937c](https://github.com/advisories/GHSA-3x94-m842-937c) (high) — XmlScanner DOCTYPE regex only handles NUL interleaving.** Pattern `/\0*<\0*!\0*D\0*O.../` misses ISO-2022 escape sequences: `ESC ( B` bytes inserted between the characters of `<!DOCTYPE` break the match, then libxml's charset normalization *strips the ESC bytes* and the parser sees a valid DOCTYPE. Seven ISO-2022 variants bypass (ISO-2022-JP, JP-2, KR, CN…). Entity-expansion DoS on all PHP versions; XXE/SSRF on PHP <8.0 or `LIBXML_NOENT`. **Operator rule: the guard regex and the XML parser implement different byte-level grammars — enumerate every interleaving the parser normalizes away (NUL was tested; ESC, zero-width UTF-7-style `+AC0-`, UTF-16 BOM spellings were not). Charset-encoding itself is a bypass channel at security gates: submit the payload re-encoded, and with per-character escape sequences interleaved.**
- **[CVE-2026-108357 / GHSA-rxj4-h86g-25gc](https://github.com/advisories/GHSA-rxj4-h86g-25gc) (high) — check-decode-check TOCTOU via double HTML-entity encoding.** `scan()` runs its pattern match *before* the `unentity()` callback; the `Reader\Xml` path scans content **twice**, so `&#38;#60;` decodes one layer per scan: first scan leaves `&#60;`, second scan leaves `<`, and no check ever sees `<!DOCTYPE`. Same shape as the Sept 18 "extract-before-verify" Grafana leg: **when a decode step sits between two identical checks, encode for N+1 passes — count the decode invocations on the code path and stack encodings one deeper than the count.**
- **[CVE-2026-108359 / GHSA-j2w7-387v-m2rq](https://github.com/advisories/GHSA-j2w7-387v-m2rq) (high) — ODS `number-rows-repeated` unbounded (classic spreadsheet decompression leg, tracked-adjacent).**

Validation boundaries unchanged from §2: owned redirect matrix, synthetic workbook canaries, expansion payloads sized to a lab worker; never test XXE against metadata ranges.
