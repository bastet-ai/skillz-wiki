---
title: Ghost fetch, upload, import, and offer-state boundaries
---

# Ghost fetch, upload, import, and offer-state boundaries

Ghost advisories published on August 4 provide a reusable CMS test sequence: normalize the destination actually reached, enumerate every feature that performs the fetch, constrain archive and generated-backup paths, rotate authentication state, project only role-appropriate fields, sanitize remote and imported content at the final render boundary, and revalidate mutable commerce state at the state-changing sink.

Primary sources:

- IPv4-mapped IPv6 SSRF-filter bypass [GHSA-wvp2-4qqp-4h3r / CVE-2026-53944](https://github.com/advisories/GHSA-wvp2-4qqp-4h3r);
- Admin API upload `Content-Type` spoofing on S3/GCS backends [GHSA-944x-pm95-3jpr / CVE-2026-53948](https://github.com/advisories/GHSA-944x-pm95-3jpr);
- Universal Import post-content XSS [GHSA-2gx6-7gx2-wwcf / CVE-2026-70588](https://github.com/advisories/GHSA-2gx6-7gx2-wwcf);
- archived subscription-offer redemption [GHSA-4wx2-7gvj-qfq3 / CVE-2026-70589](https://github.com/advisories/GHSA-4wx2-7gvj-qfq3);
- DNS-rebinding external-fetch SSRF [GHSA-ch52-px8q-f22j / CVE-2026-53945](https://github.com/advisories/GHSA-ch52-px8q-f22j), Mobiledoc image-dimension SSRF [GHSA-g366-23fw-ggp6 / CVE-2026-53946](https://github.com/advisories/GHSA-g366-23fw-ggp6), and staff image-fetch SSRF [GHSA-gcvv-72q8-9v76 / CVE-2026-70591](https://github.com/advisories/GHSA-gcvv-72q8-9v76);
- database-backup path traversal [GHSA-cj62-hvv2-2q5h / CVE-2026-70592](https://github.com/advisories/GHSA-cj62-hvv2-2q5h) and theme-upload path traversal [GHSA-cjc9-q5gf-327p / CVE-2026-70593](https://github.com/advisories/GHSA-cjc9-q5gf-327p);
- Ghost Admin session fixation [GHSA-7mpp-r37j-x5wh / CVE-2026-70594](https://github.com/advisories/GHSA-7mpp-r37j-x5wh) and blind password-hash disclosure [GHSA-jm22-3w23-5q7w / CVE-2026-70590](https://github.com/advisories/GHSA-jm22-3w23-5q7w);
- ActivityPub client rendering XSS [GHSA-xpp7-93x6-v29m / CVE-2026-53950](https://github.com/advisories/GHSA-xpp7-93x6-v29m);
- member-existence response discrepancy [GHSA-chgm-3698-jm42 / CVE-2026-53947](https://github.com/advisories/GHSA-chgm-3698-jm42); and
- donation-to-paid-gift-membership value mismatch [GHSA-xm43-3m56-w3wf / CVE-2026-59817](https://github.com/advisories/GHSA-xm43-3m56-w3wf);
- public Content API filter projection of private fields [GHSA-jx35-x7fj-vgpr](https://github.com/advisories/GHSA-jx35-x7fj-vgpr);
- staff-authored feature-image caption rendering [GHSA-pr22-p9rp-2cqv](https://github.com/advisories/GHSA-pr22-p9rp-2cqv); and
- unauthenticated feature-specific fetches such as Webmentions reaching internal-network hosts [GHSA-x5mm-wm4g-j5xv](https://github.com/advisories/GHSA-x5mm-wm4g-j5xv).

The records span several independently patched release lines. The API package metadata lists 6.21.1 for the mapped-address upload-era wave, 6.21.2 for DNS rebinding, Mobiledoc fetches, and member-response behavior, 6.44.0 for the donation/gift flow, and 6.54.1 for import, offer, filesystem, session, general image-fetch, and field-projection issues. `@tryghost/activitypub` is independently fixed in 3.1.0. Confirm the exact affected range in each advisory; prose and package metadata differ by one patch number in some records, so do not infer that one Ghost version fixes every path.

!!! warning "Owned Ghost lab and inert canaries only"
    Use a disposable site, synthetic staff/members/offers/posts, owned network listeners, patched file/session/API sinks, and a test S3/GCS-compatible bucket on an isolated origin. Never target metadata or internal production services, overwrite files, retrieve password hashes, upload executable content, run script, redeem a paid offer, or involve real identities, billing instruments, sessions, or production media.

## 1. Compare policy address to transport address

The fetch issue accepted an IPv6 literal whose low 32 bits represented a private IPv4 destination. Build a destination matrix around one owned public listener and one lab-private canary:

- ordinary public IPv4 and IPv6 controls;
- direct private and loopback negatives;
- IPv4-mapped IPv6 forms of the same private canary;
- compressed, expanded, uppercase/lowercase, and parser-canonicalized IPv6 text; and
- redirects and DNS names only as separate controls—do not attribute a redirect or rebinding result to this literal-address bug.

Record raw host, URL-parser output, canonical IP object, embedded IPv4 value where defined, policy class, and final socket peer. A strong positive is **literal IPv6 passes the external-address filter -> transport recorder connects to the denied IPv4 canary**. The proof ends at an owned callback; never request cloud metadata or a real internal endpoint.

## 2. Trace upload metadata through object storage to browser interpretation

Use a benign file whose bytes are unmistakably non-HTML and contain only a random text marker. Submit it through the authorized Admin API while varying filename, declared multipart type, detected byte type, object metadata, download response `Content-Type`, `Content-Disposition`, storage backend, and media origin.

| Input/storage condition | Evidence to capture | Secure result |
| --- | --- | --- |
| declaration matches benign bytes | request and stored metadata | normal control |
| declaration claims active HTML for benign bytes | stored object headers and GET response | reject or serve inert type/download |
| S3/GCS-compatible backend | object metadata plus CDN/origin response | server-derived type wins |
| same-origin media | browser parser mode in a sessionless profile | no active document interpretation |
| isolated media origin | origin and response policy | no access to application origin |

Do not upload a script or handler. A bounded positive is **client-declared active type -> object metadata preserves it -> same-origin GET enters an HTML document parser**, demonstrated only with an inert visible marker. Separate upload acceptance, stored metadata, served headers, origin placement, and script capability; the first three do not alone prove cross-site scripting.

## 3. Treat universal import as a second parser boundary

Export a synthetic Ghost post, modify only one rich-text field with harmless structural markers, and re-import it into the disposable site. Exercise HTML cards, Markdown conversion, nested or malformed elements, encoded markup, attributes, links, media blocks, and content that passes through more than one serializer. Instrument each representation: archive member, importer model, stored post document, editor preview, and public render.

Use an inert custom element or disallowed attribute as the canary and disable script execution. The reportable transition is **import accepts a marker outside the supported content schema -> persisted post -> final renderer reparses it as an active DOM structure**. Do not use cookie/session access or publish to real subscribers. Compare an equivalent post created through the normal editor; import and editor paths should converge on the same sanitized stored representation.

## 4. Revalidate offer state at redemption time

Create a zero-value synthetic offer and one disposable member. Record offer identifiers but use a payment-provider stub that can never charge. Compare active, archived, expired, deleted, wrong-product/tier, already-redeemed, and caller-modified identifiers across offer preview, checkout/session creation, and final redemption.

The security decision belongs at the state-changing sink, not only when the offer link was issued or rendered. Capture member, offer ID, current server-side state, product/tier binding, requested benefit, and whether the no-op subscription mutation recorder ran. A bounded positive is **previously valid link or known ID -> offer archived -> final redemption still reaches the mutation recorder**. Do not claim price or privilege impact unless the synthetic fixture proves the exact benefit that would have been applied.

## 5. Inventory fetch sinks, then bind every connection

Do not stop after validating one generic URL helper. Build a feature-to-sink map for image cards with missing dimensions, Admin image fetches, oEmbed, webmentions, recommendations, previews, imports, and any background re-render or migration job. Route each feature to an owned hostname whose authoritative DNS service can return an owned public address first and an isolated lab-private canary later.

Record URL parsing, every DNS answer and TTL, policy decision, redirect hop, connection-time resolution, and final socket peer. Run controls where the address remains public, starts private, changes public-to-private, changes between redirect hops, or returns mixed A/AAAA answers. A bounded positive is **feature accepts a public DNS answer -> later connection resolves or selects the denied canary -> owned canary records the request**. Do not probe metadata, loopback, or a real internal service. A timeout or DNS log without a canary HTTP request does not prove destination reachability.

For stored image cards, test both create-time and later re-render behavior. The key invariant is that a URL approved when content was stored does not remain trusted when a worker fetches it later; the final peer must be classified for every connection.

## 6. Separate archive-member paths from generated-backup paths

Use a disposable content root containing only marker files and replace the final file writer with a canonical-path recorder. Exercise two independent paths:

- theme archives with POSIX and Windows separators, absolute names, dot segments, duplicate entries, symlink members, and symlink-parent directories; and
- database-backup names or selectors with dot segments, absolute forms, encoded separators, normalization collisions, and pre-existing symlink parents.

Capture the raw archive member or backup selector, decoded value, normalized relative path, intended root, canonical parent, final candidate, and allow/deny decision. A reportable result is **authorized staff input -> final candidate escapes the intended root -> patched writer records an outside-root write attempt**. Never overwrite a real Ghost file, configuration, theme, database, or startup artifact. Keep theme extraction and backup generation as separate findings unless one input demonstrably reaches both sinks.

## 7. Treat federated content as hostile at the final render

Stand up an owned ActivityPub fixture that emits a synthetic actor and post with inert structural markers in one field at a time. Trace the ActivityStreams object through signature/fetch acceptance, normalization, persistence, API serialization, list/card views, detail view, notifications, and any rich-text renderer. Disable script and replace dangerous DOM APIs with recorders.

Vary HTML-like text, encoded markup, link/media attributes, malformed nesting, unexpected field types, and content that is sanitized before being combined with local markup. A bounded positive is **owned remote field -> accepted federated object -> final client inserts a disallowed element or event-capable attribute into the DOM**. Do not execute JavaScript or access storage. Report the exact remote field and final sink; merely receiving attacker-authored HTML over ActivityPub is not XSS.

## 8. Verify session identity changes at authentication boundaries

Session fixation requires a separate same-origin prerequisite, so use only a lab helper that can set a known pre-auth session identifier. Record identifier hashes—not cookie values—before login, after successful Admin login, after privilege or MFA transitions, and after logout. Compare fresh login, failed login, concurrent tabs, remembered devices, and an already-authenticated session.

The secure invariant is **authentication changes principal or assurance level -> old identifier becomes invalid -> new identifier is issued**. A bounded positive is **known pre-auth identifier survives successful login and authorizes the synthetic Admin marker endpoint**. Do not claim remote exploitability without independently proving how an attacker can plant or learn that identifier on the same origin, and never capture a real staff session.

## 9. Test role-aware field projection without collecting hashes

Create two synthetic staff users with random generated passwords, then patch the serializer or response logger to replace any password-derived field value with `[REDACTED:PRESENT]`. As the lower-role user, enumerate staff list/detail endpoints, include/fields/filter expansions, sort/export paths, nested relations, error responses, and alternate API versions.

Record route, caller role, target identity, requested projection, response schema, and only whether a restricted field was present. The bounded positive is **staff-level caller selects another staff object -> serializer marks a password-derived field present**. Do not preserve, compare, crack, or transmit the value. Distinguish object authorization from field authorization: permission to view a staff profile never implies permission to receive authentication material.

## 10. Bind payment amount, purchased object, and granted entitlement

Use a provider stub that accepts only random canary payment tokens and cannot move money. Model donation, paid gift membership, ordinary paid membership, and free membership as distinct server-side products. Vary amount, currency, gift recipient, tier, interval, product/price ID, checkout return state, duplicate callbacks, and client-supplied metadata.

At the no-op entitlement recorder, capture the provider-verified amount/currency, server-selected product, intended recipient, granted tier/duration, and source transaction ID. A strong result is **minimal donation payment succeeds -> callback is treated as a paid gift product -> recorder grants the higher-value membership**. Never use a real card or recipient. A low payment is not a finding unless the server actually binds it to and attempts to grant a stronger synthetic entitlement.

## 11. Compare magic-link responses as structured observations

Seed one existing and one absent synthetic email address. Replay identical sign-in requests while recording status, body schema, header set, redirect, response size class, and bounded latency distribution. Normalize dynamic request IDs and timestamps before diffing. Repeat across JSON, form, localization, malformed-email, rate-limit, and resend paths.

The reportable result is a stable response-class oracle that separates the two synthetic populations; a one-off timing difference is not enough. Do not test real addresses or automate account discovery. Preserve only labels such as `existing-synthetic` and `absent-synthetic`, never the addresses themselves.

## August 5 follow-up: filters, captions, and feature-specific fetchers

The later records add three edges to the same harness. First, public API filters are executable query structure, not merely search strings. Seed only synthetic staff records with random marker fields, patch query execution, and vary allowed fields, nested expressions, aliases, comparison operators, wildcards, and case behavior. Record parsed filter AST, selected database columns, projection schema, and a redacted `restricted-field-present` boolean. A bounded positive is **public filter syntax selects or infers a field excluded from the public schema**. Never retrieve, compare, or brute-force password-derived values.

Second, feature-image captions must be traced through editor input, storage, Admin preview, public render, and any email or feed serializer. Use inert structural markers in a script-disabled detached DOM. A positive requires a disallowed node or attribute at the final parser context; caption storage or HTML acceptance alone is not XSS.

Third, add Webmentions and every newly identified feature-specific fetcher to the section 5 feature-to-sink matrix. Test unauthenticated reachability separately from destination policy, redirects, DNS changes, and response disclosure. Use owned public and isolated canary peers only. A blind callback proves outbound reachability, not response read or code execution.

## Reporting boundaries

- Name the exact mismatch: canonical-address class, declared-versus-derived media type, importer-versus-renderer schema, or link-time-versus-redemption-time state.
- Include affected and corrected build results with identical fixtures.
- Keep each edge independent. An accepted upload is not XSS without active same-origin rendering; imported markup is not executable without a final active sink; an archived ID being readable is not redemption without a state mutation.
- For the follow-up wave, separate fetch feature from network helper, archive extraction from backup generation, profile visibility from restricted-field projection, donation payment from gift entitlement, and pre-auth session planting from post-login reuse.
- Preserve only canary headers, identifier hashes, redacted field-presence markers, IDs, state transitions, and DOM/parser decisions. Exclude content, password-derived values, tokens, member data, and provider secrets.
## October 1 follow-up: the 25-advisory Ghost wave (12:31Z, folded)

A single 12:31Z batch published ~25 Ghost advisories across a decade of versions. Six carry new operator-relevant edges beyond this page's fetch/upload matrices:

- **Suspended staff self-reactivation via password reset** ([CVE-2026-103268 / GHSA-m47h-25hm-c3r9](https://github.com/advisories/GHSA-m47h-25hm-c3r9), high, <6.62.0): the self-service reset flow never checks account *status*, so a suspended staff member regains an active session and original privileges. Lifecycle-state axis (join Vaultwarden membership-status on the Sept 21 precedence page): on any platform with suspend/deactivate, drive the full credential-recovery flow (forgot-password → token → set-password → login) as the suspended account and check which step re-validates status.
- **Staff login-as-staff with password only, 2FA bypassed** ([CVE-2026-103283 / GHSA-xwp3-2mhg-j9rp](https://github.com/advisories/GHSA-xwp3-2mhg-j9rp), high, 6.20.0–<6.57.1): session handling lets an authenticated staff user with only their password log in **as any other staff user**, skipping the target's 2FA. Test with two lab staff accounts: does the session after "switch" carry the target's full admin scope *without* a second factor? (Pair with the WP login-as family on the Sept 19 page — same missing authority-over-target check, plus a factor-suppression leg.)
- **Staff invite acceptance binds any email** ([CVE-2026-103267 / GHSA-34x9-xfcp-9vvr](https://github.com/advisories/GHSA-34x9-xfcp-9vvr), medium, <6.62.0): the accept flow takes the email from the request, not the invite — leaked invite tokens become accounts at attacker-chosen addresses. Sweep rule: for every invite/accept link, mutate the identity field in the acceptance POST.
- **oEmbed preview executes external scripts in the admin session** ([CVE-2026-103277 / GHSA-h526-5mvq-49p7](https://github.com/advisories/GHSA-h526-5mvq-49p7), high, 2.5.0–<6.34.0): remote oEmbed content isn't sandboxed → staff-session script execution from content, i.e., a content-features → admin-console bridge. Any "preview remote URL" feature in a CMS admin is an iframe/sandbox audit target before it is an SSRF test.
- **URL-encoded extension-filter bypass on theme files** ([CVE-2026-103276 / GHSA-v575-g66p-vj84](https://github.com/advisories/GHSA-v575-g66p-vj84), medium, <6.20.0, unauthenticated): `%68bs`-style encoding defeats the extension denylist → theme template/metadata read. Encoding-the-critical-segment is the standard re-check for every extension/name denylist.
- **Low-privilege staff read Admin API keys** ([CVE-2026-103281 / GHSA-crq6-86x9-65hj](https://github.com/advisories/GHSA-crq6-86x9-65hj), medium, 3.23.0–<6.23.0): the Admin API returned key material to roles below its intended ceiling — Ghost's own repeat of the credential-view-under-low-role class (Quay robot tokens, Keycloak follow-ups). Enumerate token/key sub-resources under every role, not just the admin role.

Same wave, tracked without new guidance: session-invalidation gap after password change (103279), bulk-Admin-API info disclosure (103275), member data via Feedback endpoint (103284), CSRF on comments (103285), comment-like/input-validation singles (103288/103289), staff enumeration via content API (103272), path traversal in media (103290), invite concurrency race (103282), unsanitized fields (103292), comment access-control drift (103274), admin-iframe input validation (103278), unauthenticated read via missing authorization (103269/103271/103266), API SSRF pair (103287/103291) — all classes already covered by the matrices above; re-run this page's existing harness against 6.57–6.62 range before reporting.

## October 2 follow-up: the Ghost 6.64.0 wave — theme-loading RCE, invite-token escalation, and content-feature XSS trio (12:31Z, folded)

A second Ghost batch (CVE-2026-104411–104418, all fixed in 6.64.0) lands on this page's fetch/upload matrices with four new edges:

- **Theme translation-file loading → authenticated-admin RCE** ([CVE-2026-104418 / GHSA-5pc5-4pc7-5x44](https://github.com/advisories/GHSA-5pc5-4pc7-5x44), 7.2, 6.10.3–<6.64.0) plus its read twin ([CVE-2026-104417 / GHSA-3h86-86h6-p5gj](https://github.com/advisories/GHSA-3h86-86h6-p5gj), 4.9, 1.20.0–<6.64.0): the locale setting steers which JSON translation file is loaded, escaping the active theme directory — read any server-side JSON (server config secrets), then upload a crafted theme whose translation file executes code. Rule: *any "language/locale/template" selector that resolves a file path is a traversal-then-deserialization/exec chain, not a display setting*. On a CMS admin foothold, test whether locale/theme selectors accept absolute or traversal paths before hunting for classic upload filters. The read leg's exposure of config JSON makes it a token-harvest route on shared hosts.
- **Pending-invite secret tokens readable by staff, and staff can accept invites for roles above their own** ([CVE-2026-104416 / GHSA-8gr3-r7fg-c83w](https://github.com/advisories/GHSA-8gr3-r7fg-c83w), 7.5, 4.39.0–<6.64.0): the Admin API exposes invite tokens to users with invite-view permission, and the accept path doesn't bind the accepting identity to a role ceiling → escalate by *accepting someone else's pending admin invite*. Composition rule: viewable-invite-list × unscoped-accept = standing escalation without phishing anyone; pair with the Oct 1 invite-accepts-any-email leg (103267) — enumerate invite sub-resources under the lowest staff role and try accepting every pending invite as that user.
- **Editor/Super Editor assigns own role to others** ([CVE-2026-104412 / GHSA-g74c-47mq-8gfq](https://github.com/advisories/GHSA-g74c-47mq-8gfq), 4.3, 0.5.0–<6.64.0): role assignment isn't restricted to roles *below* your own grant authority. Sweep: as role R, assign role R (and R+1) to a second lab user via every member-update endpoint.
- **Content-feature stored-XSS trio**, each a different feature→sink bridge into staff admin sessions: **oEmbed photo responses** inject scripts into post content that run in editor, published site, *and newsletter emails* ([CVE-2026-104414 / GHSA-7wpv-mphg-4gmw](https://github.com/advisories/GHSA-7wpv-mphg-4gmw), 8.1); **bookmark-card image fetching** stores non-image files from external sites as card icons/thumbnails served as HTML ([CVE-2026-104413 / GHSA-5pj5-x6hq-mvq7](https://github.com/advisories/GHSA-5pj5-x6hq-mvq7), 7.3, Contributor-writable); and **local-storage uploads served with extension-derived content types** ([CVE-2026-104411 / GHSA-6v5j-39pg-pv7v](https://github.com/advisories/GHSA-6v5j-39pg-pv7v), 7.3) — upload an HTML-bearing file, get script execution on the site's own origin. Sweep rule for CMSs with rich editors: every "preview/fetch remote URL" card feature (oEmbed, bookmark card, link preview, og:image grabber) must be tested by hosting a *response that isn't what the feature expects* (HTML served where an image/embed was requested), and the storage adapter's content-type derivation (extension vs stored MIME vs sniffing) checked with an inert HTML canary on the default local adapter. The newsletter-email leg additionally means the payload renders in *recipient clients* — capture the email render in evidence, not just the editor.

Tracked from this wave without new guidance: password-hash ordering oracle via Admin API (CVE-2026-104415, info-only, no practical recovery).
