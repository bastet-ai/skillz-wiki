# OliveTin action execution, OpenAM identity, and Concrete CMS boundary checks

Source: hourly offensive-security scan, 2026-06-24. Primary entries: GitHub Advisory Database [GHSA-7fq5-7wr8-rjwj](https://github.com/advisories/GHSA-7fq5-7wr8-rjwj), [GHSA-prj9-97mp-mwh2](https://github.com/advisories/GHSA-prj9-97mp-mwh2), [GHSA-f637-w7p2-m7fx](https://github.com/advisories/GHSA-f637-w7p2-m7fx), [GHSA-6c99-87fr-6q7r](https://github.com/advisories/GHSA-6c99-87fr-6q7r), [GHSA-p462-xxwx-pqf4](https://github.com/advisories/GHSA-p462-xxwx-pqf4), [GHSA-x2fp-hj8c-mmxh](https://github.com/advisories/GHSA-x2fp-hj8c-mmxh), [GHSA-h72c-xx3w-w8h7](https://github.com/advisories/GHSA-h72c-xx3w-w8h7), and [GHSA-9v2g-37mp-qpxf](https://github.com/advisories/GHSA-9v2g-37mp-qpxf). June 25 OpenAM updates: [GHSA-pp89-732f-3g8q](https://github.com/advisories/GHSA-pp89-732f-3g8q), [GHSA-cj8f-2fhf-826r](https://github.com/advisories/GHSA-cj8f-2fhf-826r), and [GHSA-386j-6m86-78f9](https://github.com/advisories/GHSA-386j-6m86-78f9) / CVE-2026-46560. June 26 OpenAM updates: [GHSA-gf57-4mp6-m85x](https://github.com/advisories/GHSA-gf57-4mp6-m85x) / CVE-2026-46623 and [GHSA-xq73-fvmr-jvmm](https://github.com/advisories/GHSA-xq73-fvmr-jvmm) / CVE-2026-46619. June 29 OpenAM updates: [GHSA-4v2w-2wqp-mc85](https://github.com/advisories/GHSA-4v2w-2wqp-mc85) / CVE-2026-48717, [GHSA-f2cx-463q-7m2c](https://github.com/advisories/GHSA-f2cx-463q-7m2c) / CVE-2026-47426, and [GHSA-69j4-qvqr-hpw3](https://github.com/advisories/GHSA-69j4-qvqr-hpw3) / CVE-2026-47424. June 29 Concrete CMS updates: [GHSA-q9fm-mpg8-8jqm](https://github.com/advisories/GHSA-q9fm-mpg8-8jqm) / CVE-2026-8353, [GHSA-xjg6-5v39-v7fc](https://github.com/advisories/GHSA-xjg6-5v39-v7fc) / CVE-2026-8340, and [GHSA-jqvq-gv67-3567](https://github.com/advisories/GHSA-jqvq-gv67-3567) / CVE-2026-8347.

These advisories are durable for operators because they expose reusable trust boundaries: action-runner templates and argument filters crossing into shell command construction, unauthenticated helper RPCs leaking action metadata, identity-provider storage attributes crossing into deserialization, elevated SOAP writes, OAuth account-linking state mutating local credentials, PKCE and private-key client authentication state crossing into token issuance, server-side script sandbox policy crossing into JVM command execution, telephony header values crossing into LDAP filters, and CMS public widgets or admin-controlled names crossing into private calendar data or trusted login-page HTML.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-7fq5-7wr8-rjwj](https://github.com/advisories/GHSA-7fq5-7wr8-rjwj) / CVE-2026-48708 | OliveTin action executor | a shared Go `text/template.Template` instance was parsed and executed concurrently for action commands | Test action runners for cross-request command contamination with two-user canaries and high-concurrency harnesses, not only single-request injection. |
| [GHSA-prj9-97mp-mwh2](https://github.com/advisories/GHSA-prj9-97mp-mwh2) / CVE-2026-53541 | OliveTin argument filtering | user-supplied argument names beginning with `ot_` bypassed defined-argument filtering, skipped type checks, became environment variables, and entered template context | Add reserved-prefix and environment-variable checks to action-runner reviews; prove only with inert marker variables. |
| [GHSA-f637-w7p2-m7fx](https://github.com/advisories/GHSA-f637-w7p2-m7fx) / CVE-2026-48709 | OliveTin `ValidateArgumentType` RPC | unauthenticated callers could query action binding IDs and argument validation behavior even when guests must log in | Treat validation and schema-check endpoints as recon oracles for command/action surfaces. |
| [GHSA-6c99-87fr-6q7r](https://github.com/advisories/GHSA-6c99-87fr-6q7r) / CVE-2026-45051 | OpenAM WebAuthn module | WebAuthn authenticator storage could deserialize attacker-controlled data when the configured storage attribute was user-writable | Identity-provider module settings need attribute-writability checks before deserialization proof; stop at safe canary serialization in labs. |
| [GHSA-p462-xxwx-pqf4](https://github.com/advisories/GHSA-p462-xxwx-pqf4) / CVE-2026-45052 | OpenAM Liberty ID-WSF SOAP receiver | anonymous Liberty Discovery SOAP requests could write persistent discovery records to user or root-realm stores with server-side privileges | Legacy federation endpoints are useful pre-auth identity-boundary checks when exposed; evidence should be route/auth decision plus disposable discovery records. |
| [GHSA-pp89-732f-3g8q](https://github.com/advisories/GHSA-pp89-732f-3g8q) / CVE-2026-45794 | OpenAM Push Notification SNS callback | a low-privileged Push Registration participant could plant a CTS predicate blob and later trigger anonymous SNS callbacks that load attacker-named classes and deserialize attacker-controlled JSON | Test push/SNS callback paths as identity-provider object-construction boundaries; keep proof to inert class-loading or benign construction markers in labs. |
| [GHSA-cj8f-2fhf-826r](https://github.com/advisories/GHSA-cj8f-2fhf-826r) / CVE-2026-46498 | OpenAM OAuth2 token-read path | shared CTS rows were accepted as OAuth tokens based on caller-controlled identifiers and untrusted BLOB contents instead of an OAuth-only namespace and trusted CTS type binding | Hunt for token families that trust shared-store rows without type, namespace, or integrity binding; prove with disposable realm/client/user scopes only. |
| [GHSA-386j-6m86-78f9](https://github.com/advisories/GHSA-386j-6m86-78f9) / CVE-2026-46560 | OpenAM RADIUS authentication module | the client accepted the first UDP response on an unconnected socket without source, identifier, Response Authenticator, or Message-Authenticator verification | Treat external identity protocols as pre-auth session minting boundaries; prove only in isolated labs with owned RADIUS/OpenAM hosts and packet-level canaries. |
| [GHSA-gf57-4mp6-m85x](https://github.com/advisories/GHSA-gf57-4mp6-m85x) / CVE-2026-46623 | OpenAM OAuth2 authentication module | OAuth2 re-login for an existing account could rewrite the local password to the literal username and reactivate disabled accounts | Test OAuth account-linking and account-creation modules for credential mutation side effects with disposable users; prove only with lab accounts and negative controls. |
| [GHSA-xq73-fvmr-jvmm](https://github.com/advisories/GHSA-xq73-fvmr-jvmm) / CVE-2026-46619 | OpenAM MSISDN authentication module | request-supplied MSISDN values were concatenated into LDAP search filters in a default trusted-gateway configuration | Treat telephony and gateway identity modules as pre-auth LDAP-filter boundaries; prove with synthetic directory users and canary filters only. |
| [GHSA-4v2w-2wqp-mc85](https://github.com/advisories/GHSA-4v2w-2wqp-mc85) / CVE-2026-48717 | OpenAM OAuth2 authorization-code grant | PKCE-protected authorization codes could be redeemed without a `code_verifier` unless realm-wide enforcement was enabled | Add token-endpoint negative tests for missing and mismatched verifier values; prove only with disposable clients and authorization codes. |
| [GHSA-f2cx-463q-7m2c](https://github.com/advisories/GHSA-f2cx-463q-7m2c) / CVE-2026-47426 | OpenAM `private_key_jwt` client authentication | JWKS resolver cache behavior could let one registered client mint tokens as another JWKS-backed client without the victim signing key | Test client-authentication caches for issuer/client binding, key-owner binding, and cross-client token minting with fake clients only. |
| [GHSA-69j4-qvqr-hpw3](https://github.com/advisories/GHSA-69j4-qvqr-hpw3) / CVE-2026-47424 | OpenAM server-side scripting sandbox | authenticated script authors could escape the Groovy sandbox and execute OS commands from the OpenAM JVM | Treat script-author roles as runtime execution boundaries; prove with inert marker commands in isolated labs only. |
| [GHSA-x2fp-hj8c-mmxh](https://github.com/advisories/GHSA-x2fp-hj8c-mmxh) / CVE-2026-8204 | Concrete CMS calendar event frontend dialog | a public calendar block could pivot into private cross-calendar event data | Add public-widget-to-private-object pivot checks for CMS calendar, file, and content dialogs. |
| [GHSA-h72c-xx3w-w8h7](https://github.com/advisories/GHSA-h72c-xx3w-w8h7) / CVE-2026-8197 | Concrete CMS OAuth integration name | an admin-controlled integration name was rendered as raw HTML in the OAuth authorization template | Treat IdP/client names and integration labels as login-page render sinks; prove with harmless DOM markers only. |
| [GHSA-9v2g-37mp-qpxf](https://github.com/advisories/GHSA-9v2g-37mp-qpxf) / CVE-2026-8203 | Concrete CMS height parameter | editor-controlled height values could become stored browser-executed markup | Include numeric-looking layout parameters in CMS editor-to-visitor render reviews. |
| [GHSA-q9fm-mpg8-8jqm](https://github.com/advisories/GHSA-q9fm-mpg8-8jqm) / CVE-2026-8353 | Concrete CMS Atomik theme page name | editor-controlled page names could render as stored markup on authenticated account pages | Treat navigation/page metadata as trusted-theme render input, especially on account or authorization surfaces. |
| [GHSA-xjg6-5v39-v7fc](https://github.com/advisories/GHSA-xjg6-5v39-v7fc) / CVE-2026-8340 | Concrete CMS `Backend\File::approveVersion` | missing CSRF protection could approve an attacker-chosen previously uploaded file version | Test file-version workflows for token-bound side effects with synthetic file revisions. |
| [GHSA-jqvq-gv67-3567](https://github.com/advisories/GHSA-jqvq-gv67-3567) / CVE-2026-8347 | Concrete CMS Express association reorder dialog | view-level access could reorder associations across entities | Add relationship/order mutation checks to CMS builder UIs, not only create/update/delete endpoints. |

## Operator triage

1. **Action runners are command surfaces even when arguments are typed.** Check reserved prefixes, hidden/system arguments, environment construction, and template context separately from the visible action schema.
2. **Concurrency can be an exploit primitive.** For OliveTin-style runners, run paired actions from separate users with distinct canary arguments and record whether either rendered into the other command.
3. **Validation endpoints are recon endpoints.** Any helper RPC that answers whether a binding ID, argument, type, or workflow node is valid can map hidden actions before direct execution testing.
4. **Identity stores need attribute ownership maps.** For OpenAM WebAuthn, the important precondition is whether the authenticator storage attribute is server-managed or user/provisioning-writable.
5. **Legacy federation routes stay in scope.** Liberty ID-WSF endpoints may be shipped even when not actively used; validate route reachability and auth gating before attempting writes.
6. **Push registration is an identity-store write primitive.** If a low-privileged user can start a Push Registration flow and later unauthenticated callbacks process persisted state, test for stale message IDs, shared secrets, CTS row type confusion, and server-side object construction.
7. **Token stores need family binding.** OAuth/OIDC token-read paths should reject rows that lack an OAuth-specific namespace, trusted CTS type, issuer/client/realm binding, and integrity protection independent of caller-supplied identifiers.
8. **UDP identity protocols need response binding.** RADIUS, TACACS+, LDAP gateways, and legacy auth modules should bind replies to the expected peer, outstanding request identifier, and protocol authenticator before minting application sessions.
9. **OAuth login modules can mutate local identity state.** Account-linking and auto-provisioning flows should be tested for password, active/disabled, group, and profile-field side effects after repeat IdP logins.
10. **Telephony identity modules are parser boundaries.** MSISDN, gateway headers, and subscriber identifiers often reach LDAP or directory searches before password verification; test filter construction with harmless canaries.
11. **PKCE must be enforced at redemption, not only at authorization.** A stored `code_challenge` is insufficient evidence; the token endpoint must reject missing, mismatched, and reused `code_verifier` values.
12. **Client-authentication caches need client identity binding.** For `private_key_jwt`, key material discovered through a `jwks_uri` must remain bound to the client that owns that URI and the expected JWT claims.
13. **Script-author roles can be code-execution roles.** Server-side scripting sandboxes need allow/deny-list and classloader tests before assuming realm-admin-only script editing is a safe administrative feature.
14. **CMS public widgets can pivot across private objects.** Calendar/file/dialog routes should be tested with synthetic public and private objects to show object-boundary drift.
15. **Login and authorization pages are high-trust render origins.** OAuth client names, integration labels, and dimensions rendered there can become stronger findings than generic admin-only XSS.
16. **CMS metadata and workflow routes are state boundaries.** Page names, file-version approvals, and Express association order should have explicit output encoding, CSRF tokens, and object-level permission checks before changing authenticated-user state.

## Replayable validation boundaries

### OliveTin action-runner harness

- Preconditions: OliveTin lab or explicitly scoped instance, disposable actions, two test users if role separation matters, and commands that only print marker strings.
- Create two actions whose templates include distinct canary arguments. Fire them concurrently in a tight loop and capture rendered command logs or output artifacts.
- Submit additional arguments using reserved-looking names such as `ot_skillz_canary` and confirm whether they are accepted, appear in the template context, or become process environment variables.
- Query `ValidateArgumentType` without authentication only against lab binding IDs and record whether valid/invalid action and argument names produce distinguishable responses.
- Stop before executing destructive shell commands, reading environment secrets, or enumerating production action names beyond the approved test set.

### OpenAM WebAuthn and Liberty SOAP harness

- Preconditions: OpenAM lab realm, disposable users, no production SSO sessions, and explicit approval to test legacy federation endpoints.
- For WebAuthn, first document the configured `userAttribute` and whether the test user can modify it through delegated admin, REST self-service, provisioning, or direct directory write. Use only inert serialized canaries if deserialization behavior must be demonstrated.
- For Liberty Discovery, send paired unauthenticated SOAP requests that attempt to create a disposable marker record under a lab user or root-realm test branch, then verify only marker presence and cleanup.
- Evidence should include route, module/version, auth state, attribute ownership, marker ID, and patched or access-denied negative controls.
- Do not serialize gadget chains, execute server commands, write to real identity records, alter production federation data, or capture live tokens.

### OpenAM Push Registration and OAuth token-store harness

- Preconditions: OpenAM Community Edition lab through an affected version, OAuth2 Provider service enabled in a test realm, Push Notification service/SNS callbacks enabled, disposable users/clients/scopes, and no production identity data.
- Map the Push Registration flow first: who can start registration, whether QR-code payloads expose a message ID, shared secret, or challenge to that user, when in-memory dispatcher entries expire, and which callback routes remain anonymous.
- For SNS deserialization testing, use an inert class-loading or benign-constructor marker in a lab classpath only. Evidence should show stale message ID handling, CTS row mutation, callback auth state, class name attempted, and a patched negative control.
- For OAuth token-store testing, create only synthetic CTS rows in a disposable realm/client/user namespace and verify whether the token-read path accepts caller-known identifiers whose stored BLOB claims OAuth/OIDC fields such as subject, client, realm, and scope.
- Stop at proof that a fake lab token or inert object-construction marker is accepted. Do not mint tokens for real users, request production scopes, dump CTS contents, write to root-realm data, or load gadget chains.

### OpenAM RADIUS response-binding harness

- Preconditions: isolated OpenAM Community Edition lab through an affected version, RADIUS module enabled in a test realm/login chain, disposable usernames, and packet capture on lab interfaces you own.
- Map the RADIUS request from OpenAM to the test server: source/destination IP and port, request identifier, username, and expected accept/reject result.
- Send only lab-crafted Access-Accept canaries that prove whether OpenAM accepts a response from the wrong source, wrong identifier, missing/invalid Response Authenticator, or absent Message-Authenticator.
- Evidence should show packet metadata, OpenAM auth outcome, realm/module/version, named disposable principal, and a fixed-version or correctly verified negative control.
- Do not race or spoof production RADIUS traffic, impersonate real users, capture shared secrets, or use forged sessions outside the lab realm.

### OpenAM OAuth2 local-credential and MSISDN LDAP-filter harness

- Preconditions: OpenAM Community Edition lab through an affected version, OAuth2 and/or MSISDN modules enabled only in a test realm, disposable local users, disposable upstream IdP accounts, and synthetic directory attributes.
- For OAuth2 account-linking, record a baseline local-user state: password policy outcome, active/disabled flag, group/role membership, and whether account creation is enabled. Perform first and repeat OAuth2 logins for a disposable upstream identity that maps to the local user, then test only whether the lab user's local password was changed to the username and whether disabled state was flipped.
- For MSISDN, map the authentication chain and trusted-gateway list before sending requests. Use a synthetic directory user whose MSISDN value and username are canaries, then test whether special LDAP filter characters in the supplied MSISDN alter match behavior without touching real subscribers.
- Evidence should include realm/module/version, chain selection, account-creation setting, local-user before/after table, request-supplied MSISDN canary, resulting principal, and fixed-version or access-denied negative controls.
- Do not target production IdP accounts, real phone numbers, real subscriber directories, administrator accounts, or live user passwords; do not keep any generated sessions beyond lab validation.

### OpenAM PKCE, `private_key_jwt`, and script-sandbox harness

- Preconditions: OpenAM Community Edition lab through an affected version, OAuth2 Provider service in a disposable realm, two fake OAuth clients, test users, script-author role if scripting is enabled, and no production identity data.
- For PKCE, register a public test client that uses `S256`, request an authorization code with a known `code_challenge`, then replay token requests with a missing verifier, mismatched verifier, correct verifier, and reused code. Evidence is the token endpoint decision table, not token use against real resources.
- For `private_key_jwt`, create two disposable clients with separate JWKS URIs you control. Attempt only cross-client assertion combinations that prove whether JWKS cache entries, `iss`, `sub`, `aud`, `kid`, and client ID are bound to the client being authenticated.
- For scripting, use a lab-only server-side script context and an inert command marker such as writing a temporary marker under an approved scratch directory or printing a fixed string. Pair with fixed-version or deny-list negative controls.
- Evidence should include realm, OpenAM version, client IDs redacted to canaries, grant type, verifier decision table, JWKS owner/binding table, script role, marker output, and patched behavior.
- Do not mint tokens for real clients/users, request production scopes, reuse captured authorization codes, call live APIs, leak private keys, run shell payloads beyond inert markers, or give script-author privileges on production realms.

### Concrete CMS widget and trusted-render harness

- Preconditions: Concrete CMS lab, synthetic public/private calendars, disposable OAuth integration, and editor/admin test roles.
- Place a public calendar block on a test page and attempt to request only synthetic private-calendar event IDs through the frontend dialog path. Evidence is controlled cross-calendar marker disclosure, not broad calendar scraping.
- Set OAuth integration names and layout height fields to harmless DOM markers and observe whether they render as markup on authorization or visitor-facing pages.
- Negative controls: Concrete CMS 9.5.1+, role without edit/admin permissions, HTML-encoded integration names, and server-side validation of numeric layout fields.
- Do not snoop login submissions, hijack sessions, enumerate real calendars, or use persistent payloads outside disposable lab content.

### Concrete CMS file-version and Express association harness

- Preconditions: Concrete CMS lab through 9.5.0, disposable pages/files/Express entities, a user with only the minimum editor/view permissions under test, and harmless marker revisions.
- For Atomik page-name rendering, set a page name to a harmless DOM marker and visit only authenticated account/theme pages that are in scope. Capture encoded vs raw rendering with a fixed-version negative control.
- For file approval CSRF, upload two synthetic versions of a disposable file and test whether a cross-site request can approve the attacker-chosen older or co-editor version without a valid CSRF token.
- For Express association reordering, seed two entities with visible canary associations and verify whether a view-only or lower-tier role can reorder relationships across the intended authorization boundary.
- Do not target production account pages, approve real assets, alter customer forms, use session-hijacking payloads, or persist unapproved content after validation.

## Reporting notes

- Lead with the exact boundary: **reserved argument to command template/environment**, **shared template to cross-user command contamination**, **unauthenticated validation RPC to action enumeration**, **user-writable IdP attribute to deserialization**, **anonymous SOAP to identity-store write**, **push-registration state to anonymous object construction**, **shared token-store row to OAuth/OIDC token acceptance**, **unauthenticated RADIUS reply to application session minting**, **OAuth2 re-login to local credential rewrite**, **MSISDN input to LDAP-filter injection**, **PKCE challenge to token redemption without verifier**, **JWKS cache state to cross-client private-key authentication**, **script sandbox allow/deny list to JVM command execution**, **public calendar widget to private event**, **admin/editor field to trusted browser origin**, **file-version workflow to tokenless approval**, or **Express relationship UI to cross-entity state mutation**.
- Include product version, package/advisory ID, route or module, role/auth state, canary value, concurrency level where relevant, and a negative control.
- Keep artifacts synthetic and redacted: marker arguments, lab binding IDs, fake identity records, synthetic calendars/events, and harmless DOM markers.
