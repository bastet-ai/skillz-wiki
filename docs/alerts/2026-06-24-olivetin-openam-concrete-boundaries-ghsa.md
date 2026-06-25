# OliveTin action execution, OpenAM identity, and Concrete CMS boundary checks

Source: hourly offensive-security scan, 2026-06-24. Primary entries: GitHub Advisory Database [GHSA-7fq5-7wr8-rjwj](https://github.com/advisories/GHSA-7fq5-7wr8-rjwj), [GHSA-prj9-97mp-mwh2](https://github.com/advisories/GHSA-prj9-97mp-mwh2), [GHSA-f637-w7p2-m7fx](https://github.com/advisories/GHSA-f637-w7p2-m7fx), [GHSA-6c99-87fr-6q7r](https://github.com/advisories/GHSA-6c99-87fr-6q7r), [GHSA-p462-xxwx-pqf4](https://github.com/advisories/GHSA-p462-xxwx-pqf4), [GHSA-x2fp-hj8c-mmxh](https://github.com/advisories/GHSA-x2fp-hj8c-mmxh), [GHSA-h72c-xx3w-w8h7](https://github.com/advisories/GHSA-h72c-xx3w-w8h7), and [GHSA-9v2g-37mp-qpxf](https://github.com/advisories/GHSA-9v2g-37mp-qpxf). June 25 OpenAM push-registration update: [GHSA-pp89-732f-3g8q](https://github.com/advisories/GHSA-pp89-732f-3g8q) and [GHSA-cj8f-2fhf-826r](https://github.com/advisories/GHSA-cj8f-2fhf-826r).

These advisories are durable for operators because they expose reusable trust boundaries: action-runner templates and argument filters crossing into shell command construction, unauthenticated helper RPCs leaking action metadata, identity-provider storage attributes crossing into deserialization and elevated SOAP writes, and CMS public widgets or admin-controlled names crossing into private calendar data or trusted login-page HTML.

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
| [GHSA-x2fp-hj8c-mmxh](https://github.com/advisories/GHSA-x2fp-hj8c-mmxh) / CVE-2026-8204 | Concrete CMS calendar event frontend dialog | a public calendar block could pivot into private cross-calendar event data | Add public-widget-to-private-object pivot checks for CMS calendar, file, and content dialogs. |
| [GHSA-h72c-xx3w-w8h7](https://github.com/advisories/GHSA-h72c-xx3w-w8h7) / CVE-2026-8197 | Concrete CMS OAuth integration name | an admin-controlled integration name was rendered as raw HTML in the OAuth authorization template | Treat IdP/client names and integration labels as login-page render sinks; prove with harmless DOM markers only. |
| [GHSA-9v2g-37mp-qpxf](https://github.com/advisories/GHSA-9v2g-37mp-qpxf) / CVE-2026-8203 | Concrete CMS height parameter | editor-controlled height values could become stored browser-executed markup | Include numeric-looking layout parameters in CMS editor-to-visitor render reviews. |

## Operator triage

1. **Action runners are command surfaces even when arguments are typed.** Check reserved prefixes, hidden/system arguments, environment construction, and template context separately from the visible action schema.
2. **Concurrency can be an exploit primitive.** For OliveTin-style runners, run paired actions from separate users with distinct canary arguments and record whether either rendered into the other command.
3. **Validation endpoints are recon endpoints.** Any helper RPC that answers whether a binding ID, argument, type, or workflow node is valid can map hidden actions before direct execution testing.
4. **Identity stores need attribute ownership maps.** For OpenAM WebAuthn, the important precondition is whether the authenticator storage attribute is server-managed or user/provisioning-writable.
5. **Legacy federation routes stay in scope.** Liberty ID-WSF endpoints may be shipped even when not actively used; validate route reachability and auth gating before attempting writes.
6. **Push registration is an identity-store write primitive.** If a low-privileged user can start a Push Registration flow and later unauthenticated callbacks process persisted state, test for stale message IDs, shared secrets, CTS row type confusion, and server-side object construction.
7. **Token stores need family binding.** OAuth/OIDC token-read paths should reject rows that lack an OAuth-specific namespace, trusted CTS type, issuer/client/realm binding, and integrity protection independent of caller-supplied identifiers.
8. **CMS public widgets can pivot across private objects.** Calendar/file/dialog routes should be tested with synthetic public and private objects to show object-boundary drift.
9. **Login and authorization pages are high-trust render origins.** OAuth client names, integration labels, and dimensions rendered there can become stronger findings than generic admin-only XSS.

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

### Concrete CMS widget and trusted-render harness

- Preconditions: Concrete CMS lab, synthetic public/private calendars, disposable OAuth integration, and editor/admin test roles.
- Place a public calendar block on a test page and attempt to request only synthetic private-calendar event IDs through the frontend dialog path. Evidence is controlled cross-calendar marker disclosure, not broad calendar scraping.
- Set OAuth integration names and layout height fields to harmless DOM markers and observe whether they render as markup on authorization or visitor-facing pages.
- Negative controls: Concrete CMS 9.5.1+, role without edit/admin permissions, HTML-encoded integration names, and server-side validation of numeric layout fields.
- Do not snoop login submissions, hijack sessions, enumerate real calendars, or use persistent payloads outside disposable lab content.

## Reporting notes

- Lead with the exact boundary: **reserved argument to command template/environment**, **shared template to cross-user command contamination**, **unauthenticated validation RPC to action enumeration**, **user-writable IdP attribute to deserialization**, **anonymous SOAP to identity-store write**, **push-registration state to anonymous object construction**, **shared token-store row to OAuth/OIDC token acceptance**, **public calendar widget to private event**, or **admin/editor field to trusted browser origin**.
- Include product version, package/advisory ID, route or module, role/auth state, canary value, concurrency level where relevant, and a negative control.
- Keep artifacts synthetic and redacted: marker arguments, lab binding IDs, fake identity records, synthetic calendars/events, and harmless DOM markers.
