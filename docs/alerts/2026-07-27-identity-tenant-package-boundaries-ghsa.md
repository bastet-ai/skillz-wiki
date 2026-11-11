---
title: Identity, tenant, webhook, and package boundaries from July 27 GHSA updates
---

# Identity, tenant, webhook, and package boundaries from July 27 GHSA updates

A late July 27 GitHub advisory wave, plus two July 28 Pocket ID follow-ups, yields seven durable operator workflows: authorization against one identifier followed by action on another, SSO identity/session proof that is only partially validated, refresh-token renewal after current authorization is removed, weak-login proof accepted as passkey reauthentication, a token-selected signature algorithm, cross-tenant webhook creation, and privileged package/update fields crossing into application-root files. These are useful beyond the named products because each bug breaks the binding between a decision and the object, identity, authentication method, token, tenant, or artifact later consumed.

Sources:

- [GHSA-jhfj-h4g6-q9h9 / CVE-2026-15630: Casdoor query/body tenant mismatch](https://github.com/advisories/GHSA-jhfj-h4g6-q9h9)
- [Voke Research: Casdoor cross-tenant authorization](https://vokecyber.com/research/cve-2026-15630-casdoor-cross-tenant-authz)
- [GHSA-26cp-25m8-5fgc / CVE-2026-15611: Logto unverified-email SSO linking](https://github.com/advisories/GHSA-26cp-25m8-5fgc)
- [GHSA-2r4j-c245-2qx7 / CVE-2026-15612: Logto absent OIDC nonce acceptance](https://github.com/advisories/GHSA-2r4j-c245-2qx7)
- [GHSA-crqf-jj8w-c292 / CVE-2026-15614: Logto IdP-initiated SAML session reuse](https://github.com/advisories/GHSA-crqf-jj8w-c292)
- [GHSA-vxqj-8hg5-3v79 / CVE-2026-15615: Logto SAML `Conditions` validation](https://github.com/advisories/GHSA-vxqj-8hg5-3v79)
- [GHSA-cv5x-2gg8-4hc7 / CVE-2026-15616: Logto local MFA enforcement drift](https://github.com/advisories/GHSA-cv5x-2gg8-4hc7)
- [GHSA-257m-4vpx-xg86 / CVE-2026-15617: Logto identifier normalization](https://github.com/advisories/GHSA-257m-4vpx-xg86)
- [GHSA-fr32-wcm4-p6hf / CVE-2026-13089: Perl OIDC::Lite token-selected algorithm](https://github.com/advisories/GHSA-fr32-wcm4-p6hf)
- [OIDC::Lite algorithm-pinning fix](https://github.com/ritou/p5-oidc-lite/pull/31)
- [GHSA-72qw-2qpq-fg7j / CVE-2026-16624: Cal.com cross-team webhook creation](https://github.com/advisories/GHSA-72qw-2qpq-fg7j)
- [Voke Research: Cal.com cross-tenant webhook plant](https://vokecyber.com/research/calcom-cross-tenant-webhook-plant)
- [GHSA-c4f8-v76x-mwx3 / CVE-2026-66398: phpMyFAQ package extraction to application root](https://github.com/advisories/GHSA-c4f8-v76x-mwx3)
- [Primary phpMyFAQ package advisory](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-4fv7-8rr6-rf2w)
- [GHSA-5w7v-f8fx-865c / CVE-2026-66399: phpMyFAQ group-membership escalation](https://github.com/advisories/GHSA-5w7v-f8fx-865c)
- [GHSA-4cv6-9jjm-xp2g / CVE-2026-66397: phpMyFAQ category-image deletion traversal](https://github.com/advisories/GHSA-4cv6-9jjm-xp2g)
- [GHSA-w6p7-2fxx-4f44 / CVE-2026-43983: Pocket ID refresh-token authorization-state bypass](https://github.com/pocket-id/pocket-id/security/advisories/GHSA-w6p7-2fxx-4f44)
- [Pocket ID authorization-state fix](https://github.com/pocket-id/pocket-id/commit/978ac87deffec58beaccd15aead975e91b94c8a5)
- [Pocket ID v2.6.0 release](https://github.com/pocket-id/pocket-id/releases/tag/v2.6.0)
- [GHSA-hp74-gm6m-2qm5: Pocket ID one-time-token reauthentication bypass](https://github.com/pocket-id/pocket-id/security/advisories/GHSA-hp74-gm6m-2qm5)

The July 27 GitHub records were unreviewed when scanned; both Pocket ID records were GitHub-reviewed when added on July 28. Confirm the exact product, affected version, route, configured identity provider, caller privilege, and fixed-build behavior from primary sources before reporting.

!!! warning "Authorized validation only"
    Use disposable tenants, synthetic users and identity-provider claims, fake keys, redacted test tokens, owned webhook listeners, marker-only archives, and temporary application roots. Never link a real person's account, forge a production identity, retain or replay production refresh tokens, bypass passkey step-up for a real account, receive customer booking data, delete live configuration, upload executable code, or trigger an update against a production installation.

## Boundary matrix

| Surface | Decision input | Later action/sink | Safe proof |
| --- | --- | --- | --- |
| Casdoor organization API | query `id` used for authorization | body organization used for create/update/delete | reversible marker on a second disposable tenant |
| Logto SSO | email, identifier, nonce, SAML conditions/session, IdP MFA state | local subject, account link, session, or assurance level | two synthetic accounts and claim/session decision tables |
| Pocket ID refresh grant | previously valid refresh token | renewed tokens after client revocation, account disablement, or group removal | disposable user/client and a status-only resource |
| Pocket ID reauthentication | fresh access token from one-time access or signup-token login | passkey-required reauthentication token and OIDC grant | disposable passkey user/client and token decision table |
| OIDC::Lite | token header `alg` | verifier algorithm allowlist | local verifier harness with canary claims only |
| Cal.com webhook | request `teamId` | subscription and event delivery for that team | owned receiver plus synthetic booking marker |
| phpMyFAQ administration | group ID, category image path, attachment/package setting | inherited rights, file deletion, package extraction | inert group, temporary file, and non-executable archive markers |

Capture both representations whenever a check and action can select different objects. A `200` response, accepted token syntax, stored webhook row, or uploaded attachment is not enough by itself; prove the smallest downstream marker and then stop.

## Query/body authorization drift

CVE-2026-15630 describes Casdoor organization handlers authorizing a non-global organization administrator against `?id=` while selecting the organization to mutate from the request body. This is a reusable **check object A, act on object B** pattern.

### Two-tenant differential

1. Create disposable organizations A and B. Give user A organization-admin rights only in A.
2. Seed one reversible, non-sensitive marker in each organization.
3. Capture a normal update to A and identify every object selector in the route, query, body, path, and authenticated session.
4. Build a small matrix where query and body both name A, both name B, and name A/B in opposite combinations.
5. For a mismatched request, change only B's synthetic description marker; do not delete organizations, users, applications, certificates, or providers.
6. Read the marker back as B's authorized test administrator, restore it, and repeat on the fixed build.

A decisive result is **user authorized only for A + query selects A + body selects B -> B's canonical record changes**. Record which identifier reached the policy check and which reached the data-layer operation. Do not describe this as unauthenticated access or global-administrator compromise.

Apply the same matrix to bulk endpoints, nested JSON, GraphQL variables, duplicate parameters, path/query disagreement, and create/delete variants. Test one reversible update first; destructive verbs are unnecessary.

## SSO: bind proof, principal, assurance, and session lifecycle

The Logto records cover different edges and should not be collapsed into “SSO bypass” without evidence:

- an email from a permissive IdP can link to an existing local account without proof that the IdP verified it;
- an absent OIDC `nonce` can bypass replay binding;
- omitted SAML `Conditions` can remove audience and time restrictions;
- IdP-initiated SAML session state can remain reusable after expected consumption;
- locally required MFA can be skipped on an SSO path;
- case- or Unicode-different identifiers can collide during principal lookup.

### Owned-identity fixture

Use a local or owned test IdP and two Logto users containing only synthetic data. Never impersonate a real email address.

| Dimension | Baseline | Negative mutation | Evidence |
| --- | --- | --- | --- |
| email ownership | IdP marks canary email verified | same email with verification absent/false | local account-link decision |
| OIDC nonce | exact transaction nonce | missing, changed, and replayed nonce | callback/session result |
| SAML conditions | valid audience/time window | missing, expired, future, and wrong audience | assertion decision |
| session consumption | first owned IdP-initiated login | exact replay after completion/logout | session ID state and result |
| assurance | flow satisfying local MFA | SSO assertion without required local factor | `amr`/assurance and route decision |
| identifier identity | exact canonical canary | case, normalization form, and confusable controls | canonical principal selected |

1. Record connector type, expected issuer/audience, local MFA policy, account-linking mode, and the canonical local subject before mutations.
2. Change one dimension at a time and preserve the signed assertion/token when testing lifecycle behavior.
3. For email linking, use two aliases or mailboxes owned by the assessment; stop if the second test identity links to the first synthetic account.
4. For replay checks, use a harmless profile/status endpoint and immediately revoke the disposable session.
5. For normalization, compare code points, normalization forms, lowercasing, database collation, and the final principal ID. A UI display collision alone is not account access.
6. Repeat every positive case after the fix with identical IdP fixtures.

Bound claims precisely: absent nonce acceptance is replay weakness only when the application initiated and expected a nonce; missing `Conditions` is meaningful when the assertion crosses an audience or validity boundary; and MFA drift requires a documented local requirement that the SSO route failed to enforce.

## Pocket ID: re-evaluate authorization on refresh

GHSA-w6p7-2fxx-4f44 / CVE-2026-43983 describes Pocket ID through `2.5.0` continuing to accept an already-issued OIDC refresh token after three kinds of current authorization change: the user revokes that client, an administrator disables the user, or the user leaves a group required by the client. The primary advisory says each successful refresh rotates the token with a fresh 30-day expiry. The durable pattern is **historical grant proof remains cryptographically valid, but present authorization no longer permits renewal**.

This is not a bearer-token theft test. Begin with a refresh token legitimately issued to a disposable user and client that the assessor controls.

### Three-transition lifecycle fixture

1. Run the affected build in an isolated lab. Create one synthetic user, one confidential OIDC client, one allowed group, and a harmless relying-party route that returns only a random test marker.
2. Complete a normal authorization-code flow requesting `openid` plus only the scopes needed for the fixture. Store token hashes or short redacted prefixes in evidence, not complete token values.
3. Use the refresh token once as a baseline. Confirm rotation behavior and that the resulting access token reaches only the harmless marker route.
4. Reset the fixture and test one transition at a time:
   - revoke the user's authorization for the client;
   - disable the synthetic user;
   - remove the user from the client's allowed group while group restriction is enabled.
5. After each transition, submit the exact pre-transition refresh token once. Record the token-endpoint status, OAuth error, whether a new token pair was issued, and whether the status-only marker remains reachable.
6. Add controls for an unmodified authorized user, a corrupted refresh token, a token belonging to another disposable client, and an expired token. Do not test cross-user tokens.
7. Repeat the same matrix on `2.6.0` or commit `978ac87deffec58beaccd15aead975e91b94c8a5` and confirm rejection after each state transition.

| Transition after issuance | Affected behavior to verify | Fixed control from the patch |
| --- | --- | --- |
| client authorization revoked | old refresh token still rotates | revoke deletes matching stored refresh tokens; refresh also requires the authorization record |
| user disabled | old refresh token still rotates | refresh rejects a disabled user |
| allowed-group membership removed | old refresh token still rotates | refresh loads allowed groups and re-runs the group authorization check |

The strongest bounded evidence is **valid baseline refresh -> one recorded authorization transition -> same pre-transition token still produces a new pair on the affected build -> fixed build rejects it**. Keep the three transitions separate: client revocation, principal lifecycle, and group-policy enforcement are distinct findings even though they converge on the same refresh endpoint. Do not claim initial authentication bypass,the precondition is a refresh token issued while the user was authorized.

Also distinguish token minting from downstream reachability. A new token pair proves renewal after revocation; accessing the canary route proves the relying party accepts the new access token. Neither requires viewing profile data, group membership beyond the synthetic fixture, or any real application resource.

## Pocket ID: bind reauthentication to the required method and session

GHSA-hp74-gm6m-2qm5 describes a second Pocket ID boundary fixed by the same `2.6.0` release/commit. For clients configured with `RequiresReauthentication: true`, the affected fallback path accepted a recently issued access token without proving how the user authenticated. A one-time access-token or signup-token login could therefore satisfy a passkey step-up requirement. The advisory also says the handler checked only for the presence of a `session` cookie on that fallback path rather than binding a valid server-side session.

Treat the edges separately: **weaker login method -> fresh access token**, **freshness-only fallback -> reauthentication token**, and **reauthentication token -> grant for a client requiring passkey step-up**. Do not claim the full chain if only one transition is shown.

### Authentication-method decision table

1. Run the affected build in an isolated lab. Create one disposable passkey user and one OIDC client with `RequiresReauthentication: true`. Configure a status-only relying-party marker.
2. Establish a normal passkey reauthentication baseline. Record only token hashes, issue times, authentication-method labels, session IDs replaced with aliases, and endpoint decisions.
3. Reset the fixture and obtain a fresh access token through an owned one-time access-token login. In a separate run, test the signup-token path only if the lab configuration exposes it legitimately.
4. Call the reauthentication endpoint with a deliberately non-WebAuthn body so the documented access-token fallback is reached. Test a missing session cookie, random cookie value, expired lab session, valid unrelated lab session, and valid current session independently.
5. If a reauthentication token is returned, use it once against only the disposable client. Confirm issuance through response metadata and the harmless relying-party marker; do not request profile, group, or application data.
6. Add stale access token, malformed token, token for a second disposable user, valid passkey assertion, and `RequiresReauthentication: false` controls. Never reuse another real user's token.
7. Repeat on `2.6.0` or commit `978ac87deffec58beaccd15aead975e91b94c8a5`. The weak-method token and arbitrary session cookie must not satisfy passkey step-up.

| Login/session condition | Expected affected decision to test | Required fixed behavior |
| --- | --- | --- |
| valid passkey assertion + current session | reauthentication succeeds | succeeds |
| fresh one-time-login access token + arbitrary `session` cookie | fallback may issue reauthentication proof | rejects as wrong method/session |
| fresh signup-token access token + arbitrary `session` cookie | fallback may issue reauthentication proof | rejects as wrong method/session |
| stale or malformed access token | freshness/token validation fails | rejects |

The strongest bounded evidence is **client explicitly requires passkey reauthentication -> owned user logs in with a weaker one-time method -> fresh token plus non-validating session-cookie gate yields reauthentication proof -> disposable client grant succeeds**, followed by fixed-build rejection. This is not a general passkey bypass unless the exact client flag, fallback route, token provenance, and downstream grant are all established.

## OIDC::Lite: the token cannot choose the verifier policy

CVE-2026-13089 says the unpinned Perl `OIDC::Lite::Model::IDToken` verification path copies the token's `alg` header into the accepted-algorithm list. That can admit `none` or reuse an RSA public key as an HMAC secret. The durable check is **untrusted header -> accepted algorithm set**, not blind JWT mutation.

1. Build a local harness around the exact application call path: unpinned `load(token)->verify`, key-only `load(token, key)`, and an explicitly pinned algorithm control.
2. Use a generated disposable RSA keypair and synthetic subject/audience claims.
3. Confirm rejection of a corrupted signature, wrong audience, and expired token before algorithm tests.
4. Test an unsigned canary and an HMAC canary made with the disposable public key only in the isolated harness.
5. Instrument the algorithm list passed to `decode_jwt`; this proves policy provenance without targeting an application account.
6. Compare with the patched implementation or explicit caller pinning.

The strongest bounded evidence is **header says `none` or `HS256` -> library constructs the same accepted-algorithm list -> altered canary subject is returned**, while explicit pinning rejects it. Never use a production key or real subject. See the broader [JWT algorithm-confusion testing workflow](../methodology/jwt-algorithm-confusion-testing.md).

## Cross-tenant webhook creation

CVE-2026-16624 describes Cal.com accepting a request-supplied `teamId` without proving the authenticated user may create webhooks for that team. A webhook is both a durable control-plane object and a future data-delivery channel, so validate creation and delivery separately.

1. Create teams A and B, users scoped to only one team each, and an owned HTTPS receiver that logs only a nonce and event type.
2. Capture user A's normal webhook-create request for team A.
3. Replace only `teamId` with B's ID; use a unique secret and callback path for the canary.
4. Read the webhook row through B's authorized administrator or a lab database snapshot. Do not enumerate another tenant's webhooks.
5. If creation succeeds, trigger one synthetic B booking containing only a random marker and fake addresses; verify that the owned listener receives that marker.
6. Delete the webhook, rotate its fake secret, and repeat on the fixed build.

Report the edges separately: **A's user created a webhook bound to B** and, if proven, **B's synthetic event reached A's owned receiver**. Do not collect organizer details, attendee fields, custom responses, video credentials, or production events.

## phpMyFAQ: validate each package/update edge separately

The phpMyFAQ records describe three privileged boundaries before `4.1.6`:

- group-management authority can attach the caller to a pre-existing group carrying stronger user-management rights;
- `existing_image` traversal can steer category-image cleanup outside its intended directory;
- an administrator holding `CONFIGURATION_EDIT` and `ATTACHMENT_ADD` can point `upgrade.lastDownloadedPackage` at an uploaded ZIP and extract it into the application root.

These can form chains, but do not combine them unless every prerequisite and transition is reproduced.

### Marker-only fixture

1. Install the affected build in a disposable container with a copied application root and no real FAQ data, mail, credentials, or outbound network.
2. Create separate low-privilege, group-manager, configuration-editor, and full-admin canaries. Record canonical rights server-side.
3. **Group edge:** attempt to add the group-manager only to an inert group whose extra permission exposes a harmless marker route. Read back memberships and effective rights; remove membership afterward.
4. **Deletion edge:** place a unique text marker outside the category-image directory but inside the temporary container. Submit the minimum traversal needed to address only that marker. Never name `database.php`, environment files, logs, keys, or setup gates.
5. **Package edge:** upload a ZIP containing one non-executable `.txt` entry under a unique subdirectory. Point the package setting only at that attachment and trace extraction paths.
6. Disable PHP/script execution in the proof directory and verify only the text marker hash. Do not include PHP, server configuration, symlinks, or traversal entries in the archive.
7. Repeat each edge with missing and expected permissions, an invalid object/path/package, and version `4.1.6` or later.

Bound the finding to what was shown: unauthorized group attachment, arbitrary marker deletion within the service account's authority, or package-controlled application-root write. A text file in the application tree does not prove code execution; deleting a marker does not prove setup takeover; and legitimate package-install authority may alter severity even when the write primitive is real.

## Reporting checklist

Include:

- product/version, deployment mode, caller role, tenant, connector, route, and relevant feature state;
- every competing selector and the canonical object that policy checked versus the object acted upon;
- IdP verification flags, nonce/conditions/session lifecycle, assurance policy, and final synthetic principal;
- Pocket ID transition type, client group/reauthentication settings, authentication-method provenance, aliased session state, redacted token lineage, endpoint decision, rotation or grant result, and canary-resource result;
- algorithm-list provenance, disposable key type, and pinned-algorithm control;
- webhook owner/team IDs, marker-only delivery evidence, deletion, and secret rotation;
- phpMyFAQ effective-rights, canonical paths, archive listing, marker hashes, and cleanup;
- affected/fixed decision tables and a narrow statement separating authorization drift, identity linkage, replay, MFA bypass, webhook creation, file effects, and untested execution.

Redact tokens, assertions, cookies, webhook secrets, user paths, and full request bodies. Do not infer cross-tenant impact from an accepted request unless the foreign synthetic object changed, infer account takeover from claim parsing alone, or infer RCE from a non-executable write.