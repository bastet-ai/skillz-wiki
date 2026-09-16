# Identity-provider authority boundaries: ZITADEL token exchange, Keycloak stale link proof, Nezha Host-injected redirect (3 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-16 (reviewed wave published 2026-09-15/16).

Three identity-boundary records that share one operator lesson: **an identity provider's authority decision is only as strong as the weakest binding in the flow — exchanged-token provenance, link-proof lifecycle, or the value the server uses to build the redirect target.**

## Advisory table

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-vrh8-c9cm-wh8v](https://github.com/advisories/GHSA-vrh8-c9cm-wh8v) | CVE-2026-56668 | high (CVSS 8.1) | ZITADEL OAuth2 Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`): the server never verifies that the submitted access token belongs to / is authorized for the client initiating the exchange, and does not constrain requested scopes to the original token's scopes. A low-privilege app's token can be exchanged for a token on a highly-privileged target application — administrative project roles, profile data, cross-application access. Public clients (no secret) make it require zero client authentication. Affected: 4.0.0–4.15.2 and 3.0.0–3.4.12, fixed 4.15.3. |
| [GHSA-prm3-wvj6-64vx](https://github.com/advisories/GHSA-prm3-wvj6-64vx) | CVE-2026-92358 | medium (CVSS 6.4) | Keycloak first-broker-login account linking: the temporary cross-browser proof created when a user confirms an account-link request is **not cleared** after the link is established, nor when the user later removes the link. An attacker who controls the external identity can reuse the leftover proof to silently re-establish the link and access the victim account with no further confirmation. |
| [GHSA-rf68-8gjr-36q7](https://github.com/advisories/GHSA-rf68-8gjr-36q7) | — | low | Nezha v2.2.3 regresses the [GHSA-9rc6-8cjv-rcvx](https://github.com/advisories/GHSA-9rc6-8cjv-rcvx) Host-header fix when the new optional `dashboard_host` setting is left empty: `/api/v1/oauth2/{provider}` again reflects the request `Host` header into the OAuth2 `redirect_uri` sent to the IdP, even with `install_host` configured. A forged `Host` at OAuth-start time can point the authorization code at an attacker origin. Configuration-dependent but realistic because the empty default is the upgrade state. |

## Why this is worth an operator page

- **Token exchange is the newest large IdP attack surface and it is consistently under-tested.** RFC 8693 exchanges cross application boundaries inside one IdP; if the server skips "does this subject token belong to this client?" and "are requested scopes ⊆ original scopes?", the entire per-app role model collapses to "hold any token." Any ZITADEL/Auth0-style deployment with token exchange enabled deserves a dedicated exchange matrix, not a spot check.
- **Proof lifecycle bugs are quiet and persistent.** The Keycloak record is not a bypass of the confirmation step — the confirmation worked. The finding is that the *receipt* outlived its purpose, and the product also fails to revoke it when the user explicitly unlinks. Identity proofs must be single-use *and* revoked when the relationship they authorized is dissolved. This is a reusable check on any "confirm in another device/browser" flow (SSO link, device pairing, passkey enrollment).
- **Fix regressions hide behind new optional config.** The Nezha record is a previously-fixed Host-injection that returns whenever a newly added setting defaults to empty. When a product ships a fix that is gated on configuration, the empty/unconfigured state is the first thing to re-test — upgrade paths and defaults frequently land in the regressed state.

## Validation workflows (authorized scope only)

!!! warning "Disposable IdPs, synthetic clients, synthetic users only"
    Run every proof against a lab IdP you own with throwaway realms/organizations, fake client credentials, and canary users. Never exchange real user tokens, never target a production IdP, and never collect real authorization codes or tokens in report evidence.

### 1. ZITADEL-style token-exchange matrix

Preconditions: lab IdP with token exchange enabled, one low-privilege client/app (A) you can authenticate as, one high-privilege target app (B) with an administrative role assignable to a canary user, and two canary users (low, high).

1. Mint a low-privilege access token for app A (client credentials or a disposable low-role user).
2. Send a token-exchange request with `subject_token` = A's token, `audience` = app B, and `scope` requesting B's highest available role/scope.
3. Record the decision table: token accepted/rejected, returned token's app audience, returned roles/scopes, and whether requested scopes exceeding the subject token's scopes are honored.
4. Cross-product variants: submit app B's own token from client A (token/client mismatch), submit a token from an unrelated app C, submit with a public client (no secret), and request scopes beyond the subject token's grants.
5. Positive: a low-privilege token yields a B-audience token with administrative roles, or out-of-scope requests honored. Confirm the negative on the patched build (4.15.3+), then delete all minted tokens and canary grants.

Report the exchange as a **provenance + scope-containment** failure with the exact grant type, request parameters (token labels only), and the role/scope delta between subject and issued token.

### 2. Link-proof lifecycle check (Keycloak-style first-broker-login)

Preconditions: lab realm with identity brokering, a fake external IdP you control, two disposable browsers/profiles (victim + attacker), and a canary victim account.

1. Drive the normal flow: victim initiates login via the external IdP, confirms account linking from the second browser, capture the temporary proof's lifetime and binding.
2. After the link succeeds, **replay the proof** from the attacker-controlled external identity — the check is whether the still-stored proof lets the attacker's identity re-establish (or re-bind) the link without victim confirmation.
3. Add the removal path: victim manually unlinks, then the attacker replays the same proof again. A leftover proof that re-links after explicit removal is the durable finding.
4. Record: proof creation trigger, TTL, subject binding, whether link success clears it, whether manual unlink clears it, and the re-link decision. Use a harmless canary attribute (e.g., a marker email on the fake IdP), never real identities.

### 3. Host-header redirect regression check (Nezha-style)

Generalize the check to any self-hosted app that builds an OAuth2 `redirect_uri` at login-start time:

1. Enumerate the app's configuration surface and find settings that changed in recent releases; note every newly-optional setting whose **empty/default state** selects a different code path.
2. Start an OAuth login with a forged `Host` header (point it at an owned no-content observer) and capture the exact `redirect_uri` sent to the IdP in the outbound request — compare against the configured install/dashboard host.
3. Repeat with the setting populated (control) and empty (suspected regression). The positive is `redirect_uri` host following the request header in the empty/default state on a build that supposedly fixed the original advisory.
4. Prove only destination control at the IdP request boundary with an owned observer; never complete a real code exchange with a victim authorization code.

## Adjacent records processed without publication

From the same reviewed wave: @zereight/mcp-gitlab SSRF/DNS-rebinding/safety-control-bypass and Http4s Ember parser records were already published on the [Sept 15 MCP/agent local-surface page](2026-09-15-mcp-dns-rebinding-alternate-auth-path-and-sandbox-boundaries-ghsa.md) and the [Sept 15 Http4s/Traefik page](2026-09-15-http4s-ember-traefik-parser-header-route-boundaries-ghsa.md) — the GitLab MCP trio (SSRF, DNS rebinding to local Streamable HTTP transport, `execute_graphql` read-only/allow-list bypass plus unauthenticated transports) and all 13 Http4s records fold there. ZITADEL [GHSA-v859-c572-qh5p](https://github.com/advisories/GHSA-v859-c572-qh5p) (cross-org project-grant role revocation skips roles when multiple roles are deleted at once, fixed 4.16.0) is tracked as an authorization-state hygiene note: re-check residual grants after bulk revocations in any IdP, but it adds no new workflow. [GHSA-4595-rvpx-4q34](https://github.com/advisories/GHSA-4595-rvpx-4q34) emp3r0r unauthenticated HTTP-polling session creation before CBOR `MsgAuth` is a C2-transport pre-auth dispatch DoS — the axis (authentication deferred past session establishment) is already covered on existing listener-trust pages. October CMS [GHSA-2xmm-m4wv-3fjh](https://github.com/advisories/GHSA-2xmm-m4wv-3fjh) (`http` prefix check + `://` substring admitting `phar://`/`file://` wrappers into the resizer cache, gated on an existing template-authoring primitive) and [GHSA-2ff2-mx52-q8wp](https://github.com/advisories/GHSA-2ff2-mx52-q8wp) (widget session `base64(serialize())` consumed with unrestricted `unserialize()`, `cms.safe_mode` only) extend axes already on the CMS renderer and PHP deserialization pages — scheme-prefix vs scheme-allowlist is a worthwhile reminder when any field later reaches a PHP file operation, but the preconditions keep it below publication. Netmaker [GHSA-r8cr-4f9w-7r75](https://github.com/advisories/GHSA-r8cr-4f9w-7r75) (authenticated boolean-based SQLi via string-concatenated `DELETE` from a DNS path parameter), ESPHome renamed-auth-env-var auth disable, and emp3r0r/libp2p-quic records were processed without publication.

## Reporting heuristics

- For token exchange, report the **two missing checks separately**: token↔client provenance and scope containment. They can be fixed independently.
- For proof-lifecycle bugs, state explicitly which lifecycle event failed to revoke the proof (link success, link removal) — that is the boundary, not "account linking is insecure."
- For config-gated regressions, cite the original advisory being regressed, the exact setting whose empty state restores the vulnerable path, and the version. Empty-default regressions are frequently absent from vendor fix notes.
- Keep evidence to parameter tables and token/proof labels; never include live tokens, authorization codes, or real IdP metadata.
