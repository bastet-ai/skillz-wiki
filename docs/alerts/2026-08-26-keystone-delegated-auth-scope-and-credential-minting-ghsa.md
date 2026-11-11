# OpenStack Keystone delegated-authentication scope and credential-creation boundaries

Source: GitHub Security Advisories, 2026-08-26 hourly scan: [GHSA-x764-fvmq-4x2r](https://github.com/advisories/GHSA-x764-fvmq-4x2r) / [CVE-2026-80184](https://nvd.nist.gov/vuln/detail/CVE-2026-80184) (high) and [GHSA-964p-6x56-c2xp](https://github.com/advisories/GHSA-964p-6x56-c2xp) / [CVE-2026-80182](https://nvd.nist.gov/vuln/detail/CVE-2026-80182) (high). Affected: OpenStack Keystone before `29.0.3`. All Keystone deployments that permit delegated authentication through OAuth1 access tokens, application credentials, or trusts are in range.

These are durable, replayable operator findings because they are a clean, reusable **delegated-token privilege-escalation** pattern: a token minted for one narrow purpose (an OAuth1 grant, an application credential, or a trust) is fed into a *different* Keystone auth path, the token-method reauthentication path, and that path does not honour the original token's project scope or its delegation restrictions. The two CVEs are two faces of the same gap: one escapes the *project scope* of a delegated token, the other lets a delegated token *mint new long-lived credentials and new delegations* that outlive the token that created them. Both belong on the same page family as the [2026-04-29 Spring Security issuer/misconfig batch](2026-04-29-spring-security-servlet-path-and-issuer-validation-batch-ghsa.md): a trust-boundary that accepts a credential in one context and re-interprets it in another.

## What changed

- **`GHSA-x764-fvmq-4x2r` / [CVE-2026-80184](https://nvd.nist.gov/vuln/detail/CVE-2026-80184), project-scope escape via the token-method path.** Tokens obtained via delegated mechanisms (OAuth1 access tokens, application credentials, trusts) can be submitted to the *token-method authentication* path for reauthentication. When an application-credential token is presented with no explicit scope, Keystone issues a new token scoped to the credential owner's *default* project rather than the project the credential was issued for. A narrowly-scoped delegated credential is thereby promoted to the owner's default project, bypassing the intended project boundary.
- **`GHSA-964p-6x56-c2xp` / [CVE-2026-80182](https://nvd.nist.gov/vuln/detail/CVE-2026-80182), delegated token can create new credentials / new delegations.** A token from OAuth1, an application credential, or a trust can create new long-lived credentials or authorize new delegations that persist independently of, and outlive, the credential that obtained them. The delegation restrictions that block these operations for some delegated token types were not consistently applied to *all* delegated token types, e.g. an OAuth1-scoped token could create application credentials or authorize OAuth1 request tokens even though those operations are restricted for other delegated token types.

The reusable pattern, split into two trust transitions:

1. **Cross-path re-interpretation (80184).** A token minted under delegated-auth semantics is re-submitted to the token-method auth path, which re-scores it with a *default* scope instead of the scope it was issued with. Scope is a property of the *minting context*, not the token, and the reauth path does not preserve it.
2. **Inconsistent delegation gating (80182).** The "you may not mint new credentials / new delegations" restriction is applied per token-type, and some delegated token types slip through, letting a low-privilege delegated token bootstrap higher-privilege, long-lived credentials.

## Operator triage

1. **Fingerprint Keystone and its delegated-auth surface.** Confirm Keystone `29.0.3` or earlier is reachable and that any of the delegated mechanisms are enabled: OAuth1 (OpenID Connect / OAuth1 1.0A provider config), application credentials (service-enabled), or trusts. The presence of `/v3/auth/tokens` plus a delegated-credential endpoint is the trigger.
2. **Determine which delegation is in play.** The two CVEs surface differently per delegation type. Identify whether the target uses OAuth1 access tokens, application credentials, or trusts, and whether the token-method reauth endpoint is reachable from the delegated token's context.
3. **Prioritize by the value of the escaped scope / minted credential.** 80184 matters when the owner's default project is more privileged than the issued project (cross-tenant or cross-project blast radius). 80182 matters because a *single* low-priv delegated token can be turned into a *persistent* credential (application credential or OAuth1 request token) that survives after the original token expires, a durable foothold.
4. **Separate scope-escape from credential-minting.** Report them as two independent primitives: (a) does reauth widen project scope? (b) can this token type create new credentials / delegations?

## Replayable validation boundaries

Validate on an authorized lab Keystone deployment (a disposable `keystone` with a synthetic project layout and a controlled delegated-credential provider). Use synthetic projects, synthetic users, and synthetic delegated tokens; do not target a production OpenStack control plane, do not mint or retain real credentials, and do not read or exfiltrate real tenant data.

### Lab setup
- A lab Keystone `< 29.0.3` (affected) and a `29.0.3+` control.
- Two synthetic projects: `A` (the intended, narrow project) and `B` (the owner's more-privileged default project).
- A synthetic owner user whose default project is `B`, and a delegated credential (application credential or OAuth1 access token) explicitly scoped to project `A`.
- A second synthetic user to hold the "minted" credential, to confirm the minted token persists independently.

### Scope-escape check (80184)
1. Mint a delegated token (application credential or OAuth1) explicitly scoped to project `A`. Confirm it can reach `A` resources.
2. Submit that token to the token-method authentication path with **no explicit scope** (reauth).
3. Inspect the returned token's `project` claim. The vulnerable result is a token scoped to the owner's default project `B` rather than `A`; the secure result preserves scope `A`. Record the exact request, the absence of a scope param, and the resulting `project` on both builds.
4. Repeat for each delegated type (OAuth1, application credential, trust) that the deployment enables.

### Credential-minting / new-delegation check (80182)
1. As the delegated (project-`A`) token, attempt to **create an application credential** and/or **authorize a new OAuth1 request token**.
2. The vulnerable result is a new long-lived credential or new delegation being issued even though the delegating token itself is restricted; the secure result is 403/401.
3. Confirm persistence: after the original delegated token expires, the minted credential/delegation still authenticates. Record the minted credential id, its expiry behaviour, and the auth decision on both builds.
4. Compare the restricted and unrestricted delegated token types to document the *inconsistent* gating (the exact gap the advisory names).

## Reporting heuristics
- Frame as **delegated token -> token-method reauth path -> scope not preserved (80184)** and **delegated token -> inconsistent delegation gating -> new long-lived credential / new delegation minted (80182)**. Name the Keystone version (`< 29.0.3`) and the affected delegation types.
- Lead with 80182 for durability (a single delegated token becomes a persistent credential) and 80184 for blast radius (project-scope escape).
- For each: record the delegated token type, the exact request (with/without scope), the resulting token's project claim or the minted credential, the auth decision, and the version before/after.
- Distinguish "scope widened on reauth" from "new credential minted from a restricted token", different controls, different remediation.

## Safety
- **Authorized lab only.** Run a disposable Keystone; never run these against a production OpenStack control plane or a shared staging cloud.
- **Synthetic identities only.** Use synthetic projects/users/credentials; never mint, retain, or replay real delegated credentials, real application credentials, or real trust tokens.
- **No tenant data access.** The canary is the scope claim / minted-credential decision; do not read or exfiltrate real tenant data or real project resources.
- **No destructive credential mutation.** Do not create or delete real credentials in a live system; all minting happens on the lab Keystone.
