---
title: Docker Hub GhostPat — account-conversion PAT reassignment and registry identity-binding checks
---

# Docker Hub GhostPat: your account's new token isn't yours (CVE-2026-105445)

Source: [GHSA-phq5-vq2m-8rp9 / CVE-2026-105445](https://github.com/advisories/GHSA-phq5-vq2m-8rp9) (critical, Docker Hub account-to-organization conversion), [Docker's advisory](https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445), and the researcher's full writeup at [ghostpat.com](https://ghostpat.com). Published to GitHub 2026-10-13T18:30Z; fixed server-side 2026-09-30; victim notifications 2026-10-02; transferred tokens force-deactivated 2026-10-08.

The durable axis: **an account-lifecycle transition (convert personal account → organization) silently carried the *attacker's* personal access token onto the *victim's* identity.** No exploit code, no exploit chain — a missing consent step in a web-UI flow. The minted token then authenticated to the registry *as the victim*, inheriting the victim's org memberships: pull private repositories, push into the victim's namespace and any org the victim belongs to. This is the registry instance of a general class this wiki keeps meeting (SkillHub account-merge token echo on the [Sept 18 client-supplied-proofs page](2026-09-18-grafana-extract-before-verify-sogo-origin-reset-and-client-supplied-proofs-ghsa.md)): **flows that move identity between states must be audited for what credentials, bindings, and capabilities ride along.**

## The published chain

1. Attacker registers throwaway account A, mints a PAT with read/write/delete scope (cost: one free account).
2. A is converted to an organization; the conversion's **receiver is set to victim B** — any existing username.
3. **No confirmation email, no notification of any kind** is sent to B.
4. A's PAT is reattached to B's account and **authenticates as B**, inheriting B's org memberships.

Independently reproduced twice by the researcher: `docker login` as the victim with a token minted on a throwaway account the same morning; repository created and pushed in the victim's own namespace; push into an org repository the victim belonged to; **pull of the victim's private repositories** (read, not just write); the registry API accepted the token for bearer exchange (`POST /v2/auth/token`) and repository listing. The victim's inbox stayed empty throughout.

Traces left: one entry in the victim's token list — **with an attacker-chosen display name, so a familiar-looking name proves nothing** — and a new organization visible only via the account switcher.

Exposure window: the flaw existed since 2026-08-26 two years prior (introduced 2024-08-26); Docker reviewed all conversions since then and the ~304,000 pushes made with transferred tokens and found no evidence of exploitation. Flagged-but-unconfirmed worst case from the writeup: if Official Images (`library/*`) publish under a plain account reachable by the same conversion path, one conversion = push into ecosystem base images — root-of-trust, not just supply-chain.

## Why this is worth an operator page

- **Identity-transition flows are credential-carrying state machines.** Enumerate every flow where the platform moves an identity between states: account→org conversion, account merge, marketplace connect, SSO link, team transfer, deletion-with-handover. For each, the operator questions are fixed: (1) does the transition notify/require consent from the *receiving* principal? (2) which credentials, sessions, webhooks, and grants transfer, and do they keep their old scopes or gain the new identity's authorization? GhostPat answers both "no" and "they transfer and gain."
- **Token-to-identity binding outlives the account that minted it.** The PAT's *owning account was deleted by the conversion*, yet the token kept authenticating — now as someone else. Grep heuristic for self-hosted twins (GitLab/Gitea/Forgejo org flows, package registries, artifact stores): the conversion/merge handler updates the token's user foreign key (or copies rows) without rotating or invalidating the secret. Absent rotation = standing ATO primitive.
- **Registry trust is name trust.** A push under a trusted user's (or org's) name looks legitimate to every puller — that *is* the container supply-chain trust model. For red-team supply-chain paths: a silent write primitive into a maintainer identity beats phishing the maintainer. For bug hunters on any registry/SaaS platform: test conversion/merge flows with **two accounts you own** (attacker + designated victim) and check whether the attacker's token authenticates as the victim before writing anything.
- **Post-engagement hygiene checklist that generalizes to any platform:** audit token lists assuming names are attacker-authored; check for orgs/teams/workspaces you don't remember joining; revoke-and-reissue anything not actively needed; look for API activity from tokens or memberships you can't explain.

## Validation workflow (authorized scope only)

!!! warning "Two owned accounts, read-only proofs, vendor scope rules"
    The published PoC used only researcher-controlled accounts. Reproduce at most with two accounts you own (attacker + designated victim) on a platform whose bug-bounty scope explicitly covers this flow. Never run the conversion against a third-party username on a live registry — even without notification, the transferred token is a real credential in someone else's account, and Docker's window is closed anyway (fixed 2026-09-30, force-deactivation 2026-10-08). The workflow below is the reusable probe for *self-hosted* registries and identity platforms in engagement scope.

1. **Fixture:** self-hosted registry/identity platform (or in-scope SaaS with org-conversion/merge flows), two disposable accounts A and B, one inert test repository owned by B.
2. **Probe:** mint a token on A, execute the transition flow with B as receiver/target, then attempt (a) token-authenticated read of B's test repository, (b) token-authenticated write of a marker tag, (c) any bearer-exchange or listing API. Evidence: login/accept artifacts with the token redacted, plus confirmation that B received no notification.
3. **Consent-state table:** per flow — receiver notified? receiver approval required? transferred credentials rotated/invalidated? If any cell reads "no" on a credential-bearing path, that's the finding.
4. **Stop before damage:** marker tags in owned repos only; never push to real namespaces, never test on the public hub.

## Reporting checklist

- Exact flow name/endpoint (UI conversion wizard vs API), source and target account types, token type and scopes at mint time vs post-transfer effective authorization.
- Whether the transition notified the receiver, and whether transferred tokens were rotated or silently carried — the finding is the missing consent *and/or* the missing rotation, name which.
- Read-vs-write legs actually demonstrated against owned accounts (pull private, push marker, bearer exchange), token values redacted.
- Bounded impact language: "token authenticates as another user within its scopes" is proven by login + one owned-repo operation; official-images root-of-trust framing stays flagged-and-unconfirmed unless the target's publishing accounts are shown reachable by the same path.
