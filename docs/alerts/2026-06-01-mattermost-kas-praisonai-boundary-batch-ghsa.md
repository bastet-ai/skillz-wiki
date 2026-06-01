# Mattermost OAuth/command boundaries, kas SHA-like branch checkout, and PraisonAI tenant IDOR batch

Source: GitHub Security Advisories, updated 2026-06-01: [GHSA-jp3f-x449-4q75](https://github.com/advisories/GHSA-jp3f-x449-4q75) / CVE-2026-6334, [GHSA-wvcv-9xpm-7mqc](https://github.com/advisories/GHSA-wvcv-9xpm-7mqc) / CVE-2026-28732, [GHSA-v549-xx3c-6pc8](https://github.com/advisories/GHSA-v549-xx3c-6pc8) / CVE-2026-3637, [GHSA-jx93-pf6x-874r](https://github.com/advisories/GHSA-jx93-pf6x-874r) / CVE-2026-3495, [GHSA-qjwp-hrq6-r26r](https://github.com/advisories/GHSA-qjwp-hrq6-r26r) / CVE-2026-47191, [GHSA-8g2p-pqm3-fcfh](https://github.com/advisories/GHSA-8g2p-pqm3-fcfh) / CVE-2026-47413, [GHSA-g8rr-7rj2-f627](https://github.com/advisories/GHSA-g8rr-7rj2-f627) / CVE-2026-47412, [GHSA-xwq8-frcg-77q8](https://github.com/advisories/GHSA-xwq8-frcg-77q8) / CVE-2026-47415, [GHSA-cp4f-5m9r-5jc2](https://github.com/advisories/GHSA-cp4f-5m9r-5jc2) / CVE-2026-47417, [GHSA-943m-6wx2-rc2j](https://github.com/advisories/GHSA-943m-6wx2-rc2j) / CVE-2026-47418, and [GHSA-rcmc-q9rj-4wmq](https://github.com/advisories/GHSA-rcmc-q9rj-4wmq) / CVE-2026-47411.

This batch is durable because it captures reusable offensive validation patterns: OAuth authorization-code client binding, command-name collision checks in chatops, permission re-checks on edit APIs, supply-chain pinning by object ID versus attacker-controlled refs, and multi-tenant workspace object binding in AI/agent platforms.

## What changed

- **Mattermost OAuth code redemption** — affected Mattermost versions do not bind an authorization code to the OAuth client that redeems it, allowing one authenticated OAuth client to redeem a code issued to another client through a crafted token exchange.
- **Mattermost slash command trigger update** — an authenticated team member with `Manage Own Slash Commands` can update their own command trigger to collide with an existing system or custom trigger, creating a command impersonation/hijack primitive.
- **Mattermost post edit permission drift** — users with revoked channel posting privileges can still modify existing posts via direct post update/patch APIs when edit flows fail to re-check `create_post`.
- **Mattermost configuration-driven error-page script injection** — users who can edit certain site configuration values can influence unescaped variables in error-page composition.
- **kas commit-pin confusion** — kas before 5.3 can treat a SHA-like branch name as a valid commit checkout. If a referenced repository is taken over or malicious, a branch named like the expected SHA can defeat workflows that rely solely on the commit string as the integrity proof.
- **PraisonAI Platform workspace escalation and IDOR** — new platform advisories reinforce the broader tenant-isolation pattern: ordinary workspace members can add arbitrary owners, delete workspaces, rewrite workspace settings, and substitute cross-workspace project/issue/comment IDs beneath a workspace-scoped URL prefix.

## Operator triage

1. **Prioritize trust-boundary tests over severity labels:** the Mattermost OAuth item is listed as low severity, but authorization-code client binding is a high-value identity invariant in SSO/chat integrations.
2. **Model chatops commands as privileged UI:** slash command collisions can redirect human operators into attacker-controlled integrations even when no server-side RCE exists.
3. **Re-test permissions on secondary verbs:** create/post privileges, owner-only workspace controls, and tenant object ownership must be enforced on update, patch, delete, and stats/list paths—not just create/list paths.
4. **Treat git object IDs and refs separately:** a string that looks like a commit hash is not enough if the tool may resolve it as a branch or tag.
5. **Use disposable tenants and callback clients:** validate with lab OAuth clients, canary commands, synthetic posts, and throwaway workspaces only.

## Replayable validation boundaries

### Mattermost OAuth client-binding check

- In a lab Mattermost deployment running an affected version, create two OAuth clients: `client_a` and `client_b`.
- Start a normal authorization flow for `client_a` and capture only the disposable authorization code for a lab user.
- Attempt token redemption using `client_b` credentials and the code issued to `client_a`.
- A vulnerable result is token issuance or any proof that the token endpoint accepted the mismatched client. A safe result is rejection tied to client/code mismatch.
- Do not reuse real SSO clients, production users, or long-lived tokens. Revoke all lab grants after testing.

### Mattermost slash-command collision check

- With a low-privileged lab team member that has `Manage Own Slash Commands`, create a harmless personal command with a unique trigger.
- Pick a non-destructive existing trigger in the same team, preferably a lab custom command rather than a production system workflow.
- Call the command update API to change the lab command trigger to the existing trigger.
- Validate whether the server accepts the duplicate trigger and whether subsequent command invocation routes to the attacker-controlled command or creates ambiguous dispatch.
- Keep evidence to trigger ownership, command ID, update response, and a benign marker response.

### Mattermost post-edit permission re-check

- Create a lab channel and a lab post as the test user.
- Revoke the user's posting privilege in that channel while leaving the historical post in place.
- Attempt direct post update and patch API calls against the user's own existing post.
- A vulnerable result is successful content modification after posting rights were revoked. Use a benign marker edit and restore the original content.

### kas SHA-like branch checkout check

- Create a disposable git repository with two refs:
  - a known commit that represents the intended trusted state;
  - a branch whose name is a SHA-like string that kas may confuse with a commit selector.
- Reference the repository from a kas configuration using the SHA-like value, then run checkout with the affected kas version.
- Prove whether kas materializes the branch content instead of the intended commit object by comparing `git rev-parse HEAD` and a canary file unique to the branch.
- Strong reports should distinguish branch-name resolution from SHA-1 collision theory; this issue is easiest to validate with SHA-256-looking names or tool ref-resolution behavior, not real collision generation.

### PraisonAI Platform tenant and role checks

- Reuse the two-workspace lab pattern from the existing PraisonAI platform boundary note.
- As a normal member in workspace A, attempt owner-only actions against workspace A: add another account with `owner`, patch settings, and delete only a disposable workspace.
- For IDOR checks, create synthetic projects, issues, and comments in workspace B. Send requests under `/workspaces/{workspace_A}/...` while substituting object IDs from workspace B.
- Stop at read-only proof when possible; if mutation is required, mutate only synthetic records and restore the lab.
- Report the authorized workspace ID from the route prefix and the actual owning workspace ID of the substituted object.

## Reporting heuristics

- For OAuth code redemption, include both client IDs, the authorization request redirect URI, token endpoint request shape, and the exact mismatch accepted or rejected.
- For slash command hijack, include command owner, trigger before/after, collision target, and the command dispatch result.
- For permission drift, include the revoked permission, the route used, and whether UI and API behavior differ.
- For kas, include the configured ref string, actual checked-out commit, local branch/tag refs present, and whether signed tags/commits were enforced.
- For PraisonAI Platform, group findings by missing invariant: caller role, workspace ownership, or object-to-workspace binding. Avoid listing every endpoint as an isolated one-off when the same service lookup pattern repeats.

## Notes on skipped items from this scan

- Mattermost 7zip archive memory exhaustion ([GHSA-cjm8-jxpw-g43m](https://github.com/advisories/GHSA-cjm8-jxpw-g43m) / CVE-2026-6340) was not promoted into the validation workflow because it is primarily a resource-exhaustion condition, not a durable offensive operator pattern beyond standard parser bomb testing.
- The new PraisonAI Platform advisories overlap with the existing May 29 PraisonAI tenant-isolation guidance; they are included here only as fresh, concrete endpoints that sharpen the reusable workspace-object binding workflow.
- CISA KEV stayed on catalog `2026.05.29` with PAN-OS CVE-2026-0257 already reflected. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits, and Disclosed had no separate promotable deltas in this pass.
