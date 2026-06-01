# Mattermost shared-channel, AI rewrite, support-packet secret, and chatops boundary batch

Source: GitHub Security Advisories, updated 2026-06-01: [GHSA-hqpj-f3jh-29vx](https://github.com/advisories/GHSA-hqpj-f3jh-29vx) / CVE-2026-4273, [GHSA-8h9w-w78c-vvr3](https://github.com/advisories/GHSA-8h9w-w78c-vvr3) / CVE-2026-28759, [GHSA-82j6-4fq7-fx62](https://github.com/advisories/GHSA-82j6-4fq7-fx62) / CVE-2026-6347, [GHSA-9p64-jpc7-m2rp](https://github.com/advisories/GHSA-9p64-jpc7-m2rp) / CVE-2026-6346, [GHSA-m79q-8qf5-v622](https://github.com/advisories/GHSA-m79q-8qf5-v622) / CVE-2026-6343, [GHSA-wvgv-4fc3-2rcp](https://github.com/advisories/GHSA-wvgv-4fc3-2rcp) / CVE-2026-6345, [GHSA-vqp5-2mrp-qqxg](https://github.com/advisories/GHSA-vqp5-2mrp-qqxg) / CVE-2026-6333, [GHSA-8r89-8w26-cq32](https://github.com/advisories/GHSA-8r89-8w26-cq32) / CVE-2026-5163, [GHSA-xvcx-mgpc-5xh3](https://github.com/advisories/GHSA-xvcx-mgpc-5xh3) / CVE-2026-6339, and [GHSA-gvg4-jhmr-6j23](https://github.com/advisories/GHSA-gvg4-jhmr-6j23) / CVE-2026-4286.

This batch is durable because the advisories point to reusable operator checks for collaboration platforms: remote-cluster trust boundaries, AI helper endpoints that replay private thread context, support export secret handling, host-header callback construction, burn-after-read request forgery, and playbook/chatops permission drift.

## What changed

- **Remote cluster invite token rotation** — affected Mattermost versions can accept an invite confirmation where `RefreshedToken` equals the original invite token, allowing authenticated reuse of a token that should have rotated.
- **Shared-channel membership sync authorization** — a malicious remote cluster can send crafted membership-removal sync messages for channels it should not control, including private channels.
- **Support-packet secret exposure** — Mattermost core and the Calls plugin can include sensitive configuration fields in support packets, including plaintext TURN credentials for Calls deployments.
- **Playbooks public/private permission check** — users lacking public/private playbook permissions can still access public playbooks through the `/get` path.
- **Created-user password disclosure** — created user passwords may be exposed in a way that enables impersonation when an attacker can observe the relevant output path.
- **Slash-command response URL host-header trust** — custom slash command response URLs can be constructed from an attacker-supplied `Host` header, redirecting command responses to an attacker-controlled listener.
- **AI-assisted rewrite channel-membership check** — crafted post-rewrite requests can expose private-channel or direct-message thread content to a user who is not a member.
- **Burn-on-read reveal request forgery** — a crafted Markdown image tag can force reveal of a burn-on-read message because the reveal endpoint does not validate the expected `X-Requested-With` request shape.
- **Playbook team reassignment drift** — users with only `Manage Playbook Configurations` can change a playbook's `team_id` through the update API and bypass manage-members restrictions.

## Operator triage

1. **Start with cross-boundary features:** remote clusters, shared channels, Calls, AI rewrites, support packets, and playbooks all bridge internal trust zones. They are more likely to yield high-signal findings than generic chat message CRUD.
2. **Separate UI role checks from API invariants:** test the direct API path after proving the UI blocks the action. The highest-value evidence is a UI/API split with the same principal.
3. **Use canary secrets only:** for support-packet and password-disclosure checks, seed unique lab values such as `SKILLZ_CANARY_TURN_SECRET_<case>` and never export real tenant secrets into reports.
4. **Prefer proof of routing over destructive mutation:** for host-header and remote-cluster checks, a callback hit or rejected/accepted status with synthetic IDs is enough; do not disrupt real channels or remove real members.
5. **Bundle repeated Mattermost findings by invariant:** report missing channel membership, missing team ownership, and unsafe callback construction as boundary failures rather than as isolated endpoint trivia.

## Replayable validation boundaries

### Remote-cluster invite token rotation check

- In a lab Mattermost deployment running an affected version, create two remote-cluster test instances or use a disposable remote-cluster integration fixture.
- Capture the original invite token during a normal invite confirmation flow.
- Send a crafted confirmation where `RefreshedToken` is identical to the original token.
- A vulnerable result is acceptance of the confirmation or continued reuse of the original token after the flow claims rotation occurred.
- Evidence to capture: cluster IDs, token fingerprints only, request timestamp, and whether the original token remains valid. Do not store full tokens in the wiki or report body.

### Shared-channel membership-removal authorization check

- Create a lab shared-channel relationship where remote cluster B legitimately has access to channel `allowed` but no access to private channel `private-target`.
- From the remote-cluster side, craft a membership sync/removal message targeting a synthetic user in `private-target`.
- A vulnerable result is a successful membership removal or state transition in a channel the remote cluster is not authorized to manage.
- Keep the test to disposable users and channels. Restore membership immediately if the test mutates state.

### Support-packet and Calls plugin secret canary check

- Configure only lab credentials: a fake SMTP/API secret, a fake plugin credential, and a fake Calls TURN username/password with unique canary values.
- Generate a support packet using the documented System Console path or equivalent admin API in a controlled lab.
- Search the export for the exact canary strings and for sensitive field names near plaintext values.
- A vulnerable result is plaintext or trivially recoverable secret material in the support bundle.
- Report only redacted matches, field names, and file paths inside the support packet; do not include full secret values.

### Playbooks permission and `team_id` drift checks

- Create two lab teams and a public playbook owned by team A.
- Test `/get` or the affected playbook retrieval path with a user that lacks the relevant public/private playbook permission.
- For team reassignment, use a user with `Manage Playbook Configurations` but without manage-members authority, then attempt a direct update API call changing `team_id` from team A to team B.
- Vulnerable results are playbook retrieval despite missing permission, or accepted cross-team reassignment without the stronger team/member authorization.
- Capture the before/after team IDs, caller role, and route. Use a disposable playbook and revert the team assignment.

### Slash-command Host-header callback check

- Create a harmless custom slash command in a lab team that returns a benign marker.
- Invoke or update the command through the API while sending a `Host` header pointing at an operator-controlled HTTPS listener such as `callback.example.test`.
- A vulnerable result is any slash-command response URL, callback, or command response delivered to the attacker-controlled host.
- Capture callback timestamps, the spoofed host, and the command ID. Avoid sending production command output to external infrastructure.

### AI-assisted rewrite private-thread check

- Create a private channel or direct-message thread containing a benign canary phrase.
- Authenticate as a user outside that private conversation.
- Send the affected AI rewrite request referencing the inaccessible post/thread ID.
- A vulnerable result is rewritten text, summary text, or model prompt output containing the canary phrase or other private thread context.
- Use synthetic messages only. Do not ask the AI endpoint to transform real private content.

### Burn-on-read forced reveal check

- Send a burn-on-read lab message to a consenting test recipient.
- From an authenticated channel member, place a crafted Markdown image tag that references the reveal endpoint for that message.
- Observe whether the message transitions to revealed/read state without the recipient deliberately opening it.
- A vulnerable result is reveal state change caused by image fetching rather than an intentional AJAX request with the expected request headers.
- Evidence should include message ID, pre/post reveal state, and the rendered Markdown request path; do not expose message content beyond a canary.

### Created-user password disclosure canary

- Create a disposable user with a unique random password canary through the affected account-creation path.
- Monitor only authorized outputs available to the test role: API response body, logs exposed to that role, email templates, admin views, or generated bundles.
- A vulnerable result is disclosure of the plaintext created-user password or enough material to impersonate the account.
- Immediately rotate or delete the test user after evidence collection.

## Reporting heuristics

- For remote-cluster issues, include both the channel object being targeted and the remote cluster's authorized channel set. The finding is the mismatch.
- For AI rewrite leakage, include the inaccessible post/thread ID, caller membership state, and the exact canary phrase returned by the endpoint.
- For support-packet leaks, include redacted file paths and field names, not actual credentials.
- For host-header findings, include the raw `Host` header, the constructed URL, and the callback proof.
- For burn-on-read, prove the state transition was caused by automatic content loading, not recipient interaction.

## Notes on skipped items from this scan

- Mattermost oversized `/api/v1/meetings` request body handling ([GHSA-m3p3-8frq-q7qh](https://github.com/advisories/GHSA-m3p3-8frq-q7qh) / CVE-2026-2325) was processed but not promoted into validation steps because it is primarily resource-exhaustion/DoS rather than durable offensive operator guidance beyond standard parser and upload-size testing.
- CISA KEV stayed on catalog `2026.05.29`; PortSwigger stayed on the Top 10 web hacking techniques of 2025; ProjectDiscovery stayed on already-covered Neo/Nuclei/DAST material; GitHub Security Blog stayed GHES signing-key rotation / IR-oriented; Trail of Bits feed parsing remained non-actionable on older material; Disclosed stayed lander-only.
