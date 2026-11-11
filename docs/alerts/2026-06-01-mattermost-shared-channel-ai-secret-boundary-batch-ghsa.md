# Mattermost shared-channel, AI rewrite, support-packet secret, and chatops boundary batch

Source: GitHub Security Advisories, updated 2026-06-01: [GHSA-hqpj-f3jh-29vx](https://github.com/advisories/GHSA-hqpj-f3jh-29vx) / CVE-2026-4273, [GHSA-8h9w-w78c-vvr3](https://github.com/advisories/GHSA-8h9w-w78c-vvr3) / CVE-2026-28759, [GHSA-82j6-4fq7-fx62](https://github.com/advisories/GHSA-82j6-4fq7-fx62) / CVE-2026-6347, [GHSA-9p64-jpc7-m2rp](https://github.com/advisories/GHSA-9p64-jpc7-m2rp) / CVE-2026-6346, [GHSA-m79q-8qf5-v622](https://github.com/advisories/GHSA-m79q-8qf5-v622) / CVE-2026-6343, [GHSA-wvgv-4fc3-2rcp](https://github.com/advisories/GHSA-wvgv-4fc3-2rcp) / CVE-2026-6345, [GHSA-vqp5-2mrp-qqxg](https://github.com/advisories/GHSA-vqp5-2mrp-qqxg) / CVE-2026-6333, [GHSA-8r89-8w26-cq32](https://github.com/advisories/GHSA-8r89-8w26-cq32) / CVE-2026-5163, [GHSA-xvcx-mgpc-5xh3](https://github.com/advisories/GHSA-xvcx-mgpc-5xh3) / CVE-2026-6339, and [GHSA-gvg4-jhmr-6j23](https://github.com/advisories/GHSA-gvg4-jhmr-6j23) / CVE-2026-4286. August 25 follow-up wave: [GHSA-6hxm-w4hv-vgvw](https://github.com/advisories/GHSA-6hxm-w4hv-vgvw) / CVE-2026-7387, [GHSA-9p44-r552-4wp9](https://github.com/advisories/GHSA-9p44-r552-4wp9) / CVE-2026-7184, [GHSA-m2w9-h2mm-79qr](https://github.com/advisories/GHSA-m2w9-h2mm-79qr) / CVE-2026-6739, [GHSA-3vmp-whvv-5v9v](https://github.com/advisories/GHSA-3vmp-whvv-5v9v) / CVE-2026-6046, [GHSA-c28q-m4gf-vg4q](https://github.com/advisories/GHSA-c28q-m4gf-vg4q) / CVE-2026-6689, and [GHSA-rp4v-qc77-phm4](https://github.com/advisories/GHSA-rp4v-qc77-phm4) / CVE-2026-3433.

This batch is durable because the advisories point to reusable operator checks for collaboration platforms: remote-cluster trust boundaries, AI helper endpoints that replay private thread context, support export secret handling, host-header callback construction, burn-after-read request forgery, playbook/chatops permission drift, and the August 25 wave of route-scoped authorization checks on role, group-link, team-creation, bot-registration, and websocket-broadcast surfaces.

## What changed

- **Remote cluster invite token rotation**, affected Mattermost versions can accept an invite confirmation where `RefreshedToken` equals the original invite token, allowing authenticated reuse of a token that should have rotated.
- **Shared-channel membership sync authorization**, a malicious remote cluster can send crafted membership-removal sync messages for channels it should not control, including private channels.
- **Support-packet secret exposure**, Mattermost core and the Calls plugin can include sensitive configuration fields in support packets, including plaintext TURN credentials for Calls deployments.
- **Playbooks public/private permission check**, users lacking public/private playbook permissions can still access public playbooks through the `/get` path.
- **Created-user password disclosure**, created user passwords may be exposed in a way that enables impersonation when an attacker can observe the relevant output path.
- **Slash-command response URL host-header trust**, custom slash command response URLs can be constructed from an attacker-supplied `Host` header, redirecting command responses to an attacker-controlled listener.
- **AI-assisted rewrite channel-membership check**, crafted post-rewrite requests can expose private-channel or direct-message thread content to a user who is not a member.
- **Burn-on-read reveal request forgery**, a crafted Markdown image tag can force reveal of a burn-on-read message because the reveal endpoint does not validate the expected `X-Requested-With` request shape.
- **Playbook team reassignment drift**, users with only `Manage Playbook Configurations` can change a playbook's `team_id` through the update API and bypass manage-members restrictions.

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

### Federated shared-channel file-sync path-traversal check

[GHSA-8qq9-cqj8-82w4](https://github.com/advisories/GHSA-8qq9-cqj8-82w4) / [CVE-2026-6961](https://nvd.nist.gov/vuln/detail/CVE-2026-6961) (MMSA-2026-00661, high) is a remote-cluster-to-filestore trust break: during shared-channel file sync, the target server does not sanitize `FileInfo.Name` received from a federated peer, so a controlled federated server can write files to arbitrary locations within the target's filestore via path-traversal sequences in the filename field.

- **Version scope:** affected releases are `11.6.x <= 11.6.1`, `11.5.x <= 11.5.4`, `10.11.x <= 10.11.15` (and `<= 10.11.16` per the advisory). Fixed in `11.6.2`, `11.5.5`, `10.11.17`.
- **Trust model:** the actor is a *federated* server the target trusts for shared-channel file sync. This extends the [shared-channel membership-removal check](#shared-channel-membership-removal-authorization-check) from the same page: both treat remote-cluster metadata as privileged input that must be re-bound to an authorized location.
- **Lab setup:** two disposable Mattermost instances in an affected version with a working federation relationship and a shared channel. One instance is the "attacker" peer the tester controls; both use throwaway filestore roots.
- **Workflow:** from the controlled peer, emit a shared-channel file-sync event whose `FileInfo.Name` carries a traversal-shaped canary (for example `../../canary.txt` or a sibling-above-canary), referencing a synthetic, non-sensitive source object.
- **Expected secure result:** the file lands under the shared-channel filestore sub-path for that channel, or the event is rejected. **Vulnerable result:** a marker file appears at a location above the expected channel sub-path within the target filestore.
- **Bound the claim:** this is a *filestore-relative* write primitive, not arbitrary host filesystem write. Prove it with a synthetic canary and stop at the placement decision. Do not overwrite real stored files, do not read other tenants' files, and do not use the write to plant executable content on a live server.
- **Report** as **federated-peer `FileInfo.Name` -> shared-channel file sync -> unsanitized filename -> filestore path outside the channel sub-path**, and pair it with the membership-sync mismatch so the report frames a consistent "remote-cluster metadata reaches privileged target state" pattern.

## August 25 follow-up: route-scoped authorization wave

Six new Mattermost records (MMSA-2026-00616/00649/00655/00656/00662/00665) all land in the same 10.11.x / 11.5.x / 11.6.x window and share one operator pattern: **an API route enforces its object-level permission but not the authority-level permission the mutation actually grants**. Each check below binds one route to one missing authority check.

### Group-sync link `scheme_admin` escalation check

[GHSA-6hxm-w4hv-vgvw](https://github.com/advisories/GHSA-6hxm-w4hv-vgvw) / [CVE-2026-7387](https://nvd.nist.gov/vuln/detail/CVE-2026-7387) (MMSA-2026-00665, high, CVSS 8.8): the group syncable link and patch endpoints accept a `scheme_admin` flag without requiring role-management authorization, so a user holding group-link permissions can escalate themselves and linked group members to team or channel admin.

- **Version scope:** `11.6.x <= 11.6.1`, `11.5.x <= 11.5.4`, `10.11.x <= 10.11.15/16`; patched `11.6.2`, `11.5.5`, `10.11.17`, `8.0.0-20260506065351`.
- **Lab setup:** one disposable instance in an affected version; a group (for example Ldap-group or a local syncable group) and two synthetic users; one principal with `manage_group` / group-link permission but explicitly without role-management authority.
- **Workflow:** from that principal, POST the group syncable link (or PATCH the existing link) with the scheme `scheme_admin` / role-escalating payload against the synthetic group; then read back the group membership roles for the two synthetic users.
- **Expected secure result:** the route rejects the payload or applies only the scheme the caller is authorized to set. **Vulnerable result:** the link records the escalated scheme and the synthetic users now resolve team/channel-admin permissions.
- **Bound the claim:** prove with synthetic users only. Do not escalate real users, do not grant real admins the flag, and revert any mutated group or role state immediately.
- **Report** as **group syncable link/patch -> `scheme_admin` accepted without role-management authorization -> synthetic users gain admin role**, including the exact endpoint, caller permission set, and before/after role resolution.

### Protected system-role patch check

[GHSA-m2w9-h2mm-79qr](https://github.com/advisories/GHSA-m2w9-h2mm-79qr) / [CVE-2026-6739](https://nvd.nist.gov/vuln/detail/CVE-2026-6739) (MMSA-2026-00656, medium, CVSS 6.7): patching protected default system roles does not require system-level permission, so a delegated user-management principal can alter built-in role permissions.

- **Version scope:** same 10.11/11.5/11.6 window; patched `10.11.17`, `11.5.5`, `11.6.2`, `8.0.0-20260501142004`.
- **Lab setup:** one affected instance; a principal with delegated user-management (for example manage users) but not system-admin; a synthetic custom role plus one default protected role (for example `team_admin`).
- **Workflow:** PATCH the default role's permission set with a benign added permission (for example `create_post`), then read the role back and test a synthetic low-privilege user against the newly added permission.
- **Expected secure result:** the patch is rejected for the protected default role. **Vulnerable result:** the built-in role's permission set changes and the synthetic user now exercises the added permission.
- **Bound the claim:** only add a low-impact permission on a disposable instance and revert the role immediately; never widen system-admin or delete roles.
- **Report** as **role PATCH on protected default role -> accepted without system-level permission -> synthetic principal exercises the added permission**, with the role diff.

### Remote-cluster API token disclosure on PATCH check

[GHSA-9p44-r552-4wp9](https://github.com/advisories/GHSA-9p44-r552-4wp9) / [CVE-2026-7184](https://nvd.nist.gov/vuln/detail/CVE-2026-7184) (MMSA-2026-00662, medium, CVSS 6.5, CWE-201): the Remote Cluster API response is not sanitized on PATCH, so a user with `manage_secure_connections` can obtain remote-cluster authentication tokens through the PATCH response.

- **Version scope:** same window; patched `10.11.17`, `11.5.5`, `11.6.2`, `8.0.0-20260428142921`.
- **Lab setup:** two instances with a working remote-cluster relationship; the target's cluster token is a synthetic lab value.
- **Workflow:** as a user holding `manage_secure_connections` on the target, send a PATCH to the remote cluster endpoint and inspect the response body and headers for the cluster token or token-derivable material.
- **Expected secure result:** the PATCH response is sanitized and carries no cluster authentication material. **Vulnerable result:** the response (or a field of it) contains the remote-cluster token or enough material to reconstruct it.
- **Bound the claim:** use only synthetic tokens you mint for the lab; capture redacted token fragments, not the full value, in the report.
- **Report** as **remote-cluster PATCH -> unsanitized response -> cluster token disclosure**, with the response field that leaked and the caller permission.

### Bot-registration username validation check

[GHSA-3vmp-whvv-5v9v](https://github.com/advisories/GHSA-3vmp-whvv-5v9v) / [CVE-2026-6046](https://nvd.nist.gov/vuln/detail/CVE-2026-6046) (MMSA-2026-00649, medium, CVSS 5.3): the server does not validate that a username returned during bot registration belongs to a bot account, enabling an unprivileged user who pre-registers a predictable plugin bot username to intercept private plugin DMs.

- **Version scope:** same window; patched `10.11.17`, `11.5.5`, `11.6.2`, `8.0.0-20260428151657`.
- **Lab setup:** one affected instance with a plugin (or a stub bot client) that DMs a user using a predictable bot username pattern.
- **Workflow:** pre-register a normal user account with the predictable bot username; trigger the plugin DM; observe whether the message lands in the attacker-controlled account's DM channel instead of the bot's.
- **Expected secure result:** registration of a bot username by a non-bot principal is rejected, or the DM resolves to the bot account regardless of pre-registration. **Vulnerable result:** the synthetic plugin DM is delivered to the attacker-controlled user account.
- **Bound the claim:** use a synthetic plugin message only; do not target real user DMs or capture real plugin output.
- **Report** as **bot registration returns username not bound to bot account -> pre-registered user intercepts plugin DM**, with the username, registration time, and delivery evidence.

### Team-creation open-invite / allowed-domains check

[GHSA-c28q-m4gf-vg4q](https://github.com/advisories/GHSA-c28q-m4gf-vg4q) / [CVE-2026-6689](https://nvd.nist.gov/vuln/detail/CVE-2026-6689) (MMSA-2026-00655, medium, CVSS 4.3): `POST /api/v4/teams` with `allow_open_invite: true` and/or non-empty `allowed_domains` does not enforce `PermissionInviteUser` on the resulting team, while the update/patch route does.

- **Version scope:** same window; patched `10.11.17`, `11.5.5`, `11.6.2`, `8.0.0-20260501144115`.
- **Lab setup:** one affected instance; a principal with `PermissionCreateTeam` but not `PermissionInviteUser` on teams they create.
- **Workflow:** create a team via `POST /api/v4/teams` with `allow_open_invite: true` and a synthetic `allowed_domains` entry; read back the team; then compare with the same settings applied via the team update/patch route.
- **Expected secure result:** either both routes reject the settings for this principal, or the created team does not expose open-invite/domain-controlled membership to the caller. **Vulnerable result:** the created team accepts the invite settings at creation time while the patch route rejects them for the same principal.
- **Bound the claim:** use a disposable team and revert or delete it; do not open invite settings on real teams or invite real users.
- **Report** as **create-route omits `PermissionInviteUser` that the patch-route enforces -> team-creation accepts open-invite/allowed-domain settings**, with the create/patch decision matrix.

### `role_updated` websocket broadcast scope check

[GHSA-rp4v-qc77-phm4](https://github.com/advisories/GHSA-rp4v-qc77-phm4) / [CVE-2026-3433](https://nvd.nist.gov/vuln/detail/CVE-2026-3433) (MMSA-2026-00616, medium, CVSS 4.3, CWE-200): `role_updated` websocket events are not restricted to members of the affected team or channel, so a guest-level user can observe permission-scheme change notifications for private teams they do not belong to.

- **Version scope:** same window; patched `10.11.17`, `11.5.5`, `11.6.2`, `8.0.0-20260504071740`.
- **Lab setup:** one affected instance; a synthetic private team; a guest-level principal with no membership in that team; a second principal authorized to trigger a `role_updated` event in the private team.
- **Workflow:** open the websocket as the guest principal; trigger the role update in the private team; record which events the guest receives.
- **Expected secure result:** the guest receives no `role_updated` event for the private team (or only events scoped to surfaces the guest is part of). **Vulnerable result:** the guest's socket receives the `role_updated` event naming the private team/channel scope.
- **Bound the claim:** capture event names and scope identifiers only; do not enumerate real teams or exfiltrate real role data.
- **Report** as **`role_updated` broadcast not scoped to team/channel membership -> guest socket receives private-team scheme-change event**, with the event payload (redacted) and the principal's membership state.

## Reporting heuristics

- For remote-cluster issues, include both the channel object being targeted and the remote cluster's authorized channel set. The finding is the mismatch.
- For federated file-sync path traversal, include the peer-supplied `FileInfo.Name`, the resolved filestore path, and the expected channel sub-path; the finding is the placement outside that sub-path. Prove with a synthetic canary only.
- For the August 25 route-scoped wave, include the exact route, the permission the route should have required, the caller's actual permission set, and a create-vs-patch or authorized-vs-unauthorized decision table. The finding is the route/authority mismatch, not the resulting role by itself.
- For AI rewrite leakage, include the inaccessible post/thread ID, caller membership state, and the exact canary phrase returned by the endpoint.
- For support-packet leaks, include redacted file paths and field names, not actual credentials.
- For host-header findings, include the raw `Host` header, the constructed URL, and the callback proof.
- For burn-on-read, prove the state transition was caused by automatic content loading, not recipient interaction.

## Notes on skipped items from this scan

- Mattermost oversized `/api/v1/meetings` request body handling ([GHSA-m3p3-8frq-q7qh](https://github.com/advisories/GHSA-m3p3-8frq-q7qh) / CVE-2026-2325) was processed but not promoted into validation steps because it is primarily resource-exhaustion/DoS rather than durable offensive operator guidance beyond standard parser and upload-size testing.
- CISA KEV stayed on catalog `2026.05.29`; PortSwigger stayed on the Top 10 web hacking techniques of 2025; ProjectDiscovery stayed on already-covered Neo/Nuclei/DAST material; GitHub Security Blog stayed GHES signing-key rotation / IR-oriented; Trail of Bits feed parsing remained non-actionable on older material; Disclosed stayed lander-only.
