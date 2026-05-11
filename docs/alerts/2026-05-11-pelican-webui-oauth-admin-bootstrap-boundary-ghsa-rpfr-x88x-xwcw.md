# Pelican WebUI OAuth admin-bootstrap boundary

Source: GitHub Security Advisory [GHSA-rpfr-x88x-xwcw / CVE-2026-42571](https://github.com/advisories/GHSA-rpfr-x88x-xwcw), updated 2026-05-11.

This advisory is durable because it shows a subtle identity bootstrap failure: an authenticated but non-admin WebUI user could create database state that later caused Pelican to grant admin privileges when configured admin users or admin groups had not logged in yet.

## Advisory covered

- **Pelican WebUI privilege escalation** — [GHSA-rpfr-x88x-xwcw](https://github.com/advisories/GHSA-rpfr-x88x-xwcw) / CVE-2026-42571: affected Pelican WebUI deployments between `v7.21` and `v7.24` when OIDC login is enabled and admin identity is bootstrapped from `Server.UIAdminUsers` or `Server.AdminGroups` under specific first-login conditions. Patched lines include `>=v7.21.5`, `>=v7.22.3`, `>=v7.23.3`, and `>=v7.24.2`.

## Operator triage

1. Identify Pelican Director, Registry, Origin, and Cache services with OIDC enabled and `Server.UIAdminUsers` or `Server.AdminGroups` configured.
2. Treat first-login admin bootstrap as suspect: review user, group-membership, and API-token database rows before assuming an upgrade alone removed access.
3. Look for authenticated users whose records, group memberships, or API tokens appeared before a legitimate configured admin or admin-group member completed their first WebUI login.
4. Review privileged configuration changes after any suspicious login: Registry namespace edits, Director federation steering, Origin export paths, write-enable changes, Cache exposure settings, API-token creation, and admin-password changes.
5. If immediate patching is blocked, disable the vulnerable OIDC admin-bootstrap settings only after confirming a working break-glass admin path remains.

## Durable controls

- Do not let ordinary authenticated users create or pre-seed records that will later be interpreted as admin identity, group membership, or role grants.
- Admin bootstrap should be single-purpose, explicit, audited, and closed after first use; runtime login paths should not share the same mutable state transitions.
- Group-derived admin authorization needs a trusted group source and server-side proof at authorization time, not only a stored local group-name match.
- Upgrades that fix authorization logic should be paired with data-plane review: existing user rows, group rows, API tokens, and admin-password state can preserve compromise.
- Federation components should model admin compromise blast radius separately: Registry and Director changes can affect trust routing beyond the local service, while Origin and Cache changes can expose or redirect protected data.
