# Open WebUI, Electerm, and Kuma local-boundary batch

**Signal:** The **2026-05-14 20:15 UTC** advisory scan added a small but durable boundary batch: authenticated Open WebUI users could cross file/profile trust boundaries, Electerm bookmark import/sync could turn local terminal metadata into command execution, and default local Kuma control planes could leak admin material cross-origin.

## Advisory cluster

- **Open WebUI files API authorization gap** — [GHSA-r8wh-8m7r-fh33](https://github.com/advisories/GHSA-r8wh-8m7r-fh33): `open-webui <= 0.3.15`, fixed in `0.3.16`, let any authenticated user list, read, and delete every uploaded file because `/api/v1/files/` endpoints checked login but not file ownership.
- **Open WebUI profile-image stored XSS** — [GHSA-6gh2-q7cp-9qf6](https://github.com/advisories/GHSA-6gh2-q7cp-9qf6): `open-webui < 0.8.0`, fixed in `0.8.0`, accepted attacker-controlled `data:` profile-image URIs. The higher-impact path re-served `data:image/svg+xml` inline from the application origin, enabling account-token theft when victims loaded the profile image.
- **Electerm bookmark/sync execution boundary** — [GHSA-jgg9-rw32-44pj](https://github.com/advisories/GHSA-jgg9-rw32-44pj): `electerm <= 3.8.8` can execute attacker-supplied local-PTY commands after users import unsafe bookmark JSON or apply compromised gist/WebDAV sync data containing `exec*` fields or unsafe global config. No patched version was listed when scanned.
- **Kuma local control-plane CORS/admin-token leak** — [GHSA-3vcp-chfh-f6r2](https://github.com/advisories/GHSA-3vcp-chfh-f6r2): default `kuma-cp` combined wildcard CORS with `LocalhostIsAdmin`, so attacker JavaScript in a browser on the operator machine could read admin bootstrap token/signing material from a reachable local control plane. Fixed in `2.7.25`, `2.9.15`, `2.11.13`, `2.12.10`, and `2.13.5`.

## Why this matters

Local or “authenticated only” features are not low-risk when the data they expose is shared across users, profile-rendered in the application origin, synchronized from untrusted storage, or reachable by a browser with ambient localhost access. These bugs are all examples of missing second-factor checks: owner checks after login, MIME checks after accepting image input, provenance checks after sync, and origin/host checks after localhost-admin shortcuts.

## Triage

1. Patch Open WebUI instances to at least `0.8.0` where possible; specifically verify `0.3.16+` for file ownership and `0.8.0+` for profile-image validation.
2. Search Open WebUI logs for low-privilege calls to `/api/v1/files/`, `/api/v1/files/{id}/content`, file deletes, and user profile updates containing `data:` URLs, especially `image/svg+xml` or `text/html`.
3. Treat imported or synced Electerm bookmarks as executable input. Disable untrusted sync sources, inspect bookmark JSON for `exec*` fields or unexpected local-type bookmarks, and avoid opening imported entries until reviewed.
4. For developer or port-forwarded Kuma control planes, set `KUMA_API_SERVER_AUTHN_LOCALHOST_IS_ADMIN=false` and replace wildcard CORS with an explicit allowlist. Avoid browsing untrusted sites from machines running reachable local control planes.

## Durable controls

- Every file/content API should enforce object ownership or explicit sharing on each list, read, update, and delete route; UI filtering is not authorization.
- Treat profile images and avatars as active content until MIME type, decoded bytes, response headers, and `Content-Disposition` are all constrained.
- Desktop terminal clients should treat imported/synced profiles as untrusted code: strip execution fields by default and require explicit user approval before local command launch.
- Localhost admin shortcuts must be disabled in production-like workflows and hardened with Host, Origin, Fetch Metadata, and proxy-header checks when retained for development.
