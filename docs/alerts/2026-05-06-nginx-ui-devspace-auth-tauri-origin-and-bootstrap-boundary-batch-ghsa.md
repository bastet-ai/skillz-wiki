# Nginx-UI, DevSpace, Auth0.js, and Tauri origin/bootstrap boundary batch

**Sources:** GitHub Security Advisories published 2026-05-06 16:58-17:06 UTC.

## Why this matters

This batch is a clean reminder that “local”, “first run”, “encrypted”, and “authenticated” are not equivalent security boundaries. Several advisories turn setup windows, localhost WebSockets, custom URL schemes, and user-profile token flows into admin takeover, command execution, or secret exposure.

## Advisory summary

| Advisory | Component | Issue | Fixed version |
|---|---|---|---|
| [GHSA-4pvg-prr3-9cxr](https://github.com/advisories/GHSA-4pvg-prr3-9cxr) / CVE-2026-42238 | `github.com/0xJacky/nginx-ui` | Unauthenticated `POST /api/restore` during setup can restore attacker-controlled config/database, then trigger command execution through `TestConfigCmd`. | 2.3.8 |
| [GHSA-h27v-ph7w-m9fp](https://github.com/advisories/GHSA-h27v-ph7w-m9fp) / CVE-2026-42221 | `github.com/0xJacky/Nginx-UI` | Remote unauthenticated first-run installer lets an attacker claim the initial admin account. | 2.3.8 |
| [GHSA-mxqh-q9h6-v8pq](https://github.com/advisories/GHSA-mxqh-q9h6-v8pq) / CVE-2026-42222 | `github.com/0xJacky/nginx-ui` | First-boot installer accepts attacker-controlled bootstrap credentials and trust material in the setup window. | No patched version listed in metadata for the narrow 2.3.5 range; upgrade to the vendor’s fixed line when available and prefer 2.3.8+ where applicable. |
| [GHSA-q4w7-56hr-83rm](https://github.com/advisories/GHSA-q4w7-56hr-83rm) / CVE-2026-42223 | `github.com/0xJacky/nginx-ui` | Settings read API serializes fields tagged `protected:"true"`, leaking JWT, node, OIDC, and Casdoor secrets to authenticated users. | 2.3.8 |
| [GHSA-hqwm-7x7x-8379](https://github.com/advisories/GHSA-hqwm-7x7x-8379) / CVE-2026-42283 | `github.com/loft-sh/devspace` | UI WebSocket accepts all origins; a malicious site can connect to `ws://127.0.0.1:8090` and reach logs, pod shell, or pipeline commands. | 6.3.21 |
| [GHSA-8qjv-jj2q-x832](https://github.com/advisories/GHSA-8qjv-jj2q-x832) / CVE-2026-42280 | `auth0-js` | Crafted invalid ID token plus valid access token can return profile data when Actions-based access controls are relied on. | 10.0.0 |
| [GHSA-7gmj-67g7-phm9](https://github.com/advisories/GHSA-7gmj-67g7-phm9) / CVE-2026-42184 | `tauri` | Windows/Android local-origin check classifies `http://<scheme>.evil.tld` as local when the first DNS label matches a registered scheme. | 2.11.1 |

## Triage now

- **Nginx-UI:** find exposed or recently restarted fresh installs, especially Docker/LAN/test instances. Upgrade to 2.3.8+ where covered, rotate JWT/node/OIDC/Casdoor secrets, and inspect restore/install logs for first-run claims or backup uploads.
- **DevSpace:** upgrade to 6.3.21+ and treat developer browsers as hostile input to localhost tooling. If the UI was used while browsing untrusted sites, review pod logs, interactive shell history, and pipeline-command execution.
- **Auth0.js:** upgrade `auth0-js` to 10.0.0+ for applications using Auth0 Actions as an access-control boundary. Review profile-access assumptions where access tokens and ID tokens are mixed.
- **Tauri:** upgrade to 2.11.1+ on Windows/Android apps using custom protocols or local-only IPC capabilities. Audit any command marked local-only and reachable from WebViews opened to remote content.

## Hunt prompts

- Search Nginx-UI reverse-proxy/access logs for `GET /api/install`, `POST /api/install`, `POST /api/restore`, `GET /api/settings`, and follow-up `POST /api/nginx/test` within minutes of process start.
- Look for Nginx-UI config changes to `JwtSecret`, node `Secret`, `TestConfigCmd`, `ReloadCmd`, `RestartCmd`, OIDC/Casdoor client secrets, and database replacement timestamps.
- On developer workstations, search browser history and DevSpace logs for external pages opened while `127.0.0.1:8090` was listening.
- In Tauri apps, fuzz origin checks with `http://<scheme>.example.test/`, custom scheme names, and redirected remote pages before exposing privileged commands.

## Durable controls

- Never protect setup or restore with a time window alone. Require a one-time bootstrap token generated locally and consumed atomically.
- Treat restore/import as authenticated privileged writes, then validate restored config before use. Strip or reject command-bearing settings from externally supplied backups.
- Redact protected fields symmetrically: write protection is not read protection.
- Localhost services and desktop IPC must validate `Origin`; DNS labels that merely start with a trusted scheme are not local.
- Token handlers should validate token family, audience, issuer, and intended use before returning profile or authorization data.
