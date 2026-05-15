# Exchange render, filesystem, and CGI boundary batch

Sources: GitHub Security Advisories and CISA KEV updates on 2026-05-15.

This batch ties together one exploited Exchange render bug and seven newly published application advisories. The common lesson is boundary canonicalization: rendered user content, uploaded/imported files, CGI path splitting, logout redirects, and peer-provided protocol bytes must be normalized and authorized on the server side before they touch privileged browser, filesystem, process, or network state.

## Advisories covered

- **Microsoft Exchange Server OWA cross-site scripting** — [CVE-2026-42897](https://nvd.nist.gov/vuln/detail/CVE-2026-42897): CISA added this to KEV on 2026-05-15. Exchange Server can execute attacker-controlled JavaScript in an Outlook Web Access browser context when interaction conditions are met. CISA due date: 2026-05-29; follow [MSRC guidance](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-42897), keep Exchange Emergency Mitigation Service healthy, and apply vendor mitigations or discontinue exposed use where mitigations are unavailable.
- **FrankenPHP CGI path splitting execution boundary** — [GHSA-3g8v-8r37-cgjm / CVE-2026-45062](https://github.com/advisories/GHSA-3g8v-8r37-cgjm): `github.com/dunglas/frankenphp >= 1.11.2, <= 1.12.2` mishandles non-ASCII path matching in CGI split logic, letting attacker-controlled uploaded/non-PHP files be treated as PHP scripts in affected deployments. Fixed in `1.12.3`.
- **Pipecat Runner encoded-slash file read** — [GHSA-3363-2ph6-35wh / CVE-2026-44716](https://github.com/advisories/GHSA-3363-2ph6-35wh): `pipecat-ai >= 0.0.90, < 1.2.0` exposes `GET /files/{filename:path}` in runner mode and joins decoded path parameters without a containment check. `%2F`-encoded traversal can read files outside the configured folder. Fixed in `1.2.0`.
- **Joplin OneNote importer arbitrary file overwrite** — [GHSA-gcmj-c9gg-9vh6 / CVE-2026-22810](https://github.com/advisories/GHSA-gcmj-c9gg-9vh6): `@joplin/onenote-converter < 3.5.7` writes embedded attachment names from `.one` imports without sanitizing traversal segments, allowing malicious imports to overwrite files reachable by the user. Fixed in `3.5.7`.
- **Nimiq Ed25519 DHT verifier panic** — [GHSA-27w2-87xv-37c6 / CVE-2026-40092](https://github.com/advisories/GHSA-27w2-87xv-37c6): `nimiq-keys <= 0.2.0` unwraps malformed Ed25519 signature bytes in `TaggedPublicKey::verify`, letting a malicious peer crash full nodes through crafted Kademlia DHT records. Fixed through the Nimiq `v1.4.0` release line.
- **NukeViet CMS stored XSS via Request-class trust** — [GHSA-64rr-pp78-62ww / CVE-2026-41147](https://github.com/advisories/GHSA-64rr-pp78-62ww): NukeViet CMS user HTML input can bypass client-side filtering and persist server-side XSS in modules using the Request class. Upgrade to the fixed NukeViet release line and enforce server-side sanitization.
- **Weblate editor search-preview stored HTML injection** — [GHSA-6wxc-8mgq-w26m / CVE-2026-45106](https://github.com/advisories/GHSA-6wxc-8mgq-w26m): `weblate < 2026.5` renders translation unit `source` and `context` in live search previews without escaping, executing contributor-controlled HTML/CSS in authenticated editor sessions. Fixed in `2026.5`.
- **SimpleSAMLphp CAS logout open redirect** — [GHSA-cvrm-5hp6-h523 / CVE-2025-65954](https://github.com/advisories/GHSA-cvrm-5hp6-h523): `simplesamlphp-module-casserver < 6.3.1` and `>= 7.0.0-rc1, < 7.0.0-rc3` trust logout `url` parameters instead of validating them against service URLs. Fixed in `6.3.1` and the `7.0.0` release path.

## Operator triage

1. Treat internet-facing Exchange OWA as KEV priority: confirm exact Exchange build/mitigation state, verify Emergency Mitigation Service health, and restrict OWA/admin exposure while patching.
2. Hunt Exchange for suspicious OWA access patterns, unexpected mailbox rules, OAuth/app-consent changes, delegated access changes, export activity, and JavaScript-like payloads in request parameters or message-render paths.
3. Inventory FrankenPHP deployments that combine CGI mode with writable uploads, user-managed files, CMS media libraries, or shared storage. Upgrade to `1.12.3` and test non-ASCII path handling against uploaded `.txt`, image, and extensionless files.
4. Remove public access to Pipecat Runner and other development runners. Upgrade `pipecat-ai` to `1.2.0`; if the runner must exist, bind to localhost/private networks and enforce canonical `resolve()` plus `is_relative_to()` checks on every download path.
5. For desktop/import workflows, treat `.one` files and other archive-like project files as untrusted code-adjacent inputs. Upgrade Joplin/`@joplin/onenote-converter` to `3.5.7`, and watch for unexpected writes under profiles, shell startup files, extensions, and sync directories after imports.
6. For Nimiq and similar P2P nodes, prioritize malformed-message negative tests: invalid signature lengths should return verification failure, not panic. Upgrade to the fixed Nimiq release line and alert on peer-triggered crash loops.
7. For Weblate, NukeViet, and Exchange, search for stored payloads before assuming patching removed risk. Review contributor-submitted strings, contact/comment content, translation context/source fields, and admin/moderator views that render user-originated HTML.
8. For CAS/SAML logout flows, validate redirect targets against registered service URLs after canonicalization. Disable `skip_logout_page` or external logout redirects until fixed where the module is exposed to untrusted users.

## Durable controls

- Server-side canonicalization is the boundary. Client filtering, framework routing normalization, and UI-only constraints do not protect privileged render or filesystem sinks.
- Encoded separators, Unicode case folding, archive/import filenames, and redirect URLs need explicit allowlist tests. Include `%2F`, mixed normalization forms, path roots, symlinks, dot segments, and alternate encodings in regression suites.
- Render sinks in admin/editor interfaces deserve the same escaping discipline as public pages because authenticated browser context usually carries stronger permissions.
- Development runners and import utilities are production risk when reachable by networks, sync folders, shared desktops, or automation. Give them least privilege and treat them as exploit surfaces.
- KEV entries need a hunt-and-mitigate owner with a dated deadline, not only a dependency ticket. For identity or messaging surfaces, include token/session review and post-patch payload cleanup.
