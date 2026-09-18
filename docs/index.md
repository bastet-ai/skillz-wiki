---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Agent-built audit tooling for custom VMs and DSLs** (Trail of Bits Miden zkVM review): have agents build the missing LSP → subset decompiler/IR → abstract-interpretation passes → Lean formal model before hand-review on no-tooling bytecode targets; reusable vuln pattern — untrusted witness operands coupled only by a reconstruction equation (validated quotient + unvalidated remainder in `mod_12289`) let a malicious prover trade slack between fields and forge Falcon signatures; sweep every (length, checksum) / (offset, size) / advice-pair crossing a verify boundary](methodology/agent-built-audit-tooling-custom-vm.md)

- [WordPress core 7.1.1 security release: **unauthenticated stored XSS in `wpautop()`** on default installs (moderation off + previously-approved bypassable; CVE-2026-93485), XML-RPC `customize_changeset` publish bypassing `edit_css` (transport parity), HTML-API comment breakout, crafted-URL theme install/preview, contributor+ post overwrite/slug disclosure, private parent-title leak, any-user comment reparenting (11 core fixes); + Sept 18 plugin wave folded onto the July 28 page (Ai1wm export secret → import → admin, timestamp-derived tokens, PDF-renderer artifact SSRF)](alerts/2026-09-18-wordpress-core-7-1-1-parser-xmlrpc-and-object-scope-boundaries-ghsa.md)

- [Nextcloud app-layer authority drift: Circles fetches the attacker-supplied `keyId` URL **before** establishing trust and whitelists local/private addresses → unauthenticated blind SSRF past core protections (CVE-2026-77164); WebDAV locks resolve from the absolute URI with no owner check → cross-user locks + lock-token leak (CVE-2026-82980); Deck board-config skips ownership (CVE-2026-77170); Photos smart albums apply the **viewer's** folder scope to the owner's files (CVE-2026-82985); Approval etag check only fires when the client sends the etag (CVE-2026-82982); + yt-dlp-web-ui `params`→argv injection folded onto the Aug 5 page (7 GHSAs)](alerts/2026-09-18-nextcloud-app-layer-authority-drift-circles-keyid-ssrf-webdav-locks-and-deck-config-ghsa.md)

- [Extraction-before-verification and client-supplied proofs: Grafana extracts plugin archives **before signature verification** → chained relative symlinks escape the plugin dir, drop an executable backend binary, RCE as the server process — a valid signature doesn't help (CVE-2026-15815); SOGo password-reset links built from the client-supplied `Origin` header → token mailed to the victim pointing at attacker infra → ATO (CVE-2026-93453); Amelia customer endpoint has no ownership check → provider role resets any customer's WordPress password (CVE-2026-14311); Motors ajax leaks draft/private/future listings unauthenticated (CVE-2026-16750)](alerts/2026-09-18-grafana-extract-before-verify-sogo-origin-reset-and-client-supplied-proofs-ghsa.md)

- [User input as CLI argv / platform-structural sinks: MISP contact form forwards fields into CakePHP console **argv** where `ShellDispatcher` honors `-app`/`-webroot` path switches → `person=-app` + `message=phar://…` → bootstrap include of attacker archive = unauthenticated RCE; SAP `@sap/cds-mtxs` unauthenticated tenant-credential disclosure (CVE-2026-76969, critical); Verizon Cloud for Android exported share-activities unsanitized `_display_name` → arbitrary file write from co-resident apps; + MISP Overmind legend innerHTML stored XSS folded into Sept 7 page (4 GHSAs)](alerts/2026-09-17-misp-cakephp-argv-phar-rce-sap-cds-mtxs-tenant-credentials-and-android-exported-activity-file-write-ghsa.md)

- [Python/PHP policy-sandbox traversal + reference-expansion authz + client-side trust violations: RestrictedPython escape via `string.Formatter.get_field` internal traversal (never enters `safer_getattr`), Zope AccessControl `str.format`/`format_map` real-`getattr` disclosure with `str`-subclass mitigation miss, Umbraco Delivery API expands picker-referenced protected nodes with no access check (direct 401 vs expanded 200), MariaDB Connector/J ignores `allowLocalInfile=false` on server-initiated `0xfb`; late wave: Kestra unauth management port 8081 + Pebble `http()` pre-auth SSRF, AsyncHttpClient creds-on-plaintext-CONNECT + redirect config-realm re-derivation + log-only mutual-auth, SSH.NET SCP path injection through default double-quoting, oras-go `Link`-header SSRF + lexical symlink-chain tar slip; + folds: Grav Flex incomplete-fix RCE + watermark traversal, Skipper `truncated_body` fail-open, amqp091-go frame desync, Junrar mkdir escape (20 GHSAs)](alerts/2026-09-17-python-policy-sandbox-traversal-umbraco-reference-expansion-and-mariadb-local-infile-ghsa.md)

- [Request-derived identity, injected-guard composition, and a blind-SSRF status oracle: TinaCMS `isAuthorized` validates the token against the caller-supplied `clientID` app → any TinaCloud user authorizes against any self-hosted site (CVE-2026-63506); Vendure unverified-email external-login ATO + `filterOperator: OR` defeats the injected Shop API visibility guard + `innerHTML` fake-sanitizer stored XSS (CVE-2026-63472/63461/63459); Marten LINQ dictionary indexer **key** interpolated unescaped into SQL (CVE-2026-75513); Nuxt OG Image unauth SSRF whose outer 500/200 status is a blind-target oracle (CVE-2026-61793)](alerts/2026-09-17-request-derived-identity-vendure-guard-composition-and-blind-ssrf-oracle-ghsa.md)
- [FatPipe MPVPN/WARP/IPVPN EOL firmware 10.1.2r60p100 management-plane pair: unauthenticated `AuthFormServlet`→`xtremed` shell command injection + `/usr/sbin/auth_user_pass` stack overflow, both preauth root, interface disabled-by-default so exposure-state is the finding on unpatchable EOL trains (2 CVEs)](alerts/2026-09-17-fatpipe-eol-management-plane-preauth-root-rce-ghsa.md)
- [Validate-then-redirect SSRF and integration-identity squatting: Graylog allow-list not re-checked after redirects → internal fetch/return via owned redirector (CVE-2026-92789), Wiki.js Image Prefetch full-read SSRF from page-edit + tagless GraphQL resolvers + no-separator path-rule match (3 GHSAs), Trigger.dev GitHub App installation squatting by sequential ID + state replay (CVE-2026-92773), Rundeck archive import rewrites node executors/SSH key paths (CVE-2026-92763), Empire C2 multipart filename traversal, Coze Studio plugin-registration SSRF, decap-server sibling-prefix containment, OpenNHP evidence-selected attestation verifier; + folds: changedetection.io browser-step Goto SSRF, browserless websocket `file:` bypass, ComfyUI dataset-save folder_name write→initializer RCE, Feast JWT never signature-verified, Chroma tenant segments unvalidated to 1.5.9 (18 GHSAs)](alerts/2026-09-17-graylog-redirect-ssrf-wikijs-triggerdev-rundeck-empire-and-attestation-verifier-boundaries-ghsa.md)
- [Craft CMS wave: HMAC signatures bound to no purpose/parameter name → low-privilege signed-envelope transplant reaches unsandboxed Twig SSTI RCE (CVE-2026-92592/92593, one fix commit added its own signing oracle); GraphQL draftCreator/revisionCreator returns raw User elements below the user-data scope → unauthenticated editor PII on public schemas (CVE-2026-92594); DB-outage installer fail-open expands `${CRAFT_SECURITY_KEY}` via `App::env()` (CVE-2026-92591); read-only view grants reorder write flag (6 GHSAs)](alerts/2026-09-17-craft-cms-hmac-purpose-binding-ssti-graphql-field-auth-and-install-gate-ghsa.md)




































































## What lives here

- **Skills**: installable, tool-specific guides that agents can execute step by step
- **Recon**: workflows for turning scope into a prioritized asset map
- **Exploit Paths**: concrete attack chains that are specific enough to replay during authorized testing
- **Templates**: reusable report skeletons and delivery formats
- **Notes**: editorial guidance, taxonomy, and source tracking
- **Blog**: short updates when major skills or exploit paths land

Older alert and mitigation-oriented reference pages may remain in the repo, but the primary site surface is intentionally centered on pentesting, red-team, and bug-bounty operator workflows.

## How the skills are written

Each skill page is structured so it can be reused outside the wiki:

- When to use the tool
- Required inputs and prerequisites
- Command patterns worth reusing
- Expected outputs and what to capture
- Safety constraints and scope boundaries

!!! warning "Authorized use only"
    These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test.
