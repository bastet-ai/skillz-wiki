---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**ORM query-grammar injection + authorization-target fallback**: Mongoid cluster — caller-supplied **field names reflected into internal method invocation** (unauthenticated disclosure + record removal, CVSS 9.8/9.1), string criteria forwarded as **server-side JavaScript**, operators unrestricted from caller filters, nested-attributes IDOR, and CSFLE schema silently storing "encrypted" embedded-model fields in cleartext (6 GHSAs); OpenStack Blazar authz wrapper looks up its target under `lease_id` while the router delivers `id` → **falls back to the caller's own scope** → cross-tenant lease modify/delete, chained with the unscoped lease list that supplies the IDs; Cotonti `md5(microtime())` recovery tokens precomputable from the `Date` header → admin ATO + `unserialize()` without `allowed_classes`; Azkaban `fetchSchedule` sibling-action authz gap. Axes: **key-position injection, authz-target-name drift, read-bug-feeds-write-bug, clock-derived token scripts, per-action authz matrices**; + http-cache-semantics and LightLLM `/pd_register` folds (11 GHSAs + 2 folds)](alerts/2026-09-18-mongoid-orm-query-grammar-blazar-authz-fallback-and-cotonti-predictable-tokens-ghsa.md)

- [**Scope parameters that are accepted but never enforced**: kcp front-proxy **appends instead of replacing** `X-Remote-*` identity headers → any tenant asserts `system:masters` (CVSS 9.9); Convoy `FindSourceByID` takes the project ID and never uses it — SQL has no `project_id` predicate → cross-tenant **plaintext broker credentials** (no patch); Perses `?project=` query shadows the path-authorized project + list-query path traversal skips body-only validation + proxy decrypts Secrets outside your scope; Moquette Will-publish path skips `canWrite()`; Obot unauthenticated DCR + no consent + audience-ignored group-carrying token = one-click ATO-adjacent token theft. Sweep axes: **list-vs-get authz diff, query-shadows-path, read-vs-write validation asymmetry, method-to-action collapse, broker side-channels** (11 GHSAs + 2 folds)](alerts/2026-09-18-ignored-scope-parameters-kcp-identity-header-smuggling-convoy-perses-obot-ghsa.md)

- [**Semantic MediaWiki server-side boundary wave**: `api.php?action=smwtask` runs admin-only maintenance tasks unauthenticated (MediaWiki's anonymous CSRF token `+\` is fixed and public — a token check is not an authorization check); `Special:Ask` cursor = **unsigned base64url JSON** whose fields reflect into raw error HTML; `format=debug` echoes query/SQL/EXPLAIN unescaped; `FacetedSearch` gate is `crc32(q)` — compute and pass; `URIResolver` interwiki open redirect. Rule: test every alternate programmatic surface (API module, debug/raw output, pagination token, checksum gate) as its own trust boundary (8 GHSAs)](alerts/2026-09-18-semantic-mediawiki-unauth-api-tasks-unsigned-cursor-and-debug-sinks-ghsa.md)

- [**Media caption/subtitle tracks as a stored-XSS carrier** (Opencast Paella player): `innerHTML += cue` renders WebVTT/DFXP cue text as live DOM in every viewer's session — non-admin author → anonymous+staff execution on default config, caption file served raw via `/search/episode.json` (CVE-2026-77615); auxiliary-asset formats (captions/transcripts/chapters/playlists) are an input channel form fuzzers never touch; + Caddy replacer-layer fold onto the July 24 page: `rewrite` trailing-`?` placeholder double-expansion leaks `{env.*}`/`{file.*}` (the unextended `vars_regexp` gadget family, CVE-2026-77281) + case-sensitive `hide` matcher bypassed by `.GIT`/`.ENV` on case-insensitive filesystems](alerts/2026-09-18-opencast-caption-track-stored-xss-carrier-ghsa.md)

- [**Agent-built audit tooling for custom VMs and DSLs** (Trail of Bits Miden zkVM review): have agents build the missing LSP → subset decompiler/IR → abstract-interpretation passes → Lean formal model before hand-review on no-tooling bytecode targets; reusable vuln pattern — untrusted witness operands coupled only by a reconstruction equation (validated quotient + unvalidated remainder in `mod_12289`) let a malicious prover trade slack between fields and forge Falcon signatures; sweep every (length, checksum) / (offset, size) / advice-pair crossing a verify boundary](methodology/agent-built-audit-tooling-custom-vm.md)

- [WordPress core 7.1.1 security release: **unauthenticated stored XSS in `wpautop()`** on default installs (moderation off + previously-approved bypassable; CVE-2026-93485), XML-RPC `customize_changeset` publish bypassing `edit_css` (transport parity), HTML-API comment breakout, crafted-URL theme install/preview, contributor+ post overwrite/slug disclosure, private parent-title leak, any-user comment reparenting (11 core fixes); + Sept 18 plugin wave folded onto the July 28 page (Ai1wm export secret → import → admin, timestamp-derived tokens, PDF-renderer artifact SSRF)](alerts/2026-09-18-wordpress-core-7-1-1-parser-xmlrpc-and-object-scope-boundaries-ghsa.md)

- [Nextcloud app-layer authority drift: Circles fetches the attacker-supplied `keyId` URL **before** establishing trust and whitelists local/private addresses → unauthenticated blind SSRF past core protections (CVE-2026-77164); WebDAV locks resolve from the absolute URI with no owner check → cross-user locks + lock-token leak (CVE-2026-82980); Deck board-config skips ownership (CVE-2026-77170); Photos smart albums apply the **viewer's** folder scope to the owner's files (CVE-2026-82985); Approval etag check only fires when the client sends the etag (CVE-2026-82982); + yt-dlp-web-ui `params`→argv injection folded onto the Aug 5 page (7 GHSAs)](alerts/2026-09-18-nextcloud-app-layer-authority-drift-circles-keyid-ssrf-webdav-locks-and-deck-config-ghsa.md)

- [Extraction-before-verification and client-supplied proofs: Grafana extracts plugin archives **before signature verification** → chained relative symlinks escape the plugin dir, drop an executable backend binary, RCE as the server process — a valid signature doesn't help (CVE-2026-15815); SOGo password-reset links built from the client-supplied `Origin` header → token mailed to the victim pointing at attacker infra → ATO (CVE-2026-93453); Amelia customer endpoint has no ownership check → provider role resets any customer's WordPress password (CVE-2026-14311); Motors ajax leaks draft/private/future listings unauthenticated (CVE-2026-16750)](alerts/2026-09-18-grafana-extract-before-verify-sogo-origin-reset-and-client-supplied-proofs-ghsa.md)

- [User input as CLI argv / platform-structural sinks: MISP contact form forwards fields into CakePHP console **argv** where `ShellDispatcher` honors `-app`/`-webroot` path switches → `person=-app` + `message=phar://…` → bootstrap include of attacker archive = unauthenticated RCE; SAP `@sap/cds-mtxs` unauthenticated tenant-credential disclosure (CVE-2026-76969, critical); Verizon Cloud for Android exported share-activities unsanitized `_display_name` → arbitrary file write from co-resident apps; + MISP Overmind legend innerHTML stored XSS folded into Sept 7 page (4 GHSAs)](alerts/2026-09-17-misp-cakephp-argv-phar-rce-sap-cds-mtxs-tenant-credentials-and-android-exported-activity-file-write-ghsa.md)

- [Python/PHP policy-sandbox traversal + reference-expansion authz + client-side trust violations: RestrictedPython escape via `string.Formatter.get_field` internal traversal (never enters `safer_getattr`), Zope AccessControl `str.format`/`format_map` real-`getattr` disclosure with `str`-subclass mitigation miss, Umbraco Delivery API expands picker-referenced protected nodes with no access check (direct 401 vs expanded 200), MariaDB Connector/J ignores `allowLocalInfile=false` on server-initiated `0xfb`; late wave: Kestra unauth management port 8081 + Pebble `http()` pre-auth SSRF, AsyncHttpClient creds-on-plaintext-CONNECT + redirect config-realm re-derivation + log-only mutual-auth, SSH.NET SCP path injection through default double-quoting, oras-go `Link`-header SSRF + lexical symlink-chain tar slip; + folds: Grav Flex incomplete-fix RCE + watermark traversal, Skipper `truncated_body` fail-open, amqp091-go frame desync, Junrar mkdir escape (20 GHSAs)](alerts/2026-09-17-python-policy-sandbox-traversal-umbraco-reference-expansion-and-mariadb-local-infile-ghsa.md)





































































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
