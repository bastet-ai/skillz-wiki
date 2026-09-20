---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Grammar-desync pair (Sept 20)**: **Exim SMTP smuggling** where the delivered message depends on bytes sent **after a DATA-phase rejection** — matches no transaction sent; test via three-way sent-pre/sent-retry/delivered diff on an owned MTA (CVE-2026-94057). **Expat UTF-16 lone high surrogates consume the following code unit**, hiding `<`/`>`/`&` from one decoder while another assembles markup → XXE batteries must include invalid surrogate sequences on UTF-16 XML inputs (CVE-2026-93990). Rule: buffer/decoder state surviving its kill-boundary. + folds: Argo **NotEquals** field selector dropping cluster-scoped review, Mistral Vibe **`post-checkout` hooks before trust validation**, Exim PROXY-parser memory safety](alerts/2026-09-20-exim-smtp-rejection-smuggling-and-expat-surrogate-markup-hiding-ghsa.md)

- [**JS sandbox-validator + async-render escape wave**: OpenPanel webhook-template validator misses **computed member access to constructor chains** → project-write becomes worker-process RCE (9.9, CVE-2026-93985) — after any template/expression-sandbox fix, enumerate every language alias reaching the same power; ClickHouse **filter-key** SQLi = project-isolation bypass (keys not parameterized); hono/jsx `< 4.13.7` plain strings **unescaped on async composition paths** (`Suspense`/`ErrorBoundary`/`Context.Provider`/`renderToReadableStream`) — escaping is a property of the render path, not the framework (5 GHSAs)](alerts/2026-09-19-js-sandbox-validator-constructor-chain-and-async-render-escape-ghsa.md)

- [**WordPress alternate-surface authorization drift wave (09:32Z)**: unauthenticated REST routes with **no permission_callback** (Botiga Pro arbitrary-options write + site-wide stored scripts; Master Blocks → admin-session stored XSS in wp-admin; MgoSync leaks read/write WooCommerce API keys); delegated plugin permission ≠ implied core capability — WP Import Export Lite import **creates admins / overwrites credentials**; UsersWP social login resolves accounts by **asserted email without provider ownership confirmation** → ATO; AI booking-assistant conversation IDs unowned → read **and inject into** another visitor's live AI conversation; `current_user_can` **int-cast vs string-sink differential**; nonce-only + `eval()` Subscriber RCE with public nonce-mint JS asset; predictable-path arbitrary-extension upload → `.phar` RCE **only where the target's Apache handler maps it** (17 GHSAs)](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md)

- [**WordPress protective-transform-inverted wave**: PDFCrowd Save-as-PDF — server **AES-encrypts an attacker-chosen `pdf_created_callback`** from shortcode attributes, anonymous AJAX endpoint decrypts and **invokes it as a PHP callable** (8.8, encryption ≠ sanitization); Gravity Forms 9.8 — **hidden File Upload fields skip extension validation** yet the persist leg still calls `upload_file()` on the rejected upload state → unauthenticated arbitrary upload; WP Recipe Maker 9.1 + Forminator 9.1 — **`do_shortcode()` runs on untrusted comment/action input before `strip_shortcodes()`**, JSON-LD `reviewBody` is the disclosure channel; Better Messages — privileged "AI bot" identity **prefix-matched from the client-controlled `X-Real-IP`** short-circuits room authz. Axes: **encrypt-then-dispatch field semantics, validate-leg ≠ persist-leg, sanitize-after-execute ordering, header-derived internal principals**; + Divi Essential conditional-nonce full-DB read and WPPA+ `escapeshellcmd()` argument-injection folds (5 GHSAs + 2 folds)](alerts/2026-09-19-wordpress-shortcode-execution-hidden-field-upload-and-encrypted-blob-dispatch-ghsa.md)

- [**ORM query-grammar injection + authorization-target fallback**: Mongoid cluster — caller-supplied **field names reflected into internal method invocation** (unauthenticated disclosure + record removal, CVSS 9.8/9.1), string criteria forwarded as **server-side JavaScript**, operators unrestricted from caller filters, nested-attributes IDOR, and CSFLE schema silently storing "encrypted" embedded-model fields in cleartext (6 GHSAs); OpenStack Blazar authz wrapper looks up its target under `lease_id` while the router delivers `id` → **falls back to the caller's own scope** → cross-tenant lease modify/delete, chained with the unscoped lease list that supplies the IDs; Cotonti `md5(microtime())` recovery tokens precomputable from the `Date` header → admin ATO + `unserialize()` without `allowed_classes`; Azkaban `fetchSchedule` sibling-action authz gap. Axes: **key-position injection, authz-target-name drift, read-bug-feeds-write-bug, clock-derived token scripts, per-action authz matrices**; + http-cache-semantics and LightLLM `/pd_register` folds (11 GHSAs + 2 folds)](alerts/2026-09-18-mongoid-orm-query-grammar-blazar-authz-fallback-and-cotonti-predictable-tokens-ghsa.md)

- [**Scope parameters that are accepted but never enforced**: kcp front-proxy **appends instead of replacing** `X-Remote-*` identity headers → any tenant asserts `system:masters` (CVSS 9.9); Convoy `FindSourceByID` takes the project ID and never uses it — SQL has no `project_id` predicate → cross-tenant **plaintext broker credentials** (no patch); Perses `?project=` query shadows the path-authorized project + list-query path traversal skips body-only validation + proxy decrypts Secrets outside your scope; Moquette Will-publish path skips `canWrite()`; Obot unauthenticated DCR + no consent + audience-ignored group-carrying token = one-click ATO-adjacent token theft. Sweep axes: **list-vs-get authz diff, query-shadows-path, read-vs-write validation asymmetry, method-to-action collapse, broker side-channels** (11 GHSAs + 2 folds)](alerts/2026-09-18-ignored-scope-parameters-kcp-identity-header-smuggling-convoy-perses-obot-ghsa.md)

- [**Semantic MediaWiki server-side boundary wave**: `api.php?action=smwtask` runs admin-only maintenance tasks unauthenticated (MediaWiki's anonymous CSRF token `+\` is fixed and public — a token check is not an authorization check); `Special:Ask` cursor = **unsigned base64url JSON** whose fields reflect into raw error HTML; `format=debug` echoes query/SQL/EXPLAIN unescaped; `FacetedSearch` gate is `crc32(q)` — compute and pass; `URIResolver` interwiki open redirect. Rule: test every alternate programmatic surface (API module, debug/raw output, pagination token, checksum gate) as its own trust boundary (8 GHSAs)](alerts/2026-09-18-semantic-mediawiki-unauth-api-tasks-unsigned-cursor-and-debug-sinks-ghsa.md)

- [**Media caption/subtitle tracks as a stored-XSS carrier** (Opencast Paella player): `innerHTML += cue` renders WebVTT/DFXP cue text as live DOM in every viewer's session — non-admin author → anonymous+staff execution on default config, caption file served raw via `/search/episode.json` (CVE-2026-77615); auxiliary-asset formats (captions/transcripts/chapters/playlists) are an input channel form fuzzers never touch; + Caddy replacer-layer fold onto the July 24 page: `rewrite` trailing-`?` placeholder double-expansion leaks `{env.*}`/`{file.*}` (the unextended `vars_regexp` gadget family, CVE-2026-77281) + case-sensitive `hide` matcher bypassed by `.GIT`/`.ENV` on case-insensitive filesystems](alerts/2026-09-18-opencast-caption-track-stored-xss-carrier-ghsa.md)

- [**Agent-built audit tooling for custom VMs and DSLs** (Trail of Bits Miden zkVM review): have agents build the missing LSP → subset decompiler/IR → abstract-interpretation passes → Lean formal model before hand-review on no-tooling bytecode targets; reusable vuln pattern — untrusted witness operands coupled only by a reconstruction equation (validated quotient + unvalidated remainder in `mod_12289`) let a malicious prover trade slack between fields and forge Falcon signatures; sweep every (length, checksum) / (offset, size) / advice-pair crossing a verify boundary](methodology/agent-built-audit-tooling-custom-vm.md)

- [WordPress core 7.1.1 security release: **unauthenticated stored XSS in `wpautop()`** on default installs (moderation off + previously-approved bypassable; CVE-2026-93485), XML-RPC `customize_changeset` publish bypassing `edit_css` (transport parity), HTML-API comment breakout, crafted-URL theme install/preview, contributor+ post overwrite/slug disclosure, private parent-title leak, any-user comment reparenting (11 core fixes); + Sept 18 plugin wave folded onto the July 28 page (Ai1wm export secret → import → admin, timestamp-derived tokens, PDF-renderer artifact SSRF)](alerts/2026-09-18-wordpress-core-7-1-1-parser-xmlrpc-and-object-scope-boundaries-ghsa.md)








































































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
