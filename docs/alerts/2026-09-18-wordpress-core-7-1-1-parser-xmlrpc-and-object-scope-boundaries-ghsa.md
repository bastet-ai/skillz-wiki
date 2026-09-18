---
title: WordPress core 7.1.1 — anonymous stored XSS in wpautop(), XML-RPC capability bypass, theme-install-by-URL, and core object-scope drift
---

# WordPress core 7.1.1 — anonymous stored XSS in wpautop(), XML-RPC capability bypass, theme-install-by-URL, and core object-scope drift

A WordPress **core** security release (7.1.1, shipped September 17, 2026, backported to 7.0.4/6.9.7/6.8.8 and every train back to 4.7) carries eleven security fixes that are directly operator-relevant, and the headline one reproduces **unauthenticated on a default installation**: a stored XSS in `wpautop()` reachable through the comment flow, where comment moderation is disabled by default and the "commenter must have a previously approved comment" requirement is itself bypassable. The first GitHub record for this cluster landed as [GHSA-2pgq-4jch-68j8 / CVE-2026-93485](https://github.com/advisories/GHSA-2pgq-4jch-68j8) (CVSS 7.1, scope changed) at 06:31Z September 18; the remaining fixes are named in the release post but had no individual GHSA records at scan time.

Sources:

- [GHSA-2pgq-4jch-68j8 / CVE-2026-93485 — WordPress core unauthenticated stored XSS](https://github.com/advisories/GHSA-2pgq-4jch-68j8)
- [Patchstack entry for CVE-2026-93485 (credits, timeline, unauthenticated privilege)](https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-7-1-cross-site-scripting-xss-vulnerability?_s_id=cve)
- [WordPress 7.1.1 maintenance and security release post (full credited fix list)](https://wordpress.org/news/2026/09/wordpress-7-1-1-maintenance-and-security-release/)
- [WordPress 7.1.1 HelpHub security updates page](https://wordpress.org/documentation/wordpress-version/version-7-1-1/)

!!! warning "Authorized validation only"
    Reproduce only on disposable WordPress installations you control, with synthetic commenters and pages. Use inert DOM markers, never script payloads that exfiltrate, persist, or pivot. Never publish a working comment-XSS vector against a live site, never install themes on a target you do not own, and never read another site's private drafts, slugs, or post content. Version-fingerprinting a customer-owned target is fine inside scope; exploitation is not.

## Why this wave matters more than a routine core update

1. **Anonymous stored XSS on a default install is a supply-chain-scale surface.** WordPress core is the delivery platform for a huge fraction of the web, and a comment-flow stored XSS needs no plugin, no login, and no admin interaction beyond normal site defaults. Any engagement that touches WordPress should test 7.1.0-and-below comment rendering as a first-class anonymous attack path, separate from plugin findings.
2. **Three fixes describe the same parser-boundary class.** `wpautop()` injecting script and the HTML API's `set_modifiable_text()` allowing "breaking out of a comment via abrupt-closing sequences" are tokenizer/serialization differentials — the same failure shape as the Grav `detectXss()` tokenizer gap and the Plate parse-before-sanitize item: code that rewrites HTML text (autop, sanitizers, modifiable-text editors) can emit byte sequences a downstream parser re-tokenizes differently than the writer intended.
3. **One fix is a transport-parity failure.** XML-RPC could publish `customize_changeset` posts bypassing the `edit_css` check — the capability decision lived in one transport's code path, not at the storage boundary. This is the core-level version of the REST-vs-DAV-vs-OCS verdict table from the Nextcloud page: enumerate every transport that writes the same object and diff their authorization decisions.
4. **Object-scope drift reached core itself.** Contributor+ arbitrary post overwrite, contributor draft/pending slug disclosure, a private parent-post title leaking through attachment metadata, and any authenticated user reparenting comments are the IDOR/authorization axes this wiki tracks for plugins, now confirmed in core.

## Fix inventory and the durable axis each one gives

| # | Fix (as credited in the release post) | Reported by | Durable operator axis |
| --- | --- | --- | --- |
| 1 | Stored XSS in `wpautop()`, unauthenticated visitor, subject to comment approval | Rafie Muhammad (Awesome Motive) | Text-rewriting filters as XSS boundaries; default-config comment flow is an anonymous stored-content channel |
| 2 | HTML API `set_modifiable_text()` breaks out of a comment via abrupt-closing sequences | WordPress Security Team | Writer/parser re-tokenization differential in HTML APIs; abrupt-closing sequences (`</x>`, unbalanced quotes) as the probe family |
| 3 | Stored XSS in some themes supporting custom headers | WordPress Security Team | Theme-controlled header image metadata reaching frontend render without escaping — theme, not just plugin, is an attack surface |
| 4 | Crafted URL automatically installs and previews an inactive theme from WordPress.org | Paulos Yibelo, pwn.ai | URL-triggered state-changing side effects (silent install/preview); inactive-theme surfaces activated by request |
| 5 | Site Administrator can network-activate an installed Network-only plugin | Jesse McNeil | Network vs site authority drift in multisite |
| 6 | Authenticated path traversal in WP REST Templates Controller | Anthropic | Low-role file-boundary on a core REST route; template-controller path handling |
| 7 | XML-RPC publishes `customize_changeset` posts bypassing `edit_css` checks | WordPress Security Team | Alternate-transport authorization parity (same write, different gate) |
| 8 | Contributor+ arbitrary post overwrite | Anthropic | Core-level per-object authorization drift |
| 9 | `attachment_submitbox_metadata()` missing `read_post` leaks private parent-post title | HDWSec | Sub-resource metadata route skipping the parent's read check — the Deck board-config pattern in core |
| 10 | Missing authorization → draft/pending post slug disclosure by Contributor+ | hermanhms | Non-public status-state enumeration via alternate routes (same fuzz rule as the Motors admin-ajax item: request non-public `status`/`post_status` values explicitly) |
| 11 | Any authenticated user can reparent comments (incl. notes) | viridis | Object-graph mutation without ownership — moving another object's child changes whose context displays it |

Treat table rows 1 and 7–11 as the high-value set for a WordPress target; rows 2–6 are conditional on theme/multisite/HTML-API usage.

## Anonymous comment-flow stored XSS: validation workflow

The GHSA record states the reproduction conditions but not the payload mechanics: stored XSS in `wpautop()`, unauthenticated, reproducible on a **default** install because comment moderation is off by default, and the previously-approved-commenter requirement can be bypassed. Do not reconstruct or reuse a live payload; validate the *boundary*, not an exploit.

1. **Fingerprint first.** Confirm core version from `/` (generator meta, RSS, `/feed/`, `wp-includes/version.php` assets with cache-busting), then check whether the site has updated past 7.1.1 (or the train-matched fix: 7.0.4, 6.9.7, 6.8.8, …). The whole class is version-gated; plugin-style fuzzing is secondary to the version diff.
2. **Lab reproduction on a disposable install.** Install 7.1.0 (or the matching older train), leave defaults on, and post a comment containing only an inert structural canary — a uniquely-marked sequence that exercises the same tokenizer boundary (e.g. an abruptly-closed tag or unbalanced quote inside otherwise-benign text). Record four states separately: raw submitted bytes, comment HTML as stored (`comment_content` in the DB), the post-`wpautop()` rendered HTML, and the browser DOM. The finding class exists when stored bytes or rendered bytes gain structure the writer never emitted.
3. **Config matrix.** Repeat with moderation on/off, "must be previously approved" on/off, and a logged-in control, on both vulnerable and fixed builds. The GHSA explicitly says the approval-gating requirement is bypassable — so moderation state is a *precondition to measure*, never evidence that the vector is closed.
4. **Fixed-build control.** On 7.1.1, the same structural canary must be stored and rendered inert (escaped or rejected) at all three stages. Keep marker hashes, not payloads, in notes.

Bounded positive: **anonymous comment with inert structural canary on default-config 7.1.0 lab -> rendered DOM contains structure the input did not author** (with a harmless counter proving execution reachability, if execution matters). Reporting on a real target should stop at version evidence plus lab reproduction; do not plant comments on a customer site unless the engagement authorizes stored-content proofs, and never with executable payloads.

## Alternate-transport parity: XML-RPC and every other writer

Fix #7 means a caller without `edit_css` could complete the write through `xmlrpc.php`. Generalize into a standing probe for any WordPress engagement (and any platform with multiple write paths):

1. Enumerate transports that reach one object type: wp-admin UI, REST (`/wp-json/wp/v2/...`), XML-RPC (`wp/xmlrpc.php`, `system.multicall`), `admin-post.php`/`admin-ajax.php` handlers, and plugin routes. The WordPress-specific rule from the July 28 page — treat the wp-admin namespace and standalone plugin PHP files as public — still applies; now re-apply it across transports for **core** post types.
2. With two disposable accounts (one holding the named capability, one not), map a decision table per transport: capability present/absent × transport × target post status (publish/draft/pending/private). A finding is any cell where the unauthorized caller reaches the storage sink the authorized path reaches.
3. For `customize_changeset`-style meta post types specifically, inventory *all* core post types that are "machinery" rather than content (`customize_changeset`, `nav_menu_item`, `revision`, `wp_block`, plugin/theme-managed types) — capability checks around these are historically transport-local.
4. Confirm against fixed builds that the capability decision moved to the storage boundary (rejects on every transport), not just the UI path.

Prove with reversible synthetic posts in a lab; never publish machinery posts on a target to "test the gate."

## Core object-scope drift: the low-role IDOR sweep

Rows 8–11 all describe the same test you already run against plugins, now worth running against core routes themselves because contributors (a very grantable role on editorial sites) reach arbitrary objects:

- **Overwrite:** contributor edits a post they do not own through every content-write path; watch for a handler that checks `edit_posts` globally but never `edit_post` on the target ID.
- **Slug/status disclosure:** request `?status=draft,pending,private,future` and slug fields from contributor and subscriber contexts; presence-only (ID + slug + status), never content extraction, on a real target.
- **Sub-resource parent check:** attach a synthetic image to a private lab post, then read the attachment's metabox metadata (`attachment_submitbox_metadata()`-backed routes) from a caller without `read_post` on the parent. The positive is the parent title reaching the response.
- **Comment reparenting:** as user B, submit a comment-reparent request changing a comment's `comment_parent`/post association to objects owned by A; the positive is a persisted parent change, not a 200.

On a real engagement, run these only in a lab against the same core version and report as version evidence; per-object writes against a customer's real posts are out of bounds without explicit authorization.

## Theme install/preview by crafted URL

Fix #4 is a state-changing side effect triggered purely by a URL: a specially crafted link caused WordPress to install and preview an inactive theme from WordPress.org. Two operator notes:

1. **Passive recon:** if you encounter legacy links or click-through telemetry referencing `?preview-theme=theme/slug`-style parameters, the site may have accepted preview/install flows from the request. On your own lab, verify whether an unauthenticated (or subscriber) URL still mutates installed-theme state on old trains; stop at `wp-content/themes/` directory-creation evidence.
2. **Surface activation:** previewing an inactive theme renders its templates against live content. When a theme is known-vulnerable, request-level preview parameters are a route to render code paths that are installed-but-inactive on the target. Test only on disposable sites with themes you control.

## Adjacent plugin records from the same wave (folded or processed)

The September 18 06:31Z WPScan-derived plugin wave is folded into the [July 28 WordPress boundary page](2026-07-28-wordpress-payment-device-boundaries-ghsa.md): the All-in-One WP Migration export-capability-discloses-installation-secret -> import -> admin chain (extends the delegated import/export and Ai1wm sections), Easy Appointments' hardcoded-salt-plus-timestamp mail-link token (predictable-proof entropy, sibling of the Fluent Forms receipt-hash check), Generate PDF for Contact Form 7's renderer-side image fetch returning internal responses through the generated PDF (SSRF with an artifact response channel), VikBooking's unauthenticated live-chat attachment storing active content for the admin viewer, and Filter Gallery's nonce-verified-only-when-present handlers (the parameter-ABSENT axis). Routine object-scope, unauthenticated-SQLi, and stored-XSS singles from the same wave (Bookit, MasterStudy LMS, King Addons for Elementor, Tz Weekly Radio Schedule, Price Drop Alert, Product Q&A, wp shortcut link, RestroPress, Easy Form Builder, UpsellWP, iGMS, All Bootstrap Blocks, RT Mega Menu, Biggop, AF Companion) reuse axes already covered and are marked processed without publication. ManageEngine DataSecurity Plus agent-authentication bypass and technician-role Reports SQLi (CVE-2026-18911/18912) are single-product, credential-gated items — tracked, not published.

## Reporting notes

- State the exact core version and train (7.1.1 / 7.0.4 / 6.9.7 / …) — every finding here is version-gated, and the plugin-style "fuzz everything" pattern adds noise.
- Keep the four stages separate for parser findings: submitted bytes, stored bytes, filter-rendered bytes, DOM. "Comment accepted" ≠ XSS; "structure appears in rendered HTML" ≠ execution.
- Attribute the XML-RPC fix as authorization-parity drift, not "XML-RPC RCE." The write was legitimate; the gate was missing on one transport.
- For multisite engagements, re-test row 5 (Network-only plugin activation) per-network: site-admin to network-effect is a scope jump that needs its own decision table.
- The credited fix list is the authoritative inventory until individual CVEs publish; the first GHSA covered only the `wpautop()` XSS. Track the remaining CVE IDs as records land before citing numbers per fix.
