# beets web UI stored XSS via raw metadata template interpolation (GHSA-3gxm-wfjx-m847)

**Signal:** GitHub Security Advisory published **2026-04-29**. beets rendered attacker-controlled media metadata into its bundled web UI with raw template interpolation and DOM insertion.

## What it is
The beets web plugin displayed metadata fields such as titles, lyrics, and comments through Underscore templates using raw interpolation, then inserted rendered output with `.html(...)`. A malicious audio file or metadata source can store HTML/JavaScript in fields that later execute when a victim opens the web UI.

Affected package:

- PyPI: `beets`
- Vulnerable range: `< 2.10.0`
- Advisory CVE: `CVE-2026-42052`

References:

- GitHub advisory: <https://github.com/advisories/GHSA-3gxm-wfjx-m847>

## Triage
1. Search for deployments of `beetsplug.web` or the beets web UI, especially on shared servers and home-lab hosts exposed beyond localhost.
2. Identify workflows that ingest untrusted music files, scraped metadata, lyrics, comments, or tags from external libraries.
3. Check whether the web UI is reachable by privileged users or shares an origin with other sensitive services.
4. Review any reverse-proxy authentication; stored XSS can still act as the logged-in viewer inside the protected origin.

## Mitigation
- Upgrade beets to `2.10.0` or later.
- Keep the beets web UI bound to localhost or behind strong authentication; do not expose it directly to untrusted networks.
- Sanitize or strip rich metadata from untrusted files before library import where practical.
- Avoid raw template interpolation for user-controlled metadata; use escaped output and text-safe DOM APIs.
- Serve hobby/admin media tools from isolated origins so UI compromise cannot reach broader admin cookies or panels.

## Detection ideas
- Search imported metadata for HTML tags, event handlers, `<script>`, SVG payloads, and `javascript:` URLs in `title`, `lyrics`, `comments`, and similar fields.
- Review web UI access logs for sessions that viewed recently imported suspicious media.
- If exposed, inspect browser-side reports, CSP violations, or unexpected requests from the beets UI origin.

## Durable lesson
Media metadata is untrusted input. Admin and hobby web UIs need the same output encoding discipline as public applications, especially when they render fields collected from files or third-party metadata providers.
