# 2026-02-06 — Pydantic AI web UI: SSRF + CDN-path traversal → XSS (GHSAs)

GitHub advisories:

- SSRF in URL download handling: <https://github.com/advisories/GHSA-2jrp-274c-jhv3>
- Stored XSS via path traversal in web UI CDN URL: <https://github.com/advisories/GHSA-wjp5-868j-wqv7>

## Summary

Two high-impact issues were disclosed affecting **applications that expose Pydantic AI’s web UI / chat interface**:

- **SSRF**: if your app accepts **message history** (or “file” parts) from untrusted users, attacker-supplied URLs can cause your server to fetch internal resources (e.g., `127.0.0.1`, RFC1918, metadata services).
- **Client-side compromise (XSS)**: if the web UI can be influenced to load attacker-controlled HTML/JS (via a path traversal style URL construction), an attacker can execute code in the user’s browser context and steal **chat history** and other browser-accessible data.

## Who is at risk

You are in-scope if you:

- Use `Agent.to_web` / `clai web` (or similar) to serve a browser-based chat UI, and
- Allow untrusted users to submit message history or message “parts” that include URL references.

Higher risk when:

- The UI is exposed on a remote host (not just `localhost`).
- The server environment has access to cloud metadata endpoints or internal APIs.
- Chat history contains secrets (API keys, tokens, incident notes) that are retrievable client-side.

## Immediate actions

1. **Upgrade** to the fixed versions (preferred)
   - Apply upstream patches for both issues (see advisory “Fixed in” versions).
2. **Assume chat history may be sensitive**
   - Treat chat logs and localStorage as potential secret-bearing data.
3. **Constrain outbound fetches** (defense-in-depth)
   - Block access to:
     - `127.0.0.0/8`, `::1`, RFC1918 ranges, link-local, CGNAT, and other non-public ranges.
     - Cloud metadata endpoints (e.g., `169.254.169.254`) **always**.
   - Validate **every redirect target** and defend against DNS rebinding (resolve + verify).
4. **Do not accept arbitrary message history** without a sanitizer/processor
   - Strip or reject URL-based parts unless explicitly required.

## Detection / hunt

- Server logs: suspicious downloads to internal IPs, loopback, link-local, or unusual domains.
- Egress monitoring: HTTP(S) calls from the app to RFC1918 or metadata service ranges.
- Web access logs: unexpected query parameters to the chat UI endpoints; requests that look like crafted “version”/asset selectors.
- Client-side: reports of “weird UI behavior” or unexpected redirects; sudden loss/changes of chat state.

## Notes

Even if your UI is “intended to be local only”, many incidents start with an accidental exposure (tunnel, misconfigured reverse proxy, `0.0.0.0` bind). Treat “local web UIs” as potentially internet-reachable and harden accordingly.