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
## October 8 follow-up: the same local chat UI, now a browser-reachable tool-execution surface (CVE-2026-107295 / [GHSA-h4xc-3qfq-jf93](https://github.com/advisories/GHSA-h4xc-3qfq-jf93) high, and CVE-2026-107292 / [GHSA-q2xc-rrxj-58x9](https://github.com/advisories/GHSA-q2xc-rrxj-58x9) medium)

Two more `Agent.to_web()` / `clai web` legs (fixed 1.107.4/2.28.0 and 1.107.5/2.30.0):

1. **No Content-Type check on the chat endpoint**: a website the developer visits POSTs to `http://localhost:<port>` (text/plain simple request — no preflight, no CORS needed), the agent runs, and **its tools execute with the local process's privileges and credentials**. `requires_approval=True` tools were *also* reachable because the endpoint **trusts approval decisions relayed by the client** — client-side approval UIs are not access controls. Fix: require `Content-Type: application/json` before parsing.
2. **No Host-header validation → DNS rebinding makes the local UI same-origin**: attacker name TTL=0 → loopback, browser treats `http://attacker-tld:port` as same-origin, Origin checks and any token in the served UI are defeated; Chromium's Local Network Access gates subresources but **not top-level navigations**, and Safari doesn't implement it. Fix: Host allow-list with `421 Misdirected Request`.

Durable rules (this is the same product's web-UI surface on its *third* advisory generation — same-product re-sweep again):

- **Local dev/agent UIs get the full browser-origin battery by default**: simple-content-type POST, DNS rebinding, Host decision table, top-level-navigation exceptions to LNA. Loopback binding proves nothing — the victim's browser is the attack path (July 8 browser-to-loopback family).
- **Approval/confirmation flows rendered in a local web UI must be re-authorized server-side**: any endpoint that accepts a client-relayed "user approved" decision has no approval gate at all. Grep: `approved`/`approval` fields in request models.
- Black-box probe on any local agent/dashboard port you find during desktop/loopback recon: POST a simple text/plain body and watch for state change; rebind a lab domain to 127.0.0.1 and check for `421`-style Host rejection vs same-origin reads.
