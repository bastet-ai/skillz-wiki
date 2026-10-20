---
title: Canonicalization differentials at security gates
---

# Canonicalization differentials at security gates

A large share of "fixed but still bypassable" findings share one shape: a **security gate and the actual router disagree about which representation of the path is authoritative**. The gate tests one string, the router resolves another, and an attacker crafts input that passes one but is interpreted by the other.

The canonical example is [Mailpit GHSA-8r62-w5wh-fc5m / CVE-2026-67448](https://github.com/advisories/GHSA-8r62-w5wh-fc5m): a cross-site WebSocket hijacking fix was reimplemented as an origin check gated on a **raw-URI prefix test**, but Go's `ServeMux` routes on the **percent-decoded** path. Requesting `/%61pi/events` skips the origin gate (`strings.HasPrefix("/%61pi/events", "/api/")` is false) while the mux decodes `%61` → `a` and dispatches to `/api/events`. The upgrader's `CheckOrigin` returns `true`, so the browser upgrades to a cross-origin WebSocket with no credential or auth. The original CVE-2026-22689 was "fixed" by deleting `CheckOrigin`; the regression reintroduced it as `true` and moved the control into the bypassable raw-prefix test.

This is the same bug class as return-URL scheme bypasses and backslash open redirects, but pointed at **auth/origin/CORS gates** instead of redirect sinks. The reusable rule: a security decision and the eventual sink must operate on the **same normalized representation** that the downstream router/browser/fetcher will follow.

## Operator signal

Look for this pattern whenever you see a security control that:

- keys on the raw request target / `RequestURI` / `r.URL.RawPath` / `Host` header / SNI while the handler routes on a decoded, normalized, or differently-parsed value;
- runs a **prefix / substring / regex allowlist** on a path or URL before the router normalizes it;
- makes an origin/host/CORS decision in middleware but the actual socket, fetch, redirect, or upgrade applies a different check (or none);
- was patched by *moving* the control rather than *adding* it, especially a fix that swaps one representation for another.

High-signal gate surfaces to check for representational drift:

| Gate | Raw representation it tends to test | Router/browser representation it disagrees with |
| --- | --- | --- |
| Go `ServeMux` path-prefix origin/CSRF gate | `r.RequestURI` (wire target, percent-encoded) | `r.URL.Path` (decoded) |
| Host/`X-Forwarded-Host` trust decision | client `Host` | SNI, `:authority`, decoded path in the backend |
| Redirect / `Location` allowlist | pre-normalization string | browser URL parser (double-decode, `\`→`/`) |
| CORS / `CheckOrigin` on a WS/upgrade | middleware prefix test | upgrade handshake origin (often unenforced) |
| Signed-token / JTI / nonce scope check | string compare on a field | canonical decoded value the verifier later uses |

## Preconditions

- You have explicit permission to test the application or service.
- You can identify at least one security gate (origin, CSRF, CORS, host-trust, path allowlist, token scope) that guards an interesting sink (WebSocket/upgrade, API route, redirect, authenticated fetch, SSRF-adjacent proxy).
- You can observe the gate's decision (status code, response header, whether the upgrade/handshake succeeds) without needing to exfiltrate data or touch real users.

## Lab harness (safe, replayable)

Set up a local instance of the target so you can produce a **control pair** — one request the gate should block and one that should bypass it. For Mailpit, the advisory's own proof is a loopback binary plus a tiny SMTP/WebSocket client:

```bash
# Loopback lab instance, no UI auth (the pre-condition the advisory used).
./mailpit --disable-version-check \
  --database ./mailpit-lab.db \
  --listen 127.0.0.1:8025 \
  --smtp 127.0.0.1:1025 \
  --max-message-size 50
```

```python
#!/usr/bin/env python3
# Control pair: same cross-origin Origin, plain vs percent-encoded target.
import socket, urllib.request

def ws_upgrader(target):
    req = urllib.request.Request(
        f"http://127.0.0.1:8025{target}",
        headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": "https://evil.example",  # cross-origin, should be gated
        },
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status  # 403 = gated, 101 = bypass

print("plain     /api/events ->", ws_upgrader("/api/events"))
print("encoded   /%61pi/events ->", ws_upgrader("/%61pi/events"))
```

Positive result: plain path returns `403` while the percent-encoded path returns `101 Switching Protocols`. Keep this control pair in every report — it is the entire proof. Do **not** exfiltrate mail content; proving the cross-origin socket opens is enough.

## Validation workflow

1. **Locate the gate and the router.** Find where the security decision is made (middleware, `CheckOrigin`, header trust, path allowlist) and where the actual routing/normalization happens. Note which representation each uses.
2. **Produce the control pair.** One input the gate should block, one that changes only the representation while keeping the decoded/normalized value identical. Record both status codes / handshake outcomes.
3. **Enumerate the representation space** for the specific sink:
   - percent-encoding of path segments (`%61` → `a`, `%2F` → `/`)
   - overlong / double-decoded forms (`%252F`, `//` collapse)
   - backslash vs forward-slash on Windows-ish or Go-ish routers
   - mixed-case scheme/segment where only one side normalizes case
   - userinfo / `@` / trailing dot / trailing `%00` where the parser and the gate differ
   - `Host` / SNI / `:authority` / `X-Forwarded-Host` divergence
4. **Confirm the sink is reachable** through the bypassed representation (upgrade succeeds, API returns the guarded resource, redirect resolves off-origin).
5. **Scope the impact** to the actual user context: cross-origin socket, cross-origin credentialed fetch, off-origin redirect, or scope confusion in a token. Label any inference; separate the bypass from any secondary data-exfil claim.
6. **Capture version provenance.** Record the exact version/build where the bypass holds and the first patched version that keys the gate on the router's representation.

## Related examples in this class

- **Concourse** post-login redirect via `redirect_uri` double-decode: `/%252F` → `//` after the router normalizes — see [return-URL scheme-bypass testing](return-url-scheme-bypass-testing.md).
- **Gogs** `redirect_to` backslash smuggling: `/a/../\\example.com` passes a leading-slash same-site check, browser normalizes `\`→`/` → off-origin.
- **CakePHP Authentication** backslash normalization before slash conversion, bypassing a "local target only" check.
- **Puma** PROXY-protocol v1 source-IP trust when a trusted edge keeps `Host`/SNI and origin disagree.
- **Apache Shiro Jakarta EE** trusting client-controlled `Referer` as the post-login return target.
- **Reverse::Proxy** (GHSA-5xq5-hx4g-f5v6 / CVE-2026-75922): routing decision and upstream serializer disagree on encoded versus decoded `PATH_INFO`, turning `%0d%0a` in the client target into a CRLF in the proxy's self-serialized request line — the same representational drift pointed at a **request-framing sink** rather than a gate. See the "Decoded `PATH_INFO` framing at serialized upstream request lines" section of the [HTTP desync research campaigns](http-desync-research-campaigns.md) page.
- **Echo (Go web framework)** `%2F` static-file differential: the router matches routes on the raw encoded path (`req.URL.RawPath`, preserving `%2F`), so `/admin%2Fsecret.txt` is a single segment that does **not** match the protected `/admin/*` route, while `StaticDirectoryHandler` calls `url.PathUnescape()` before resolving the filesystem path and converts `%2F` → `/`, reading `admin/secret.txt` on disk. A security gate (route-level auth) and the file sink disagree on which representation of the path is authoritative. See [GHSA-vfp3-v2gw-7wfq / CVE-2026-55677](https://github.com/advisories/GHSA-vfp3-v2gw-7wfq).
- **Hono `serveStatic` double-decode** (GHSA-5r4p-p66f-jhc7 / CVE-2026-111757, fixed 4.13.11): Hono decodes the request path once before routing; `serveStatic` decodes it **again** before resolving the file. A malformed percent-encoded sequence (e.g. `%25`-prefixed or invalid escape that survives the first decode still encoded) makes the router match the encoded form — so middleware mounted on the static prefix, such as an auth check, never runs — while the second decode inside the handler resolves the real file. The file stays inside the configured root (no traversal); the bypass is purely **gate-skipping on a route-vs-handler decode-count mismatch**. Operator fingerprint: on any framework where a static-file handler is mounted under middleware, send one request with a double-encoded segment (`%2561` where `%61`/`a` is expected) and compare whether prefix middleware fires (cookie set, redirect, log line) against whether the file body is served — mismatch = auth-less read of protected static assets. Same-wave Angular SSR siblings on this class: `@angular/platform-server` protocol-relative open redirect where the `startsWith('//')` guard runs **before** WHATWG dot-segment normalization (`/.;/(//evil.test)` → `Location: //evil.test` 302; GHSA-w739-gvwx-grc3 / CVE-2026-111754, fixed 22.2.1/21.2.25/20.3.33) — grep app-side return-URL guards for checks on the pre-normalization raw string, and probe `;`-parameter and `/.//` shapes when the edge proxy passes semicolons/dot-segments through; plus `@angular/router` unconfigured empty-path outlet-group recursion SSR heap DoS (`/shop/(a:/()//b:/()//...)` re-instantiates ActivatedRouteSnapshot trees per outlet; GHSA-62vg-58rm-qff7 / CVE-2026-111752, fixed 22.2.1) — outlet-segment grammar is attacker-controlled input to SSR route matchers, worth a low-rate single-request probe on any Node SSR target.

## What to report

- The gate and the router, and which representation each uses
- The exact input form that bypasses the gate while still reaching the sink
- The control pair (block vs bypass) with status codes / handshake results
- The affected version/build and the first patched version
- Impact scoped to the real user context
- Minimal proof (a benign marker or upgrade result), no real-user targeting, no exfiltration

## Heuristics that catch weak fixes

Flag fixes that only change the representation the gate tests instead of making the gate and router agree:

```text
strings.HasPrefix(r.RequestURI, webroot+"api/")      // raw wire target, not decoded
r.URL.RawPath != "" && allow(prefix(RawPath))        // RawPath vs Path
if host := r.Host; allowlist[host]                  // Host vs SNI vs :authority
allow = strings.HasPrefix(loc, "/")                  // no //, backslash, or double-decode reject
CheckOrigin: return true                              // control moved out, not added
```

Useful regression inputs (keep to lab / owned hosts only):

```text
/%61pi/events          # %61 = 'a'
/%2561pi/events        # double-encoded
/\\example.invalid/x   # backslash router collapse
//example.invalid/x    # protocol-relative collapse
/%2f%2fexample.invalid # encoded slash collapse
JaVaScRiPt:alert(1)    # mixed-case scheme
```

## Safe boundaries

- Keep testing in lab instances or explicitly authorized systems; use `example.invalid` / owned hosts.
- Prove the gate bypass with a control pair and a benign marker; do not exfiltrate, target real users, or read real mail/data.
- Do not send crafted upgrade/redirect links to other users.
- Stop at proof of the representational differential unless the engagement explicitly permits deeper impact.

## Sources

- [GitHub Advisory Database: Mailpit GHSA-8r62-w5wh-fc5m / CVE-2026-67448](https://github.com/advisories/GHSA-8r62-w5wh-fc5m) — WebSocket origin check bypass via percent-encoded path (regression of CVE-2026-22689)
- [GitHub Advisory Database: Mailpit GHSA-r553-m4fv-5v97 / CVE-2026-67447](https://github.com/advisories/GHSA-r553-m4fv-5v97) — SMTP DATA line buffered before size enforcement (availability-only; reviewed, not promoted)
- [GitHub Advisory Database: gettext-converter GHSA-f4jp-rw7w-ccwg / CVE-2026-55451](https://github.com/advisories/GHSA-f4jp-rw7w-ccwg) — prototype pollution in `js2i18next()` (app-dependent; reviewed, not promoted)
- [Return URL scheme-bypass testing](return-url-scheme-bypass-testing.md) — same representational-drift class pointed at redirect sinks
- Mailpit advisories: https://github.com/axllent/mailpit/security/advisories
