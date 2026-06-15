# Jupyter, VM2, and token-type boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because all three clusters are recurring trust-boundary mistakes: URL/path prefix checks that are not canonical boundary checks, JavaScript sandbox escapes that rely on new language/runtime surfaces, and JWT validation that treats any trusted signature as sufficient proof of token purpose.

## Advisories covered

- **Jupyter Server <= 2.17.0** — fixed in **2.18.0**:
  - [GHSA-5789-5fc7-67v3](https://github.com/advisories/GHSA-5789-5fc7-67v3): authenticated path traversal via `startswith()` root-directory checks that can expose sibling directories sharing the same prefix.
  - [GHSA-24qx-w28j-9m6p](https://github.com/advisories/GHSA-24qx-w28j-9m6p): CORS origin bypass when `allow_origin_pat` is evaluated with `re.match()` instead of a full-string match.
  - [GHSA-5mrq-x3x5-8v8f](https://github.com/advisories/GHSA-5mrq-x3x5-8v8f): password reset and server restart do not revoke existing authentication cookies because the cookie secret remains persistent.
  - [GHSA-qh7q-6qm3-653w](https://github.com/advisories/GHSA-qh7q-6qm3-653w): open redirect through insufficiently validated `next` query parameter.
- **vm2 sandbox escapes**:
  - [GHSA-v37h-5mfm-c47c](https://github.com/advisories/GHSA-v37h-5mfm-c47c): inspect-function proxy unwrap breakout, fixed in **3.11.0** for `<= 3.10.3`.
  - [GHSA-qvjj-29qf-hp7p](https://github.com/advisories/GHSA-qvjj-29qf-hp7p): Promise species bypass of a prior sandbox fix, fixed in **3.10.5** for `<= 3.10.3`.
  - [GHSA-55hx-c926-fr95](https://github.com/advisories/GHSA-55hx-c926-fr95): `SuppressedError` escape on modern Node, fixed in **3.11.0** for `<= 3.10.4`.
  - [GHSA-ffh4-j6h5-pg66](https://github.com/advisories/GHSA-ffh4-j6h5-pg66): WASM exception-handling / `JSTag` escape on Node 25, fixed in **3.10.5** for `3.10.4`.
- **nuts-node <= 1.1.0** — [GHSA-9hmg-827w-9rhj](https://github.com/advisories/GHSA-9hmg-827w-9rhj): v1 access-token introspection accepts Verifiable Presentation JWTs as active access tokens because it validates a known signature without enforcing JWT type, issuer-to-key binding, and required access-token claims. No patched version was listed in the advisory at scan time.

## Operator triage

### Jupyter Server

1. Inventory exposed notebook/server instances and confirm `jupyter-server` version. Treat public, shared, or multi-tenant servers as priority targets.
2. Upgrade to **2.18.0+**.
3. After upgrade, rotate secrets by deleting/regenerating the Jupyter cookie secret on affected hosts and force active sessions to reauthenticate. A password reset alone was not enough for the cookie-secret issue.
4. Review configuration for `allow_origin_pat`; anchor patterns or convert them to exact-origin allowlists. Do not rely on prefix-like regex behavior.
5. Hunt for path traversal attempts against `/api/contents/` using encoded `..`, sibling directory names that share the configured root prefix, or checkpoint/create/delete calls outside expected notebooks.
6. Hunt for login URLs with external `next` targets such as protocol-relative URLs (`///host`) or lookalike domains.

### vm2

1. Treat any service that runs attacker-controlled JavaScript in vm2 as high risk, especially if it is reachable from tenants, users, CI jobs, templates, extensions, agents, or plugin systems.
2. Upgrade to a version containing the relevant fix; for mixed advisory coverage, prefer **3.11.0+** rather than stopping at a narrower **3.10.5** fix.
3. If untrusted code has run, assume possible host-process command execution. Preserve logs, rotate secrets reachable by the Node process, and rebuild worker hosts from clean images when exposure was internet-facing or multi-tenant.
4. Reduce blast radius even after patching: run sandbox workers in containers or microVMs, with no long-lived credentials, read-only filesystems where possible, egress allowlists, low privileges, and per-job teardown.
5. Add regression tests for new JavaScript/runtime surfaces: `SuppressedError`, `DisposableStack`, Promise species manipulation, `inspect`/custom inspection, WASM exception handling, and current Node release lines.

### nuts-node / JWT type confusion

1. Do not treat a trusted JWT signature as sufficient authorization. Verify token family/type, issuer-to-key binding, audience, subject semantics, expiry, and all purpose-specific claims before returning `active: true`.
2. For affected deployments, disable or restrict the v1 introspection endpoint until fixed, especially across trust domains where Verifiable Presentation JWTs may be attacker-controlled.
3. Hunt for introspection calls where the presented JWT resembles a Verifiable Presentation rather than an access token, including missing service/purpose claims or ambiguous `typ: JWT` headers.
4. Prefer explicit JOSE media types such as `vp+jwt` / `at+jwt` and reject ambiguous tokens at the boundary.

## Durable controls

- Replace string-prefix path containment with canonical path resolution plus boundary checks (`commonpath`/realpath-style logic), then test sibling-prefix cases (`root` vs `root2`).
- Prefer exact origin allowlists or full-string regex matching for browser security decisions. Prefix matches are not origin checks.
- Couple credential rotation with session-secret rotation. If the signing key remains valid, old cookies remain credentials.
- Do not depend on language-level JavaScript membranes as the only isolation boundary for hostile code. Runtime features evolve faster than proxy-based sandboxes.
- Model token validation as a typed protocol decision, not a crypto-only decision: every token class needs an allowlisted issuer, audience, type, and claim contract.

## Jupyter CORS origin-regex validation update

Updated: hourly offensive-security scan, 2026-06-15. GitHub updated [GHSA-24qx-w28j-9m6p / CVE-2026-40110](https://github.com/advisories/GHSA-24qx-w28j-9m6p) with a clear exploit precondition: Jupyter Server validates `allow_origin_pat` with Python `re.match()`, so an unanchored trusted-origin regex can match an attacker-controlled suffix origin. Upstream references include the [Jupyter Server advisory](https://github.com/jupyter-server/jupyter_server/security/advisories/GHSA-24qx-w28j-9m6p), [pull request 603](https://github.com/jupyter-server/jupyter_server/pull/603), and patch commits [`057869a`](https://github.com/jupyter-server/jupyter_server/commit/057869a327c46730afede3eab0ca2d2e3e74acea) and [`49b3439`](https://github.com/jupyter-server/jupyter_server/commit/49b34392feaa97735b3b777e3baf8f22f2a14ed8).

### Why this is operator-useful

This is a reusable **browser-origin trust-boundary** pattern: a server accepts a regex for trusted CORS origins, but evaluates it as a prefix match instead of a whole-origin match. A suffix domain such as `https://trusted.example.com.attacker-owned.test` can satisfy a pattern intended only for `https://trusted.example.com` when that pattern lacks explicit anchors.

### Safe validation workflow

1. **Confirm the path exists.** Test only deployments using `allow_origin_pat` or an equivalent regex-based CORS allowlist. Do not assume every Jupyter deployment is affected.
2. **Use an owned suffix origin.** Host the proof page on a canary domain controlled by the test team, for example `https://trusted.example.com.attacker-owned.test`.
3. **Baseline regex behavior locally.** Show the semantic mismatch without touching the target:

   ```python
   import re

   pattern = r"https://trusted\.example\.com"
   origins = [
       "https://trusted.example.com",
       "https://trusted.example.com.attacker-owned.test",
       "https://other.example.com",
   ]

   for origin in origins:
       print(origin, bool(re.match(pattern, origin)), bool(re.fullmatch(pattern, origin)))
   ```

4. **Exercise only a harmless endpoint.** From the canary origin, request an owner-approved status/version route with browser `fetch(..., { credentials: "include", mode: "cors" })`. The proof is the browser exposing a response or CORS header to the suffix origin, not access to notebooks or files.
5. **Add controls.** Compare the suffix origin with a clearly unrelated origin and, where possible, a lab configuration using anchored `^...$` matching.

### Evidence boundaries

- Capture version/package evidence, the redacted `allow_origin_pat` shape, the request `Origin`, and the CORS response header.
- Keep screenshots and HAR files limited to harmless status/version responses.
- Never collect notebooks, terminals, tokens, model files, datasets, environment variables, cloud credentials, or user content.
- Report the root cause as **prefix regex matching used for origin authorization**, not merely generic CORS misconfiguration.
