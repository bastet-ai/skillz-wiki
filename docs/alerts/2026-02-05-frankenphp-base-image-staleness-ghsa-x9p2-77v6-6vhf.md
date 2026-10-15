# 2026-02-05 — FrankenPHP images: base-image security fixes may not propagate (GHSA-x9p2-77v6-6vhf)

**Source:** https://github.com/advisories/GHSA-x9p2-77v6-6vhf  
**Published:** 2026-02-05  
**Type:** Supply-chain / deployment hygiene (stale container base layers)

## What happened
FrankenPHP’s published container images were historically built only when **version tags** changed or when builds were manually triggered.

That means if an upstream base image (e.g., **Alpine**, **official PHP**, **official Go**) shipped a security fix by **moving an existing tag** to a new digest, FrankenPHP images could remain on **older vulnerable base layers**, even when users pulled what they believed was the “latest” for a given FrankenPHP tag.

## Why this matters (durable guidance)
This is a recurring failure mode across container ecosystems:

- **Tags are not immutable.** Many upstream images publish security fixes by **reusing the same tag name**.
- If your pipeline rebuilds only on *your* repo tags (or only on Git changes), you can silently ship **known-vulnerable OS/libs**.
- The fix is process-level: treat **base image digest changes** as a rebuild trigger.

## What to do (defensive actions)
### If you consume third-party images
- Prefer **digest pinning** for production (while having an intentional upgrade process):
  - `FROM alpine@sha256:...` instead of `FROM alpine:3.21`
- Add a job that periodically:
  - pulls the base tag,
  - checks if its digest changed,
  - rebuilds and republishes.
- In CI builds, use `docker build --pull ...` so you don’t build on stale local cache.

### If you publish your own images
- Implement a **scheduled rebuild** (daily/weekly) even if no code changes.
- Monitor base-image digests (or use tooling that does this for you).
- Surface a **“rebuilt at”** label/annotation (or SBOM) so consumers can tell when an image is fresh.

## References
- GitHub Advisory: https://github.com/advisories/GHSA-x9p2-77v6-6vhf
- Related best practice: /best-practices/container-base-image-refresh.md

## October 15 follow-up: worker-mode session-id leak that exists only in *packaged* builds — `#ifdef HAVE_PHP_SESSION` compiled the per-request reset out (CVE-2026-82416 / [GHSA-v3ph-cgqh-r8p5](https://github.com/advisories/GHSA-v3ph-cgqh-r8p5), high)

FrankenPHP's `frankenphp_reset_session_state()` releases `PS(id)` after each worker request so the next `session_start()` re-reads the request cookie. The whole function sits behind `#ifdef HAVE_PHP_SESSION`, defined only when session-extension headers were visible **at FrankenPHP compile time** — i.e. when `session` is statically linked into the PHP it built against. On any build where `session` is a shared module (RPM/Debian `php-zts` packages that ship `session` under `conf.d`), the macro is undefined, the reset is compiled out, `PS(id)` survives the request boundary, and `session_start()` skips the cookie lookup entirely (`try_find_session_id_in_cookies()` returns early when `PS(id)` is non-NULL). Result under concurrency in worker mode: request A's client receives request B's `session_id()` — cross-user session exposure plus the functional tell of intermittent random logouts.

The advisory's own field note is the operator lesson: "1.12.2 works / 1.12.3 leaks on the same host" was **two different package builds, not a source change** — the C reset code is identical across 1.11.x–1.12.x, and official static binaries/Docker images are unaffected.

Durable rules (build-provenance class, sibling of this page's stale-base-image axis):

- **Version numbers do not describe security posture when behavior is decided by build-time feature detection.** Any `#ifdef HAVE_X` around a security-relevant reset/clear/init call makes the *build recipe* part of the vulnerability. Fingerprint class: persistent-app-server / worker-pool / pre-fork runtimes that reuse process state across requests (FrankenPHP worker mode, PHP workers, mod_php, Tomcat/Undertow thread reuse, Node clusters). Grep the C for security resets guarded by feature macros, then check whether the guard's dependency is static or `conf.d`/dlopen-loaded in the deployed package.
- **Detect behaviorally, never by version.** Own-instance probe with two pre-created lab sessions and ≥2 workers: fire concurrent alternating-cookie requests and count responses where the server's reported `session_id()` differs from the cookie sent (the advisory's repro is a 20-line worker script + `xargs -P32`). Nonzero = affected build; zero on a static build is the control. Two targets on the same version can differ — record package/origin (distro package vs official static binary vs Docker image) alongside the result.
- **The functional symptom is a recon signal for a security defect**: users reporting random logouts / "sometimes I'm logged out" on a persistent-worker PHP host should raise a session-integrity probe, not a support ticket. Intermittent auth weirdness in state-reusing runtimes = check for cross-request state bleed first.
