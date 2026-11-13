# 2026-02-05, FrankenPHP images: base-image security fixes may not propagate (GHSA-x9p2-77v6-6vhf)

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

## October 15 follow-up: worker-mode session-id leak that exists only in *packaged* builds, `#ifdef HAVE_PHP_SESSION` compiled the per-request reset out (CVE-2026-82416 / [GHSA-v3ph-cgqh-r8p5](https://github.com/advisories/GHSA-v3ph-cgqh-r8p5), high)

FrankenPHP's `frankenphp_reset_session_state()` releases `PS(id)` after each worker request so the next `session_start()` re-reads the request cookie. The whole function sits behind `#ifdef HAVE_PHP_SESSION`, defined only when session-extension headers were visible **at FrankenPHP compile time**, i.e. when `session` is statically linked into the PHP it built against. On any build where `session` is a shared module (RPM/Debian `php-zts` packages that ship `session` under `conf.d`), the macro is undefined, the reset is compiled out, `PS(id)` survives the request boundary, and `session_start()` skips the cookie lookup entirely (`try_find_session_id_in_cookies()` returns early when `PS(id)` is non-NULL). Result under concurrency in worker mode: request A's client receives request B's `session_id()`, cross-user session exposure plus the functional tell of intermittent random logouts.

The advisory's own field note is the operator lesson: "1.12.2 works / 1.12.3 leaks on the same host" was **two different package builds, not a source change**, the C reset code is identical across 1.11.x-1.12.x, and official static binaries/Docker images are unaffected.

Durable rules (build-provenance class, sibling of this page's stale-base-image axis):

- **Version numbers do not describe security posture when behavior is decided by build-time feature detection.** Any `#ifdef HAVE_X` around a security-relevant reset/clear/init call makes the *build recipe* part of the vulnerability. Fingerprint class: persistent-app-server / worker-pool / pre-fork runtimes that reuse process state across requests (FrankenPHP worker mode, PHP workers, mod_php, Tomcat/Undertow thread reuse, Node clusters). Grep the C for security resets guarded by feature macros, then check whether the guard's dependency is static or `conf.d`/dlopen-loaded in the deployed package.
- **Detect behaviorally, never by version.** Own-instance probe with two pre-created lab sessions and ≥2 workers: fire concurrent alternating-cookie requests and count responses where the server's reported `session_id()` differs from the cookie sent (the advisory's repro is a 20-line worker script + `xargs -P32`). Nonzero = affected build; zero on a static build is the control. Two targets on the same version can differ, record package/origin (distro package vs official static binary vs Docker image) alongside the result.
- **The functional symptom is a recon signal for a security defect**: users reporting random logouts / "sometimes I'm logged out" on a persistent-worker PHP host should raise a session-integrity probe, not a support ticket. Intermittent auth weirdness in state-reusing runtimes = check for cross-request state bleed first.

## November 13 follow-up: FrankenPHP coordinated wave, dot-form headers forge `$_SERVER` identity keys, `.php.txt/b.php` path-split executes uploads, and `putenv` leaks env across concurrent requests (9 GHSAs, < 1.13.x depending on leg)

FrankenPHP shipped ~9 GHSAs at 12:31Z; four legs carry durable operator value, five are worker-mode memory-safety DoS/UAF legs (2v43/128015, f45r/128016, cwwm/128017, xvmj/128018, 67qw/128019, 3wfj/128020, hm4x/128024, v6wj/128022, g6wj/128021) tracked without promotion per the parser-memory-safety precedent:

- **Dot-form header names rewrite into `$_SERVER` keys: unauthenticated identity spoofing** ([GHSA-prm4-w6g7-pw64 / CVE-2026-128023](https://github.com/advisories/GHSA-prm4-w6g7-pw64), critical, < 1.13.0): send `X.Authenticated.User: admin` or `X.Forwarded.For: 127.0.0.1` and PHP's header normalization maps them to `$_SERVER['HTTP_X_AUTHENTICATED_USER']` / `HTTP_X_FORWARDED_FOR`, spoofing app identity, client IP, or scheme with zero credentials. The header *name grammar* is the bypass: apps and intermediaries that match or strip `X-Authenticated-User` never see `X.Authenticated.User`. Standing battery extension for every PHP-behind-proxy target: for each trusted `$_SERVER` key the app reads, try dash, dot, mixed-case, and doubled-separator spellings, and diff what the edge filter sees vs what PHP populates. Sibling of the Sept 15 header-route and Nov 10 Rack `Forwarded`-vs-XFF preeminence families: header *grammar* decisions live in the parser, not the policy.
- **`/uploads/a.php.txt/b.php` executes `uploads/a.php`** ([GHSA-xwc7-ppx8-9c7r / CVE-2026-128025](https://github.com/advisories/GHSA-xwc7-ppx8-9c7r), medium, < 1.13.0): `splitPos` in cgi.go splits at the *first* `.php` substring inside any path component, so `.php` embedded in a filename defeats route-level/WAF deny rules and forges `PATH_INFO`, `SCRIPT_NAME`, and `PHP_SELF`. Same-product sibling of the May 15 Unicode CGI path-split leg (GHSA-3g8v-8r37-cgjm): the rule generalizes to *any substring-match split*, test `.php`, `.php.`, embedded-in-component, and non-ASCII spellings against every upload directory on a FrankenPHP target, then diff WAF verdict vs execution result.
- **`putenv()` writes the process-wide OS environment: cross-request secret leak** ([GHSA-3pr5-hpcj-9r5h / CVE-2026-128026](https://github.com/advisories/GHSA-3pr5-hpcj-9r5h), medium, 1.5.0-< 1.13.0): `putenv` calls `os.Setenv`, so values set by one request are visible to concurrent requests, and any request path that spawns children via `proc_open`/`exec` with the default environment hands the child *another tenant's* DB passwords. This is the Oct 15 session-id-bleed axis (per-request state should not survive the request) in the environment namespace. Probe shape on your own lab: request A sets an env-derived marker, request B on a different worker/connection reads it back through a child process (`proc_open('env')`); on engagements, fingerprint apps that call `putenv` per-request (framework cache config, per-site envs) as the bleed candidates.
- **Static binaries bundle the vulnerable Brotli 1.2.0 decoder; Docker images shipped stale base layers** ([GHSA-g5qv-p6x9-9wpv / CVE-2026-128014](https://github.com/advisories/GHSA-g5qv-p6x9-9wpv), critical, standalone binaries 1.8.0-< 1.13.2) re-pairs the Aug 3/Oct 27 Brotli OOBW (CVE-2026-111497) with this page's founding stale-base-image axis ([GHSA-vjcc-8rh5-xp2j / CVE-2026-128027](https://github.com/advisories/GHSA-vjcc-8rh5-xp2j), critical, Docker images < 1.1.11): the decoder bug reaches FrankenPHP through *two different supply-chain doors* (static link + unmoved base tags). Fingerprint rule from the Oct 27 shared-dependency-fanout page applies: `frankenphp`-br in a `Content-Encoding` header or a per-deployment build origin tells you which door an instance came in; version string alone does not.
- Validation boundary: lab FrankenPHP builds (official static binary + distro-package build + Docker, three origins = three security postures), owned WAF-equivalent intermediary for the mismatch tables, synthetic env markers; never forge identity headers against production apps beyond the in-scope authorization.
