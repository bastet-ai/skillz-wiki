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
