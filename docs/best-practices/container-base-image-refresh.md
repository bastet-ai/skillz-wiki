# Container base images: avoid “tag drift” and stale security fixes

Container incidents often aren’t “we used a vulnerable app version” — they’re “we shipped an image built on an old base layer even though upstream fixed it.”

This is common when a pipeline only rebuilds images when **your** repo changes, while upstream base images ship security fixes by **moving an existing tag** to a new digest.

## The core problem
- **Tags are mutable** (`alpine:3.21`, `python:3.12-slim`, etc.).
- Registries can (and do) publish security fixes under the *same* tag.
- If you don’t rebuild, you keep shipping the old vulnerable layers.

## Recommended approach (practical)
### 1) Use digest pinning in production
Pin the base image by digest for repeatability:

```Dockerfile
FROM alpine@sha256:<digest>
# or
FROM python@sha256:<digest>
```

Then update those digests intentionally (PR + review), rather than “whatever the tag is today.”

### 2) Still rebuild periodically
Even with digest pinning, you need a process to **refresh**:
- schedule a rebuild (daily/weekly),
- update pinned digests (or at least alert on changes),
- publish new artifacts.

### 3) Treat base-image digest change as a rebuild trigger
If you keep using tags (common in early-stage teams), at minimum:
- compare upstream digest vs what you last built,
- if it differs, rebuild and republish.

### 4) Force pulling fresh bases during builds
- CI: `docker build --pull ...`
- Local (when you expect freshness): `docker pull <base>:<tag>` before building

### 5) Make freshness visible
Add metadata so operators can tell if an image is stale:
- OCI labels (`org.opencontainers.image.created`, `revision`)
- SBOM publication
- release notes that include rebuild timestamps

## What to watch for (signals of trouble)
- “We used the latest tag” but SBOM/vuln scan still shows fixed CVEs.
- Your pipeline has **no scheduled builds**.
- Your build cache never invalidates base layers.

## References
- Example incident pattern: FrankenPHP advisory (GHSA-x9p2-77v6-6vhf)
