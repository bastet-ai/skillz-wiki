# File, project, and local-viewer boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced file/project boundary issues updated on **2026-05-06** across Hugo, Magic Wormhole, and OpenClaw.

## Advisories covered

- **Hugo Node tool execution can access files outside the project** — [GHSA-x597-9fr4-5857](https://github.com/advisories/GHSA-x597-9fr4-5857): project-driven Node tooling crossed the expected project directory boundary. Fixed in `github.com/gohugoio/hugo` 0.161.0.
- **Magic Wormhole receive path traversal** — [GHSA-cf92-gfcw-6v53](https://github.com/advisories/GHSA-cf92-gfcw-6v53): `receive --output` targeting an existing directory could be path-traversed in 0.23.0. Fixed in 0.24.0.
- **OpenClaw diffs viewer loopback misclassification** — [GHSA-3xv9-89fm-7h4r](https://github.com/advisories/GHSA-3xv9-89fm-7h4r): proxied remote requests could be treated as loopback when `allowRemoteViewer` was disabled. Fixed in 2026.3.31.

## Why this is durable

Local tools often assume “project file,” “received file,” or “loopback viewer” means safe. The attacker-controlled part is the path, proxy chain, project config, symlink, or generated helper process that decides what local resource is actually touched.

## Immediate triage

1. Patch Hugo to **0.161.0+**, Magic Wormhole to **0.24.0+**, and OpenClaw to **2026.3.31+** where deployed.
2. Inventory build/docs sites that run project-supplied Node tools or package hooks.
3. For file-transfer inboxes, inspect recent receives for filenames containing separators, Unicode confusables, dot segments, or symlink interactions.
4. For local viewers, verify access-control decisions use the trusted socket peer, not forwarded/proxied address headers.
5. Add regression tests that attempt traversal through archive names, transfer names, project config, symlinks, redirects, and proxy headers.

## Durable controls

- Treat project configuration as code execution unless sandboxed with a minimal filesystem view.
- Use openat-style path resolution and post-open containment checks for receive/extract/write flows.
- Separate local-only developer surfaces from remotely reachable routes at the listener, not only in middleware.
- Ignore `X-Forwarded-*` and similar headers for local/remote security decisions unless inserted by a trusted reverse proxy.
