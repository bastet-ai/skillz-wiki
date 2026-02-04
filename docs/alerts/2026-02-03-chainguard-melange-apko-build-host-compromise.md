---
title: "Chainguard melange/apko: build-host compromise primitives (command injection, path traversal, resource exhaustion)"
date: 2026-02-03
---

# 2026-02-03 — Chainguard melange/apko: build-host compromise primitives

Multiple Go-based supply-chain/build tools used in container/image build pipelines received security advisories that matter **most** in CI, build-as-a-service, and PR-driven automation.

These issues are especially relevant when:

- untrusted contributors can influence build inputs (PRs, forks, user-submitted recipes), or
- build jobs process third-party artifacts/repositories.

## What happened (high level)

### melange (chainguard.dev/melange)
Several advisories describe **shell command injection** and **path traversal** paths in parts of the build pipeline and related features (e.g., patch pipeline inputs, workspace retrieval, license file collection).

**Why it matters:** if an attacker can influence recipe inputs (filenames, paths, config fields) that get embedded into a shell script without robust quoting/validation, they can often execute arbitrary commands on the build host.

### apko (chainguard-dev/apko)
Advisories include **path traversal** in filesystem abstractions (risking writes outside an intended base directory) and **resource exhaustion** when expanding attacker-controlled package streams.

**Why it matters:** CI builders commonly run with powerful filesystem access and secrets; path traversal + symlink tricks can turn “write in workspace” into “write anywhere the runner can write”. Resource exhaustion can be a cheap DoS against shared runners.

## Affected / fixed versions (as reported in GHSA)

- **melange:** fixed in **0.40.3** (multiple advisories reference this release)
- **apko:** fixed in **1.1.0** (multiple advisories reference this release)

If you’re using these tools, **upgrade** and ensure your builders are pulling patched versions.

## Defensive guidance (durable)

### 1) Treat build config and patch inputs as untrusted
If PR authors can change:

- melange configs (including “license-path” / patch series paths / pipeline inputs)
- patch filenames or patch content
- any value that may reach a shell script

…assume an attacker can attempt command injection.

**Controls:**

- Require review/approval before running builds that execute untrusted recipes.
- Prefer running untrusted builds in a **sandbox/VM** with no persistent credentials.
- Don’t allow arbitrary shell steps in “untrusted” build tiers.

### 2) Sandbox the build host (so a build compromise stays contained)
A good baseline for untrusted builds:

- ephemeral runner (throw away after job)
- no long-lived cloud credentials in environment
- read-only mounts where possible
- limited outbound network (or proxy/allowlist)
- separate secrets contexts for trusted vs untrusted jobs

### 3) Defend against path traversal + symlink escapes
Even with patches, keep guardrails:

- Always resolve/normalize paths and enforce “must stay within workspace” checks.
- Treat extracted archives and package contents as hostile.
- Consider running extraction/build steps in a dedicated filesystem namespace/container.

(See also: **Best Practices → Archive Extraction: Symlink + Path Traversal**.)

### 4) Put hard limits on decompression and artifact expansion
Resource-exhaustion issues are a recurring class:

- enforce maximum uncompressed bytes
- enforce maximum file count / recursion depth
- apply timeouts and CPU/memory limits in CI

### 5) Detection: log and alert on “weird build behavior”
If you run build-as-a-service:

- alert on unexpected network egress from builders
- alert on writes outside workspace paths
- alert on unusually large temporary directories / cache growth

## References

- melange GHSA (command injection / path traversal family):
  - https://github.com/advisories/GHSA-rf4g-89h5-crcr
  - https://github.com/advisories/GHSA-2w4f-9fgg-q2v9
  - https://github.com/advisories/GHSA-qxx2-7h4c-83f4
  - https://github.com/advisories/GHSA-vqqr-rmpc-hhg2
- apko GHSA (path traversal / resource exhaustion family):
  - https://github.com/advisories/GHSA-5g94-c2wx-8pxw
  - https://github.com/advisories/GHSA-6p9p-q6wh-9j89
  - https://github.com/advisories/GHSA-f4w5-5xv9-85f6
