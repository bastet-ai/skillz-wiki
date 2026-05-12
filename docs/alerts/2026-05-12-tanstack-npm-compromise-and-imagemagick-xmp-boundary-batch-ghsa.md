# TanStack npm compromise and ImageMagick XMP boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-12 00:15 UTC.

These advisories are durable because they hit two places defenders routinely underestimate: package install is code execution, and image metadata parsing is attacker-controlled input parsing. The TanStack compromise is the high-priority item: trusted-publisher identity did not mean the published artifact was trustworthy after a `pull_request_target`/cache-poisoning/OIDC-token extraction chain. The ImageMagick item is lower-severity but reinforces that metadata profiles should be treated like active parser input, especially in upload and thumbnail services.

## Advisories covered

- **Malware in `@tanstack/*` packages exfiltrates cloud credentials, GitHub tokens, npm tokens, Vault tokens, Kubernetes service-account tokens, and SSH keys** — [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx), CVE-2026-45321 (Critical): 84 malicious versions across 42 npm `@tanstack/*` packages were published on 2026-05-11 between roughly 19:20 and 19:26 UTC. Clean follow-up releases are listed in the advisory; affected versions should be treated as credential-theft malware.
- **ImageMagick / Magick.NET: invalid XMP profile heap-use-after-free crash while printing metadata values** — [GHSA-r83h-crwp-3vm7](https://github.com/advisories/GHSA-r83h-crwp-3vm7), CVE-2026-40311 (Medium): NuGet `Magick.NET-*` packages < 14.12.0; fixed in `14.12.0`. Upstream ImageMagick fixed in 7.1.2-19.

## TanStack compromise triage

1. Search dependency manifests, lockfiles, SBOMs, and package-manager cache for `@tanstack/*` installs that resolved during or after **2026-05-11 19:20-19:30 UTC**. Include developer laptops, CI runners, build containers, and release automation.
2. Treat any host that ran `npm install`, `pnpm install`, or `yarn install` against an affected version as compromised. Rotate every secret reachable by that install process: cloud credentials, GitHub tokens, npm tokens, SSH keys, Vault tokens, Kubernetes service-account tokens, and CI signing/deploy credentials.
3. Inspect packages without executing lifecycle scripts. Prefer `npm pack @tanstack/<name>@<version>` plus archive inspection over install. The malicious manifest included an `optionalDependencies` entry for `@tanstack/setup` pointing at `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`; payloads included an obfuscated `router_init.js` at the tarball root.
4. Delete `node_modules`, package-manager caches, and lockfiles that may have resolved malicious versions, then reinstall pinned patched versions from a clean environment. Temporarily use `ignore-scripts=true` in CI where feasible until the dependency graph is proven clean.
5. Review egress logs for Session/Oxen messenger infrastructure (`filev2.getsession.org`, `seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`) and audit npm publish events for packages maintained by affected identities.

## ImageMagick / Magick.NET triage

1. Upgrade Magick.NET packages to **14.12.0+** and native ImageMagick to **7.1.2-19+** where used directly.
2. Prioritize systems that parse user-supplied images, print metadata, generate previews, or run thumbnail workers over untrusted uploads.
3. Keep media parsing in a low-privilege worker with no cloud metadata access, no deployment secrets, no internal network reachability, and tight CPU/memory/time limits.
4. Strip or normalize EXIF/XMP/IPTC metadata before storing or forwarding user-uploaded images unless retention is explicitly required.

## Durable controls

- Trusted publishing proves who requested a publish, not that the artifact is benign. Release pipelines still need fork/base isolation, cache namespace separation, short-lived token scoping, and artifact attestation that ties the published tarball to reviewed source.
- `pull_request_target` workflows should never run attacker-controlled code, restore attacker-controlled caches, or mint publish-capable OIDC tokens in the same trust boundary.
- Package install is code execution. High-value CI should install with minimal credentials, no long-lived cloud tokens, no SSH private keys, and egress policies that make secret exfiltration noisy.
- Optional dependencies and git URL dependencies deserve supply-chain review because failed optional installs can hide traces while still executing lifecycle scripts.
- Media metadata is parser input. Treat XMP/EXIF/IPTC parsing like archive extraction or document rendering: isolate it, patch it, budget it, and do not run it beside secrets.

## Related Wisdom

- [Git scanner, attestation, and build-boundary batch](2026-05-11-git-scanner-attestation-and-build-boundary-batch-ghsa.md)
- [Provenance, signature, and sphere-boundary batch](2026-05-08-provenance-signature-and-sphere-boundary-batch-ghsa.md)
- [Parser, model, signature, and crypto-boundary batch](2026-05-08-parser-model-signature-and-crypto-boundary-batch-ghsa.md)
- [FacturaScripts upload, render, and install-boundary batch](2026-05-07-facturascripts-upload-render-install-boundary-batch-ghsa.md)
