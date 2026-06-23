# BoxLite sandbox and Alist storage-boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: GitHub advisories [GHSA-g6ww-w5j2-r7x3](https://github.com/advisories/GHSA-g6ww-w5j2-r7x3), [GHSA-f396-4rp4-7v2j](https://github.com/advisories/GHSA-f396-4rp4-7v2j), [GHSA-x4q4-7phh-42j9](https://github.com/advisories/GHSA-x4q4-7phh-42j9), and [GHSA-8jmm-3xwx-w974](https://github.com/advisories/GHSA-8jmm-3xwx-w974).

This batch is durable because it gives operators reusable checks for sandbox and storage-control assumptions: a `read_only` mount flag that does not survive guest remount capabilities, OCI layer symlink extraction that can write outside an image root, multi-user file operations that trust filename components after directory authorization, and storage-driver TLS defaults that accept attacker-controlled endpoints.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-g6ww-w5j2-r7x3](https://github.com/advisories/GHSA-g6ww-w5j2-r7x3) | BoxLite virtiofs volume mounts | user-facing `read_only=True` volume policy was logged and mounted as read-only after VM start, but guest capabilities allowed remounting the shared directory read-write | Agent-sandbox reviews should verify the enforced mount state from inside the guest, not just the API option or host-side configuration. |
| [GHSA-f396-4rp4-7v2j](https://github.com/advisories/GHSA-f396-4rp4-7v2j) | BoxLite OCI layer extraction | layer symlink targets could be absolute or escaping paths, then later entries followed those symlinks during extraction | Sandbox image-ingestion tests should include symlink-chain and later-write canaries before trusting registry images as isolated filesystem roots. |
| [GHSA-x4q4-7phh-42j9](https://github.com/advisories/GHSA-x4q4-7phh-42j9) | Alist file-management APIs | authorized base directories were joined with attacker-controlled filename components containing traversal sequences | File-manager reviews should test every batch, rename, copy, move, and delete route where per-user base paths are validated separately from item names. |
| [GHSA-8jmm-3xwx-w974](https://github.com/advisories/GHSA-8jmm-3xwx-w974) | Alist outbound storage drivers | default storage-provider HTTP clients skipped TLS certificate verification | Storage-connector assessments should confirm whether server-to-provider clients preserve certificate validation and provider identity under DNS/redirect/certificate canaries. |

## Operator triage

1. **Inventory control surfaces.** Identify sandbox volume flags, OCI/image-pull paths, file-manager APIs, shared storage mounts, and outbound storage-provider clients reachable by lower-trust users or imported content.
2. **Compare declared policy to runtime behavior.** A UI/API setting such as `read_only`, a cleaned base directory, a verified image digest, or an HTTPS URL is not proof that the runtime enforces the same boundary.
3. **Use canaries, not secrets.** Keep evidence to disposable directories, marker files, owned registry layers, two-user lab storage mounts, and owned TLS endpoints. Do not read credentials, production files, model weights, notebooks, customer media, or other tenants' data.
4. **Prove both positive and negative controls.** Capture vulnerable behavior and patched or hardened behavior for the same mount flag, image layer, file-operation route, and outbound storage endpoint.

## Replayable validation boundaries

### BoxLite read-only mount enforcement

- Preconditions: isolated BoxLite lab, disposable host directory mounted into a test box as read-only, and no production credentials or source trees mounted.
- Place a marker file in the host directory and launch a container that attempts only a harmless remount decision check plus a write to a new marker path.
- Evidence should show the API-declared `read_only` setting, guest mount flags before and after the remount attempt, and whether the marker write reached the host directory.
- Stop at the marker write. Do not overwrite project files, package caches, shell startup files, SSH keys, cloud config, model files, or mounted secrets.
- Negative controls: drop remount-capable privileges, enforce read-only in the hypervisor/shared-filesystem layer, and validate the same attempt against the patched release.

### BoxLite OCI symlink extraction containment

- Preconditions: disposable BoxLite image cache/root, owned local registry or tar fixture, and a temporary out-of-root canary directory.
- Build a synthetic OCI layer that creates an in-root symlink whose target points only to the temporary canary directory, followed by a later entry that would write through that symlink.
- Positive evidence is an attempted or completed marker write outside the intended extraction root. Do not target `/etc`, home directories, Docker sockets, cron paths, SSH keys, or real application directories.
- Negative controls: reject absolute symlink targets, reject `..`-escaping relative targets, open paths with no-follow containment checks, and verify the final canonical write target remains under the extraction root.

### Alist file-operation traversal in shared mounts

- Preconditions: Alist lab with a shared storage mount, two disposable users, and synthetic files such as `/shared/alice/canary.txt` and `/shared/bob/do-not-touch-canary.txt`.
- As the lower-privilege user, exercise each permitted file route with traversal-like filename components while keeping the authorized `dir` parameter inside that user's base path.
- Cover single and batch variants: remove, copy, move, rename, batch rename, archive/extract helpers, and any route that joins `dir` plus caller-supplied names.
- Evidence should be a decision table: route, authenticated user, supplied `dir`, supplied name, canonical target, and whether the operation was blocked before touching another user's marker.
- Never delete or modify real user data. Use dry-run-style routes when available; otherwise operate only on disposable markers.

### Alist storage-driver TLS identity checks

- Preconditions: owned Alist lab, disposable storage-provider credentials or mock provider, and an owned TLS endpoint with a deliberately untrusted certificate.
- Configure or redirect only the lab storage provider hostname to the owned endpoint and trigger a harmless metadata/list operation.
- Positive evidence is whether the server attempts the connection despite certificate mismatch, plus redacted request metadata proving provider-client reachability. Do not capture real provider cookies, OAuth tokens, filenames, or file contents.
- Negative controls: default certificate verification on, custom CA bundles only when explicitly configured, host/SNI validation, redirect-target validation, and patched-release behavior.

## Reporting notes

- Lead with the crossed boundary: **sandbox read-only flag to writable host mount**, **OCI layer symlink target to host filesystem write**, **file-operation name to sibling-user storage target**, or **storage driver TLS default to attacker endpoint trust**.
- Include version, required role, exact route or API field, canonical path/mount evidence, and patched negative controls.
- Keep screenshots and logs boring: marker file paths, mount flags, canonicalized route decisions, and owned TLS callback records only.
