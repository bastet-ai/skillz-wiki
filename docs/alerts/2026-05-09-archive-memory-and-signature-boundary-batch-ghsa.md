# Archive, memory, and signature-boundary batch

**Signal:** The **2026-05-09 00:15 UTC** scan added boundary failures in archive extraction, safe Rust capacity math, certificate-signature validation, and unauthenticated session storage.

## Advisory cluster

- **SharpCompress directory traversal in `WriteToDirectory()`** — [GHSA-6c8g-7p36-r338](https://github.com/advisories/GHSA-6c8g-7p36-r338) / CVE-2026-44788: directory entries bypassed the file-entry full-path guard; TAR symlink handling could escalate to arbitrary file writes when callers supplied a naive `SymbolicLinkHandler`. `SharpCompress <0.48.0` is affected; use **0.48.0+** as the fixed control.
- **smallbitvec safe-API heap buffer overflow** — [GHSA-97wc-2hqc-cjgr](https://github.com/advisories/GHSA-97wc-2hqc-cjgr) / CVE-2026-44983: unchecked capacity arithmetic could wrap, allocate too small, and let safe APIs reach unsafe out-of-bounds internals. `smallbitvec 1.0.1 through 2.6.0` were affected; no patched version was listed at scan time.
- **epa4all-client VAU signature bypass** — [GHSA-g8r3-5hwf-qp96](https://github.com/advisories/GHSA-g8r3-5hwf-qp96) / CVE-2026-44900: ECDSA verification discarded the boolean result from `Signature.verify()`, returning trusted after chain/OCSP setup even when the signature did not match. Patch to **1.2.1+**.
- **OpenStack Horizon pre-auth session-storage exhaustion** — [GHSA-vxvf-xvm3-p8j5](https://github.com/advisories/GHSA-vxvf-xvm3-p8j5) / CVE-2026-43002: Horizon **25.6 through <25.7.3** wrote to the session backend before authentication, regressing a CVE-2014-8124-style unauthenticated storage exhaustion issue. Patch to **25.7.3+**.

## Why this matters

These are all “check the result, not the shape” failures: paths that look nested but resolve outside the root, integer calculations that look safe until they wrap, certificate workflows that do everything except consume the verification result, and auth flows that create server-side state before proving identity.

## Triage

1. Patch `epa4all-client` and Horizon immediately where deployed; pin or isolate `SharpCompress` and `smallbitvec` until fixed versions are available.
2. For archive extraction, reject absolute paths, `..` components, and symlink targets that resolve outside the extraction root before creating directories, links, or files.
3. Review Rust dependencies that expose “safe” collection APIs backed by unsafe internals; add fuzz cases near `usize::MAX`, huge reserves, and capacity growth boundaries.
4. Add tests that assert cryptographic verification methods fail when `Signature.verify()` returns false; chain validation is not a substitute for signature validation.
5. Rate-limit and quota pre-auth Horizon endpoints, and monitor session backend write volume by unauthenticated source.

## Durable controls

- Normalize and bound every archive entry type, not just regular files; directory and symlink fast paths need the same guard as file extraction.
- Use checked arithmetic for capacity calculations and reject allocations whose rounded-up storage length overflows.
- Make cryptographic wrappers return only after both policy checks and primitive verification results are explicitly true.
- Keep authentication before persistence: unauthenticated requests should not create unbounded server-side state.

## July 21 SharpCompress fixed-version validation update

The updated advisory now identifies 0.48.0 as the fixed release and supports a bounded extractor test. Build local ZIP/TAR fixtures containing normal, `..`, and rooted **directory** entries, then extract into a temporary root. Capture archive format, entry type/name, extraction root, resolved path, created marker directories, exception, and package version. Test regular file entries separately to show where the pre-existing full-path guard already applies.

Only in a disposable TAR harness, enable a deliberately permissive `SymbolicLinkHandler` that points to a sibling canary directory and attempt to write one benign marker through that synthetic link. Compare no handler, a handler that enforces root containment, ZIP, TAR, and SharpCompress 0.48.0. Report **directory entry skips the regular-file path guard -> directory appears outside the temporary extraction root** separately from **TAR plus caller-supplied symlink handler -> marker-only file write**. Do not call the ZIP case arbitrary file write, and never target shell, service, cron, home, credential, or application paths.
