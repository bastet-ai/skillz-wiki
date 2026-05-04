# Runtime package and build execution-boundary batch (GHSA)

**Signal:** GitHub Security Advisories surfaced a **2026-05-04** batch where package parsing, build inputs, archive/crawl configuration, Git options, and radio/media app parameters crossed from data into code or filesystem authority.

## Advisories in this batch

- **protobufjs arbitrary code execution** — `protobufjs >= 8.0.0, < 8.0.1` and `< 7.5.5` can execute attacker-controlled code during protobuf handling. Fixed in 8.0.1 and 7.5.5. Reference: <https://github.com/advisories/GHSA-xq3m-2v4x-88gg>, CVE-2026-41242.
- **GitPython option command injection** — `GitPython < 3.1.47` has command-injection paths where option validation happens before shell-style splitting, plus related Git option bypasses. References: <https://github.com/advisories/GHSA-x2qx-6953-8485>, <https://github.com/advisories/GHSA-rpm5-65cw-6hj4>, CVE-2026-42284, CVE-2026-42215.
- **ArchiveBox per-crawl config RCE** — `archivebox <= 0.8.6rc0` allowed unvalidated per-crawl config overrides in AddView to reach code execution. Reference: <https://github.com/advisories/GHSA-3h23-7824-pj8r>, CVE-2026-42601.
- **apko build-root/package trust issues** — `apko < 1.2.7` failed to verify downloaded apk packages against APKINDEX checksums; `apko >= 0.14.8, < 1.2.5` followed symlinks outside dirFS build roots; `DiscoverKeys` could panic on non-RSA JWKS keys. References: <https://github.com/advisories/GHSA-hcwr-pq9g-rq3m>, <https://github.com/advisories/GHSA-qq3r-w4hj-gjp6>, <https://github.com/advisories/GHSA-m7hm-vm4x-28jf>, CVE-2026-42575, CVE-2026-42574, CVE-2026-42576.
- **AzuraCast execution and media-boundary flaws** — `azuracast/azuracast <= 0.23.5` had Liquidsoap code injection through remote relay password migration gaps and path traversal in `currentDirectory` enabling RCE via media upload. Fixed in 0.23.6. References: <https://github.com/advisories/GHSA-q4ph-8x8g-95f8>, <https://github.com/advisories/GHSA-vp2f-cqqp-478j>, CVE-2026-42605.

## Why this is durable

These are different surfaces with the same failure mode: trusted runtimes accepted attacker-shaped strings, files, symlinks, package metadata, or configuration and later interpreted them with stronger authority.

## Immediate triage

1. Patch protobufjs, GitPython, apko, and AzuraCast to fixed versions; isolate ArchiveBox AddView exposure until an upstream fix or compensating gate exists.
2. Rebuild images produced by affected apko versions where repository compromise, untrusted mirrors, or writable build contexts were possible.
3. Treat ArchiveBox crawl submissions, AzuraCast media uploads, remote relay passwords, and GitPython multi-option inputs as suspicious if exposed to non-admin users.
4. Rotate secrets on hosts where package/build/archive inputs could have reached command execution.

## Hunt ideas

- Search CI logs for GitPython calls with user-controlled `multi_options`, embedded spaces, shell metacharacters, or split-sensitive quoting.
- Review apko build contexts for symlinks, hard links, unexpected device files, or package downloads whose digest only matched repository metadata.
- Inspect ArchiveBox access logs for AddView requests carrying config override keys, downloader settings, or shell-like payloads.
- Review AzuraCast station logs for unusual media upload paths, `../`, encoded separators, and Liquidsoap syntax in relay password fields.

## Durable controls

- Split and normalize command options before validation, then pass them as argv arrays rather than shell strings.
- Verify downloaded packages against immutable digest metadata and pin repository trust roots.
- Open build-root files with no-follow semantics and enforce canonical path containment at every file operation.
- Keep per-request configuration overrides on a strict allowlist with types, ranges, and no command/runtime keys.

## Operator lesson

If an input can change how a tool builds, crawls, parses, uploads, or shells out, it is not metadata. Treat it as code until proven otherwise.
