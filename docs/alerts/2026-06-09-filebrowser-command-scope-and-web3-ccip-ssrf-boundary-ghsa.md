# File Browser command-scope and web3.py CCIP SSRF boundaries

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-hc8f-m8g5-8362](https://github.com/advisories/GHSA-hc8f-m8g5-8362) / CVE-2025-52904 and [GHSA-5hr4-253g-cpx2](https://github.com/advisories/GHSA-5hr4-253g-cpx2) / CVE-2026-40072.

This batch is durable because both items expose reusable offensive validation patterns: feature-granted command execution that ignores an application's file-scope boundary, and smart-contract-controlled HTTP fetches that turn default-on blockchain lookup behavior into a backend SSRF primitive.

## What changed

- **File Browser command execution escapes user scope** — File Browser before `2.33.8` can grant users `Execute Commands`. Shell commands run as subprocesses of the File Browser server process and are not restricted to the user's configured file scope. The advisory notes that command execution is disabled by default from `2.33.8` onward and requires an administrator to re-enable the dangerous feature.
- **web3.py CCIP Read SSRF** — web3.py `6.0.0b3` through `< 7.15.0` and `8.0.0b1` enable CCIP Read by default. A malicious contract can return `OffchainLookup` URLs that cause backend `.call()` flows to make HTTP requests to attacker-chosen destinations, including redirect chains and private networks if the deployment has reachability.

## Operator triage

1. **Prioritize enabled feature paths, not package presence alone.** File Browser impact needs command execution granted to a user; web3.py impact needs server-side `.call()` against untrusted or user-selected contracts with CCIP Read enabled.
2. **Map the crossed principal boundary:** File Browser user scope to server-process filesystem access, or smart contract revert data to backend HTTP client egress.
3. **Look for high-value deployment contexts:** shared File Browser instances, managed file portals with per-user scopes, automation that grants limited command allowlists, web3 indexers, API backends, bots, custodial services, and internal analytics systems that accept arbitrary contract addresses.
4. **Separate configuration from exploitability.** A patched File Browser may still be risky if an operator re-enables command execution; a patched web3.py deployment may still be risky if downstream code overrides safe CCIP policy without destination controls.
5. **Use canaries and callback tokens.** Strong reports prove boundary crossing with planted files and tester-owned HTTP listeners instead of reading secrets or scanning internal networks.

## Replayable validation boundaries

### File Browser scope-escape checks

- Only test accounts where `Execute Commands` is explicitly in scope. Do not run destructive commands or inspect other users' real files.
- Create two disposable file scopes and a planted canary outside the low-privilege user's scope but readable by the File Browser process. Use the least-powerful permitted command to prove whether the canary can be referenced from outside the GUI scope.
- Prefer benign commands such as path listing or fixed-string reads of a synthetic canary. Avoid shells, pipelines, environment dumps, database reads, credential files, or writes outside the test area unless explicitly authorized.
- Capture role/permission settings, command allowlist, server process user, configured scopes, and transcript showing that GUI access is denied while command execution can cross the scope boundary.

### web3.py CCIP Read SSRF checks

- Use a tester-controlled malicious contract and a tester-controlled HTTP listener. Avoid probing cloud metadata, loopback admin ports, or internal hosts unless explicitly authorized.
- Validate whether a backend, indexer, API, or bot performs `.call()` on untrusted contract addresses with global CCIP Read enabled. Trigger `OffchainLookup` with an HTTP URL that records only callback metadata and a unique canary token.
- Test redirect handling with a bounded redirect chain to a tester-controlled endpoint; do not create loops or large fan-out traffic.
- Record provider type, web3.py version, CCIP setting, outbound destination policy, observed callback, and whether redirects, private ranges, or non-HTTPS schemes are blocked.

## Reporting heuristics

- Lead with the **boundary crossed**, not just the advisory title: scoped file user to server process, or contract-controlled revert to backend network egress.
- Include preconditions prominently: command execution enabled and granted in File Browser, or CCIP Read default/setting plus `.call()` on untrusted contracts in web3.py.
- Keep proof minimal and repeatable: one planted canary file or one tester-owned callback with a unique token.
- Avoid sensitive reads. The finding is stronger when the report shows disciplined validation without touching real passwords, database files, cloud metadata, or tenant content.

## Notes on skipped items from this scan

- JupyterLab command-linker HTML execution, OpenClaude model-controlled sandbox disable, NiceGUI reStructuredText file insertion, and authentik SAML Source XML Signature Wrapping were already represented in earlier Skillz Wiki pages and were not duplicated here.
- Fedify unbounded redirect following during ActivityPub key/document resolution and the OpenTelemetry eBPF wave were marked as lower-signal availability/resource-boundary items for this wiki run.
- NiceGUI log-volume denial of service, Nautobot ReDoS, and similar sparse DoS entries were not promoted as standalone guidance.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, Disclosed, and CISA KEV had no separate new promotable deltas beyond items already represented in the wiki.

## October 27 21:04Z follow-up: File Browser — `EvalSymlinks` resolves then serves without re-checking scope, and the public-share handlers share the read path (CVE-2026-116682 / [GHSA-mgqf-5mf5-prfj](https://github.com/advisories/GHSA-mgqf-5mf5-prfj), high 8.6)

File Browser's read path resolves symbolic links with `filepath.EvalSymlinks` (`indexing/iteminfo/utils.go` `ResolveSymlinks`) and returns the resolved target **with no containment check against the user's scope root**; `GetRealPath` (`indexingFiles.go`) hands that target straight to the file handlers. A symlink planted inside a user-accessible directory that points at `/etc/passwd`, another tenant's directory, SSH keys, or container secrets is followed by download, preview, media, and OnlyOffice endpoints — any authenticated user with download access reads anything the server process can. The kicker: the same `FollowSymlinks: true` read path backs the **public share endpoints**, which are authorized only by a share hash — an unauthenticated holder of a share link over any directory containing such a symlink gets arbitrary file read with no credential. The project had already added `symlinkTargetStaysUnderDest` for archive *extraction*; that guard was simply never applied to the general read path.

Durable axes:

1. **Containment fixes are per-sink, not per-library — enumerate every consumer of the resolver.** One `EvalSymlinks` helper sat behind both extraction (guarded) and serving (unguarded). When a codebase ships a symlink-containment helper, grep its call sites and diff against every path where symlinks are actually followed (`FollowSymlinks: true`, `os.Stat` after join, preview/thumb/media subpipelines). The unguarded siblings are the finding. Same fix-site-enumeration rule as the Oct 9 Nginx UI router-registration leg.
2. **Shared read paths inherit the weakest authorizer.** Public-share handlers reusing the authenticated file-read pipeline means the *share-hash-only* authorization is the effective gate on arbitrary file read. On any file-share/product with unauthenticated link access, ask which code path the anonymous handler takes and whether it is the same resolver the authenticated path uses.
3. **Symlink-in-scope is a low-priv write primitive with unbounded read impact.** Proof shape (lab): two disposable scopes, plant `link -> /etc/passwd`-class marker (own synthetic canary file, not real secrets) inside the low-priv scope via any permitted upload, then request it through download **and** through a public share link; record resolved-content mismatch vs scope boundary. Test every read-flavored endpoint (download, preview, media, office-editor) — endpoint families diverge on whether they hit the resolving path.
4. Cross-reference: this product's June 9 execute-command scope escape and May 22 public-share `filepath.Join` collapse leg make File Browser a three-boundary product (command transport, write-path canonicalization, read-path symlink) — the same-product re-sweep rule keeps earning rent.
