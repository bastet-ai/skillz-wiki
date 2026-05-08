# Agent, sandbox, session, and file-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-08 16:15 UTC** batch where updated or newly published advisories hit recurring agent/runtime trust boundaries: in-process JavaScript sandboxes, repository trust prompts, channel upload paths, and session redirect handling.

## Advisories covered

- **vm2 `neutralizeArraySpeciesBatch` sandbox breakout** — [GHSA-9qj6-qjgg-37qq](https://github.com/advisories/GHSA-9qj6-qjgg-37qq): critical escape affecting `vm2 <= 3.11.1`; patch to `3.11.2+` where vm2 remains deployed.
- **Claude Code Git worktree trust-dialog spoofing** — [GHSA-q5hj-mxqh-vv77](https://github.com/advisories/GHSA-q5hj-mxqh-vv77): repository/worktree identity confusion can turn a trusted-workspace prompt into arbitrary code execution; patch `@anthropic-ai/claude-code` to `2.1.84+`.
- **OpenClaw Feishu upload file-sandbox bypass** — [GHSA-qf48-qfv4-jjm9](https://github.com/advisories/GHSA-qf48-qfv4-jjm9): `resolveUploadInput` allowed `upload_image` to read arbitrary local files outside the intended filesystem sandbox; patch `openclaw` to `2026.3.28+`.
- **Devise timeout redirect open redirect** — [GHSA-jp94-3292-c3xv](https://github.com/advisories/GHSA-jp94-3292-c3xv): `Timeoutable` session-expiry flow trusted `request.referrer`; patch `devise` to `5.0.4+`.

Related updated advisories in this scan were already represented in existing pages: Jupyter Server session/origin/path boundaries, OpenMRS path traversal, Quarkus matrix-parameter auth, Gotenberg SSRF, and Incus image-import SSRF.

## Why this is durable

The shared failure mode is **ambient trust crossing a boundary without a fresh authority check**: guest JavaScript inherits host process authority; a repo worktree identity becomes a code-execution trust signal; a chat upload helper expands local paths outside its intended root; a browser referrer becomes a safe post-timeout destination. These bugs are different products, but the durable defense is the same: revalidate the exact resource, identity, and destination at the point of use.

## Immediate triage

1. Search SBOMs and lockfiles for `vm2 <= 3.11.1`, `@anthropic-ai/claude-code < 2.1.84`, `openclaw` Feishu deployments `2026.2.6` through `2026.3.24`, and `devise <= 5.0.3`.
2. For exposed vm2 workloads, assume sandbox escape until disproved: review child processes, outbound network, package-manager writes, filesystem reads/writes, and credential access by the host account.
3. For Claude Code, review recent trust prompts on repositories using worktrees, symlinks, nested `.git` metadata, or generated project directories.
4. For OpenClaw Feishu, hunt for `upload_image` requests that reference absolute paths, `..`, symlinks, hidden files, token stores, SSH keys, browser profiles, `.env`, or workspace files outside the allowed upload root.
5. For Devise apps, check access logs for timeout redirects to external hosts, scheme-relative URLs, encoded slashes, backslashes, mixed-case schemes, or attacker-controlled referrer chains.

## Durable controls

- Treat in-process language sandboxes as convenience controls, not tenant boundaries. Run untrusted code in a separate process/container/VM with cgroups, seccomp/AppArmor, readonly filesystems, and explicit egress policy.
- Bind trust prompts to canonical repository identity: resolved path, device/inode where practical, worktree metadata, commit/worktree origin, and policy version. Re-check before executing hooks, package scripts, or tools.
- Resolve upload paths with `realpath`, reject symlink escapes, require allowlisted roots, and make upload helpers accept opaque file handles or prior-staged attachments instead of arbitrary local strings.
- Normalize redirect targets server-side and allow only relative paths or pre-registered origins. Never treat `Referer`/`Referrer` as an authority source.
- Log boundary decisions with tenant, actor, canonical path/origin, policy result, and content digest so incident response can distinguish denied probes from successful escapes.
