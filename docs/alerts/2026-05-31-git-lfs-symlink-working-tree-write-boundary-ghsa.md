# Git LFS symlink and hard-link working-tree write boundaries

Sources: [GHSA-6pvw-g552-53c5](https://github.com/advisories/GHSA-6pvw-g552-53c5), [upstream Git LFS advisory GHSA-6pvw-g552-53c5](https://github.com/git-lfs/git-lfs/security/advisories/GHSA-6pvw-g552-53c5), [Git LFS v3.7.1 release](https://github.com/git-lfs/git-lfs/releases/tag/v3.7.1), and fixing commits [`5c11ffce9a`](https://github.com/git-lfs/git-lfs/commit/5c11ffce9a4f095ff356bc781e2a031abb46c1a8), [`0cffe93176`](https://github.com/git-lfs/git-lfs/commit/0cffe93176b870055c9dadbb3cc9a4a440e98396), and [`d02bd13f02`](https://github.com/git-lfs/git-lfs/commit/d02bd13f02ef76f6807581cd6b34709069cb3615), updated on 2026-05-31.

Git LFS `git lfs checkout` and `git lfs pull` before `3.7.1` could write LFS object content through symbolic or hard links that collide with tracked LFS paths. The durable operator lesson is not “run Git LFS on random repositories”; it is to test every service that imports, clones, mirrors, analyzes, or previews untrusted Git repositories for filesystem trust-boundary enforcement around symlinks, hard links, bare repositories, and post-clone LFS materialization.

## Advisory signals

- **Working-tree link following** — when an LFS-tracked path is represented by a symlink or hard link in the working tree, vulnerable Git LFS commands may write object bytes to a target visible outside the intended checkout path.
- **Bare-repository edge case** — the advisory also calls out `git lfs checkout` / `git lfs pull` behavior in bare repositories that could write outside the repository under specific conditions.
- **Patch shape** — Git LFS now checks symbolic links similarly to Git before writing and removes existing working-tree files before writing replacements. That patch pattern is a useful review cue for custom Git importers and SCM wrappers.
- **Impact surface** — hosted code search, dependency scanners, CI preview jobs, bug-bounty “import my repo” features, AI coding-agent sandboxes, and package build systems often run Git and Git LFS on attacker-controlled repositories with valuable tokens or host-mounted caches nearby.

## Operator triage

1. Confirm whether the target executes Git LFS during repository ingestion. Look for `git lfs pull`, `git lfs checkout`, `git lfs install`, LFS smudge filters, or libraries/wrappers that materialize LFS objects after clone.
2. Prioritize flows that process untrusted repositories in a shared workspace: hosted CI, source-code analysis, SBOM generation, model/context indexing, docs preview, artifact build, and “scan a public repo URL” features.
3. Map the filesystem boundary. Identify the clone root, parent workspace, writable caches, mounted credentials, build output directories, and any path that should never be writable from repository contents.
4. In an authorized lab, use a disposable repository and harmless sentinel target outside the checkout root. The proof should be a controlled write to a test-owned file, never overwrite system files, SSH keys, tokens, or another tenant’s data.
5. Run the same validation across both normal and bare-repository code paths if the product supports mirror/bare clones. Bare clone handling often lives in a different worker or cache path than interactive preview builds.
6. Compare patched and vulnerable behavior by version. Expected safe behavior: LFS materialization refuses or replaces link collisions inside the working tree without following links outside the repository boundary.

## Safe validation boundaries

- Keep all targets under a tester-owned temporary directory. A good sentinel is a disposable file like `/tmp/skillz-lfs-sentinel` or a workspace-local sibling directory created only for the test.
- Do not attempt to write to privileged host paths, service credentials, `.ssh`, cloud-token files, shared caches, or other tenants’ repositories.
- Avoid running untrusted repository hooks or build scripts while testing this boundary. Isolate the LFS materialization step from unrelated code execution.
- Snapshot file metadata before and after testing so the evidence is a minimal path, inode/link relationship, command path, and changed sentinel content.
- If testing a SaaS import flow, coordinate with the program first. Even a harmless sentinel write can cross tenant or infrastructure boundaries if the worker layout is unknown.

## Reporting heuristics

- Frame the finding as a repository-import filesystem boundary failure, not just “outdated Git LFS.” The actionable question is whether attacker-controlled repository content can write outside its checkout root.
- Include the exact worker action that triggered the write (`pull`, `checkout`, smudge/materialize step, bare mirror refresh, scanner import, or CI prep stage).
- Show the before/after sentinel state and the intended trust boundary: checkout root, sibling directory, cache path, or host mount.
- Mention whether the product pins Git LFS below `3.7.1`, relies on system Git LFS, or vendors a wrapper with equivalent link-following behavior.
- Recommend regression coverage for symlink collisions, hard-link collisions, bare repositories, pre-existing files at LFS paths, and repository imports from untrusted users.
