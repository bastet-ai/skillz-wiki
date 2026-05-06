# Agent, MCP, Git, and file-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced agent/tooling and file-boundary advisories updated on **2026-05-06** across OpenClaw, GitPython, NLTK, MCP helpers, HyperChat, and OpenStack Ironic.

## Advisories covered

- **OpenClaw shared reply MEDIA local-file exfiltration** — [GHSA-qqq7-4hxc-x63c](https://github.com/advisories/GHSA-qqq7-4hxc-x63c): cross-channel shared reply media paths could be treated as trusted local paths. Fixed in 2026.4.8.
- **GitPython reference API path traversal** — [GHSA-7545-fcxq-7j24](https://github.com/advisories/GHSA-7545-fcxq-7j24): reference APIs could write/delete outside the repository. Fixed in 3.1.48.
- **NLTK path traversal** — [GHSA-68j8-pq59-fqgm](https://github.com/advisories/GHSA-68j8-pq59-fqgm): data/resource handling could traverse paths in affected versions.
- **notes-mcp path traversal** — [GHSA-vc5j-42hh-j3mr](https://github.com/advisories/GHSA-vc5j-42hh-j3mr): note paths could escape intended roots.
- **sqlite-mcp injection** — [GHSA-4j28-22qp-rjcf](https://github.com/advisories/GHSA-4j28-22qp-rjcf): SQL/tool input handling could inject into SQLite operations.
- **HyperChat SSRF** — [GHSA-r2jq-4h3x-rfj6](https://github.com/advisories/GHSA-r2jq-4h3x-rfj6): URL-fetching chat functionality could reach server-side targets.
- **OpenStack Ironic untrusted control-sphere inclusion** — [GHSA-wqpv-c3pp-3m58](https://github.com/advisories/GHSA-wqpv-c3pp-3m58): control-plane inputs could include functionality from an untrusted sphere.

## Why this is durable

Agent and automation tools frequently bridge chat messages, repository state, local files, SQL databases, and infrastructure control planes. The durable mistake is passing a path, URL, ref, or tool argument across that bridge without re-resolving it inside the destination trust boundary.

## Immediate triage

1. Patch OpenClaw, GitPython, and affected MCP/tooling packages where fixes exist; isolate unfixed helpers behind explicit capability policy.
2. Search for chat-to-file, media-to-attachment, Git ref, NLTK data, note path, and SQLite MCP operations that accept user-controlled names.
3. Review outbound fetch logs for loopback, metadata, RFC1918, IPv6-mapped, DNS-rebinding, and redirected SSRF attempts.
4. For Git/file APIs, validate by descriptor/root after canonicalization; reject symlinks, `..`, encoded separators, and ref names that materialize as paths.
5. For SQLite/MCP tools, expose typed verbs and parameter binding instead of free-form SQL or path-bearing helper prompts.

## Durable controls

- Treat MEDIA, repository refs, note IDs, model/data package names, and tool arguments as untrusted capabilities, not filesystem paths.
- Enforce per-tool root directories with openat-style resolution and post-open verification.
- Give URL-fetching agents an egress broker with DNS pinning, redirect rechecks, and private-network deny rules.
- Separate infrastructure control-plane policy from data-plane helper code; imported functionality must be signed and pinned.
