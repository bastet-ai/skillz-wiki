# MCP SSH and APM plugin filesystem-boundary batch

**Sources:** GHSA-j7h9-2jh7-g967, GHSA-xhrw-5qxx-jpwr / CVE-2026-44641

## Why this matters

Two new agent-tooling advisories turn convenience filesystem features into host-file authority:

- `mcp-ssh-tool <= 2.1.0` has insufficient transfer path authorization, incomplete canonicalization/segment-boundary checks for deny-prefix policy, and non-constant-time bearer token comparison for HTTP transport.
- Microsoft `apm-cli <= 0.8.11` trusts marketplace plugin manifest paths (`agents`, `skills`, `commands`, and directory-form `hooks`) without proving they stay under the plugin root. A malicious plugin can use absolute paths or `../` traversal to copy arbitrary readable host files during `apm install`; fixed in `0.8.12`.

The common failure is treating agent/plugin metadata as benign project content. In practice, MCP transfer paths and plugin manifests are control-plane inputs that can cross from a downloaded package into the operator's local filesystem.

## Operator triage

1. Upgrade `mcp-ssh-tool` to `2.1.1+` and Microsoft `apm-cli` to `0.8.12+` anywhere they are used by developers, CI runners, or agent workbenches.
2. Review recently installed APM plugins for manifest entries containing absolute paths, `..`, symlinks, or component paths outside the downloaded plugin directory.
3. Inspect `.apm/`, `.github/prompts/`, copied command/skill/agent directories, and project prompt folders for unexpected files sourced from the local host.
4. For MCP SSH deployments, avoid exposing HTTP transport beyond loopback unless it sits behind a real auth gateway; rotate bearer tokens if the endpoint was reachable over a network.
5. Re-check transfer allow/deny policies with decoded, canonicalized, symlink-resolved paths rather than string-prefix comparisons.

## Hunt prompts

- `apm install` runs against untrusted or newly published marketplace plugins immediately before sensitive project files appear under `.apm/` or `.github/prompts/`.
- Plugin manifests with path values beginning `/`, `~`, drive letters, URL-like prefixes, or repeated `../` segments.
- MCP SSH transfer requests touching dotfiles, SSH material, token stores, shell history, cloud credentials, or workspace `.env` files.
- HTTP MCP auth attempts with many near-miss bearer-token values, especially against public or reverse-proxied transports.

## Durable controls

- Resolve plugin and transfer paths with a final canonical path check against an allowlisted root after symlink resolution; deny on ambiguity or decode errors.
- Use positive allowlists for plugin component locations instead of deny-prefix rules.
- Install agent plugins in disposable, secret-free sandboxes before copying anything into a trusted repository.
- Treat prompt, skill, hook, and command files as executable supply-chain inputs; review diffs before activation.
- Compare bearer tokens with constant-time primitives and prefer short-lived scoped tokens over reusable global secrets.
