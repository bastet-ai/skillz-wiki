# Better Auth, Aider, netfoil, CKAN MCP, and uutils boundary checks

Source: hourly offensive-security scan, 2026-07-07. Primary entries: GitHub advisories [GHSA-pw9m-5jxm-xr6h](https://github.com/advisories/GHSA-pw9m-5jxm-xr6h), [GHSA-hchg-qm84-cj9p](https://github.com/advisories/GHSA-hchg-qm84-cj9p), [GHSA-7w7m-v5vp-w699](https://github.com/advisories/GHSA-7w7m-v5vp-w699), [GHSA-59qp-cfj3-rp64](https://github.com/advisories/GHSA-59qp-cfj3-rp64), [GHSA-g84h-j7jj-x32p](https://github.com/advisories/GHSA-g84h-j7jj-x32p), and [GHSA-fqf6-gxhh-2xhw](https://github.com/advisories/GHSA-fqf6-gxhh-2xhw).

This batch is durable because each item maps to a reusable operator boundary: OAuth refresh-token possession crossing into confidential-client sessions without a client-secret check, AI coding assistants fetching or executing from attacker-shaped inputs, DNS policy filters parsing a different question than the upstream resolver, MCP tool parameters crossing into server-originated network requests, and GNU-compatible command assumptions breaking file-write safety in trusted automation.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-pw9m-5jxm-xr6h / CVE-2026-53512 | `better-auth` legacy `oidcProvider()` and `mcp()` plugins | `refresh_token` grant accepted a matching refresh-token row and `client_id` without authenticating the confidential client's secret | Test OAuth/MCP token endpoints for grant-specific client-auth drift; prove with disposable clients and canary refresh tokens only. |
| GHSA-hchg-qm84-cj9p / CVE-2026-10177 | Aider `api_docs.py` AWS EC2 metadata fetch path | assistant-side documentation/API fetching could be steered toward metadata-style URLs | Treat AI coding assistants as local network clients during authorized reviews; use owned canary services, never real metadata endpoints. |
| GHSA-7w7m-v5vp-w699 / CVE-2026-10175 | Aider Architect Mode `editor_coder.run` path | model/user-shaped architect-mode data crossed into code execution behavior | Validate prompt-to-tool execution boundaries with inert marker commands in disposable repos only. |
| GHSA-59qp-cfj3-rp64 | `netfoil` domain filtering | filter decision could inspect the first DNS question while a second question reached a remote DoH resolver | Add multi-question DNS packets to resolver/filter bypass harnesses; record first-question decision and upstream query evidence. |
| GHSA-g84h-j7jj-x32p / CVE-2026-53509 | `@aborruso/ckan-mcp-server` `server_url` / `base_url` tools | MCP caller-controlled CKAN URLs filtered only hostname strings, missing loopback aliases such as `ip6-localhost` | Test MCP SSRF filters with hostname aliases, DNS rebinding, and canonical address resolution using owned callbacks and lab canaries. |
| GHSA-fqf6-gxhh-2xhw | `uutils` `cp` / `install` / `mv` / `ln` backup controls | `--suffix` alone did not enable GNU-style backup mode before overwrite | In build/deploy harnesses, compare replacement coreutils behavior against GNU semantics before relying on backup or rollback flags. |

## Operator triage

1. **Split OAuth grant paths.** Do not assume `authorization_code`, device, MCP, and refresh-token grants enforce the same client authentication. Test each endpoint and plugin path independently.
2. **Model attacker prerequisites.** A refresh-token replay finding needs a realistic token-observation path in scope, such as a lab database read, log sink, browser storage capture, or compromised client. Do not collect real user refresh tokens.
3. **Treat agent tools as privileged clients.** API-doc fetchers, code editors, architect modes, and MCP tools often run with local filesystem, network, repository, and credential context that exceeds the web user who supplied the input.
4. **Compare parser layers.** DNS and URL filters fail when the policy parser and the upstream component disagree. Capture raw input, local parse result, canonical host/address, outbound request, and final callback.
5. **Keep automation-divergence findings bounded.** For `uutils`, prove behavior with temporary files and dry-run wrappers. The evidence is a compatibility mismatch that can defeat operator assumptions, not a request to destroy data.

## Replayable validation boundaries

### OAuth/MCP refresh-token confidential-client checks

- Build a disposable application using `better-auth` with the legacy `oidcProvider()` or `mcp()` plugin enabled and a confidential client registered.
- Mint a canary refresh token for a test user and client. Store no production identities or tokens in evidence.
- Replay the refresh-token grant while omitting the confidential client's secret or supplying a known-wrong secret.
- Positive evidence is a token response tied to the canary user/client despite failed client authentication. Negative controls should include a patched version and the replacement `@better-auth/oauth-provider` path when feasible.
- Report the exact grant endpoint, plugin, client type, client-auth material supplied, token subject, and patch/version state.

### AI coding assistant SSRF and execution channels

- Use a disposable repository, a lab Aider instance, and an owned HTTP callback service. Do not target `169.254.169.254`, cloud metadata services, local admin panels, or production private networks.
- For documentation/API-fetch paths, submit only owned callback URLs plus harmless path markers. Positive evidence is a server-side callback containing the expected marker.
- For Architect Mode or `editor_coder.run`-style execution paths, use inert marker commands such as writing a file under a temporary lab directory. Do not run shells, reverse connections, credential reads, package installs, or destructive file operations.
- Capture prompt/input, tool route, generated command or request, marker output, version, and whether operator confirmation was required.

### DNS multi-question filter bypass

- Build a local DNS/DoH lab with a policy that should allow `allowed.example` and block `blocked.example`.
- Send a raw DNS packet containing multiple questions where the first question is allowed and a later question is blocked. Use a controlled resolver that supports multi-question handling.
- Record whether the filter makes the decision from the first question only and whether the upstream resolver receives or answers the later question.
- Keep domains under owned zones or local lab zones. Do not use this pattern to bypass production egress controls without explicit authorization.

### MCP URL-to-network SSRF filters

- Inventory MCP tools that accept `base_url`, `server_url`, endpoint, callback, or datasource URL parameters.
- Exercise host representations through a lab callback service: canonical hostname, `localhost`, `127.0.0.1`, `[::1]`, `ip6-localhost`, mixed-case hosts, trailing dots, userinfo, punycode, and DNS-rebinding names you control.
- Positive evidence is a callback or controlled lab response from a representation that policy intended to block.
- If the tool expects CKAN-shaped responses, use a fake CKAN fixture with only synthetic package names and IDs.

### Replacement-coreutils safety checks

- In a disposable directory, compare GNU coreutils and the replacement tool with the same `cp`, `install`, `mv`, or `ln` invocation using `--suffix` alone.
- Capture pre/post file lists and checksums for canary files only.
- Use the result to decide whether exploit-build, deployment, backup, or rollback scripts can trust GNU compatibility assumptions in the target environment.

## Reporting notes

- Name the crossed boundary precisely: **refresh-token possession to confidential-client session**, **agent URL fetch to local/private network**, **prompt/tool input to editor execution**, **first DNS question to later-question resolver behavior**, **MCP URL parameter to server-originated network request**, or **GNU compatibility flag to unsafe overwrite**.
- Include versions, plugin enablement, client type, raw packet or URL forms, canonicalization output, callback proof, and negative controls.
- Keep proofs to canary tokens, lab repositories, owned callback hosts, local DNS zones, fake CKAN data, and temporary files.
