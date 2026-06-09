# shell-quote newline operator boundary

Source: hourly offensive-security scan, 2026-06-09. Primary entry: GitHub advisory [GHSA-w7jw-789q-3m8p](https://github.com/advisories/GHSA-w7jw-789q-3m8p) / CVE-2026-9277 for `shell-quote`.

This page is durable because it captures a reusable bug-hunting pattern: shell-quoting APIs may be safe for strings but unsafe for structured tokens supplied by plugins, workflow definitions, environment callbacks, agent protocols, or deserialized job state.

## What changed

- **`shell-quote` structured-token command injection** — `shell-quote` `>= 1.1.0, <= 1.8.3` failed to validate object-token `.op` values in `quote()`. JavaScript `/(.)/g` escaping did not match line terminators, so a crafted operator such as `{ op: ';\n...' }` could place a literal newline into the shell command. POSIX shells treat that newline as a command separator. Fixed in `1.8.4` with an allowlist aligned to parser-emitted operators.
- **Direct object-token construction is the main hunt surface** — the advisory identifies callers that build `{ op: '...\n...' }` from external input, for example a deserialized argument array, and then pass the object token to `quote()`.
- **`envFn` object-token return is the second route** — `parse(cmd, envFn)` can splice an object returned by `envFn` into the token array. If `envFn` consults attacker-controlled data and the resulting tokens reach `quote()` and then a shell, the newline operator becomes a command separator.
- **The parser is not the vulnerable boundary** — `parse()` emits operators from a fixed control set. The failure is `quote()` accepting caller-provided object shapes and attempting character escaping where shape validation was required.

## Operator triage

1. **Find shell wrappers that treat `quote()` as the safety boundary:** search JavaScript/TypeScript repos for `require('shell-quote')`, `from 'shell-quote'`, `quote(tokens)`, and `parse(command, envFn)`.
2. **Follow output to shell sinks:** prioritize paths where `quote()` output flows into `child_process.exec`, `execSync`, `spawn(..., { shell: true })`, package-manager scripts, task runners, CI helpers, MCP/agent tool execution, or shell scripts.
3. **Prioritize structured-token sources:** the interesting cases are not ordinary string arguments. Look for JSON-deserialized token arrays, plugin-supplied token objects, custom `envFn` callbacks, workflow variable expansion, job replay/state files, and user-controlled objects with `op`, `comment`, or `pattern` fields.
4. **Check version and reachability together:** vulnerable range is `>= 1.1.0, <= 1.8.3`; fixed version is `1.8.4`. A dependency-only finding is weaker than a reachable structured-token-to-shell path.
5. **Use canaries over secrets:** execute only harmless local markers in a lab or staging clone. Do not prove impact by reading environment variables, keys, tokens, source files, cloud metadata, or customer data.

## Replayable validation boundaries

- Only test code paths where the application already passes `shell-quote` output to a shell. If the result is kept as an argv array or never executed, the finding may be a library exposure without reachable impact.
- In a lab clone, build a token array with an operator containing a line terminator and a benign canary command. A safe proof is that the rendered command contains a literal newline in an operator slot and, when executed in the lab, runs only a harmless `printf`/`echo` marker.
- For direct construction, trace where an attacker can influence the token object before it reaches `quote()`: API request body, config file, plugin manifest, workflow node parameter, job queue payload, or serialized task state.
- For `envFn`, show the callback can return an attacker-shaped object token. Avoid claiming parser bypass; the issue is object-token insertion by caller-supplied callback logic and insufficient validation in `quote()`.
- Capture the token source, rendered command string with control characters made visible, shell used (`sh`, `bash`, `dash`, or `zsh`), and the exact sink. Redact paths, usernames, hostnames, and internal job data unless they are synthetic.

## Reporting heuristics

- Lead with the **trust boundary**: untrusted structured token to shell command separator.
- Include preconditions explicitly: package version, object-token reachability, line-terminator preservation, shell execution sink, and whether the route is direct object construction or `envFn` return.
- Provide a minimal code or request transcript using documentation/example values and a harmless canary. Avoid weaponized commands and production-sensitive output.
- If a product embeds `shell-quote`, report the vulnerable application path rather than only the dependency version. The durable bug-hunting target is any shell-safety wrapper that accepts structured tokens from untrusted plugins, workflows, or agent protocols.
- Recommend allowlist validation for object-token shapes at the application boundary if an immediate dependency upgrade is blocked. In particular, operator values should come from the parser's fixed operator set, and comments/patterns should reject line terminators before shell rendering.

## Notes on skipped items from this scan

- GitHub's updated advisory feed also surfaced Flowise entries that are already represented by existing wiki pages for Flowise RCE, credential exposure, tenant isolation, vector-store permissions, and mass assignment. They were marked processed without duplicate publication.
- Older or low-reuse updated-feed items such as withdrawn SSRF records, historical Paramiko and parser issues, generic DoS, and sparse secret-logging advisories were marked processed without standalone publication because they did not add a fresh offensive workflow beyond existing wiki coverage.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, Disclosed, and CISA KEV had no separate new promotable delta beyond items already represented in the wiki.
