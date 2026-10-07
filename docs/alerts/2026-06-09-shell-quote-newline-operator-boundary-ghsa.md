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

## June 9 follow-up (October 6): comment-token swallows later quotes — CVE-2026-102422 / GHSA-pqg4-j6r4-53mv

`shell-quote` 1.8.4–<1.11.0 adds a second genealogy leg to this page's original CVE-2026-9277 (incomplete-fix family). `quote()` emits a `{ comment }` token as `#` plus its text, which **comments out the rest of the shell line — including the opening quote of any later string token**. A line terminator inside that later string ends the comment, and the remainder of the string parses as shell input:

```js
quote(['echo', 'ok', { comment: 'x' }, 'a\nid;#']);
// echo ok #x 'a
// id;'   -> runs `id` under sh/bash/dash/ksh/zsh
```

The prior fix rejected line terminators in the comment's **own** text but not in the tokens **after** it — the classic incomplete-fix shape this page already tracks. Two extra durable axes beyond the original triage:

- **The interaction is emission-semantics, not escaping**: the comment token's meaning (swallow-to-end-of-line) retroactively unquotes everything after it. Any serializer that emits line-oriented comment syntax must treat all *subsequent* emitted tokens as being in comment-influenced grammar, not string grammar. Same reasoning class as the HTML-comment-sanitizer-truncation and SQL-`--`-appended-fragment families.
- **`parse()`→`quote()` round-trip is a live attack route**: `parse()` emits a comment token for a mid-word `#` (e.g. `http://example.com/#frag`), so `quote(parse(untrustedCommand).concat(untrustedArg))` — command-plus-argument wrapper patterns in task runners and agent tool executors — creates the comment token from untrusted input without the caller ever constructing `{ comment }` deliberately. Grep for `quote(parse(` and `parse(`-output-concatenation specifically, not just object-token construction.
- **Fix fingerprint**: 1.11.0 throws `TypeError` when a post-comment string token contains `\n`, `\r`, U+2028, or U+2029 — version gate `>= 1.8.4, < 1.11.0` (the vulnerable range starts where the *first* fix landed). Probe with a two-token payload (`{comment}` + post-token with newline + `;#` terminator) rather than the original single-token `op` newline canary; a build that passes the 2026-06 canary but fails this one is the mid-genealogy version.

## October 7 follow-up: Rundeck option-value cmd.exe metacharacter injection — single-quote wrapping is not quoting on Windows (CVE-2026-106056 / [GHSA-jv2x-5hph-7fp2](https://github.com/advisories/GHSA-jv2x-5hph-7fp2), high)

Rundeck < 6.2.0: free-text job **option values** are interpolated into commands run on Windows nodes through `CLIUtils.quoteWindowsCMDArg`, which wraps them in **single quotes — a shell-significant character `cmd.exe` does not treat as quoting at all**. `&&`, `|`, and friends pass straight through: a user with only *job-run* permission executes arbitrary commands on Windows nodes under the node-executor credential.

Durable axes for the whole command-wrapper family on this page:

1. **Quoting must match the target shell's grammar, not the author's shell.** POSIX developers habitually reach for `'…'` because it is strongest in bash; under `cmd.exe` it is literally a printable character. Correct `cmd.exe` shapes are `^`-escaping of `& | < > ( ) ^` and `"`-doubling inside strings (or, better, no shell at all — `CreateProcess` argv). Audit rule: grep any command-wrapper/JNI/job-runner codebase for `'`-wrapping quote helpers whose sink is `cmd /c`; `quoteWindows*`/`escapeWindows*` helper names containing `'` are the finding in one grep.
2. **The option/parameter plane is its own injection surface in job schedulers.** Job *definitions* get security review; option *values* supplied at run time flow through different code paths (UI form → API → CLI → executor string concat). On authorized engagements with a Rundeck/Airflow-class scheduler, test every free-text option with `&& calc`-class inert markers (`&& echo marker`) on a lab Windows node, and note that the *legitimate* run permission is already the precondition — the finding is the privilege jump to the executor credential, so capture the node-executor identity (`whoami /priv`-class marker) as impact proof, never production payloads.
3. **Cross-shell quoting differential is a reusable matrix**: for each wrapper, run the same marker battery (`&&`, `|`, `` ` ``, `$()`, `%VAR%`, `^`, newline, `'`, `"`) and record which metacharacter survives for which target shell (sh/bash vs cmd vs PowerShell vs /bin/sh-on-node). A wrapper that passes the POSIX battery and fails the cmd battery is this class exactly. Sibling precedent on this wiki: the `shell-quote` POSIX-operator genealogy above and the CodeIgniter/mise argument-injection pages — same invariant, different host shell.
4. **Same-wave siblings, same invariant**: `patool` < 4.0.6 (CVE-2026-106057 / [GHSA-73h5-w67h-9rfh](https://github.com/advisories/GHSA-73h5-w67h-9rfh)) — Windows `shell_quote_nt` fails to escape `cmd.exe` metacharacters or embedded `"`, so an archive named `report&calc.gz` processed with `shell=True` runs the payload; the filename *is* the injection plane for every archive/email/build tool that shells out per-file, and the grep is the same (`shell_quote*`/`quote*` helpers + `shell=True`/`cmd /c`). Also same-wave: GitAhead ≤ 2.7.1 (CVE-2026-106058 / [GHSA-q252-mvpj-37m5](https://github.com/advisories/GHSA-q252-mvpj-37m5)) substitutes checked-out **file names** into clean/smudge filter commands selected via `.gitattributes`, so a cloned repo with a file literally named `$(command)` runs `bash -c` at checkout/stage — the malicious-repo class on this wiki's May 5 agent-git page, new GUI-client instance; and CVE-2026-106059 / [GHSA-3g7h-c55x-cx2v](https://github.com/advisories/GHSA-3g7h-c55x-cx2v) interpolates repo filenames unescaped into macOS AppleScript (`"` + `do shell script` in a path → code exec on "Show in Finder") — remember *third-party shells* (AppleScript, PowerShell, JScript) are quoting sinks too. Lab proof for all three: disposable repo/archive with marker filenames, victim-side harness only.

## Notes on skipped items from this scan

- GitHub's updated advisory feed also surfaced Flowise entries that are already represented by existing wiki pages for Flowise RCE, credential exposure, tenant isolation, vector-store permissions, and mass assignment. They were marked processed without duplicate publication.
- Older or low-reuse updated-feed items such as withdrawn SSRF records, historical Paramiko and parser issues, generic DoS, and sparse secret-logging advisories were marked processed without standalone publication because they did not add a fresh offensive workflow beyond existing wiki coverage.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, Disclosed, and CISA KEV had no separate new promotable delta beyond items already represented in the wiki.
