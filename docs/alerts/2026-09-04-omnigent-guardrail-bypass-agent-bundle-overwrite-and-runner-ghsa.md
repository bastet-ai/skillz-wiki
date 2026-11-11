# Omnigent: guardrail-policy bypass, agent-bundle overwrite, and runner execution boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (Omnigent cluster, 4 advisories). Durable because Omnigent is an agent-orchestration/runner platform and the cluster exposes the **trusted-automation trust boundaries** this wiki repeatedly flags: a policy/guardrail layer that can be bypassed by a crafted shell command, a shared artifact (the agent bundle) that one actor can overwrite to rewire authentication, and an upload path that lets an authenticated runner reach code execution.

Primary entries: [GHSA-7mqg-cx4g-x2rf](https://github.com/advisories/GHSA-7mqg-cx4g-x2rf) / CVE-2026-62676 (guardrail policy bypass, shell-command parser fails on crafted input), [GHSA-p8rw-8qj3-hf33](https://github.com/advisories/GHSA-p8rw-8qj3-hf33) / CVE-2026-62677 (unvalidated `os_env.cwd` in an agent bundle yields arbitrary directory), [GHSA-jrrm-9hc7-2v3h](https://github.com/advisories/GHSA-jrrm-9hc7-2v3h) / CVE-2026-62674 (shared agent-bundle overwrite leads to auth bypass), and [GHSA-756x-9hf6-q4h4](https://github.com/advisories/GHSA-756x-9hf6-q4h4) / CVE-2026-62675 (uploaded agent bundle allows authenticated runner RCE).

!!! warning "Authorized validation only"
    Keep proofs to a disposable Omnigent control/runner lab with synthetic agent bundles and inert command canaries. Use denied file/network/process sinks. Do not execute real agent payloads, reach internal services, read real credentials, or run untrusted bundle code on a shared host.

## Boundary map

| GHSA | Boundary | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-7mqg-cx4g-x2rf](https://github.com/advisories/GHSA-7mqg-cx4g-x2rf) | Guardrail policy parser | a crafted shell command evades the deny/block list so a disallowed command reaches the shell | Feed guarded commands with the bypass forms; confirm the policy decision vs. the command actually parsed/accepted. |
| [GHSA-p8rw-8qj3-hf33](https://github.com/advisories/GHSA-p8rw-8qj3-hf33) | Agent-bundle `os_env.cwd` | caller-supplied `cwd` is not validated, so the runner can start in an arbitrary directory | Supply a `cwd` outside the intended root; record the working directory the runner actually starts in. |
| [GHSA-jrrm-9hc7-2v3h](https://github.com/advisories/GHSA-jrrm-9hc7-2v3h) | Shared agent-bundle store | a low-privilege actor overwrites a bundle used by another principal's auth flow | In a two-actor lab, overwrite the shared bundle and observe whether the second principal's auth changes. |
| [GHSA-756x-9hf6-q4h4](https://github.com/advisories/GHSA-756x-9hf6-q4h4) | Uploaded agent bundle → runner | an uploaded bundle reaches execution on the runner as an authenticated user | Upload a bundle with an inert canary command; confirm execution occurs at the expected trust level with a denied sink. |

The unifying pattern: **the agent bundle is a trusted, shared, executable artifact**, and the guardrail/runner layers each have a spot where an attacker-controlled field crosses from "data describing a task" to "authority over a process."

## Replayable validation boundaries

### Guardrail shell-command parser bypass

1. In a disposable Omnigent lab, identify the guardrail deny-list / command-policy predicate.
2. Craft a set of shell commands that are semantically on the *denied* side but use parser-bypass forms: leading/trailing whitespace and no-break variants, quote/comment splits, subshell/`$( )`/backtick wrapping, variable indirection, and encoded argument forms.
3. For each, record the **policy decision** (allow/deny) and the **command the shell parser ultimately accepts/executes** (lab logging or a recorder that denies real execution). A positive is policy = deny while the parser yields an executable denied command.
4. Negative control: the fixed version, or a parser that canonicalizes before the policy check.

Report as **guarded command -> parser bypass form -> policy sees benign string / shell executes denied command**. Keep the executed command to an inert nonce/marker.

### Unvalidated `os_env.cwd`

1. Author a synthetic agent bundle whose `os_env.cwd` points one level (or more) outside the intended workspace root.
2. Run the runner and record the **actual process working directory** at start. A positive is the runner starting in the caller-selected directory outside the root.
3. Use a sibling marker file to show reach, but stop at the directory decision, do not read/write files in a real root.

### Shared agent-bundle overwrite → auth drift

1. Set up two actors: A (owner of a bundle) and B (low-privilege, able to write the shared bundle store).
2. Have B overwrite A's shared bundle with a canary bundle. Then trigger A's normal flow and record whether A's **authentication/identity decision** now reflects B's bundle content.
3. A positive is A's flow authenticating/behaving under B's overwritten bundle. Keep it to a synthetic identity marker; do not steal a real token or escalate to a real admin.

### Uploaded bundle → runner execution (authenticated)

1. As an authenticated user, upload a synthetic bundle containing one inert canary command.
2. Confirm the runner executes it and record the **trust level** of the resulting process (user, cwd, capabilities). Use a denied process/file/network sink so the proof is "execution at this trust level," not a real exploit.
3. Compare against the expected isolation (container/VM/allowlist) and report the gap between expected and observed trust.

## Durable operator value

1. **The agent bundle is the unit of trust.** In orchestration platforms, the shared, versioned, executable "bundle" is the artifact that ties a task to an identity and a capability. If any actor can read/overwrite/author it in a way that crosses a principal boundary, the whole trust chain moves with it.
2. **Guardrail lists are parsers, not filters.** A command deny-list that is checked *before* canonicalization is bypassable by construction. The reusable check is "does the policy evaluate the same string the shell will execute?"
3. **Environment fields (`cwd`, env vars) are authorization inputs.** An unvalidated `cwd` is a path-authorization bug, not just a convenience gap. Audit every env/cwd/working-dir field a caller can set in an agent/bundle/task definition.
4. **Authenticated RCE on a runner is the ceiling, but the *drift* is the report.** The decisive evidence is expected-vs-observed trust level at execution (user, root, cwd, network), not a payload.

## Safety

- **Disposable control/runner lab.** Synthetic bundles, inert canary commands, denied file/network/process sinks.
- **No real agent payloads.** Do not execute untrusted bundle code on a shared or production host.
- **No real credential/token theft.** Auth-drift proven with a synthetic identity marker.
- **No internal/metadata reach.**

---

*Source: hourly offensive-security scan, 2026-09-04. All 4 Omnigent advisories tracked in the [source index](../notes/source-index.md).*
