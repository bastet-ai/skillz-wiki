# Dalfox server-mode API boundary batch

Source: GitHub Security Advisories published 2026-05-12.

This batch is durable because it is a clean example of a security tool becoming a privileged remote API: scanner options that are safe-ish on a local CLI become command, file-read, file-write, and process-crash primitives when accepted from unauthenticated JSON.

## Advisories covered

- **Unauthenticated RCE through `found-action`** — [GHSA-v25v-m36w-jp4h](https://github.com/advisories/GHSA-v25v-m36w-jp4h), CVE-2026-45087: Dalfox server mode (`dalfox server`) binds to `0.0.0.0:6664` by default, does not require an API key unless explicitly configured, and accepted attacker-supplied `FoundAction` / `FoundActionShell` scan options. A caller who can trigger a finding can execute arbitrary shell commands as the Dalfox process.
- **Arbitrary file read with out-of-band exfiltration** — [GHSA-35wr-x7v6-9fv2](https://github.com/advisories/GHSA-35wr-x7v6-9fv2), CVE-2026-45088: attacker-controlled `custom-payload-file` could read host files and replay their lines as payloads to an attacker-controlled scan target.
- **Arbitrary file create/append** — [GHSA-8hf9-3q64-q2qf](https://github.com/advisories/GHSA-8hf9-3q64-q2qf), CVE-2026-45089: attacker-controlled `output`, `output-all`, and `debug` paths reached the logger and opened files with append/create semantics even in server/library mode.
- **Remote process crash** — [GHSA-2g4x-fq3j-cgq4](https://github.com/advisories/GHSA-2g4x-fq3j-cgq4), CVE-2026-45090: crafted POST-body parameter analysis could write to a closed channel and panic the Go process.

Affected package: `github.com/hahwul/dalfox/v2 <= 2.12.0`; fixed in `2.13.0`.

## Operator triage

1. Upgrade Dalfox to `2.13.0` before running server mode again.
2. If Dalfox server mode was exposed on a network, treat the host as potentially compromised: collect process logs, shell history, service unit changes, cron/systemd timers, modified startup files, and unexpected outbound traffic.
3. Rotate secrets readable by the Dalfox process, especially tokens in environment files, home directories, CI workspaces, and scanner configuration paths.
4. Hunt for created/appended files in locations writable by the Dalfox user, including web roots, authorized key files, shell startup files, logs, and application configs.
5. Remove public exposure; bind scanner APIs to loopback or a private management network, and require a non-empty API key plus an upstream authz layer.

## Durable controls

- Treat scanner/server mode as a privileged automation API, not as a thin wrapper around a trusted CLI.
- Split option schemas by trust context: CLI-only options such as shell hooks, output paths, local payload files, and debug paths must not be deserializable from remote requests.
- Default-deny network binding and authentication. `0.0.0.0` plus empty auth should never be the safe default for a tool that can make outbound requests or touch local files.
- Pin file access to an explicit workspace with canonical path checks; never let remote scan options name arbitrary host paths.
- Add negative tests for each dangerous CLI option in server/library mode: command hooks rejected, file paths rejected or sandboxed, and panics recovered at request boundaries.
