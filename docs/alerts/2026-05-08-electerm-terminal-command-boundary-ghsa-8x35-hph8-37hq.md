# electerm terminal command injection via Linux runner (GHSA-8x35-hph8-37hq)

**Signal:** GitHub Security Advisories updated **2026-05-08**. `electerm` fixed a critical command-injection issue in its Linux command runner.

## What it is
`electerm` is a terminal/SSH/SFTP client. The advisory reports command injection through the `runLinux` function before `3.3.8`. In a terminal client, this boundary is especially sensitive: profile names, connection metadata, generated commands, file-transfer helpers, and automation shortcuts can cross from UI/configuration into a local shell.

Affected package: npm `electerm` `< 3.3.8`. Fixed version: `3.3.8`.

Reference: <https://github.com/advisories/GHSA-8x35-hph8-37hq>

## Triage
1. Inventory developer workstations, jump boxes, and shared admin hosts running `electerm` or packaged builds derived from the npm package.
2. Check whether profiles, bookmarks, imported configs, sync data, or workspace files came from less-trusted sources.
3. Review recent local command execution around `electerm` launches, connection attempts, file-transfer operations, and helper command invocations.
4. Treat any terminal client config that can influence shell arguments as executable input until patched and reviewed.

## Mitigation
- Upgrade `electerm` to `3.3.8` or later.
- Avoid importing connection profiles or sync bundles from untrusted sources.
- Run terminal clients as a normal user, not as root or a shared privileged service account.
- Keep SSH keys agent-scoped and passphrase-protected; assume a local command injection can try to read environment variables, config files, and agent-accessible identities.

## Detection ideas
- Hunt shell history and process telemetry for commands launched by `electerm` containing shell metacharacters, unexpected redirects, curl/wget, archive extraction, credential access, or persistence attempts.
- Review modified shell rc files, desktop autostart entries, SSH config, known_hosts, and recently touched credential files after suspicious `electerm` sessions.
- Check imported/synced `electerm` profile data for characters that should never be interpreted by a shell: `;`, `&&`, `|`, backticks, `$()`, redirections, and newline injection.

## Durable lesson
Terminal clients are not just viewers; they are command brokers. Any UI/config field that reaches a shell must be modeled as untrusted data, passed as argv where possible, and rejected when it contains command syntax instead of a literal value.

## 19:15 UTC expansion — renderer, link, filename, and widget execution paths

The later **2026-05-08 19:15 UTC** scan added a broader electerm advisory cluster. Treat these as the same terminal-client trust boundary, not as isolated bugs:

- **Arbitrary protocol execution from terminal link clicks** — [GHSA-fwf6-j56g-m97c](https://github.com/advisories/GHSA-fwf6-j56g-m97c): `shell.openExternal` accepted unsafe protocols from terminal output. A malicious remote host can print links that jump from terminal text into local app/protocol execution.
- **Widget path traversal to code execution** — [GHSA-f77v-9vpc-6pjm](https://github.com/advisories/GHSA-f77v-9vpc-6pjm): `runWidget` path handling allowed traversal into unintended code paths. Patch to `3.7.16+` for that path.
- **Malicious SSH-server filename RCE** — [GHSA-q4p8-8j9m-8hxj](https://github.com/advisories/GHSA-q4p8-8j9m-8hxj): remote filenames flowing into `openFileWithEditor` could become command execution. Patch to `3.7.9+` for that path.
- **Renderer environment exposure** — [GHSA-37j4-88rp-2f6h](https://github.com/advisories/GHSA-37j4-88rp-2f6h): `window.pre.env` exposed the full `process.env` to renderer code in affected versions.
- **Dangerous link/command-line execution** — [GHSA-mpm8-cx2p-626q](https://github.com/advisories/GHSA-mpm8-cx2p-626q): affected `electerm >=3.0.6 <3.8.15`; patch to `3.8.15+`.

Upgrade target: use the newest fixed release available, and do not consider partial line-item fixes sufficient if any renderer, widget, terminal-link, external-editor, or environment-bridge advisory remains open.

Additional hunts:

- Terminal output containing `file://`, custom app protocols, `ssh://`, `vscode://`, `cursor://`, `openclaw://`, or OS-specific launcher protocols clicked from electerm.
- Unexpected editor launches after SFTP/SSH file browsing, especially filenames containing shell metacharacters, spaces/newlines, URL encodings, or path traversal sequences.
- Widget directories or cached extension bundles modified shortly before a suspicious session.
- Secrets that were only present in process environment variables on hosts where renderer compromise is plausible.

