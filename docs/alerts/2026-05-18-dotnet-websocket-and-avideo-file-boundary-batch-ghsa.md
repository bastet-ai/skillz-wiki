# .NET, WebSocket, and AVideo file-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-9v76-4qcc-frgh](https://github.com/advisories/GHSA-9v76-4qcc-frgh),
[GHSA-rg75-q538-x34v](https://github.com/advisories/GHSA-rg75-q538-x34v),
[GHSA-58qx-3vcg-4xpx](https://github.com/advisories/GHSA-58qx-3vcg-4xpx), and
[GHSA-3mjv-375j-6h92](https://github.com/advisories/GHSA-3mjv-375j-6h92).

This batch is durable because the advisories repeat three common boundary failures: framework runtimes turning malformed network or file input into process-wide impact, WebSocket APIs leaking process memory through type confusion around close reasons, and admin-only migration helpers treating attacker-selected filenames as trusted maintenance scripts.

## What changed

- **ASP.NET Core / .NET 8, 9, and 10** fixed a network-triggerable denial-of-service issue caused by an infinite-loop condition. Patched runtime trains are 8.0.27, 9.0.16, and 10.0.8 across supported platforms.
- **.NET Core runtime 8, 9, and 10** fixed an absolute-path traversal / tampering issue where specially crafted files could cause writes of arbitrary files and directories to certain locations. Patched trains are 8.0.27, 9.0.16, and 10.0.8.
- **`ws` for Node.js** fixed uninitialized memory disclosure in `websocket.close()` when a `TypedArray` is supplied as the close reason. Patch to `ws` 8.20.1 or later.
- **AVideo `view/update.php`** discloses arbitrary text files to authenticated administrators by concatenating `$_POST['updateFile']` under `updatedb/` and passing the resulting path to `file()` without path containment. `WWBN/AVideo <= 29.0` is affected; no patched version was listed in the advisory at scan time.

## Operator triage

1. Patch internet-facing ASP.NET Core services first, especially unauthenticated APIs, reverse-proxy frontends, upload processors, and high-traffic apps where a single malformed request can tie up worker capacity.
2. Patch build and job hosts running .NET workloads that process attacker-supplied archives, project files, templates, or plugin bundles; file-write tampering often becomes credential overwrite, config poisoning, or persistence when the process has broad filesystem access.
3. Upgrade `ws` to 8.20.1+ in WebSocket gateways, collaboration apps, agent backchannels, and developer tooling that may echo or log close reasons.
4. For AVideo, restrict admin access, disable direct access to `view/update.php` outside maintenance windows, and treat any admin account compromise as a potential file-disclosure incident.
5. Where immediate framework patching is blocked, add compensating controls: request-size and concurrency limits, worker recycling, WAF rules for known probes, least-privilege service accounts, and filesystem ACLs that keep secrets outside runtime-writable/readable paths.

## Replayable validation boundaries

- **Framework network DoS boundary:** replay malformed requests against patched ASP.NET Core services in a lab and verify workers recover without sustained CPU spin, thread starvation, or request-queue collapse.
- **Runtime file-write boundary:** process crafted files through every .NET import/build/conversion path and verify outputs cannot escape the intended extraction or working directory, including absolute paths, drive-letter paths, UNC paths, symlinks, and dot segments.
- **WebSocket memory boundary:** call `close()` with `TypedArray`, `ArrayBuffer`, invalid UTF-8, and oversized reason payloads; peers must receive only initialized, bounded, spec-compliant close data.
- **AVideo update-file boundary:** submit traversal values, absolute paths, URL-like paths, symlinked update files, and Unicode separator variants to the update endpoint; the handler must resolve to an allowlisted migration basename under `updatedb/` or fail closed.
- **Secret placement boundary:** confirm `.env`, app configs, database dumps, logs, and private keys are not readable by web-server users or located in sibling directories reachable through relative traversal from web roots.

## Durable controls

- Keep framework runtimes on the same patch cadence as application dependencies; runtime advisories can be exploitable even when app code and packages have not changed.
- Treat file import, migration, archive, and update helpers as untrusted-input parsers, not operator-only shortcuts. Admin authentication reduces exposure but does not make path input safe.
- Canonicalize paths with final realpath containment checks, allowlist migration filenames, reject absolute paths and separators, and avoid echoing file contents back to operators unless the file is explicitly selected from a trusted manifest.
- Zero-initialize or copy buffers before exposing them across protocol boundaries; typed views over memory should never be serialized directly into network-visible fields.
- Run web apps and maintenance endpoints with read access only to the files they need. Secrets should be outside web roots and unreadable by the application identity unless required at runtime.
