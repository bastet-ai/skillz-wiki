# rclone `--rc-serve` inline-remote command boundary checks

Source: hourly offensive-security scan, 2026-07-21 GitHub Advisory Database update. Primary entry: [GHSA-qw24-gh76-8rvv](https://github.com/advisories/GHSA-qw24-gh76-8rvv) / CVE-2026-49980.

This advisory is durable for operators because it exposes a reusable local-control-plane chain: an unauthenticated rclone Remote Control listener started with `--rc-serve` parses a remote specification from ordinary `GET` or `HEAD` paths, initializes caller-selected inline backends, and can cross into local command execution as the rclone process user. Browser subresource requests can deliver the same path to a localhost-only listener, so loopback binding alone does not remove the browser-to-local-service boundary.

!!! warning "Authorized validation only"
    Use a disposable rclone process, empty temporary config, inert command marker, synthetic files, and a lab browser profile. Do not target customer storage, real remotes, credentials, cloud metadata, internal services, production files, shell startup paths, or shared workstation RC listeners. Do not enable or reconfigure RC on a production host for testing.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-qw24-gh76-8rvv](https://github.com/advisories/GHSA-qw24-gh76-8rvv) / CVE-2026-49980 | rclone `rcd --rc-serve` / RC file-serving paths | unauthenticated `GET` and `HEAD` paths of the form `/[remote:path]/object` pass the URL-derived remote into backend initialization; inline backend options can execute local commands | Treat RC file serving as an unauthenticated backend-construction boundary, including direct network reachability and browser-to-loopback request delivery. |

Affected ranges and controls reported by the advisory:

- rclone `1.55.0` through `1.74.2`: inline backend option overrides make command execution reachable;
- rclone `1.46.0` through `1.74.2`: the same route family can expose local files through inline `local` remotes, although releases before `1.55.0` lack the command-execution path;
- first patched release: rclone `1.74.3`;
- required conditions: RC enabled, listener reachable, no global RC HTTP authentication, and `--rc-serve` enabled.

The advisory also reports that inline `global.*` options can mutate process-wide rclone configuration, including proxy state. Keep public validation focused on one inert marker and configuration decision evidence; do not redirect real process traffic.

## Recon and preconditions

1. **Establish the exact startup mode.** Look for `rclone rcd`, `--rc`, and specifically `--rc-serve` in service units, containers, desktop integrations, CI jobs, or process arguments. An installed rclone binary is not sufficient.
2. **Record listener topology.** Capture bind address, port, TLS, reverse proxy, and whether `--rc-user`, `--rc-pass`, `--rc-htpasswd`, or equivalent global HTTP authentication is active.
3. **Map request principals.** Separate remote network callers, same-host processes, and a browser on the workstation. Loopback exposure can still matter when a public page can issue an `<img>`-style subresource request.
4. **Confirm version-specific impact.** Distinguish backend initialization, local-file selection, global-option mutation, and command execution. Do not claim command execution for versions before `1.55.0` based only on the shared route.
5. **Use a throwaway process identity.** The lab rclone user should have no credentials, mounted customer data, sensitive environment variables, or access outside a dedicated temporary tree.

High-value targets include backup/orchestration hosts, developer workstations, agent sandboxes, shared service containers, and CI runners where rclone runs with more authority than the HTTP caller. Report that authority as impact context; do not exercise unrelated filesystem or storage access.

## Replayable validation boundaries

### Unauthenticated path-to-backend initialization matrix

1. Start an affected rclone release in a disposable container or VM with:
   - an empty temporary config and home directory;
   - no cloud credentials or customer mounts;
   - RC bound only to the lab interface;
   - `--rc-serve` enabled; and
   - one temporary directory for canary files and command markers.
2. Send baseline `GET` and `HEAD` requests to a normal nonexistent remote path and record status, response length, and whether backend initialization occurs.
3. Repeat with an inline remote path whose only backend-initialization effect is writing a unique inert marker under the temporary lab directory. Keep the exact command-option syntax in private evidence; the public artifact needs only the redacted path shape, process trace, and marker result.
4. Positive evidence is marker creation by the rclone process after an unauthenticated `GET` or `HEAD`. Stop immediately—do not open a shell, read environment variables, make network callbacks, or modify persistent configuration.
5. Repeat with:
   - rclone `1.74.3` or newer;
   - global RC HTTP authentication enabled and no credentials supplied;
   - `--rc-serve` disabled; and
   - a pre-`1.55.0` release if the assessment must separate local-file behavior from command execution.
6. Record the remote string as a redacted structural representation rather than publishing a copy-paste command-execution URL.

Report this as **unauthenticated RC file-serving path -> inline backend initialization -> inert command marker as the rclone process user**. Include rclone version, process identity, startup flags, authentication state, request method, marker path, and patched controls.

### Local-file selection control

For versions in the broader `1.46.0` through `1.74.2` range, create one synthetic file inside the disposable lab tree and test whether an inline `local` remote can select it through the unauthenticated file-serving path.

- Use only the known synthetic file; never request `/etc`, home directories, environment files, configs, keys, logs, or customer data.
- Compare `GET` with `HEAD` and distinguish response-body disclosure from backend initialization alone.
- Repeat with authentication enabled, `--rc-serve` disabled, and `1.74.3+`.

Report this separately as **unauthenticated URL-derived inline local remote -> synthetic file read**. Do not infer arbitrary command execution for old versions unless the command-capable inline option path is independently proven.

### Browser-to-loopback delivery check

1. Use an owned public test origin and disposable browser profile on the lab workstation.
2. Embed only a harmless `<img>` or equivalent subresource whose URL targets the lab RC listener and the inert marker path.
3. Record whether the browser sends the request and whether rclone creates the marker. Response readability is not required for a state-changing blind request.
4. Compare Firefox and the actual browser in scope, ordinary public HTTP/HTTPS origins, RC authentication enabled/disabled, and patched rclone.
5. Distinguish request delivery from CORS-enabled response access. Do not claim browser-readable local data when the proof shows only blind request delivery and marker creation.

Report this as **public browser origin -> loopback RC subresource request -> unauthenticated backend initialization**. Include browser/version, page origin, request method, listener address, authentication state, and marker-only result.

## Evidence and reporting

Capture:

- rclone version and exact RC startup flags;
- listener address, reverse-proxy topology, TLS, and global RC HTTP authentication;
- caller class: remote client, same-host process, or browser origin;
- escaped/redacted request path and method;
- backend-initialization trace and inert marker ownership;
- vulnerable-versus-fixed decision table; and
- whether the proven impact is backend initialization, synthetic local-file read, process-global option mutation, or command execution.

Lead with the exact crossed boundary: **unauthenticated URL path -> inline rclone backend configuration -> process-context side effect**. Do not publish weaponized URLs, real remote configurations, credentials, production filesystem paths, or command output beyond a unique inert marker.
