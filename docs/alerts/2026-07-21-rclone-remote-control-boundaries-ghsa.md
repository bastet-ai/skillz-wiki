# rclone remote-control, path, symlink, and metadata boundary checks

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

## August 5 follow-up: untrusted-remote filesystem boundaries

Four reviewed rclone advisories published on August 5 extend the operator model beyond Remote Control. Three yield durable validation paths; the RC stack-trace record is useful only as adjacent version and error-surface context.

| Advisory | Boundary | Affected / fixed range | Bounded proof |
| --- | --- | --- | --- |
| [GHSA-cf44-9pgv-m4xc](https://github.com/advisories/GHSA-cf44-9pgv-m4xc) / CVE-2026-54572 | an attacker-controlled `.rclonelink` body becomes a local symlink target; a later object can follow that link outside the destination | `<= 1.74.3`; fixed in `1.74.4` | patched symlink and file-open recorders prove the final canonical path would leave a disposable destination |
| [GHSA-45pq-889g-fcgh](https://github.com/advisories/GHSA-45pq-889g-fcgh) / CVE-2026-71309 | `serve restic` accepts a leading parent path and passes it to the configured backend, whose path joining may escape its root | `1.40.0` through `1.74.4`; fixed in `1.75.0` | a synthetic sibling marker plus backend path recorder proves root escape without reading or changing unrelated objects |
| [GHSA-945v-v9p3-v5xw](https://github.com/advisories/GHSA-945v-v9p3-v5xw) | local `--metadata` applies source-supplied ownership and Go file-mode bits to copied content | `<= 1.74.3`; fixed in `1.74.4` | a patched `chown`/`chmod` sink records requested IDs and special bits for an inert file |
| [GHSA-gwfq-86j8-7qhv](https://github.com/advisories/GHSA-gwfq-86j8-7qhv) | recovered RC panics can return stack and path details in API errors | `<= 1.74.4`; fixed in `1.75.0` | ordinary synthetic error comparison only; never select host files to manufacture a panic |

!!! warning "No outside-root writes or privileged artifacts"
    Use an unprivileged disposable rclone process, synthetic remote objects, temporary destination and sibling directories, patched filesystem sinks, and no-op ownership/mode recorders. Never overwrite startup files, SSH keys, scheduled tasks, service files, repositories, backups, or customer objects. Do not create setuid/setgid files, run copied binaries, follow links into the host, or test delete semantics against a real backend.

### Symlink-following copy matrix

The relevant chain is ordered: untrusted remote object -> translated local symlink -> later descendant object -> filesystem operation follows the planted link. Test the chain without allowing the final write:

1. Create a temporary destination and a sibling directory containing one unique marker filename. Neither directory should contain sensitive data.
2. Replace or interpose the local backend's symlink and file-open operations with recorders. The symlink recorder logs the requested target but creates only an inert in-root placeholder; the open recorder resolves the would-be final path and denies the syscall.
3. Seed a synthetic source listing with a translated-link object followed lexically by one descendant object. Record object order explicitly.
4. Compare relative in-root, parent-relative, and absolute symlink targets. Do not use real home or system paths.
5. Require evidence that the affected build requests an outside-destination final path and that `1.74.4+` rejects or safely handles the same fixture.

Report **untrusted remote link metadata -> translated local symlink -> descendant write would escape destination**. A symlink target alone is weaker than proof that a later operation follows it; preserve both recorder events.

### `serve restic` backend-root matrix

The advisory identifies a backend-independent acceptance point followed by backend-specific propagation. Do not assume every backend escapes identically.

1. Start `rclone serve restic` in an isolated lab with authentication, one empty backend root, and no reusable credentials.
2. Instrument the middleware-to-backend path value and the backend's final object selector.
3. Seed an in-root canary and a synthetic sibling-root canary with distinct hashes.
4. Compare a normal object path, an encoded harmless separator control, and one parent-path structural test generated by the lab client.
5. Exercise `HEAD` or a denied read recorder first. Test write/delete dispatch only through no-op recorders; never mutate the sibling canary.
6. Repeat across the actual backend in scope and `1.75.0+`.

Evidence should bind **request path -> middleware context path -> backend selector -> final canonical/object key**. Report each backend separately. A WebDAV result does not prove identical FTP, SFTP, cloud-object, or local behavior.

### Metadata-to-privilege recorder

Test metadata handling without generating a privileged file:

1. Run rclone as an unprivileged user in a disposable mount or namespace.
2. Create one inert non-executable text object on the synthetic source.
3. Attach ordinary mode/ownership metadata as the baseline, then a canary value containing a special-mode bit and a numeric owner that the test user cannot assume.
4. Patch `chown` and `chmod` immediately before the operating-system call. Record the requested path, uid, gid, raw parsed mode, and masked ordinary permission bits, then return a denied result.
5. Compare copy with and without `--metadata`, affected `<=1.74.3`, and fixed `1.74.4+`.

The positive is a sink record showing source-controlled ownership or special-mode bits would be applied to attacker-controlled content. Do not create an executable, invoke the copied file, run the test as root, or treat ordinary permission preservation as privilege escalation.

### Follow-up evidence fields

```text
rclone version and command family:
Source trust and synthetic object order:
Destination/backend root:
Raw selector and canonical final path/key:
Symlink target recorder:
File-open/write/delete recorder:
Requested uid/gid/mode recorder:
Affected-versus-fixed result:
Strongest supported claim:
Excluded write, execution, or disclosure claims:
```

Keep the RC error disclosure as supporting recon only. A normal API error containing a synthetic path or build detail can establish response behavior, but do not repoint configuration at host files, force panics on a shared service, or publish stack addresses.

## August 5 second follow-up: encoding, archive, tenant-path, protocol, and redirect boundaries

Eight additional reviewed records expand the same invariant: after filename decoding, URL normalization, archive joining, or redirects, the final path, command frame, principal, and transport must retain the authority selected by the operator.

| Advisory | Boundary | Affected / fixed range |
| --- | --- | --- |
| [GHSA-7p4m-qxvv-g567](https://github.com/advisories/GHSA-7p4m-qxvv-g567) | non-default local filename encodings can decode standard object names into native parent paths | `1.51.0` through `1.74.4`; fixed in `1.75.0` |
| [GHSA-4vr5-p2gc-h23p](https://github.com/advisories/GHSA-4vr5-p2gc-h23p) | `archive extract` joins an entry containing parent components to an S3 destination prefix | `<= 1.74.3`; fixed in `1.74.4` |
| [GHSA-fqj9-69pf-6pjg](https://github.com/advisories/GHSA-fqj9-69pf-6pjg) | `serve restic --private-repos` authorizes one path representation but derives the backend selector from an uncanonicalized one | `<= 1.74.3`; fixed in `1.74.4` |
| [GHSA-8v25-v8p6-qf7v](https://github.com/advisories/GHSA-8v25-v8p6-qf7v) | `serve s3` joins bucket and object names so parent segments can select root-level objects inside the configured serve root | `<= 1.74.3`; fixed in `1.74.4` |
| [GHSA-2m8m-jhrm-w6j2](https://github.com/advisories/GHSA-2m8m-jhrm-w6j2) | SFTP filenames reach PowerShell hash commands through ASCII-only quote handling | `<= 1.74.4`; fixed in `1.75.0` |
| [GHSA-8c48-q9wj-3w37](https://github.com/advisories/GHSA-8c48-q9wj-3w37) | a custom FTP encoding can restore CR/LF before a filename enters the control channel | `< 1.75.0`; fixed in `1.75.0` |
| [GHSA-gx4c-2hqx-cw2r](https://github.com/advisories/GHSA-gx4c-2hqx-cw2r) and [GHSA-h4mf-4v27-hggj](https://github.com/advisories/GHSA-h4mf-4v27-hggj) | same-host HTTPS-to-HTTP redirects preserve S3 STS or WebDAV Basic/Cookie credentials | S3 `<= 1.74.3`, fixed in `1.74.4`; WebDAV `<= 1.74.0`, fixed in `1.75.0` |
| [GHSA-8mxv-9xhp-86h4](https://github.com/advisories/GHSA-8mxv-9xhp-86h4) | S3 redirects retain IBM IAM bearer tokens or SSE-C headers across weaker or foreign destinations | `<= 1.74.0`; fixed in `1.75.0` |

The ranges above are those recorded by the reviewed advisories. Confirm the exact backend, build, and configuration in scope. Several paths require non-default encodings, a feature flag, an unsafe redirect emitted by an otherwise legitimate endpoint, or a lower-trust source namespace.

!!! warning "Patched sinks, fake credentials, and disposable roots only"
    Use synthetic object names, archives, users, repositories, protocol servers, fake tokens, and patched filesystem, command, FTP, and HTTP transports. Never write outside a temporary root, read or alter another backup, execute PowerShell, inject a real FTP command, expose reusable credentials, downgrade production transport, or target customer storage.

### Post-decoding and archive containment matrix

Build one harness that records the original object/archive name, configured encoding, decoded portable path, native path, selected destination root/prefix, and final canonical path or object key. Replace open, create, overwrite, and cloud-write operations with deny-by-default recorders.

Exercise:

- default local encoding, `Slash`, `None`, `Raw`, and platform-relevant masks that omit `Dot` or `BackSlash`;
- fullwidth-dot components, native separators, ordinary dotted names, and benign Unicode controls;
- archive entries that are in-prefix, contain parent components, begin with `./`, or use platform separators; and
- local and object-store destinations, keeping every target inside disposable buckets or directories.

A bounded positive is **untrusted standard/archive name -> conversion or join -> final selector leaves the chosen destination -> denied sink records only the synthetic sibling marker**. Default encoding rejecting the fixture does not clear a deployment that explicitly uses a weaker custom encoding. Enforce containment after conversion to the platform-native path; checking only whether an encoder mask contains `Dot` misses separator-specific variants.

### Multi-user service path normalization

Use two fake Basic-auth users, two empty restic prefixes, two synthetic S3 buckets, and distinct random marker object IDs. Instrument raw request target, framework-decoded route parameters, authenticated username, private-repository authorization input, backend path input, normalized final selector, and no-op read/write/delete sink.

Compare ordinary paths with literal and encoded dot-segment variants. For `serve restic --private-repos`, require the authenticated username and canonical repository prefix to agree after one shared normalization pipeline. For `serve s3`, bind bucket authorization to the final normalized object key, not the pre-join bucket segment.

The proof is **user A passes the route-level check -> a different path representation selects user B's repository or a root-level synthetic object -> denied backend sink records the foreign marker ID**. Do not return object content, overwrite a config, or issue a real delete. Note that the `serve s3` record describes escape from a bucket directory into the configured serve root, not escape from the rclone remote itself.

### String-to-protocol grammar recorders

For SFTP, replace process execution with an argv and PowerShell-parser recorder. Feed ordinary names, ASCII quote controls, and inert Unicode quote markers through the real filename conversion and hash-command builder. A positive requires the final PowerShell parse tree to contain syntax outside the intended single path literal. Stop before process creation and do not publish an executable payload.

For FTP, use a local fake server whose control-channel parser records command boundaries but refuses mutations. Compare default encoding with explicitly configured masks that preserve CR/LF. Feed a filename containing only an inert second-command marker and prove whether the client emits one command frame or two. Do not use `DELE`, upload executable content, or connect to an operational FTP service.

Keep configuration preconditions in the report. If the source actor already has equivalent rights on the SFTP/FTP destination, the parser defect may have no authority gain; establish the lower-trust source to stronger destination boundary separately.

### Redirect authority and transport matrix

Use an owned TLS endpoint, owned plaintext listener, locally trusted test CA, and fake credentials with no external value. Patch the final sender to log only header names and hashes. Test same-host and cross-host redirects across HTTPS-to-HTTPS, HTTPS-to-HTTP, and port changes.

Record for every hop:

- original and destination scheme, hostname, and effective port;
- resolved and selected peer;
- redirect policy decision;
- presence/hash of `Authorization`, `Cookie`, `X-Amz-Security-Token`, IBM IAM bearer, SSE-C, and copy-source SSE-C headers; and
- whether the request would traverse plaintext.

The secure origin comparison is the tuple **scheme + canonical host + effective port**. Any downgrade must fail closed; sensitive credentials should not be replayed merely because `URL.Host` is unchanged. A bounded positive is **trusted fake credential reaches the initial owned HTTPS peer -> redirect changes authority or transport strength -> patched next-hop recorder observes the credential header**.

Do not frame a malicious original endpoint as the primary attacker: it already receives the credentials. Establish the credible boundary as a legitimate endpoint, gateway, accelerator, or redirect behavior followed by an adjacent/on-path observer or a foreign redirect origin.

### Second-follow-up evidence fields

```text
rclone version, backend, and exact feature flags:
Source actor and destination authority:
Raw object, archive, or URL representation:
Configured filename encoding:
Decoded / native / canonical path or key:
Authenticated user and authorized prefix:
Protocol parse tree or command-frame count:
Redirect hop scheme / host / effective port:
Fake credential header presence and hash:
Denied filesystem / backend / process / network sink:
Affected-versus-fixed result:
Deployment-specific preconditions:
Strongest supported claim and excluded effects:
```


## September 16 follow-up: the `--auth-proxy` auth chain and RC per-server config drift (9 GHSAs)

A nine-advisory rclone wave published 2026-09-10 lands on the same remote-control/serve trust surface and promotes two durable operator patterns: **documentation-blessed authentication configurations that authenticate nobody**, and **request-supplied per-server options checked against process-global state**. All proofs stay in disposable rclone processes with empty temp configs and fake credentials.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-xwwr-4h3p-r22c](https://github.com/advisories/GHSA-xwwr-4h3p-r22c) / CVE-2026-88018 (critical, 9.8) | `rclone serve s3 --auth-proxy` | The middleware registers the client-chosen access key from the request's own `Authorization` header into the signature store with `s3Secret` defaulting to `""` when `--auth-key` is unset; SigV4 then verifies the client's signature against the empty key the client already knows. The proxy script never receives a real secret for S3 (unlike webdav/ftp/sftp), so no proxy script can distinguish a key holder from an attacker who picked the same string | Full SigV4 bypass in the exact standalone configuration the docs and reference `bin/test_proxy.py` present. For any auth-proxy deployment, fingerprint serve mode + presence of `--auth-key` first; a self-signed SigV4 request with a client-picked key is the bounded proof. |
| [GHSA-p569-5gjg-9cmj](https://github.com/advisories/GHSA-p569-5gjg-9cmj) / CVE-2026-88044 (critical, 9.1) | RC `serve/start` FTP/S3 adapters | Per-server `proxyOpt` from the RC request is parsed but constructors gate proxy auth on the **process-global** `proxy.Opt.AuthProxy`; with only request-local config the supplied auth proxy is silently ignored — FTP falls back to `anonymous`/any-password read-write-delete, S3 to the fixed RC filesystem behind the bare `auth_key` | Request-supplied security config validated against global state = silently unenforced. For any RC listener that can start servers, diff request-local vs global option resolution; prove with an `anonymous` login against a lab FTP fallback and a synthetic backend marker. |
| [GHSA-c476-6w5q-jw77](https://github.com/advisories/GHSA-c476-6w5q-jw77) / CVE-2026-88017 (high) | rclone FTP auth-proxy | Cross-session backend confusion in the proxy-backed FTP path | Treat proxy-session→backend binding as per-connection state; multi-session decision tables in a lab. |
| [GHSA-2p48-j3qc-rx9f](https://github.com/advisories/GHSA-2p48-j3qc-rx9f) / CVE-2026-88045 (high) | rclone S3 server | Multipart declared-length memory exhaustion | Declared-length trust on multipart uploads; lab-only resource canaries, skip on shared targets. |
| [GHSA-38xv-hf3p-h7mq](https://github.com/advisories/GHSA-38xv-hf3p-h7mq) / CVE-2026-88046 (medium) | rclone upload paths | Source object names escape the configured root on upload | Same generated-filename/root-containment class as the archive page; sibling-canary proof only. |
| [GHSA-66hp-wgxq-6f5q](https://github.com/advisories/GHSA-66hp-wgxq-6f5q) / CVE-2026-88014 (medium) | `rclone archive`/zip | Zip Slip via unsanitized entry names escaping the archive namespace | Fold under the existing archive-extraction methodology; listing-level proof. |
| [GHSA-f8g7-2xjc-7mfh](https://github.com/advisories/GHSA-f8g7-2xjc-7mfh) / CVE-2026-88016 (medium) | `rclone local --links` | chmod/chown/chtimes applied through a planted symlink outside the tree | Symlinked metadata side channel; temp-dir marker proof. |
| [GHSA-p6m2-r3w9-mpxw](https://github.com/advisories/GHSA-p6m2-r3w9-mpxw) / CVE-2026-88015 (medium) | `rclone local` | Crafted `Range` request against a translated symlink panics | Availability-only; tracked, not standalone guidance. |
| [GHSA-486v-q2wf-fp2r](https://github.com/advisories/GHSA-486v-q2wf-fp2r) / CVE-2026-88013 (low) | rclone http backend | Custom/auth headers forwarded to a different host on redirect | Header-leak-on-redirect fixture for every backend that follows redirects. |

First patched release for the wave: rclone 1.75.1 (per-server proxy bypass affects 1.70.0–1.75.0).

Durable heuristics:

1. **Fingerprint the auth mode, not the auth intent.** For any serve-with-proxy deployment (rclone, gateways, sidecars), determine the *exact flag/env combination* before trusting the auth story; docs-blessed "auth proxy alone" configurations can be no-auth by construction.
2. **Global-vs-request config resolution audit.** Any control plane that starts protocol servers from request-supplied option objects must be diffed for options that are parsed but gated on global state; the divergence is the finding.
3. **Client-known HMAC keys.** If the server-side HMAC key is derived from or defaulted to anything the client controls or knows (including `""`), signature verification is a formality; test with a self-computed signature using a client-chosen key.

!!! warning "Authorized validation only"
    Same boundaries as above: disposable rclone processes, temp configs, fake keys, lab backends. Never exercise auth-proxy bypasses against customer storage endpoints or read real buckets.
