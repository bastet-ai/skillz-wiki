# 3X-UI authenticated log-path import to arbitrary file write and RCE

Source: GitHub Security Advisories, 2026-08-24 hourly scan: [GHSA-jm48-m3rr-9hgg](https://github.com/advisories/GHSA-jm48-m3rr-9hgg) / [CVE-2026-55477](https://nvd.nist.gov/vuln/detail/CVE-2026-55477) (high). Affected panel versions are `< v3.3.1`; `v3.3.1` is the fixed release.

This is a durable, replayable operator chain rather than a one-off advisory: a trusted admin-config value (the Xray `log.access` / `log.error` path) crosses an import/import-editor boundary into a real filesystem write performed by the proxy data plane. The reusable pattern is **admin-configured path reaches a downstream process that writes attacker-controlled content to that path**, the same family as log-path, cache-path, and report-output path controls found across VPN/proxy panels and CMS export writers. It matters for red-team work because the panel is routinely deployed as a long-lived, externally reachable proxy node, and the write is performed as the user that owns the proxy service, which is frequently `root`.

## What changed

The panel exposes a database import (and a raw Xray configuration editor) that both write the `xrayTemplateConfig.log.access` / `log.error` values into the live Xray configuration. Until `v3.3.1`, those path values are used verbatim when Xray opens its log file. The content written to the log on an inbound connection includes the connecting client's `email` field, which an admin can set on a client. The result is an **arbitrary file write** (create, append, or corrupt) at a fully attacker-chosen path as the Xray process user.

The chain has three trust transitions, each a separate thing to validate:

1. **Import trust**, the database import accepts the exported SQLite file and re-applies the `log.access` / `log.error` values without constraining the path to the panel log folder.
2. **Path trust**, `resolveXrayLogPaths` did not confine `log.access` / `log.error` to the panel log directory, so an absolute path or `..` sequence names any file the Xray process can write.
3. **Content trust**, the inbound client `email` field content is written into the access log, giving the attacker the bytes that land at the chosen path.

Fixed in `v3.3.1`: `resolveXrayLogPaths` (`internal/web/service/xray.go`) reduces every configured log path to its base filename under `config.GetLogFolder()`, so absolute paths and `..` traversal can no longer escape the log folder (while `""` / `"none"` still disable logging). The confinement runs at Xray config-generation time, so it covers both the database import and the raw config editor. The client `email` field is also independently validated (control characters, spaces, and slashes rejected).

## Operator triage

1. **Fingerprint the panel.** Identify externally reachable 3X-UI panel web UIs (Xray/Shadowsocks-style proxy panels are a common target class in cloud and homelab deployments). Capture the panel version; any `< v3.3.1` is in range.
2. **Confirm the write user.** The impact ceiling is set by the user that owns the Xray process. A panel where Xray runs as `root` turns the file write into root-level persistent access; a user-scoped Xray is still an arbitrary file write within that user's writable surface.
3. **Identify a writable, high-value target.** The primitive is "write attacker-controlled bytes to a path Xray can write." Classic targets: an SSH `authorized_keys` for the process user, a cron drop directory, a config the service re-reads, or a web root for a second writable target. Choose one synthetic canary in a lab.
4. **Separate the three trust transitions in the report.** Import acceptance, path confinement, and log-content write are each independently testable and each maps to a distinct control the fix added.

## Replayable validation boundaries

All of this is validated in an authorized lab with a disposable 3X-UI panel and a disposable target file. Do not target production proxy nodes, do not create real admin accounts on managed systems, and do not exfiltrate credentials from a live host.

### Lab setup

- A 3X-UI panel `< v3.3.1` (affected) and a `v3.3.1+` (control), each with a fresh, throwaway data directory and a panel admin account.
- An Xray inbound configured on the affected panel with a synthetic client.
- A synthetic target: a marker file path the Xray process can write (for example a path under the process user's home that will receive a canary line), plus a second "secure" expectation where the write is confined to the panel log folder.
- A second lab node or container acting as the inbound peer that connects so an access-log line is emitted.

### Import trust check

1. As the panel admin on the affected panel, export the panel SQLite database through the normal export flow.
2. Record the current `xrayTemplateConfig.log.access` value, then set it to an inert absolute path inside the lab that a real host would treat as a sensitive location (e.g. a marker file that, in a lab, stands in for an `authorized_keys`).
3. Import the modified database back into the panel.
4. Record whether the import accepted the out-of-folder path verbatim. The vulnerable result is the imported value surviving into the live Xray configuration unchanged.

### Path confinement check

1. With the path set to an absolute or `..`-shaped value, trigger one inbound connection from the lab peer.
2. Observe where Xray writes the access-log line: the vulnerable result is a line at the attacker-chosen path; the secure result (`v3.3.1+`) is a line confined to the panel log folder under the same base filename.
3. Repeat with a `..` sequence and with `""` / `"none"` to confirm logging-disable behavior is preserved after the fix.

### Content-to-write check (the RCE-shaped primitive)

1. Put a controlled, unmistakable canary string (never a real key or credential) into the inbound client `email` field.
2. Trigger an inbound connection and capture the bytes written to the configured log path.
3. The vulnerable result is the canary appearing at the attacker-chosen path. This proves the arbitrary-file-write primitive. Do not complete the SSH-key-to-login step on any live system; in a lab the proof is the canary landing at the chosen path, not a real shell.
4. On the `v3.3.1+` control, confirm the same canary is confined to the log folder and that the `email` field rejects control characters, spaces, and slashes.

## Reporting heuristics

- Frame the finding as **admin-configured log path -> import/config-editor trust -> Xray data-plane log write -> arbitrary file write as the proxy process user**. The version range is `< v3.3.1`; the fix confines both log paths to the panel log folder at config-generation time.
- Include, per transition: the exact field (`xrayTemplateConfig.log.access` / `log.error`), the entry point (database import vs raw config editor), the resolved path, and the canary effect (which bytes landed where).
- State the write-user identity explicitly, because it is the difference between "arbitrary file write" and "persistent host access." Note whether the lab Xray ran as root or a scoped user.
- Separate the three controls the fix added (path confinement at generation, both-vector coverage via import *and* editor, and `email` field sanitization) so the remediation mapping is clear.
- Distinguish the primitive from RCE: the reliable primitive is arbitrary file write; code execution depends on a suitable writable target and the process privileges. Do not claim RCE without a controlled lab target that executes.

## Safety

- **Authorized, in-scope targets only.** These panels are often production proxy infrastructure; coordinating with the operator and working in a lab mirror is mandatory.
- **No live credential planting.** Never write a real SSH key, token, or config value to a live host. The lab proof is a synthetic canary at a synthetic path.
- **No destructive import on shared state.** Only import a modified database into an isolated disposable panel; never into a panel with real clients or configuration you must preserve.
- **No RCE from the write alone.** The file write is the finding; escalation to code execution is a separate, target-specific step that must be proven in isolation before being claimed.
