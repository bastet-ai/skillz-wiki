# UniFi OS and Lantronix appliance boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: CISA KEV [CVE-2025-67038](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CVE-2026-34908](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CVE-2026-34909](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [CVE-2026-34910](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); CVE records for [Lantronix EDS5000](https://cveawg.mitre.org/api/cve/CVE-2025-67038), [UniFi OS access control](https://cveawg.mitre.org/api/cve/CVE-2026-34908), [UniFi OS path traversal](https://cveawg.mitre.org/api/cve/CVE-2026-34909), and [UniFi OS command injection](https://cveawg.mitre.org/api/cve/CVE-2026-34910); Ubiquiti [Security Advisory Bulletin 064](https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b); CISA ICS advisory [ICSA-26-069-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02).

These KEV additions are worth keeping as operator guidance because they expose repeatable appliance-management boundaries: network-reachable controller services that allow unauthorized state changes, path traversal from management routes into appliance files, command construction from device input fields, and login-failure logging paths that concatenate usernames into privileged shell commands.

## What changed

| Item | Confirmed detail | Operator value |
| --- | --- | --- |
| CVE-2025-67038 | The CVE record says Lantronix EDS5000 2.1.0.0R3 concatenated the failed-login username into an HTTP RPC log-writing shell command, allowing command injection executed with root privileges. | Treat authentication failure handlers and audit logging as command-execution surfaces on embedded devices; validate only with inert username canaries in an owned lab. |
| CVE-2026-34908 | Ubiquiti says UniFi OS devices before fixed releases had improper access control that allowed a network-accessible actor to make unauthorized system changes. | Add role and route-state matrices to UniFi assessments: anonymous, low-privilege, local-network, and admin requests should produce distinct authorization outcomes before any state mutation is attempted. |
| CVE-2026-34909 | Ubiquiti says UniFi OS devices had path traversal that could access underlying-system files and potentially be manipulated to access an underlying account. | Treat management file, backup, support, import/export, and static-download routes as filesystem boundaries; prove only with synthetic canary files on lab appliances. |
| CVE-2026-34910 | Ubiquiti says UniFi OS devices before fixed releases had improper input validation that allowed command injection from network access. | Add appliance input fields that reach diagnostics, shell wrappers, upgrade helpers, or network utilities to command-boundary testing, with marker-only effects. |

## Scope and prerequisites

Validate only against owned lab appliances or customer-approved targets. Required inputs:

- Product and version evidence for UniFi OS Server, UDM, Express, or Lantronix EDS5000.
- Network placement and exposure evidence: internet-facing, management VLAN, VPN-only, or local bench network.
- Approved test roles: anonymous network client, low-privilege UniFi user if available, and administrator for setup/negative controls.
- A pre-created canary plan for any file or command proof. Do not use production configs, backups, databases, logs, keys, or customer traffic.

## Recon workflow

1. **Inventory the appliance surface first.** Record management hostnames, ports, TLS certificate names, UI/API route families, and visible product/version banners from authorized discovery only.
2. **Build an actor matrix.** For every candidate route, capture behavior as unauthenticated network client, low-privilege user, and admin. The useful proof is the unexpected crossing between role and effect.
3. **Identify command-adjacent fields.** Prioritize diagnostics, ping/traceroute, DNS/NTP/syslog settings, firmware/update helpers, backup/restore names, import/export paths, and authentication/logging inputs.
4. **Identify filesystem-adjacent routes.** Prioritize support bundles, backup downloads, uploads, static file handlers, log viewers, and path-like query/body fields.
5. **Use negative controls.** Compare fixed and vulnerable versions when available, denied roles, benign values, canonicalized paths, and inert command markers.

## Non-destructive validation boundaries

### Lantronix EDS5000 failed-login command boundary

- Use only a bench device or lab firmware instance with no production serial devices, credentials, or network dependencies.
- Send failed-login attempts with unique benign username markers first and confirm only that the marker reaches expected logging context.
- If command-boundary proof is explicitly approved, use an inert side effect such as writing a marker into a disposable lab-only temp path. Do not publish payload strings that enable arbitrary root command execution.
- Evidence should show the username value, authentication-failure path, vulnerable version, and marker-only effect. Stop before persistence, configuration changes, or device takeover.

### UniFi OS access-control boundary

- Enumerate route families rather than guessing exploit payloads: system settings, users, sites, device adoption, backup/restore, applications, diagnostics, and local account routes.
- For each route, record expected authorization and observed response as anonymous, low-privilege, and admin clients.
- Positive evidence is limited to route reachability or a harmless disposable object/state marker created in a lab. Do not mutate production networks, device adoption state, firewall rules, VPN settings, or administrator accounts.

### UniFi OS path-traversal boundary

- Create a synthetic canary file only on a lab appliance or disposable test instance at a path pre-approved by the owner.
- Test traversal normalization through file-like parameters and route families that already serve files, bundles, backups, logs, uploads, or static assets.
- Do not read `/etc/shadow`, application databases, backups, SSH keys, tokens, controller configs, or customer files. The proof is a marker file, not secret exposure.
- Capture requested path, normalized path if visible, actor role, route class, and fixed-version behavior.

### UniFi OS command-injection boundary

- Keep command proof to marker-only effects in disposable lab paths, or use a mocked command sink when possible.
- Focus on input fields likely to cross into shell helpers: diagnostics hostnames, network settings, update parameters, import/export names, and backend task arguments.
- Avoid payloads that start services, modify users, alter networking, reboot devices, or retrieve secrets.
- Evidence should name the input field, role, backend action class, and inert marker result.

## Evidence to capture

- Exact product, model, app family, and version/build.
- Network exposure and authorization role used for each request.
- Route family and trust boundary: **auth failure field to shell**, **network actor to system change**, **path selector to appliance file**, or **input field to command wrapper**.
- Canary value and why it was disposable.
- Negative controls from fixed versions, denied users, canonical path rejection, or escaped command arguments.

## Safety constraints

- Do not publish weaponized command-injection strings, arbitrary file-read paths, or exploit chains that enable root access on live appliances.
- Do not read secrets, device databases, backups, controller tokens, SSH keys, VPN configs, customer network data, or logs containing real users.
- Do not change production UniFi adoption, routing, firewall, VPN, identity, update, or backup settings.
- Keep findings scoped to authorized appliance validation and canary-only proof.

## Reporting heuristic

Strong finding titles:

- `Failed-login username reaches privileged EDS5000 shell command boundary`
- `Network-reachable UniFi OS route permits unauthorized system-state change`
- `UniFi OS file route traverses to appliance canary outside intended root`
- `UniFi OS diagnostic input reaches command wrapper without safe argument binding`

In the body, include the affected version range, network reachability, actor role, exact route class, expected boundary, observed canary-only crossing, and negative controls. Avoid claiming broad appliance compromise unless the owner separately authorized a lab exploit chain and supplied non-sensitive evidence.

## September 23 follow-up: OpenEye Apex NVR — an appliance unlock-code design break is a chain blueprint, not a finding

Four-GHSA wave on OpenEye Apex NVR firmware ≤ 3.2.9.376 (design present since ≥ 2.2.3.4, fixed 3.5.4) that reads as a complete physical-to-remote takeover ladder on a camera appliance:

- **Hardcoded undocumented recovery account with shared, unrotatable credential** — unauthenticated entry into the password-reset workflow specifically ([CVE-2026-92928 / GHSA-2h86-6hmv-8f46](https://github.com/advisories/GHSA-2h86-6hmv-8f46), 6.5; advisory explicitly states: not normal admin access, "additional vulnerabilities are required").
- **Password-reset unlock code with no per-device secret or server-side cryptographic material** — offline code forgery from the console workflow ([CVE-2026-92930 / GHSA-g4p9-62qj-r366](https://github.com/advisories/GHSA-g4p9-62qj-r366), 6.2).
- **`X-Forwarded-For` trusted from any client on the non-TLS web interface** — spoof `127.0.0.1` to pass local-connection-only controls and read configuration ([CVE-2026-92929 / GHSA-2jx4-m53c-2mqc](https://github.com/advisories/GHSA-2jx4-m53c-2mqc), 5.3).
- **Backup-area configuration crosses into a shell command** — authenticated-admin cmdi as the `nvr` user via `recbackup` ([CVE-2026-94367 / GHSA-xr8v-x794-fm52](https://github.com/advisories/GHSA-xr8v-x794-fm52), 7.2).

Operator value:

1. **Each CVSS score understates the ladder; the chain is the finding.** Recovery account → forged unlock code → admin password reset → backup-config cmdi = unauthenticated remote to code execution, composed entirely from "low-severity" advisories. When assessing NVR/camera appliances, evaluate GHSA bundles on one product as a composition, not per-CVE.
2. **Unlock/recovery codes must be keyed to per-device secret material.** Same token-authority family as the Lantronix model+clock session tokens (Sept 22 page) and the Cotonti `md5(microtime())` tokens: ask what generator inputs exist on the device and whether any of them are *actually secret to that unit*. A "code" derivable from public/algorithmic inputs is a documentation artifact, not a credential.
3. **Loopback-as-identity on management planes**: `X-Forwarded-For`-to-localhost trust is the appliance twin of the 9router `X-9r-Real-Ip` pattern — the identity check reads a client-supplied header on the *non-TLS* interface; fingerprint whether the "local-only" controls gate on header vs socket peer, with a spoofed-header vs raw-socket positive/negative pair.
4. **Firmware vintage is the posture probe**: the advisories state the design was present "since at least 2.2.3.4" — these devices sit unpatched for years; fingerprint build from login page and treat ≤ 3.2.9.x as the chain-live population. Video-surveillance appliances additionally aggregate camera streams and operator credential stores, making them standing lateral-movement targets on internal recon.

## September 23 follow-up: Reachy Mini robot — an unauthenticated app-install endpoint is a package-manager supply-chain sink

The JFrog-documented three-step chain against the Reachy Mini robot appliance landed as two fresh GHSAs plus a referenced third:

- **Unauthenticated RCE via `POST /apps/install`** (CVE-2026-96455 / [GHSA-8w3q-4cmj-h32j](https://github.com/advisories/GHSA-8w3q-4cmj-h32j)): the daemon's app-install endpoint has **no auth dependency at all**, takes a body naming a **Hugging Face Space**, and installs it as a Python package through `uv`/`pip` — package install runs the package's build/setup code, and anyone can publish a public HF Space. The wireless model binds `0.0.0.0` (vendor comment: the robot must be LAN-reachable), so any host on the LAN owns the robot. The vendor's shipped "fix" (1.8.2 replaced wildcard CORS with a localhost/Tauri allowlist) closed only the **browser drive-by leg** — direct HTTP calls were never blocked.
- **Bluetooth shared-authentication flag** (CVE-2026-96456 / [GHSA-w8hv-46m4-pm2j](https://github.com/advisories/GHSA-w8hv-46m4-pm2j)): PIN auth sets a **single shared flag on the service instance**, and the BlueZ `WriteValue(self, value, options)` handler ignores `options` (the calling device's identity) — once *any* device authenticates, *every* device in radio range can send commands until reset. No PIN guesswork; an attacker waits in range for a legit user to unlock the session. Referenced legs of the same chain: unrestricted upload in the media-sounds API (CVE-2026-55419) places the script, path traversal in the Bluetooth command handler (CVE-2026-62661) runs it as root.
- Durable axes:
  1. **"Install from marketplace/registry" endpoints are supply-chain RCE by design when unauthenticated** — the attacker picks the package (HF Space, PyPI name, VSIX, MCP registry entry), and *install executes build code*. This is the mcp-atlassian/Open VSX server-side-credential + package-swap family in robotics/IoT form. Sweep every device daemon HTTP API for install/update/load-app routes and check the dependency chain for *any* credential check (this one had literally none — `Depends(get_app_manager)` is not auth).
  2. **CORS fixes ≠ authn fixes.** The vendor's response to an unauthenticated endpoint was tightening CORS. CORS gates only cross-origin *browser* calls; any network-position client bypasses it entirely. When a patch note mentions CORS for an API that should be access-controlled, treat it as a strong signal the endpoint itself is still open, and re-test with curl.
  3. **Per-session auth state must be keyed to the authenticated peer.** A boolean flag on the service object instead of per-connection identity (BlueZ passes the device identity in `options`; the handler drops it) is the embedded twin of the Lantronix session-file and shared-state items — audit question: *which object holds "authenticated", and does the request handler know who is asking?*
- Validation boundary: your own robot/device on an isolated lab RF/network; prove with a package whose `setup.py` writes a marker file, never on shared networks (0.0.0.0 exposure means the lab unit must not sit in a public venue), and Bluetooth legs in controlled airspace only.
