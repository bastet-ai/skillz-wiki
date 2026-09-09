# Okta Access Gateway / Hyperdrive trust-boundary cluster: config-file injection, SAML/identity-source bypass, credential-in-logs, and auth-verdict integrity (17 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-09 (wave published 2026-09-08T21:34Z).

Okta published a 17-advisory batch spanning the **Okta Access Gateway (OAG)** appliance and the **Hyperdrive** agent/integration/Verify clients. The cluster is not a single CVE chain — it is a *trust-boundary audit of an identity-gateway appliance and its Windows/agent ecosystem*, with four reusable axes:

1. **Appliance config-file injection.** OAG generates `nginx` server blocks, PHP config files, and OS command lines from its own admin-configured fields (application labels, dashboard labels, custom Lua directives, SNMP values). The advisories show the sanitizers are applied *inconsistently*: a Lua directive restriction exists but is not applied to the application-level custom-config field; shell metacharacters in SNMP config are not neutralized before a privileged script builds OS commands. Each unsanitized field is a write-to-generated-code primitive on the appliance.
2. **Identity-source and assertion-integrity breaks.** An optional pass-through auth source accepts user identity from a **client-supplied HTTP header with no cryptographic validation** (session-initiation via arbitrary identity when no upstream sanitizer is configured); SAML assertion attribute values are interpolated **unsanitized into LDAP search filters**; assertion values are interpolated into **database query strings** in the advanced datastore mode; and a protected-rule authorization check mishandles input sanitization/regex evaluation so a deliberately configured Protected Rule policy can be bypassed.
3. **Credential and sensitive-material leakage in local stores.** The Hyperdrive agent writes the **decoded SAML bearer assertion to a log file at the default log level on every successful MFA completion**; the Hyperdrive Integration installer passes the **OAuth client secret as an MSI property**, landing it plaintext in the installer log, Application Event Log, and process command line — all readable by any local user.
4. **Auth-verdict and local-integrity gaps on the agent side.** The Hyperdrive agent plugin returns a **bare boolean success with no signed SAML assertion** when org policy requires no MFA — an unverifiable authentication verdict to the relying application; the Hyperdrive Integration plugin resolves a required assembly from a **user-hive registry path with no signature/integrity verification** (`Assembly.LoadFrom`); the Okta Verify for Windows uninstaller follows a **filesystem junction** with elevated delete privileges; and the Privileged Access (Scaleft) `scaleft://` URL handler appends target values **without an option terminator**, so hyphen-leading values are parsed as CLI flags of the underlying SSH client.

## Advisory table (wave 2026-09-08T21:34Z)

| GHSA | CVE | Severe. | Component | Boundary |
| --- | --- | --- | --- | --- |
| [GHSA-4vpp-8gg6-2rvh](https://github.com/advisories/GHSA-4vpp-8gg6-2rvh) | CVE-2026-78626 | high 8.1 | OAG | Protected Rule input sanitization/regex evaluation → authorization bypass |
| [GHSA-9j47-j79g-74hf](https://github.com/advisories/GHSA-9j47-j79g-74hf) | CVE-2026-78623 | high 7.7 | OAG | SAML assertion values → unsanitized SQL in advanced datastore |
| [GHSA-7xfw-pj33-px3g](https://github.com/advisories/GHSA-7xfw-pj33-px3g) | CVE-2026-78574 | high 7.5 | Hyperdrive Integration | user-hive registry path → unverified assembly load |
| [GHSA-mm4c-wvrq-74qm](https://github.com/advisories/GHSA-mm4c-wvrq-74qm) | CVE-2026-78627 | high 7.3 | Hyperdrive Integration installer | OAuth client secret unmasked in MSI property / logs / command line |
| [GHSA-vx4x-6r95-wf4x](https://github.com/advisories/GHSA-vx4x-6r95-wf4x) | CVE-2026-78579 | medium 6.8 | OAG | SAML attribute values → LDAP search filter injection |
| [GHSA-872h-225f-x88w](https://github.com/advisories/GHSA-872h-225f-x88w) | CVE-2026-78630 | medium 6.7 | OAG | SNMP config metacharacters → privileged OS command construction (root) |
| [GHSA-vp2w-94gp-w964](https://github.com/advisories/GHSA-vp2w-94gp-w964) | CVE-2026-78625 | medium 6.7 | OAG | dashboard label → generated PHP config included during auth requests |
| [GHSA-7r5r-h4wq-43gr](https://github.com/advisories/GHSA-7r5r-h4wq-43gr) | CVE-2026-78550 | medium 6.6 | OAG | management-console `eval()` of user input in admin SSH session |
| [GHSA-r66p-gcff-8wm2](https://github.com/advisories/GHSA-r66p-gcff-8wm2) | CVE-2026-78545 | medium 6.6 | OAG | application label → injected nginx server-block directives |
| [GHSA-5hj5-f578-54jw](https://github.com/advisories/GHSA-5hj5-f578-54jw) | CVE-2026-78552 | medium 6.0 | OAG | Lua directive restriction not applied to app-level custom config |
| [GHSA-63pc-vhwj-p2qm](https://github.com/advisories/GHSA-63pc-vhwj-p2qm) | CVE-2026-78622 | medium 6.0 | Okta Verify (Win) | uninstaller junction-following elevated recursive delete |
| [GHSA-q832-9j8g-vg4h](https://github.com/advisories/GHSA-q832-9j8g-vg4h) | CVE-2026-78620 | medium 5.9 | OAG | Kerberos config event payload → unvalidated file write path |
| [GHSA-p4wq-g97j-pcf5](https://github.com/advisories/GHSA-p4wq-g97j-pcf5) | CVE-2026-78629 | medium 5.6 | Hyperdrive agent plugin | no-MFA policy → success without signed SAML assertion |
| [GHSA-7x42-7j3m-qc6m](https://github.com/advisories/GHSA-7x42-7j3m-qc6m) | CVE-2026-78631 | medium 5.3 | Hyperdrive agent | decoded SAML bearer assertion written to log at default level |
| [GHSA-wf33-c5j5-v44h](https://github.com/advisories/GHSA-wf33-c5j5-v44h) | CVE-2026-78635 | medium 5.0 | PAA client | `scaleft://` URL handler missing option terminator → CLI flag injection |
| [GHSA-5fhg-v2mq-37m7](https://github.com/advisories/GHSA-5fhg-v2mq-37m7) | CVE-2026-78624 | medium 4.9 | OAG | backup restore: unvalidated filename in encrypted payload → file write |
| [GHSA-fv22-crrj-w4gc](https://github.com/advisories/GHSA-fv22-crrj-w4gc) | CVE-2026-78560 | medium 4.8 | OAG | pass-through auth source: client-supplied HTTP header as identity |

## Why this is worth an operator page

- **OAG is an internet-exposed SSO edge appliance** — the same perimeter tier as Ivanti/ScreenConnect/Pulse in the sweep order. Its config surface *writes files the appliance then executes or parses as config* (nginx blocks, PHP includes, OS commands, eval), which is the classic generated-config injection class.
- **The pass-through header auth source is the most reusable finding**: "trust an upstream proxy to strip/validate this header" is an architecture-dependent control. In any deployment where OAG is fronted without a header-sanitizing reverse proxy (or mis-ordered), the header is an unauthenticated identity-assertion channel.
- **Agent-side credential leakage and verdict integrity** are durable bug-hunting heuristics for the whole identity-client ecosystem: live assertions in logs, secrets in MSI properties/event logs, boolean-only auth verdicts, and user-hive-resolved assemblies.

## Recon: exposure and configuration fingerprinting (authorized scope)

- **OAG exposure:** identify OAG front-ends from the perimeter sweep (`httpx`/`nuclei` tech detection, OAG-branded login/console UI, `/oktapreview`-style SSO entry paths, OAG management interface where reachable). Record build/version from the console or release markers where readable; treat unreadable as *inferred*.
- **Auth-source topology (the key question for the header bypass):** determine whether OAG sits directly exposed or behind a reverse proxy/firewall, and which headers that edge strips/sets. The pass-through auth source is only exploitable in the "no upstream sanitizer" topology — record the topology as a precondition, not assume it.
- **Protective-rule presence:** note whether Protected Rule policies are configured on application resources (that is the precondition for the sanitization/regex evaluation bypass).
- **Agent fleet:** enumerate Hyperdrive agent/integration and Okta Verify hosts in the managed estate. The log-leak, MSI-secret, junction-delete, and assembly-load items are local-user→credential/verdict boundaries on workstations — relevant to red-team privilege-escalation and credential-persistence checks on authorized managed devices.

```bash
# Inert recon on an authorized scope: OAG front-ends and version markers
httpx -l scope.txt -title -tech-detect -content-length -server -silent -json > httpx_oag.json
nuclei -l scope.txt -t technologies/ -silent -json > nuclei_oag.json
# Read-only console/version probe on a confirmed OAG host
curl -sk -D - https://TARGET/ -o /dev/null -w "HTTP %{http_code}\n"
```

> **Label inference.** If the exact OAG build is not readable, record the fingerprint evidence (titles, markers, error bodies) and note version confirmation is *inferred*, not confirmed.

## Validation boundaries (authorized targets / lab only)

OAG is an internet-facing SSO appliance and its sinks write appliance-executed configuration. In an authorized assessment the safe work is **boundary confirmation**, not payload execution:

1. **Confirm product, build, and auth-source topology** with read-only markers (above). Record whether a header-sanitizing reverse proxy sits in front of OAG — that is the precondition record for the pass-through header item. Do not send crafted auth headers or config values at a production OAG without explicit owner approval for that specific action.
2. **In a lab (or owner-approved canary OAG),** enumerate the generated-config writers: nginx server-block generation, PHP config generation, SNMP→OS-command construction, `eval()` console paths, and the LDAP/SQL interpolation sites. For each writer, demonstrate *input acceptance* — a canary marker value survives into the generated artifact on the vulnerable configuration — and stop there. Do not achieve command execution, do not modify real authentication state, do not alter live SSO session behavior.
3. **Characterize the pass-through header boundary without minting sessions:** in the no-upstream-sanitizer topology, record which header name(s) the optional source accepts and that an arbitrary value reaches the session-initiation decision point. A bounded proof is the decision-point record (which identity value was accepted), not a working session.
4. **Agent-side items (workstation lab only):** on a disposable VM with the agent/integration installed, verify the log-level default emits the decoded assertion shape (capture a synthetic test assertion's presence, redacted), verify MSI install logs capture the property shape with a canary value, verify the registry assembly path resolves from the user hive, and verify the junction-follow on a marker directory tree with a *denied* delete sink. No real credential capture, no real assembly execution, no real junction targeting.
5. **Negative control:** where a fixed build/patch is identified in vendor release notes, repeat the acceptance shapes against it and record the denial.

Evidence to capture: OAG build, auth-source topology (with/without upstream sanitizer), per-writer acceptance matrix (field → artifact, canary value present), the pass-through decision-point record, agent log/MSI/registry observations with redaction, and negative-control results. Redact all credentials, assertions, and session material.

## Durable operator value

1. **Generated-config injection is the audit axis for SSO edge appliances.** OAG's nginx/PHP/command/eval writers each take a different admin field and skip the same "sanitize before emit" step in a different place. For any appliance that renders user-configured values into files it later parses or executes, build the full writer→artifact matrix; a restriction applied to one writer (Lua directive check) says nothing about its siblings (application-level custom config).
2. **"Trust the upstream proxy" is an architecture-condition, not a control.** The pass-through header auth source is only safe when a header-sanitizing edge is actually in front of OAG. Bug-hunt question: *what happens to this trust assumption when the topology changes?* Document the topology; test the un-sandboxed variant in a lab.
3. **Auth verdicts without cryptographic artifacts are reportable.** A boolean "MFA not required" response with no signed assertion is an unverifiable identity decision delivered to the relying application. For identity agents and brokers, check: does every success path carry a verifier-checked artifact? A missing-signature path on the low-friction branch (no-MFA policy) is the typical gap.
4. **Credentials travel in install-time and log-time artifacts.** MSI properties, installer logs, event logs, and default-level application logs are all credential sinks for identity tooling. Red-team heuristic: after installing any agent/broker, grep the workstation's installer/event/app logs for client-secret/assertion/token patterns — the bug is usually "logged at default level, readable by any local user."
5. **Local-user→elevated boundaries in identity clients:** junction-following delete (Verify uninstaller), user-hive assembly resolution (Hyperdrive Integration), and CLI-flag injection from URL-handler values (PAA `scaleft://`) are the standard LPE/cred-theft shapes on managed-identity estates. Include them in workstation post-exp checklists on authorized systems.

## Safety

- **Authorized scope only.** OAG sits on the identity path: any unapproved crafted request against a production OAG risks disrupting live SSO and is an incident. Confirm approval level (recon vs. boundary proof) before each action.
- **No payload execution in scope** unless explicitly approved; no command execution on the appliance, no live session minting, no auth-state modification.
- **No untrusted public exploit code** against any OAG or agent; lab reproduction only with full owner sign-off.
- **Workstation agent checks** are local, read/marker-only on authorized managed devices; no real credential capture, no real assembly execution, no real junction deletion.

---

*Sources: GitHub Security Advisories wave published 2026-09-08T21:34Z — [GHSA-4vpp-8gg6-2rvh](https://github.com/advisories/GHSA-4vpp-8gg6-2rvh) · [GHSA-9j47-j79g-74hf](https://github.com/advisories/GHSA-9j47-j79g-74hf) · [GHSA-7xfw-pj33-px3g](https://github.com/advisories/GHSA-7xfw-pj33-px3g) · [GHSA-mm4c-wvrq-74qm](https://github.com/advisories/GHSA-mm4c-wvrq-74qm) · [GHSA-vx4x-6r95-wf4x](https://github.com/advisories/GHSA-vx4x-6r95-wf4x) · [GHSA-872h-225f-x88w](https://github.com/advisories/GHSA-872h-225f-x88w) · [GHSA-vp2w-94gp-w964](https://github.com/advisories/GHSA-vp2w-94gp-w964) · [GHSA-7r5r-h4wq-43gr](https://github.com/advisories/GHSA-7r5r-h4wq-43gr) · [GHSA-r66p-gcff-8wm2](https://github.com/advisories/GHSA-r66p-gcff-8wm2) · [GHSA-5hj5-f578-54jw](https://github.com/advisories/GHSA-5hj5-f578-54jw) · [GHSA-63pc-vhwj-p2qm](https://github.com/advisories/GHSA-63pc-vhwj-p2qm) · [GHSA-q832-9j8g-vg4h](https://github.com/advisories/GHSA-q832-9j8g-vg4h) · [GHSA-p4wq-g97j-pcf5](https://github.com/advisories/GHSA-p4wq-g97j-pcf5) · [GHSA-7x42-7j3m-qc6m](https://github.com/advisories/GHSA-7x42-7j3m-qc6m) · [GHSA-wf33-c5j5-v44h](https://github.com/advisories/GHSA-wf33-c5j5-v44h) · [GHSA-5fhg-v2mq-37m7](https://github.com/advisories/GHSA-5fhg-v2mq-37m7) · [GHSA-fv22-crrj-w4gc](https://github.com/advisories/GHSA-fv22-crrj-w4gc)*

