# Nezha DDNS SSRF, Admidio document/auth boundaries, OpenC3 file/SQL boundaries, and Ouroboros tool-path batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-6x26-5727-rrm9](https://github.com/advisories/GHSA-6x26-5727-rrm9) / CVE-2026-47268, [GHSA-x628-457g-2pw9](https://github.com/advisories/GHSA-x628-457g-2pw9) / CVE-2026-47231, [GHSA-mx25-j3rc-6w2w](https://github.com/advisories/GHSA-mx25-j3rc-6w2w) / CVE-2026-47228, [GHSA-v529-vhwc-wfc5](https://github.com/advisories/GHSA-v529-vhwc-wfc5) / CVE-2026-42087, [GHSA-4jvx-93h3-f45h](https://github.com/advisories/GHSA-4jvx-93h3-f45h) / CVE-2026-42085, [GHSA-3jfp-46x4-xgfj](https://github.com/advisories/GHSA-3jfp-46x4-xgfj) / CVE-2026-41493, [GHSA-55rj-x2vc-4whq](https://github.com/advisories/GHSA-55rj-x2vc-4whq) / CVE-2026-47212, and [GHSA-c4m7-2gwp-vw76](https://github.com/advisories/GHSA-c4m7-2gwp-vw76) / CVE-2026-47211.

This batch is durable because it captures reusable offensive validation patterns: low-privileged control-plane SSRF, source/destination authorization confusion in document managers, state-changing CSRF on account workflows, SQL/file-write boundaries in operator consoles, doc-server path traversal, unsigned webhook injection, and project-local environment poisoning of agent/CLI tool paths.

## What changed

- **Nezha DDNS webhook blind SSRF** — authenticated dashboard users can create webhook-backed DDNS profiles with arbitrary URL, method, headers, and body. When DDNS fires for an owned server, the dashboard host issues the request without the SSRF protections used by notification webhooks.
- **Admidio document-manager IDOR** — upload rights are checked against the URL `folder_uuid`, while `move_save` operates on a separate `file_uuid`. A user with upload rights in one folder can move files from private folders into a controlled folder and then download them.
- **Admidio registration CSRF** — `registration.php` `send_login` regenerates and stores a new password for an arbitrary assigned user without validating a CSRF token, allowing a registration administrator's browser to be used as the state-changing principal.
- **OpenC3 COSMOS TSDB SQL injection** — the `get_tlm_values` RPC path can pass attacker-controlled time-series lookup input into QuestDB SQL, enabling telemetry disclosure or destructive statements from roles that only need telemetry-view permissions.
- **OpenC3 COSMOS plugin config file write** — tool configuration saves can escape their intended directory and create or overwrite files within the shared `/plugins` tree.
- **YARD doc server traversal** — YARD `<=0.9.41` can expose arbitrary host files through crafted HTTP paths in some `yard server` deployments, especially non-WEBrick/docroot configurations.
- **Symfony Twilio SMS Notifier unsigned callback parsing** — the parser receives a webhook secret but ignored `X-Twilio-Signature`, letting anyone who can reach the endpoint forge delivery/failure callbacks when applications wire those events into automation.
- **Ouroboros project `.env` CLI-path execution** — running Ouroboros inside an untrusted repository could load execution-affecting variables such as `OUROBOROS_CLI_PATH` or `OPENCODE_CLI_PATH` from the repo-local `.env`, causing project-controlled helper binaries or scripts to execute.

## Operator triage

1. **Prioritize authenticated control panels with low-privileged users:** Nezha, Admidio, and OpenC3 findings are most useful where non-admin accounts can own servers, folders, telemetry views, or saved tool configs.
2. **Look for source/destination mismatch:** in document or file-management bugs, compare the object named in the authorization check with the object actually modified, moved, or downloaded.
3. **Treat callback endpoints as state-changing inputs:** Symfony/Twilio impact depends on applications that trust delivery status for workflow transitions, billing logic, alerting, or user-visible message state.
4. **Map local developer-tool trust boundaries:** Ouroboros impact is strongest for AI/agent workflows where operators clone arbitrary repos and immediately run project-local agent commands.
5. **Keep proofs non-destructive:** favor controlled callbacks, canary files, read-only SQL differentials, and disposable lab accounts over data deletion or production file movement.

## Replayable validation boundaries

### Nezha DDNS blind SSRF check

- Use a low-privileged test account with ownership of a disposable server and DDNS profile.
- Configure a webhook provider to call a tester-owned callback and verify the request originates from the dashboard host.
- If internal reachability is in scope, target one benign lab service such as `127.0.0.1` or an internal canary endpoint and prove only request issuance, not data extraction.
- Compare behavior with any documented notification-webhook SSRF protections to show the DDNS path is the missing filter.

### Admidio document and registration checks

- Create two lab folders: one private source folder containing a harmless marker file and one destination folder where the test user has upload rights.
- Attempt `move_save` with the destination folder in `folder_uuid` and the private marker in `file_uuid`; stop after showing the marker becomes downloadable from the controlled folder.
- For `send_login`, use two lab users and a registration-admin session; trigger the request from a separate origin and prove the target user's password hash or login state changes without a CSRF token.
- Do not move or reset real user content. Restore the lab record after validation.

### OpenC3 COSMOS TSDB and plugin-file checks

- Use a role with telemetry access but no expected database-administration rights.
- For TSDB, prove SQL context break-out with a benign boolean, row-count, or canary-table read; avoid `DROP`, `DELETE`, or data exfiltration beyond synthetic telemetry.
- For tool config writes, save a configuration with a traversal-style name that creates a harmless canary under the shared plugins tree, then document the final canonical path.
- Capture role, endpoint/RPC path, COSMOS version, and whether the affected deployment uses shared plugin storage.

### YARD server traversal check

- Identify exposed `yard server` instances and note server backend, docroot, and version.
- Request a harmless known file outside the intended docroot in a lab deployment to confirm path normalization drift.
- For production, limit validation to a non-sensitive sentinel path authorized by the owner; do not read secrets or system files.

### Symfony Twilio webhook injection check

- Locate application endpoints using Symfony Twilio SMS Notifier callback parsing.
- Send a synthetic callback without `X-Twilio-Signature` and compare application-side state with a correctly signed lab callback.
- Prove only that unsigned payloads are accepted; avoid triggering real downstream notifications, billing, or user-impacting automation.

### Ouroboros project `.env` tool-path check

- Use a disposable clone containing a `.env` that points `OUROBOROS_CLI_PATH` or `OPENCODE_CLI_PATH` to a benign canary script.
- Run the same Ouroboros command the target workflow expects, such as initialization or adapter creation.
- Capture that execution came from the project-local path rather than a trusted user/home configuration.
- Keep the canary to echoing a marker or writing to a temp file; do not execute network, credential, or persistence actions.

## Reporting heuristics

- For Nezha, report the exact DDNS ownership path, webhook fields accepted, trigger condition, and request evidence from the dashboard host.
- For Admidio, include both identifiers: the folder used for the rights check and the separate file or user object actually modified.
- For OpenC3, separate telemetry-view SQLi from plugin-tree file writes; each has a different affected permission model and impact boundary.
- For YARD, name the server backend and docroot assumptions because vulnerable behavior is configuration-sensitive.
- For Symfony/Twilio, show the missing signature verification plus the business logic that consumes forged callback status.
- For Ouroboros, frame the bug as untrusted project configuration crossing into command selection, not just "a malicious repo has a script."

## Notes on skipped items from this scan

- Stigmem peer-token timestamp rejection was reviewed as interoperability/noise rather than offensive operator guidance; auth-disabled broad anonymous access was noted as an exposure heuristic but too configuration-obvious for a standalone workflow in this batch.
- Admidio field deletion, auto-login/session logging, PKCS#12 export CSRF, file rename/description change, SSO enable CSRF, and module category reorder/delete were lower-impact duplicates of the same Admidio authorization/CSRF theme and were not all expanded individually.
- Klever-Go compressed P2P OOM, BoxLite timeout bypass, OpenC3 self-XSS, katalyst-koi logout replay, Devise timeout open redirect, and Authelia LDAP Basic Auth rate-limit bucket drift were reviewed as availability-only, self-impacting, generic redirect/session hygiene, or too low-signal for a separate Skillz page.
- CISA KEV stayed catalog `2026.05.29` with PAN-OS CVE-2026-0257 already reflected. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.
