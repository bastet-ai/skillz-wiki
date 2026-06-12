# File Browser, Fleet, Fabric.js, and Cordova callback boundary checks

Source: hourly offensive-security scan, 2026-06-12. Primary entries: GitHub advisories [GHSA-3q2p-72cj-682c](https://github.com/advisories/GHSA-3q2p-72cj-682c) / CVE-2026-54096, [GHSA-5ww9-jg6q-38r7](https://github.com/advisories/GHSA-5ww9-jg6q-38r7) / CVE-2026-54097, [GHSA-vxm7-9x8v-8gm4](https://github.com/advisories/GHSA-vxm7-9x8v-8gm4) / CVE-2026-46370, [GHSA-x4qr-qw6h-wvxq](https://github.com/advisories/GHSA-x4qr-qw6h-wvxq) / CVE-2026-46371, [GHSA-w22m-hvvm-xmwx](https://github.com/advisories/GHSA-w22m-hvvm-xmwx) / CVE-2026-44311, and updated Cordova Plugin InAppBrowser advisory [GHSA-q42j-x8rq-pjg6](https://github.com/advisories/GHSA-q42j-x8rq-pjg6) / CVE-2026-47430.

This batch is durable because each item exposes a reusable operator boundary: future public-share grants bound to paths that do not exist yet, prefix-based cleanup that crosses user share records, cursor pagination used as a database sort oracle, canvas-to-SVG serialization that crosses into trusted DOM rendering, and mobile in-app browser messages that can dispatch predictable native callback IDs.

## What changed

- **File Browser future-share grant boundary** — `POST /api/share/<path>` could create a public share record for a path before the target file existed. When a file later appeared at the same logical path, the old public share became valid and exposed it through the public download route.
- **File Browser share cleanup prefix boundary** — a low-privileged user deleting an owned file could trigger share-record deletion by unbounded logical-path prefix match, crossing into other users' share links when paths shared byte prefixes.
- **Fleet `ORDER BY` pagination oracle boundary** — Observer-level users could supply non-allowlisted `order_key` values on host/MDM listing endpoints and combine cursor pagination with binary search to recover joined-table secrets such as host enrollment keys.
- **Fabric.js SVG serialization boundary** — user-controlled gradient color-stop values were emitted into SVG attributes without escaping. Applications that insert `toSVG()` output into the DOM can turn stored drawing/canvas data into script execution.
- **Cordova InAppBrowser callback-dispatch boundary** — iOS InAppBrowser web content could post arbitrary Cordova callback IDs to the host app. Predictable plugin callback IDs make this a mobile bridge confused-deputy issue when attacker-controlled content is opened in the in-app browser.

## Operator triage

1. **Start from role and rendering preconditions.** File Browser requires authenticated share/delete permissions; Fleet requires Observer credentials and affected endpoints; Fabric.js requires an application that accepts attacker-controlled canvas/gradient data and renders exported SVG into the DOM; Cordova requires a target app that opens attacker-controlled or interceptable content in InAppBrowser on iOS.
2. **Prove the boundary with canaries, not secrets.** Use disposable files, synthetic share links, test Fleet hosts with canary enrollment values, harmless SVG markers, and inert Cordova callback payloads. Do not read real user files, recover production enrollment secrets, delete live share links, or target real mobile users.
3. **Capture positive and negative controls.** The strongest reports show the vulnerable behavior on an affected version and the same canary blocked by path existence checks, segment-aware prefix handling, sort-column allowlists, SVG escaping, or callback-ID validation.

## Replayable validation boundaries

### File Browser future public-share validation

- Use a lab File Browser instance or explicitly approved tenant with a disposable low-privileged user that has share and download permission.
- Create a public share for a logical path that does not exist yet, such as `/canary/future.txt`, and record only the returned public hash/URL.
- Later create a harmless marker file at that exact path as the same user or via an approved setup step.
- Positive proof is that the previously issued public URL now returns the marker file without creating a new share after the file exists.
- Evidence: File Browser version, user role/scope, requested logical path, share hash, marker filename/content, public route status, and patched-version rejection for non-existent paths.

### File Browser cross-user share-prefix cleanup validation

- Build two disposable users and paths where the attacker's deleted path is a byte prefix of a victim share path, for example `/a` and `/admin-report` only in a lab namespace.
- Have the victim user create a synthetic public share to a harmless marker file.
- Have the attacker delete only their own disposable file/directory at the prefix path.
- Positive proof is removal of the victim's share record or public link availability changing solely because of prefix cleanup.
- Stop at canary share deletion. Do not target production shares, shared roots, or files that carry business impact.
- Evidence: user scopes, logical paths, share hashes before/after, delete request, and patched segment-aware cleanup behavior.

### Fleet cursor-sort oracle validation

- Validate only in a test Fleet deployment with disposable hosts and deliberately seeded canary enrollment values.
- Use an Observer or Team Observer account and target the affected host-listing or Apple MDM commands route.
- Supply a sensitive joined-table column as `order_key` only against canary columns/rows, then vary the cursor parameter to demonstrate that response ordering or presence leaks one character of the known canary.
- A minimal proof can stop after recovering a short synthetic prefix such as `CANARY-`, paired with a negative control where unsupported `order_key` values are rejected.
- Do not extract real `node_key`, `orbit_node_key`, APNS tokens, host identifiers beyond the canary scope, or production MDM data.
- Evidence: Fleet version, endpoint, Observer role, redacted request parameters, canary value, binary-search transcript for the canary prefix, and allowlist rejection on a fixed build.

### Fabric.js SVG export-to-DOM validation

- Confirm the application stores or accepts user-controlled Fabric.js object data with gradient `colorStops` and later calls `toSVG()` or otherwise serializes the canvas to SVG.
- Use a harmless attribute-breakout marker such as a non-networking event that writes to a local test DOM marker; avoid credential theft, external callbacks, or user-targeted payloads.
- Render the generated SVG only in a lab page or authorized app path that mirrors the production rendering sink, especially `innerHTML`/HTML insertion paths.
- Positive proof is controlled markup/script execution from the serialized gradient color field, plus a patched/escaped output where quotes and angle brackets remain inert.
- Evidence: Fabric.js version, sanitized object JSON, emitted SVG fragment, DOM insertion sink, marker execution, and patched serialization output.

### Cordova InAppBrowser callback-ID dispatch validation

- Use a test build of the target iOS Cordova app with non-sensitive plugins and a lab InAppBrowser URL controlled by the tester.
- Create or wait for a pending native plugin callback with a predictable test callback ID, then have the InAppBrowser content post a message to the Cordova InAppBrowser bridge with that canary ID and inert data.
- Positive proof is that the host app dispatches the plugin result for the canary callback without the message originating from the legitimate plugin flow.
- Keep payloads inert: update a test label, write a disposable local marker, or log a canary string. Do not access camera, contacts, geolocation, files, OAuth tokens, or user accounts.
- Evidence: plugin versions, iOS app build, controlled URL, callback ID format, posted message body, canary callback effect, and fixed-version validation failure.

## Reporting heuristics

- Name the exact crossed boundary in the report title: `future share grant to later file exposure`, `logical path prefix to cross-user share deletion`, `ORDER BY cursor oracle to enrollment-key leakage`, `canvas data to trusted SVG DOM`, or `InAppBrowser web content to native callback dispatch`.
- Keep impact tied to demonstrated permissions and sinks. These are high-signal when the report preserves the role, route, platform, and rendering requirements instead of claiming blanket file disclosure, database exfiltration, or mobile RCE.
- Redact share hashes, enrollment secrets, mobile device identifiers, APNS material, plugin callback data, and user files. Synthetic canaries are sufficient.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. ConnectBot DER/SSH memory-allocation items, PyO3 memory-safety issues, and generic resource-consumption updates were tracked but not promoted because they did not add a clearer replayable offensive workflow than the share, oracle, serialization, and mobile bridge boundaries above. No new PortSwigger, Trail of Bits, ProjectDiscovery, Disclosed, or CISA KEV item in this hour added additional durable guidance.
