# MindsDB file-upload to package-installer execution boundary

Source: hourly offensive-security scan, 2026-06-26. Primary entry: GitHub Advisory Database [GHSA-4894-xqv6-vrfq](https://github.com/advisories/GHSA-4894-xqv6-vrfq) / CVE-2026-27483 for MindsDB authenticated path traversal in `/api/files` leading to remote command execution.

This item is durable for operators because it captures a reusable AI/data-platform pattern: **a low-privilege upload path preserves caller-controlled multipart filenames, writes outside its temporary upload root, and can cross into later package-manager or plugin-install execution paths**.

## What changed

MindsDB's upload endpoint accepts multipart uploads at `/api/files/<name>`. The advisory describes a path traversal where the multipart `filename` value is written before filename cleanup or file-type handling. Because the upload parser keeps filenames and extensions, `../` segments in the multipart filename can escape the temporary upload directory and overwrite process-writable files.

The advisory's impact chain uses MindsDB's own handler-install workflow: after overwriting an executable/imported Python package file, a handler install action invokes `pip` through `subprocess.Popen`, causing the overwritten Python code to run. The useful operator lesson is broader than the exact path: upload destinations, dependency installers, handler/plugin installers, and process-writable virtualenvs form one execution-adjacent boundary.

## Operator triage

1. **Confirm exposure and auth model.** Identify MindsDB instances, version, whether `/api/files` is reachable, and what authenticated role can upload files. Do not test against unauthorized public services.
2. **Map upload write roots.** Determine the temporary upload base, storage directory, container mount layout, and whether the server process can write outside the intended upload tree.
3. **Look for execution-adjacent files.** In labs only, identify process-writable Python packages, handler/plugin directories, startup hooks, model/connector code paths, or installer-controlled files that may be loaded later.
4. **Separate file-write proof from execution proof.** A safe bug-bounty proof usually stops at writing a disposable marker outside the upload root. RCE proof needs explicit lab/customer approval.
5. **Prioritize install-trigger workflows.** Handler installs, connector installs, package updates, BYOM/BYO connector paths, and plugin discovery are high-value because they transform a file write into future code loading.

## Replayable validation boundary

Run this only in an owned lab, customer-approved clone, or program scope that explicitly permits upload path traversal testing.

### Minimal file-boundary proof

- Create a disposable canary directory that is outside the intended upload temp root but still harmless if written, for example a lab-only `/tmp/skillz-mindsdb-canary/` or a mounted scratch path.
- Upload a tiny inert marker file through `/api/files/<name>` with a traversal-shaped multipart filename that targets only that canary path.
- Record whether the marker appears outside the upload root, then delete it.
- Compare against a patched or validated-negative control where traversal separators are rejected or normalized before any disk write.

Evidence should include the authenticated test role, MindsDB version, endpoint, original multipart filename, expected upload root, canary target, observed file location, and cleanup confirmation. Do not target `/etc/passwd`, real virtualenv packages, shell startup files, credentials, notebooks, model weights, or production configuration.

### Lab-only execution-chain proof

Use this only when RCE validation is explicitly authorized and isolated.

- Build a disposable MindsDB container or VM with no secrets, no production data, and no network path to internal services.
- Use an inert Python marker that writes only to a lab scratch file or emits a controlled log line. Do not use reverse shells, credential access, or persistence payloads.
- Overwrite only a disposable package/module in the lab environment, then trigger the handler/plugin/package-install workflow that normally imports or invokes it.
- Capture marker-only evidence, package path, install route, subprocess/import trigger, and a fixed-version negative control.
- Rebuild the lab after the test rather than trying to surgically repair overwritten package files.

## Reporting heuristics

- Lead with the crossed boundary: **authenticated upload filename to outside-root file write**, then **process-writable package/module to handler-install execution** if proven.
- Include role preconditions. This advisory requires an authenticated attacker; avoid claiming unauthenticated RCE unless separately proven in scope.
- Show that the write occurs before cleanup or validation by using a marker path outside the upload root and a negative control.
- Keep exploit evidence synthetic. Reports should not include working payloads against production virtualenvs, package-manager internals, secrets, or customer data.
- Generalize the finding for AI/data platforms: uploaders, connector installers, dependency managers, model loaders, and plugin systems must be assessed as a single file-to-runtime trust chain.

## Notes on skipped adjacent items

The same scan rechecked Disclosed sitemap, PortSwigger Research, Trail of Bits, ProjectDiscovery, Brutecat Security, CISA KEV, and GitHub Advisory Database feeds. The June 26 Keycloak updated advisories were already folded into the existing [Kolibri/Hapi/Keycloak/Flowise/Arc boundary batch](2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md); the remaining rechecked source items did not add a new durable offensive workflow beyond existing pages.
