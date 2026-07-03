# Snapshot-write, SSR form fallback, and sudoers argument boundary checks

Source: hourly offensive-security scan, 2026-07-03. Primary entries: GitHub Advisory Database [GHSA-322x-v876-g883](https://github.com/advisories/GHSA-322x-v876-g883), [GHSA-gj2h-2fpw-fhv9](https://github.com/advisories/GHSA-gj2h-2fpw-fhv9), and [GHSA-8w6w-23mq-h8rg](https://github.com/advisories/GHSA-8w6w-23mq-h8rg) / CVE-2026-52817. Related electerm terminal-file updates were added to the existing [electerm terminal command-boundary page](2026-05-08-electerm-terminal-command-boundary-ghsa-8x35-hph8-37hq.md#july-3-expansion-remote-filenames-file-helpers-and-transfer-paths).

These advisories are durable for operators because they expose reusable seams that recur across test frameworks, SSR applications, and monitoring plugins: test-controlled snapshot paths crossing into CI filesystem writes, pre-hydration forms falling back to browser-native GET submission, and sudoers entries that allow a binary without pinning safe arguments. Keep proofs in owned labs with temp marker files, synthetic credentials, fake monitoring users, disposable VMs, and fixed-version negative controls.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-322x-v876-g883](https://github.com/advisories/GHSA-322x-v876-g883) | `@asymmetric-effort/nogginlessdom <= 0.0.21` `matchFileSnapshot` | test-controlled snapshot paths could create directories and write files outside the expected snapshot root when update mode was active | PR/CI test harness reviews should treat snapshot-update mode as a filesystem write primitive when untrusted tests can choose the path. |
| [GHSA-gj2h-2fpw-fhv9](https://github.com/advisories/GHSA-gj2h-2fpw-fhv9) | `@nuxt/ui <= 4.7.1` `UForm` / `UAuthForm` SSR markup | server-rendered forms omitted `method`/`action` and relied on hydrated `@submit.prevent`; pre-hydration submission fell back to `GET` with named fields in the query string | SSR bug hunts should test the no-JavaScript and pre-hydration browser default path for credential-shaped forms, not only hydrated client behavior. |
| [GHSA-8w6w-23mq-h8rg](https://github.com/advisories/GHSA-8w6w-23mq-h8rg) / CVE-2026-52817 | Linuxfabrik Monitoring Plugins sudoers assets | a monitoring user could run `/usr/bin/apt-get` via sudo without enforced arguments | Local privilege-boundary reviews should verify sudoers command entries include exact safe argv, not just a trusted binary path. |

## Operator triage

1. **Start from attacker-controlled strings.** Inventory snapshot paths, form field names, URL parameters, sudoers arguments, and any other value that crosses from low-trust tests or browser state into a filesystem write, browser default, or privileged binary.
2. **Prove the primitive with markers only.** Positive evidence should be a temp marker file, URL containing synthetic form values, or sudoers decision table. Do not overwrite shell startup files, credentials, CI config, user downloads, or production monitoring hosts.
3. **Record both raw and resolved values.** For paths and forms, capture the caller-supplied path or rendered HTML, normalized destination or request URL, active mode/state, and final write or submission target.
4. **Test the fallback path.** Hydrated client behavior, normal snapshot comparison mode, and plugin-intended sudo use are not enough. Exercise pre-hydration submit, snapshot update mode, and non-default sudo arguments in an isolated lab.
5. **Use fixed-version negative controls.** Nogginlessdom `0.0.22`, a patched Nuxt form wrapper with explicit `method="post"`, and sudoers entries that pin exact apt arguments should reject the same canaries.

## Replayable validation boundaries

### Snapshot-update filesystem write harness

- Preconditions: isolated CI/local test project, affected `@asymmetric-effort/nogginlessdom`, `UPDATE_SNAPSHOTS=1` or equivalent update mode intentionally enabled, temp snapshot root, and no production repository secrets or writable deployment paths mounted.
- Add a test case whose snapshot file path points outside the expected snapshot directory but still inside a disposable temp root, for example `../outside-snapshots/skillz-marker.txt`.
- Positive evidence: the test runner creates directories or writes the marker outside the intended snapshot root when update mode is enabled.
- Negative controls: patched `0.0.22`, snapshot paths resolved under an explicit root, symlink-aware containment checks, update mode disabled for untrusted PRs, and CI jobs that run untrusted tests in a throwaway filesystem.
- Do not overwrite workflow files, package scripts, shell profiles, checked-in source, or credentials. The proof should be a single temp marker file.

### SSR form pre-hydration fallback harness

- Preconditions: local or authorized staging Nuxt app using `UForm`/`UAuthForm`, synthetic accounts/credentials, browser automation such as Playwright, throttled or blocked JavaScript hydration, and no real user passwords.
- Capture the server-rendered HTML before hydration and confirm whether the `<form>` has explicit `method` and `action` attributes.
- In automation, submit the form immediately after initial HTML load and before hydration attaches `@submit.prevent`, or block the JS bundle entirely. Use credentials like `skillz@example.invalid` and `SKILLZ_FAKE_PASSWORD_<case-id>`.
- Positive evidence: the browser navigates to a URL whose query string contains named credential fields. Record only synthetic values plus request/URL evidence.
- Negative controls: explicit `method="post"`, safe `action`, disabled submit before hydration, server rejection of credential query parameters, and patched component behavior.
- Do not collect real credentials, browser history, Referer logs, or third-party analytics data.

### Sudoers binary-to-argument boundary harness

- Preconditions: disposable Linux VM/container, affected Linuxfabrik sudoers asset, fake `nagios` or monitoring user, no production monitoring plugins, and no persistent root-level changes.
- As the monitoring user, run `sudo -l` and capture whether `/usr/bin/apt-get` is allowed broadly or only with exact expected arguments.
- Positive evidence should be a safe argument-decision proof, such as `sudo -l` output plus a dry-run/wrapper harness showing arbitrary `apt-get` options would be accepted. If root execution proof is explicitly authorized in a throwaway VM, use an inert marker command only and immediately destroy the VM.
- Negative controls: sudoers pins the exact `apt-get update --quiet 2` style argv needed by the plugin, environment reset is enforced, shell-escape options are denied, and the monitoring user cannot choose arbitrary apt configuration hooks.
- Do not run shells, install packages, alter production apt state, or test on shared monitoring hosts.

## Reporting notes

Lead with the crossed boundary:

- **Untrusted test snapshot path -> CI filesystem write**
- **SSR credential form -> pre-hydration native GET query leak**
- **sudoers binary path -> arbitrary privileged arguments**

Strong reports include affected package/version, exact route or user gesture, raw input, normalized path/form/sudoers decision, temp-marker evidence, user interaction requirements, and a fixed-version or policy negative control.

## Reviewed but not promoted here

- [GHSA-x4hg-hfwf-p9mw](https://github.com/advisories/GHSA-x4hg-hfwf-p9mw) was processed as ReDoS/resource-exhaustion only and did not add a non-availability operator workflow.
- The nearby Zebra/zebrad consensus, queue, locator, and parser advisories were processed without standalone wiki content because this scan did not identify a durable web/app/agent operator workflow beyond availability or blockchain-consensus-specific handling.
- [GHSA-q4rm-m6xh-5pv7](https://github.com/advisories/GHSA-q4rm-m6xh-5pv7), [GHSA-mr9h-45p9-fg8h](https://github.com/advisories/GHSA-mr9h-45p9-fg8h), [GHSA-4q9j-6299-gxmr](https://github.com/advisories/GHSA-4q9j-6299-gxmr), and [GHSA-xv24-hxh9-2hh9](https://github.com/advisories/GHSA-xv24-hxh9-2hh9) were noted but not promoted because their sparse advisory text did not add a reusable validation workflow beyond existing authorization and secret-disclosure patterns.
