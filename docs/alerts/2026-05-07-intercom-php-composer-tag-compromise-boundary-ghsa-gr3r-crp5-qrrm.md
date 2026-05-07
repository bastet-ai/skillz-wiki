# intercom-php Composer tag compromise boundary

**Signal:** GitHub Security Advisories REST fallback surfaced **GHSA-gr3r-crp5-qrrm**: a compromised GitHub tag for `intercom/intercom-php` version `5.0.2` published a malicious Composer plugin that downloaded Bun and executed an obfuscated credential-harvesting payload. This extends the same Intercom supply-chain pattern already seen in the `intercom-client` npm compromise.

## Advisory covered

- **Compromised tag of intercom-php published via GitHub** — [GHSA-gr3r-crp5-qrrm](https://github.com/advisories/GHSA-gr3r-crp5-qrrm): version `5.0.2` of the Composer package `intercom/intercom-php` was created from a malicious commit pushed by a compromised service account. The malicious Composer plugin acted as a dropper, downloaded a JavaScript runtime, and ran credential-harvesting code. No patched Composer release is listed for `5.0.2`; treat that exact version as malicious.

## Why this is durable

This is not a normal vulnerable-code patch cycle. A trusted repository tag and package-manager install hook became the execution boundary. The reusable lesson is that package provenance checks must include **who created the tag**, **whether the package runs install-time plugins/scripts**, and **whether the release content matches a trusted source tree**, not only whether the package name is familiar.

## Immediate triage

1. Search Composer lockfiles, SBOMs, package caches, CI artifacts, and deployment images for `intercom/intercom-php` exactly `5.0.2`.
2. If present, assume install-time execution may have occurred wherever `composer install` or `composer update` ran with plugins enabled.
3. Preserve CI logs, runner filesystem snapshots when available, Composer cache contents, and outbound network telemetry before cleanup.
4. Rotate credentials exposed to affected CI jobs or developer machines: Composer/GitHub tokens, cloud deploy keys, package registry tokens, `.env` secrets, and Intercom/API credentials.
5. Pin to a known-good version, remove the malicious package from internal mirrors/caches, and block `5.0.2` in dependency policy.

## Hunt prompts

- Composer output that enabled or executed an unexpected plugin from `intercom/intercom-php`.
- Downloads or execution of Bun from PHP/Composer build jobs that do not normally use JavaScript runtimes.
- New or unusual outbound connections from package-install phases, especially shortly after April 30, 2026.
- GitHub activity from automation/service accounts creating unexpected commits, tags, releases, or package publishes.
- Credential use from new IPs after affected builds completed.

## Durable controls

- Disable Composer plugins/scripts by default in high-risk CI steps; enable only allowlisted plugins by package and version.
- Require signed, protected, or reviewed release tags for production dependencies, especially SDKs that run install hooks.
- Mirror packages only after malware scanning, lockfile review, and provenance comparison against trusted commits.
- Treat package-manager caches as execution evidence during incident response, not disposable noise.
- Add dependency firewall rules for known-malicious exact versions and rehearse fast revocation of compromised service accounts.
