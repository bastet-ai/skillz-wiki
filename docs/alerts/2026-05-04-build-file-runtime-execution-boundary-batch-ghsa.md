# Build, file, and runtime execution-boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST fallback surfaced a broad **2026-05-04** batch where build tools, file-serving helpers, agent frameworks, conversion services, and runtime parsers crossed execution or filesystem boundaries after trusting user-controlled metadata.

## Advisories in this batch

- **H2O-3 unauthenticated JDBC parameter code injection** — `ai.h2o:h2o-core < 3.46.0.10` allowed `/99/ImportSQLTable` JDBC URL parameters to bypass a MySQL-specific blacklist by switching drivers, enabling remote code execution through PostgreSQL driver parameters. Fixed in **3.46.0.10**. References: <https://github.com/advisories/GHSA-qmcv-hh7c-3m56>, CVE-2026-3960.
- **pyp2spec RPM macro injection** — `pyp2spec < 0.14.1` wrote unescaped PyPI metadata into generated spec files, letting a malicious package execute RPM macros during spec parsing by `rpmbuild`, `rpm -q --specfile`, and similar tools. Fixed in **0.14.1**. References: <https://github.com/advisories/GHSA-r35x-v8p8-xvhw>, CVE-2026-42301.
- **goshs cross-origin arbitrary file write** — `github.com/patrickhener/goshs/v2 < 2.0.2` and legacy `github.com/patrickhener/goshs <= 1.1.4` allow browser-based file writes via PUT because PUT lacks CSRF validation and CORS allows `*`. Fixed in **v2.0.2**; no legacy v1 patch was listed. References: <https://github.com/advisories/GHSA-rhf7-wvw3-vjvm>, CVE-2026-42091.
- **Zserio runtime integer overflow and unbounded allocation** — `io.github.ndsev:zserio-runtime <= 2.18.0` can allocate huge arrays/strings from tiny crafted payloads across generated deserializers, causing denial of service. Fixed in **2.18.1**. References: <https://github.com/advisories/GHSA-cwq5-8pvq-j65j>, CVE-2026-33524.
- **Evolver command injection** — `@evomap/evolver < 1.69.3` builds an `execSync()` curl command with attacker-controlled input in `_extractLLM()`, enabling remote code execution. Fixed in **1.69.3**. References: <https://github.com/advisories/GHSA-j5w5-568x-rq53>, CVE-2026-42076.
- **Evolver arbitrary file write through fetch `--out`** — `@evomap/evolver < 1.69.3` accepts unvalidated output paths for skill downloads. Fixed in **1.69.3**. References: <https://github.com/advisories/GHSA-r466-rxw4-3j9j>, CVE-2026-42075.
- **Evolver prototype pollution** — `@evomap/evolver < 1.69.3` merges user-controlled mailbox data with `Object.assign()` without filtering `__proto__`, `constructor`, or `prototype`. Fixed in **1.69.3**. References: <https://github.com/advisories/GHSA-2cjr-5v3h-v2w4>, CVE-2026-42077.
- **NornicDB wildcard Bolt listener with default credentials** — `github.com/orneryd/nornicdb < 1.0.42-hotfix` ignored the configured address for its Bolt server and bound on all interfaces, exposing default `admin:password` credentials on local networks. Fixed in **1.0.42-hotfix**. References: <https://github.com/advisories/GHSA-2hp7-65r3-wv54>, CVE-2026-42072.
- **Kata Containers CopyFile symlink policy subversion** — `github.com/kata-containers/kata-containers` before commit/version `0.0.0-20260422180503-1b9e49eb2763` allowed untrusted hosts to use CopyFile policy gaps and symlinks to write arbitrary locations inside guest workload images. Fixed in **0.0.0-20260422180503-1b9e49eb2763**. References: <https://github.com/advisories/GHSA-q49m-57vm-c8cc>, CVE-2026-41326.
- **Traefik errors middleware forwards credentials to error services** — Traefik `v2 <= 2.11.43`, `v3 <= 3.6.14`, and `v3.7.0-rc.0` through `rc.2` forward complete request headers including `Authorization` and `Cookie` to separate error-page services. Fixed in **2.11.44**, **3.6.15**, and **3.7.0-rc.3**. References: <https://github.com/advisories/GHSA-p6hg-qh38-555r>, CVE-2026-41181.
- **Gotenberg ExifTool dangerous-tag blocklist bypass** — `github.com/gotenberg/gotenberg/v8 <= 8.30.1` blocks exact tag names such as `FileName` and `Directory` but misses group-prefixed equivalents like `System:FileName`, allowing unauthenticated arbitrary file rename/move through ExifTool. No patched version was listed at scan time. References: <https://github.com/advisories/GHSA-62p3-hvxx-fxg4>, CVE-2026-40893.

## Why this is durable

The reusable lesson is that metadata is code when downstream tooling interprets it.

- JDBC URLs can instantiate driver-specific classes and helpers.
- Package descriptions can become RPM macros.
- Browser-origin requests can cross network boundaries when CORS and CSRF are incomplete.
- “Output path” and “copy file” features become arbitrary writes unless paths are resolved after symlinks and policy checks.
- Header forwarding to helper services can leak credentials outside the original trust zone.
- Blocklists fail when interpreters accept aliases, namespaces, or driver-specific parameter names.

## Immediate triage

1. **Patch known affected components:** H2O-3 **3.46.0.10+**, pyp2spec **0.14.1+**, goshs v2 **2.0.2+**, Zserio runtime **2.18.1+**, Evolver **1.69.3+**, NornicDB **1.0.42-hotfix+**, Kata Containers at or after the fixed commit, and Traefik fixed release lines.
2. **Isolate unpatched services:** remove public access to H2O import APIs, goshs upload endpoints, NornicDB Bolt, Gotenberg conversion endpoints, and agent/framework control APIs until patched or strongly authenticated.
3. **Treat build-machine exposure seriously:** if pyp2spec processed untrusted package metadata, preserve the generated specs and shell history, then rebuild/rotate credentials from a clean environment.
4. **Strip credential headers before error backends:** explicitly drop `Authorization`, `Cookie`, and sensitive custom headers when proxying to error-page or helper services.
5. **Constrain file movement:** disable or sandbox upload, copy, ExifTool, and output-path features that operate on paths supplied by tenants or documents.

## Hunt ideas

- Search H2O logs for `/99/ImportSQLTable` calls using non-MySQL JDBC schemes, `socketFactory`, `socketFactoryArg`, or other driver-specific execution hooks.
- Inspect RPM build logs/spec files for `%{...}`, `%(... )`, `%global`, `%define`, or shell-like macros sourced from package metadata.
- Review goshs access logs for cross-origin PUT uploads and unexpected browser `Origin` headers.
- Look for Evolver `execSync`/curl activity, unexpected files written by `fetch --out`, mailbox records containing prototype keys, and outbound requests to attacker-controlled hubs.
- Check NornicDB listeners and logs for Bolt exposure on `0.0.0.0` or non-loopback interfaces.
- Audit Traefik error-service logs for bearer tokens, cookies, session IDs, or auth headers.
- Inspect Gotenberg/ExifTool jobs for group-prefixed tag names such as `System:FileName` or `System:Directory`.

## Durable controls

- Prefer allowlists over parameter blocklists when invoking drivers, converters, or interpreters.
- Escape or reject package metadata before generating build files; run spec parsing in disposable, no-secret builders.
- Bind local sharing tools to localhost by default, require CSRF on every state-changing verb, and avoid wildcard CORS on credentialed or intranet-reachable services.
- Resolve paths with symlink-aware checks at the last responsible moment, then write through confined directories or file descriptors.
- Budget parser allocations using declared-size caps, decompression limits, and cumulative memory limits.
- Strip credential headers at every trust-zone transition, including error handlers, preview services, and conversion microservices.

## Operator lesson

Ask “who interprets this string next?” for every URL, package field, header, filename, tag name, or output path. If the next interpreter is more powerful than the current validator, the validator probably needs to move closer to the interpreter or be replaced with a structural allowlist.
