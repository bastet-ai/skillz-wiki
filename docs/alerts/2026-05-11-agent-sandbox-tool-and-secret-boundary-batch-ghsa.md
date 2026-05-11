# Agent, sandbox, tool, and secret-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because AI/automation runtimes repeatedly failed at the same trust boundary: untrusted tool names, archives, scripts, templates, and code-execution requests crossed into local files, process environment, or host execution without a narrow capability model.

## Advisories covered

- **PraisonAI MCP path traversal to RCE via `.pth` injection** — [GHSA-9mqq-jqxf-grvw / CVE-2026-44336](https://github.com/advisories/GHSA-9mqq-jqxf-grvw): `PraisonAI <=4.6.33`, fixed `4.6.34`, exposes default MCP file-handling tools that accept traversal paths under `~/.praison/rules/` or absolute workflow paths.
- **PraisonAI symlink archive extraction escape** — [GHSA-9q28-ghcr-c4x3 / CVE-2026-44340](https://github.com/advisories/GHSA-9q28-ghcr-c4x3): `PraisonAI <=4.6.36`, fixed `4.6.37`, validates member names but not symlink/hardlink targets before `tar.extractall()`.
- **PraisonAI unsafe tool resolution** — [GHSA-gmjg-hv98-qggq / CVE-2026-44339](https://github.com/advisories/GHSA-gmjg-hv98-qggq): `praisonaiagents <=1.6.36` and `PraisonAI <=4.6.36`, fixed `1.6.37` / `4.6.37`, can resolve undeclared tool-call names against globals and `__main__` callables.
- **PraisonAI unauthenticated legacy API server** — [GHSA-6rmh-7xcm-cpxj / CVE-2026-44338](https://github.com/advisories/GHSA-6rmh-7xcm-cpxj): `PraisonAI 2.5.6-4.6.33`, fixed `4.6.34`, ships a Flask API with auth disabled by default, allowing reachable callers to run configured workflows.
- **PraisonAI knowledge-store SQL/CQL identifier injection** — [GHSA-3643-7v76-5cj2 / CVE-2026-44337](https://github.com/advisories/GHSA-3643-7v76-5cj2): `PraisonAI 2.4.1-4.6.33`, fixed `4.6.34`, interpolates untrusted collection names into SQL/CQL identifiers.
- **Nuclei response-derived DSL environment disclosure** — [GHSA-jm34-66cf-qpvr / CVE-2026-41645](https://github.com/advisories/GHSA-jm34-66cf-qpvr): `github.com/projectdiscovery/nuclei/v3 >=3.0.0,<3.8.0`, fixed `3.8.0`, lets malicious target responses inject DSL expressions into multi-step templates; env disclosure requires `-env-vars` / `-ev`.
- **Nuclei JavaScript `require()` local file read** — [GHSA-29rg-wmcw-hpf4 / CVE-2026-41646](https://github.com/advisories/GHSA-29rg-wmcw-hpf4): `nuclei/v3 >=3.0.0,<3.8.0`, fixed `3.8.0`, lets JS templates import local `.js` / `.json` files through the default host filesystem loader.
- **electerm install-script command injection** — [GHSA-wxw2-rwmh-vr8f / CVE-2026-41500](https://github.com/advisories/GHSA-wxw2-rwmh-vr8f): `electerm <3.3.8`, fixed `3.3.8`, can append attacker-controlled release metadata to a macOS `exec("open ...")` install path.
- **Inngest TypeScript SDK env leak on unhandled methods** — [GHSA-2jf5-6wwv-vhxx / CVE-2026-42047](https://github.com/advisories/GHSA-2jf5-6wwv-vhxx): `inngest >=3.22.0,<3.54.0`, fixed `3.54.0`, can return `process.env` from `serve()` on unhandled HTTP methods.
- **OpenLearnX code-execution sandbox escape** — [GHSA-8h25-q488-4hxw / CVE-2026-41900](https://github.com/advisories/GHSA-8h25-q488-4hxw): `openlearnx <2.0.3`, fixed `2.0.3`, permits RCE through its Python code execution environment.
- **Gryph agent payload-filter logging leak** — [GHSA-f3jg-756w-gm35 / CVE-2026-45046](https://github.com/advisories/GHSA-f3jg-756w-gm35): Go module `github.com/safedep/gryph <=0.6.0`, fixed `0.7.0`, stored sensitive `file-write` payload fields such as `ContentPreview`, `OldString`, and `NewString` in the local SQLite database at the default `standard` logging level despite sensitive-file filtering expectations.

## Operator triage

1. Inventory agent/MCP servers, template scanners, code-execution services, and desktop helper installs that run near credentials or developer machines.
2. Rotate secrets if vulnerable Inngest handlers, Nuclei `-env-vars`, PraisonAI API/MCP servers, or OpenLearnX sandboxes were exposed to untrusted users or targets.
3. Treat recipe bundles, tarballs, MCP tool arguments, JavaScript templates, and package release metadata as untrusted input; look for writes outside expected workdirs and unexpected `.pth`, startup, shell-profile, or extension files.
4. For Nuclei, separate untrusted template execution from operator environments; run scans with a scrubbed env and no host-mounted secret files.
5. For Gryph, patch to **0.7.0+**, treat local SQLite logs as sensitive evidence, and review/export/delete policies anywhere agent run histories may have been synced or backed up.
6. Disable or firewall legacy agent APIs and code-execution features until patched and covered by explicit authentication, authorization, and audit logging.

## Durable controls

- Tool dispatch should be allowlist-first: only declared capabilities may execute, and failed lookup should stop rather than falling back to module globals or application internals.
- Archive extraction must reject symlinks/hardlinks/device files or use safe extraction filters; validating member names without validating link targets is incomplete.
- Agent file tools need canonical containment checks after path join and before every read, write, delete, and display operation.
- Scanner and automation runtimes should not inherit production secrets; response data and template data must not be evaluated as code unless explicitly trusted.
- Install/update scripts should avoid shell interpolation entirely; if metadata is remote-controlled, treat it as hostile code input.
- Agent observability must be redaction-first: log schemas should store opaque references or explicit allowlisted metadata, not tool payload previews or before/after file content, and default log levels must match documented privacy promises.
