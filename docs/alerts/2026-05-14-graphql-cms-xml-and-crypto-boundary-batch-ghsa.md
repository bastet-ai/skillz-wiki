# GraphQL, CMS, XML, and crypto-boundary batch

Source: GitHub Security Advisories updated 2026-05-14.

The remaining May 14 advisories cluster around parser and renderer boundaries: GraphQL validation work can become a CPU or VM-wide resource bug, CMS XML/render endpoints can leak data or execute browser code, and crypto/provider packages can carry platform-specific implementation risk. Treat every parser and UI helper as an exposed boundary with budgets, escaping, and disabled dangerous features.

## Advisories covered

- **Absinthe quadratic fragment-name uniqueness check** — [GHSA-9mhv-8h52-q7q2](https://github.com/advisories/GHSA-9mhv-8h52-q7q2): unauthenticated GraphQL queries with many fragments can trigger O(N²) validation work and exhaust worker CPU. Affected `absinthe <1.10.2`.
- **Absinthe unbounded atom creation from SDL directive names** — [GHSA-qf4g-9fqq-mmm7](https://github.com/advisories/GHSA-qf4g-9fqq-mmm7): attacker-controlled SDL parsed through Absinthe can create unbounded BEAM atoms and terminate the VM. Affected `absinthe >=1.5.0, <1.10.2`.
- **absinthe_plug GraphiQL reflected XSS** — [GHSA-c62g-j346-39v5](https://github.com/advisories/GHSA-c62g-j346-39v5): GraphiQL query embedding escaped quotes and newlines but not backslashes, enabling script breakout through a crafted query parameter. Affected `absinthe_plug >=1.2.0, <=1.5.9`.
- **OpenCms Chemistry servlet XXE information disclosure** — [GHSA-rcc6-6q2f-m2cw](https://github.com/advisories/GHSA-rcc6-6q2f-m2cw): OpenCms before 10.5.1 allowed unauthenticated sensitive-information disclosure through a `cmis-online/query` XXE path.
- **OpenCms external-host DOCTYPE XXE** — [GHSA-pj6p-9p8x-5mfc](https://github.com/advisories/GHSA-pj6p-9p8x-5mfc): OpenCms before 16 allowed XXE when a `DOCTYPE` referred to an external host.
- **OpenCms `updateModelGroups.jsp` XSS** — [GHSA-2887-f3v6-6rjf](https://github.com/advisories/GHSA-2887-f3v6-6rjf): OpenCms before 16 exposed a cross-site scripting issue in the model-group update UI.
- **Bouncy Castle BC-FIPS implementation vulnerability** — [GHSA-mx76-r943-rf8g](https://github.com/advisories/GHSA-mx76-r943-rf8g): BC-FJA/BC-FIPS 2.1.0 through 2.1.2 on Linux x86_64 with AVX/AVX-512f is affected in `gcm128w`/`gcm512w` implementation files.

## Operator triage

1. Patch Absinthe/absinthe_plug, OpenCms, and BC-FIPS packages in exposed services and shared base images.
2. Put request-size, fragment-count, directive-count, and validation-time budgets in front of GraphQL parsers. If SDL upload/import is not required, disable it for untrusted users.
3. Disable XML external entities and external DTD resolution globally; then add endpoint tests for CMS XML routes, not only generic XML parser wrappers.
4. Review GraphiQL and admin UI exposure. Developer consoles should be disabled or access-controlled in production and should never embed raw query parameters into script contexts.
5. For crypto/provider updates, include platform inventory in triage: CPU features and FIPS provider versions matter, not only library names.

## Durable controls

- Parser resource limits should cover algorithmic complexity, object/atom creation, recursion, and wall-clock time.
- Render helpers must escape for the exact target context: JavaScript string escaping is different from HTML text escaping.
- XML defaults should be hostile by default: no external entities, no network fetches, no file reads, and explicit schema/DTD policy.
- Cryptographic providers are part of the trusted computing base. Track exact provider version, platform, and acceleration path in SBOM and patch workflows.
