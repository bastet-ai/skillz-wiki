# i18n prototype and resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** batch where translation catalogs, select-format keys, crypto primality checks, and model cache code crossed resource or prototype boundaries.

## Advisories covered

- **next-intl prototype pollution during message precompile** — [GHSA-4c35-wcg5-mm9h](https://github.com/advisories/GHSA-4c35-wcg5-mm9h): npm `next-intl <= 4.9.1` could pollute `Object.prototype` when `experimental.messages.precompile` handled attacker-controlled translation keys such as `__proto__`. Fixed in `4.9.2`.
- **icu-minify select-key DoS** — [GHSA-r27j-894h-3w3p](https://github.com/advisories/GHSA-r27j-894h-3w3p): npm `icu-minify <= 4.9.1` looked up select options on prototype-bearing objects, so values like `toString` or `constructor` could crash render paths. Fixed in `4.9.2`.
- **phpseclib primality CPU exhaustion** — [GHSA-2528-jw5q-ww88](https://github.com/advisories/GHSA-2528-jw5q-ww88), duplicate withdrawn [GHSA-hg35-mp25-qf6h](https://github.com/advisories/GHSA-hg35-mp25-qf6h): malformed certificate or prime-generation inputs can force expensive primality checks. Fixed in `1.0.23`, `2.0.47`, and affected 3.x lines per upstream advisory.
- **vLLM uninitialized resource in KV block handling** — [GHSA-x368-4g9h-fvv4](https://github.com/advisories/GHSA-x368-4g9h-fvv4): pip `vllm < 0.19.1` has a remotely reachable high-complexity issue in `has_mamba_layers`. Fixed in `0.19.1`.

## Why this is durable

Translation and model-serving support code often runs in trusted build or render contexts. Small helper assumptions — plain objects with prototypes, unbounded primality checks, uninitialized cache resources — become service-wide denial of service or integrity bugs when inputs come from tenants, localization pipelines, uploaded certificates, or remote model requests.

## Immediate triage

1. Upgrade `next-intl` and `icu-minify` to `4.9.2+`, `phpseclib` to fixed lines, and `vllm` to `0.19.1+`.
2. Inventory translation catalogs sourced from vendors, CMS users, tenants, crowdsourced localization, or CI artifacts.
3. Hunt for catalog keys containing `__proto__`, `constructor`, `prototype`, or dotted paths that cross object boundaries.
4. Identify certificate parsing or prime-generation paths that accept user-provided public keys, certificates, or cryptographic parameters.
5. For vLLM, prioritize public inference endpoints and multi-tenant model-serving fleets.

## Durable controls

- Store untrusted maps in null-prototype objects or `Map`, and reject reserved prototype keys at every nested assignment boundary.
- Treat localization catalogs as code-adjacent build input; scan and sign them like dependencies.
- Bound expensive crypto validation by size, iteration, and time; isolate certificate/key parsing from request-critical threads.
- Put inference workers behind per-request resource quotas, health checks, and rapid recycle paths for cache/resource failures.
