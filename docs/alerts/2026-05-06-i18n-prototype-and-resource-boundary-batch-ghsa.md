# i18n prototype and resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** batch where translation catalogs, select-format keys, crypto primality checks, and model cache code crossed resource or prototype boundaries.

## Advisories covered

- **next-intl prototype pollution during message precompile**, [GHSA-4c35-wcg5-mm9h](https://github.com/advisories/GHSA-4c35-wcg5-mm9h): npm `next-intl <= 4.9.1` could pollute `Object.prototype` when `experimental.messages.precompile` handled attacker-controlled translation keys such as `__proto__`. Fixed in `4.9.2`.
- **icu-minify select-key DoS**, [GHSA-r27j-894h-3w3p](https://github.com/advisories/GHSA-r27j-894h-3w3p): npm `icu-minify <= 4.9.1` looked up select options on prototype-bearing objects, so values like `toString` or `constructor` could crash render paths. Fixed in `4.9.2`.
- **phpseclib primality CPU exhaustion**, [GHSA-2528-jw5q-ww88](https://github.com/advisories/GHSA-2528-jw5q-ww88), duplicate withdrawn [GHSA-hg35-mp25-qf6h](https://github.com/advisories/GHSA-hg35-mp25-qf6h): malformed certificate or prime-generation inputs can force expensive primality checks. Fixed in `1.0.23`, `2.0.47`, and affected 3.x lines per upstream advisory.
- **vLLM uninitialized resource in KV block handling**, [GHSA-x368-4g9h-fvv4](https://github.com/advisories/GHSA-x368-4g9h-fvv4): pip `vllm < 0.19.1` has a remotely reachable high-complexity issue in `has_mamba_layers`. Fixed in `0.19.1`.
- **Vue I18n / @intlify `handleFlatJson` prototype pollution**, [GHSA-p2ph-7g93-hw3m](https://github.com/advisories/GHSA-p2ph-7g93-hw3m) (no CVE assigned; upstream published 2025-03-07): npm `vue-i18n`, `@intlify/core`, `@intlify/core-base`, `@intlify/message-resolver`, `@intlify/vue-i18n-core`, and `petite-vue-i18n` could pollute `Object.prototype` when `handleFlatJson` resolved attacker-controlled flat translation keys containing reserved prototype keys. See the dedicated follow-up below.

## Why this is durable

Translation and model-serving support code often runs in trusted build or render contexts. Small helper assumptions, plain objects with prototypes, unbounded primality checks, uninitialized cache resources, become service-wide denial of service or integrity bugs when inputs come from tenants, localization pipelines, uploaded certificates, or remote model requests.

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

## Vue I18n / @intlify `handleFlatJson` follow-up

Source: GitHub Security Advisories, [GHSA-p2ph-7g93-hw3m](https://github.com/advisories/GHSA-p2ph-7g93-hw3m) (upstream published 2025-03-07; no CVE assigned). Surfaced in the 2026-08-25 hourly scan as a still-current Vue/Intlify i18n boundary.

This extends the i18n prototype-pollution boundary to the **Vue/Intlify ecosystem**, which is the localization stack for a large share of Vue 3 frontends. The reusable pattern: a "flat JSON" translation catalog loader resolves user-controlled keys through a nested-object builder that uses `Object.prototype`-bearing assignment, so reserved keys (`__proto__`, `constructor`, `prototype`, or dotted paths that traverse them) can write into the global prototype chain instead of the local object.

### Affected surface

Confirmed affected npm packages and ranges from the upstream advisory:

- `@intlify/message-resolver` `>= 9.1.0, < 9.1.11` (fixed `9.1.11`)
- `@intlify/core-base` `>= 9.1.0, < 9.1.11` (fixed `9.1.11`)
- `@intlify/core` `>= 9.1.0, < 9.1.11` (fixed `9.1.11`)
- `@intlify/vue-i18n-core` `>= 9.2.0, < 9.14.3` (fixed `9.14.3`); `>= 10.0.0-alpha.1, < 10.0.6` (fixed `10.0.6`); `>= 11.0.0-beta.0, < 11.1.2` (fixed `11.1.2`)
- `vue-i18n` `>= 9.1.0, < 9.14.3` (fixed `9.14.3`); `>= 10.0.0-alpha.1, < 10.0.6` (fixed `10.0.6`); `>= 11.0.0-beta.0, < 11.1.2` (fixed `11.1.2`)
- `petite-vue-i18n` `>= 10.0.0, < 10.0.6` (fixed `10.0.6`); `>= 11.0.0-beta.0, < 11.1.2` (fixed `11.1.2`)

Entry point: `handleFlatJson` (the flat-key to nested-message compiler used by `@intlify/message-resolver`).

### Why it is durable

The class is identical to the `next-intl` precompile and `icu-minify` select-key items above, but it lives in a different, very widely deployed library. Any Vue app that (a) loads translation catalogs from a source an attacker can influence (CMS, tenant config, crowdsourced localization, CI artifact, a JSON endpoint that echoes user input into a key set) and (b) resolves those catalogs through `handleFlatJson` / the flat-JSON path is exposed. Consequence floor is `Object.prototype` pollution → DoS; it escalates when a polluted property is read on a hot Node.js API path (`exec`, `eval`, template engine option, filesystem call), turning an integrity bug into code execution in the server context.

### Operator triage

1. **Find the catalog source and the sink.** Confirm the app uses `vue-i18n` / `@intlify/*` and whether flat-JSON catalogs (keys like `a.b.c` or objects whose keys map to nesting) are parsed from untrusted input rather than a signed build asset.
2. **Hunt reserved keys in catalogs.** Grep translation files and any user-influenced key stream for `__proto__`, `constructor`, `prototype`, `__proto__.`, and dotted keys that end in a reserved segment.
3. **Trace pollution to a sink.** Prove impact with an inert marker (e.g. set `pollutedKey=1` and read it back on a plain object, per the upstream PoC) first. Then check whether a polluted property is consumed by `exec`/`eval`/template options; only claim RCE when that sink is actually reached.
4. **Separate exposure from exploitability.** A Vue app with a static, build-time catalog and no attacker-influenced key stream has package exposure without a practical path.

### Replayable validation boundary

- Test only where client/server testing is authorized.
- Use a non-executing marker payload (`__proto__` key setting a benign `pollutedKey`) to demonstrate the cross-boundary write; confirm via reading the property on a fresh plain object.
- Capture the affected package + version, the catalog source, the key stream, the polluted property, and whether any sensitive API reads it. Do not read real secrets or trigger actual command execution in shared/production contexts.
