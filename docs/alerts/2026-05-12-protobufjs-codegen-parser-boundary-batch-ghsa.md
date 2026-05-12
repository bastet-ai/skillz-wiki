# protobuf.js codegen and parser-boundary batch

Source: GitHub Security Advisories published 2026-05-12.

This batch is durable because protobuf schemas, descriptors, generated JavaScript, CLI wrappers, and decoded message bytes sit on different trust boundaries. The same library may be safe for trusted schemas but unsafe when applications accept schemas, descriptors, file paths, or binary payloads from users.

## Advisories covered

- **CLI shell injection in `pbts`** — [GHSA-f84p-cvgm-xgjj](https://github.com/advisories/GHSA-f84p-cvgm-xgjj), CVE-2026-42290: `protobufjs-cli` built a shell command from input paths before invoking JSDoc, allowing shell metacharacters in attacker-controlled paths to execute commands.
- **Static output code injection from crafted schema names** — [GHSA-6r35-46g8-jcw9](https://github.com/advisories/GHSA-6r35-46g8-jcw9), CVE-2026-44295: `pbjs` static code generation could emit unsafe JavaScript identifiers derived from schema-controlled names.
- **Runtime code generation and conversion issues** — [GHSA-66ff-xgx4-vchm](https://github.com/advisories/GHSA-66ff-xgx4-vchm), [GHSA-75px-5xx7-5xc7](https://github.com/advisories/GHSA-75px-5xx7-5xc7), [GHSA-2pr8-phx7-x9h3](https://github.com/advisories/GHSA-2pr8-phx7-x9h3): crafted descriptors, defaults, field names, or a prior prototype-pollution primitive could inject code or break generated functions.
- **Prototype and process-state corruption** — [GHSA-fx83-v9x8-x52w](https://github.com/advisories/GHSA-fx83-v9x8-x52w), [GHSA-jvwf-75h9-cwgg](https://github.com/advisories/GHSA-jvwf-75h9-cwgg): untrusted objects or option paths could alter message instance prototypes or corrupt built-in process state.
- **Parser and string-decoder resource/validation gaps** — [GHSA-685m-2w69-288q](https://github.com/advisories/GHSA-685m-2w69-288q), [GHSA-q6x5-8v7m-xcrf](https://github.com/advisories/GHSA-q6x5-8v7m-xcrf): deeply nested protobuf data can exhaust the JavaScript stack, and fallback UTF-8 decoding accepted overlong encodings that can bypass byte-level filters.

Affected packages include `protobufjs <= 7.5.5` / `8.0.0-8.0.1` fixed in `7.5.6` / `8.0.2`, `@protobufjs/utf8 <= 1.1.0` fixed in `1.1.1`, and `protobufjs-cli <= 1.2.0` / `2.0.0-2.0.1` fixed in `1.2.1` / `2.0.2`.

## Operator triage

1. Upgrade `protobufjs`, `@protobufjs/utf8`, and `protobufjs-cli` across runtime and build images; check lockfiles, generator containers, and CI helper images, not only production services.
2. Inventory where schemas/descriptors are user-uploaded, fetched from tenants, imported from plugin packages, or generated from partner inputs.
3. Rebuild generated JavaScript after upgrading the generator; do not assume old generated artifacts become safe just because runtime packages were patched.
4. If untrusted schemas were processed in CI or server-side generation, review build logs and workers for unexpected commands, modified generated files, and unusual network egress.
5. Add size/depth limits around protobuf decoding for unauthenticated or internet-facing message ingestion.

## Durable controls

- Treat schemas and descriptors as executable build inputs. They need provenance, review, and sandboxing comparable to templates or code generators.
- Avoid shell-string command construction in CLIs; pass argument arrays to child processes and normalize attacker-controlled file names before invoking generators.
- Use null-prototype maps or own-property checks for reflection/type registries, especially when generated code later interpolates registry values.
- Validate decoded strings at the semantic sink; do not rely only on pre-decode byte filters for path, command, SQL, or policy decisions.
- Isolate untrusted schema loading and message decoding in restartable workers with CPU, memory, recursion, and wall-clock budgets.
