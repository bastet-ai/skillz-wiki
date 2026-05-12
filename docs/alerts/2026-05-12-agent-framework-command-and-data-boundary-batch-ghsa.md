# Agent, framework command, and data-boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because agent and developer-framework features repeatedly let untrusted strings become commands, SQL identifiers, templates, credentials, or privileged test executions.

## Advisories covered

- **PraisonAI patch-bypass RCE, SSRF, SQLi, and command injection** — [GHSA-xcmw-grxf-wjhj](https://github.com/advisories/GHSA-xcmw-grxf-wjhj), [GHSA-q9pw-vmhh-384g](https://github.com/advisories/GHSA-q9pw-vmhh-384g), [GHSA-rg3h-x3jw-7jm5](https://github.com/advisories/GHSA-rg3h-x3jw-7jm5), [GHSA-9qhq-v63v-fv3j](https://github.com/advisories/GHSA-9qhq-v63v-fv3j): incomplete fixes around `tool_override.py`, SSRF enforcement, conversation-store `table_prefix` identifiers, and OS-command execution show why agent tool patches need negative regression tests.
- **LiteLLM MCP/test endpoint command execution, SQLi, and SSTI** — [GHSA-v4p8-mg3p-g94g](https://github.com/advisories/GHSA-v4p8-mg3p-g94g), [GHSA-r75f-5x8p-qvmc](https://github.com/advisories/GHSA-r75f-5x8p-qvmc), [GHSA-xqmj-j6mv-4862](https://github.com/advisories/GHSA-xqmj-j6mv-4862): authenticated proxy/test surfaces can still cross into stdio process launch, database query construction, or template rendering.
- **math-codegen string-literal RCE** — [GHSA-p6x5-p4xf-cc4r](https://github.com/advisories/GHSA-p6x5-p4xf-cc4r): generated code must escape literals for the target language, not only quote them.
- **PHPUnit INI newline argument injection** — [GHSA-qrr6-mg7r-m243](https://github.com/advisories/GHSA-qrr6-mg7r-m243): config values forwarded to child processes can become extra CLI arguments when newline or delimiter handling is inconsistent.
- **go-git cross-host redirect credential leak** — [GHSA-3xc5-wrhm-f963](https://github.com/advisories/GHSA-3xc5-wrhm-f963): smart HTTP clients must not forward credentials across host/scheme boundaries after redirects.
- **YARD server path traversal/file access** — [GHSA-3jfp-46x4-xgfj](https://github.com/advisories/GHSA-3jfp-46x4-xgfj): local documentation servers need canonical file containment, even when intended for developer use.
- **AstrBot hard-coded JWT signing keys RCE** — [GHSA-4m32-cjv7-f425](https://github.com/advisories/GHSA-4m32-cjv7-f425): static signing secrets turn tokens into public forgeable capabilities.
- **Ghost Content API SQL injection** — [GHSA-w52v-v783-gw97](https://github.com/advisories/GHSA-w52v-v783-gw97): content API query parameters need typed query builders and deny-by-default raw SQL edges.

## Operator triage

1. Patch agent runtimes and LLM proxies before exposing them to users, CI, or reachable networks; especially remove unauthenticated/test endpoints from production.
2. Rotate API tokens, JWT secrets, database credentials, and Git credentials if affected services processed untrusted prompts, tool payloads, redirects, or test requests.
3. Hunt for unexpected spawned processes, modified startup files, new template/test artifacts, unknown database tables, and outbound requests to metadata/internal networks.
4. For Git clients, inspect logs for redirects from trusted hosts to attacker-controlled hosts and assume leaked Basic/token auth if redirect credential scoping was vulnerable.

## Durable controls

- Treat every agent/test/debug endpoint as a privileged remote-code-adjacent surface; gate it with explicit authz and production disablement.
- SQL identifiers and table prefixes need allowlists or compiler APIs; parameter binding does not protect identifiers.
- Template/code generation must use language-aware escaping for each sink and should prefer AST builders over string concatenation.
- Secrets used for signing must be instance-unique, generated at install/startup, rotatable, and never shipped as defaults.
- Redirect handling should strip credentials unless the target origin is exactly within the original trust scope.
