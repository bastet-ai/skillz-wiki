# Craft, PyLoad, and Wooey application authorization boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-06** application-boundary batch across Craft CMS, PyLoad, and Wooey.

## Advisories covered

- **Craft CMS `AssetsController::actionShowInFolder` information disclosure** — [GHSA-33m5-hqp9-97pw](https://github.com/advisories/GHSA-33m5-hqp9-97pw): authenticated Control Panel users without volume permissions could enumerate asset filenames and folder hierarchy. Fixed in `craftcms/cms 5.9.18`.
- **Craft CMS object-config / attached-behavior RCE** — [GHSA-qrgm-p9w5-rrfw](https://github.com/advisories/GHSA-qrgm-p9w5-rrfw): authenticated users could inject malicious Yii object configuration through field-layout hydration. Fixed in `4.17.12` and `5.9.18`.
- **Craft CMS GraphQL Address resolver cross-scope PII disclosure** — [GHSA-gj2p-p9m4-c8gw](https://github.com/advisories/GHSA-gj2p-p9m4-c8gw): GraphQL tokens scoped to one user group could query all address records because resolver-level schema filtering was missing. Fixed in `4.17.12` and `5.9.18`.
- **PyLoad WebUI traceback disclosure** — [GHSA-c3gc-9pf2-84gg](https://github.com/advisories/GHSA-c3gc-9pf2-84gg): unauthenticated template-rendering errors returned full Python tracebacks. Fixed in `pyload-ng 0.5.0b3.dev100`.
- **Wooey API incorrect privilege assignment** — [GHSA-w65c-cmxj-qrhm](https://github.com/advisories/GHSA-w65c-cmxj-qrhm): remote API manipulation in `add_or_update_script` could lead to improper authorization. Fixed in `0.13.3rc1` / `0.14.0` per advisory metadata.

## Why this is durable

These are not exotic memory bugs. They are authorization edges left out of sibling routes, resolvers, model hydration, error handlers, and script-management APIs. Patch waves often miss nearby methods introduced just before or after the fix.

## Immediate triage

1. Patch Craft CMS to `4.17.12+` or `5.9.18+`; patch PyLoad and Wooey to the fixed versions above.
2. For Craft, review authenticated CP accounts, GraphQL API tokens, asset volume permissions, and any recent calls to element search, asset folder, or address resolver endpoints.
3. For PyLoad, search access logs for unauthenticated `/web/<path>` requests that caused 500s or exposed template names.
4. For Wooey, review script creation/update events, API tokens, and jobs created by users whose role should not allow script mutation.

## Hunt ideas

- Craft: unexpected GraphQL address queries, asset ID enumeration, field-layout condition payloads containing Yii config keys, behavior names, event handlers, or command execution primitives.
- PyLoad: repeated requests for non-existent templates, stack traces in HTTP responses, and follow-on probing of file paths or configuration names disclosed by tracebacks.
- Wooey: API calls that alter script ownership, execution permissions, or command definitions outside normal deployment windows.

## Durable controls

- Centralize authorization checks in route/resolver/service layers and regression-test every sibling action that returns the same object type.
- Cleanse dynamic object configuration before construction; do not let request data reach framework magic keys, behaviors, event handlers, or class names.
- Treat GraphQL schema scopes as mandatory row-level filters, not only a binary capability check.
- Never return raw tracebacks to clients. Keep rich errors in authenticated logs and emit opaque failure IDs externally.
