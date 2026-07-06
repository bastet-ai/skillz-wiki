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

## July 2 Craft CMS peer-permission and entry-mutation follow-up

Later GitHub Advisory Database entries add four adjacent Craft CMS authorization-drift cases: [GHSA-7h62-6v23-v8fm](https://github.com/advisories/GHSA-7h62-6v23-v8fm) / CVE-2026-50284 for `AssetsController::actionDeleteFolder`, [GHSA-qh45-9g5p-m2v4](https://github.com/advisories/GHSA-qh45-9g5p-m2v4) / CVE-2026-50283 for `AssetsController::actionReplaceFile`, [GHSA-43cq-c2gq-pfpw](https://github.com/advisories/GHSA-43cq-c2gq-pfpw) / CVE-2026-50280 for `EntriesController::actionMoveToSection`, and [GHSA-qq2c-2q8j-jh27](https://github.com/advisories/GHSA-qq2c-2q8j-jh27) / CVE-2026-50279 for `EntriesController::actionSaveEntry` authorship mutation.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-7h62-6v23-v8fm](https://github.com/advisories/GHSA-7h62-6v23-v8fm) | folder-level `deleteAssets:<volume>` permission could cascade into deletion of peer-uploaded descendant assets without `deletePeerAssets:<volume>` | Test bulk/folder actions separately from single-asset routes; sibling endpoints often miss peer-permission checks. |
| [GHSA-qh45-9g5p-m2v4](https://github.com/advisories/GHSA-qh45-9g5p-m2v4) | `assetId` and `sourceAssetId` were both accepted, but authorization was evaluated against the replacement target while the source asset could be deleted | Multi-object actions need permission checks for every object that is read, written, moved, or deleted. |
| [GHSA-43cq-c2gq-pfpw](https://github.com/advisories/GHSA-43cq-c2gq-pfpw) | `entries/move-to-section` checked destination visibility rather than destination save permission | Content-management route tests should distinguish read/view access from write/save access after moves. |
| [GHSA-qq2c-2q8j-jh27](https://github.com/advisories/GHSA-qq2c-2q8j-jh27) | edit authorization happened before request-controlled `authors` / `author` mutation, without a post-mutation peer-author check | TOCTOU-style model population bugs are reportable when pre-check state differs from saved state. |

### Safe Craft validation additions

- Preconditions: disposable Craft CMS lab, affected `craftcms/cms` versions, low-privilege Control Panel users, shared test volumes/sections, and synthetic assets/entries only.
- For asset folder deletion, seed a shared volume with an attacker-owned folder containing a peer-owned canary asset. Attempt only the folder action and record whether the peer canary is deleted without `deletePeerAssets`.
- For replacement, create target and source canary assets in different permission scopes. Submit both `assetId` and `sourceAssetId` and record whether the source canary is removed without source delete permission.
- For section moves, give the test user source-section move rights plus destination-section view-only rights. Positive evidence is movement into a section where the user lacks save permission.
- For authorship mutation, capture pre-check entry author state, submitted `authors` / `author` parameter, saved author state, and whether dedicated peer-author-change permission was absent.
- Do not test against production content, media libraries, customer files, live editorial workflows, or destructive asset trees. Use tiny marker assets and disposable sections, and restore the lab state after each case.

### Reporting additions

Lead with the crossed boundary: **folder action to peer-asset deletion**, **source asset selector to unauthorized deletion**, **view-only destination to entry move**, or **pre-check entry state to post-mutation authorship change**. Strong reports include the route, affected version, permission matrix, before/after object IDs, canary-only evidence, and fixed-version negative controls.

## July 2 forced-folder-move and bulk-duplicate follow-up

Two later Craft CMS advisories add more sibling-route authorization and model-population drift under the same operator pattern: [GHSA-3w32-23wj-rxg3](https://github.com/advisories/GHSA-3w32-23wj-rxg3) / CVE-2026-50282 and [GHSA-x5m4-g2cq-52pq](https://github.com/advisories/GHSA-x5m4-g2cq-52pq) / CVE-2026-50281.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-3w32-23wj-rxg3](https://github.com/advisories/GHSA-3w32-23wj-rxg3) | `AssetsController::actionMoveFolder()` allowed `force=true` to delete a conflicting destination folder while checking source delete plus destination create/save, but not destination delete permission. | Test overwrite/force flags as delete operations against both source and destination objects. |
| [GHSA-x5m4-g2cq-52pq](https://github.com/advisories/GHSA-x5m4-g2cq-52pq) | `ElementsController::actionBulkDuplicate()` rejected top-level `id`, but accepted `newAttributes[id]`; duplication reset `id = null` before `Craft::configure()` restored an attacker-supplied ID and updated an existing element row. | Check nested request bags and safe-attribute allowlists for primary keys that can override framework clone/reset logic. |

### Safe validation additions

- Preconditions: disposable Craft CMS lab, affected `craftcms/cms` versions, low-privilege Control Panel users, synthetic assets/entries only, and fixed-version negative controls. Patched versions are `4.17.14+` / `5.9.21+` for forced folder moves and `5.9.21+` for bulk duplicate.
- For forced folder moves, create a destination conflict folder containing only marker assets. Attempt `force=true` as a user with source delete and destination create/save but without destination delete. Positive evidence is deletion of the destination conflict marker.
- For bulk duplicate, use predictable synthetic entry IDs and submit `newAttributes[id]` for a victim-owned marker entry while duplicating an attacker-owned source. Positive evidence is an update to the victim marker row instead of insertion of a new element.
- Do not test against production asset volumes, media libraries, customer entries, or editorial workflows. Avoid large folders, irreversible deletes, and any payload beyond tiny text/image marker files.

## July 6 Craft CMS referrer and file-read follow-up

The July 6 GitHub Advisory Database wave adds two Craft CMS items that extend this page's Craft boundary model: [GHSA-f74w-488g-8x5r](https://github.com/advisories/GHSA-f74w-488g-8x5r) / CVE-2026-55794 for potential authenticated remote code execution via a referrer redirect path, and [GHSA-287w-mxq6-x2cp](https://github.com/advisories/GHSA-287w-mxq6-x2cp) / CVE-2026-55792 for sensitive file disclosure / server-side file read.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-f74w-488g-8x5r](https://github.com/advisories/GHSA-f74w-488g-8x5r) | authenticated Control Panel flow where referrer/redirect-controlled state can reach a code-execution-capable backend path | Test redirect/referrer helpers as stateful server-side control inputs, not only browser navigation issues. |
| [GHSA-287w-mxq6-x2cp](https://github.com/advisories/GHSA-287w-mxq6-x2cp) | Craft route can disclose server-side files to an authenticated user | File-read proofs should use synthetic marker files and permission matrices, not real config, license, media, or credential files. |

### Safe Craft referrer and file-read harness

- Preconditions: disposable Craft CMS lab, affected versions, low-privilege Control Panel users, a synthetic marker file under a lab-only path, and fixed-version negative controls.
- For referrer/redirect handling, capture route, role, and state transition evidence with an inert marker action only. If code execution validation is explicitly allowed, stop at a temp-file or log-marker canary in the lab; otherwise report route reachability and source/patch evidence.
- For file read, request only the synthetic marker file and a denied-control marker. Positive evidence is the canary content returned where the role should not access server files.
- Do not read `.env`, `config/`, database backups, private keys, user uploads, license files, templates containing secrets, or production logs. Do not publish shell payloads.
- Report crossed boundaries as **authenticated referrer/redirect state to backend execution path** or **authenticated Craft route to server-side file read**, with version, route, role, raw/normalized path or redirect state, marker evidence, and patched negative controls.
