# Kirby, Arcane, Flarum, and PrestaShop admin/data-boundary batch (GHSA-85x2-r8xv-ww8c / GHSA-cxx3-hr75-4q96 / GHSA-xjvc-pw2r-6878 / GHSA-mqq7-wxx5-mp8h)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Several CMS/admin surfaces exposed data or execution-adjacent behavior through missing authorization, unsafe theme compilation, or unvalidated method selection.

## What it is
- `GHSA-85x2-r8xv-ww8c`: Kirby CMS does not consistently enforce `pages.access/list` and `files.access/list` in the Panel and REST API for authenticated users whose roles should not see specific pages/files. Fixed in `getkirby/cms` `4.9.0` and `5.4.0`.
- `GHSA-cxx3-hr75-4q96`: Arcane exposes custom Compose template YAML and `.env` content through unauthenticated `/api/templates*` endpoints. Fixed in `github.com/getarcaneapp/arcane/backend` `1.18.0`.
- `GHSA-xjvc-pw2r-6878`: Flarum's prior LESS hardening missed theme color / registered LESS config variables, allowing authenticated admins to inject `@import` and read server-local files during CSS compilation. Fixed in `flarum/core` `1.8.16` and `2.0.0-rc.1`.
- `GHSA-mqq7-wxx5-mp8h`: PrestaShop `ps_checkout` before `5.3.0` allows limited unauthorized method invocation through an unvalidated parameter.

References:

- <https://github.com/advisories/GHSA-85x2-r8xv-ww8c>
- <https://github.com/advisories/GHSA-cxx3-hr75-4q96>
- <https://github.com/advisories/GHSA-xjvc-pw2r-6878>
- <https://github.com/advisories/GHSA-mqq7-wxx5-mp8h>

## Triage
1. Find public or shared-admin Kirby, Arcane, Flarum, and PrestaShop deployments.
2. For Kirby, test least-privilege roles against both UI and API page/file list endpoints.
3. For Arcane, assume saved Compose templates may contain production `.env` secrets; review exposure logs before rotating.
4. For Flarum, search theme and extension settings that are interpolated into LESS variables, not just `custom_less`.
5. For PrestaShop, map `ps_checkout` exposed controller/action parameters and check version/build numbers.

## Mitigation
- Upgrade affected packages to fixed versions.
- Put admin APIs behind authentication and repeat authorization checks at every read endpoint, not only in UI routes.
- Do not store real secrets in reusable templates; use secret references or vault-backed placeholders.
- Treat theme/CSS compilers as file-reading code paths; block `@import`, remote URLs, and arbitrary function access across every interpolated config variable.
- Replace dynamic method dispatch from request parameters with explicit allowlists.

## Detection ideas
- Hunt unauthenticated `GET /api/templates*` requests, template exports, and `.env` strings in responses or access logs.
- Check Kirby API logs for low-privilege users listing pages/files they should not see.
- Review Flarum settings changes containing `@import`, `data-uri`, path traversal tokens, or URL-like values in color/theme fields.
- Alert on unusual checkout module method names, repeated parameter fuzzing, or requests from non-checkout flows.

## Durable lesson
Admin surfaces often mix content, configuration, and secrets. Enforce authorization in the backend, keep secrets out of templates, and harden every compiler/interpreter input path rather than only the obvious custom-code field.
