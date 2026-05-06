# Render, identity, and URL-canonicalization boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced render and identity-boundary issues updated on **2026-05-06** across Angular, Magento LTS, and Statamic CMS.

## Advisories covered

- **Angular i18n attribute-binding XSS** — [GHSA-g93w-mfhg-p222](https://github.com/advisories/GHSA-g93w-mfhg-p222): i18n attribute bindings could generate XSS in affected `@angular/core` ranges. Fixed in 20.3.18, 21.2.4, and 22.0.0-next.3.
- **Angular SSR protocol-relative URL injection** — [GHSA-vfx2-hv2g-xj5f](https://github.com/advisories/GHSA-vfx2-hv2g-xj5f): a single-backslash bypass could produce protocol-relative redirects in `@angular/ssr`. Fixed in 20.3.21, 21.2.3, and 22.0.0-next.2.
- **Magento LTS reflected XSS in import data-flow profiles** — [GHSA-x8jv-q8j2-487c](https://github.com/advisories/GHSA-x8jv-q8j2-487c): reflected XSS affected `openmage/magento-lts`; fixed in 20.18.0.
- **Statamic forgot-password email enumeration** — [GHSA-m24v-f7g5-gq67](https://github.com/advisories/GHSA-m24v-f7g5-gq67): observable response differences revealed account existence; fixed in 5.73.21 and 6.15.0.

## Why this is durable

Template frameworks, SSR routers, admin import UIs, and password-reset endpoints all turn user input into browser-observable differences. The persistent lesson is to canonicalize before policy, encode at the final output sink, and make identity flows indistinguishable.

## Immediate triage

1. Patch Angular core/SSR, Magento LTS, and Statamic to the fixed versions listed above.
2. Search for Angular i18n attributes that interpolate attacker-controlled strings into HTML attributes.
3. Test SSR redirects with `\example.com`, encoded backslashes, mixed separators, and scheme-relative variants.
4. Review Magento import/data-flow profile parameters for reflected values in admin responses.
5. Verify forgot-password responses have identical body, status, timing envelope, and rate-limit behavior for existing and non-existing accounts.

## Durable controls

- Normalize URLs with one parser, reject ambiguous slash/backslash forms, and re-check after redirects or framework rewrites.
- Keep translation catalogs out of trusted template/control syntax; escape translated values at the final attribute/text context.
- Use constant-response account recovery flows with per-account and per-IP throttles.
- Add browser-level XSS tests for admin import, preview, and data-mapping screens.
