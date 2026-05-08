# CMS, render, template, and secret-boundary batch

**Signal:** The **2026-05-08 21:15 UTC** advisory scan added CMS/render and template-execution issues across October Rain, banks, Babel SystemJS transform, Firestore logging, and Wagtail authorization checks.

## Advisory cluster

- **nodejs-firestore key logging** — [GHSA-4g6q-77j7-vvjc](https://github.com/advisories/GHSA-4g6q-77j7-vvjc): `@google-cloud/firestore <6.1.0` could log Firestore keys; patch to `6.1.0+` and treat logs as potential secret stores.
- **October Rain INI interpolation env exfiltration** — [GHSA-g6v3-wv4j-x9hg](https://github.com/advisories/GHSA-g6v3-wv4j-x9hg): `october/rain <=3.7.13` and `>=4.0.0,<=4.1.9` allowed environment-variable disclosure through INI interpolation; patch to `3.7.14+` or `4.1.10+`.
- **October Rain SVG stored XSS filter bypass** — [GHSA-gcqv-f29m-67gr](https://github.com/advisories/GHSA-gcqv-f29m-67gr): the same Rain branches allowed stored XSS through SVG filtering gaps; patch to `3.7.14+` or `4.1.10+`.
- **banks Jinja2 SSTI RCE** — [GHSA-gphh-9q3h-jgpp](https://github.com/advisories/GHSA-gphh-9q3h-jgpp): `banks <=2.4.1` could execute attacker-controlled template input; patch to `2.4.2+`.
- **Babel SystemJS transform arbitrary code generation** — [GHSA-fv7c-fp4j-7gwp](https://github.com/advisories/GHSA-fv7c-fp4j-7gwp): `@babel/plugin-transform-modules-systemjs >=7.12.0,<=7.29.3` and `8.0.0-alpha.0..alpha.12` could generate arbitrary code when compiling malicious input; patch to `7.29.4+` or `8.0.0-alpha.13+`.
- **Wagtail permission/restriction batch** — [GHSA-67rv-mg8q-5pf3](https://github.com/advisories/GHSA-67rv-mg8q-5pf3), [GHSA-p5gm-92h4-6pv6](https://github.com/advisories/GHSA-p5gm-92h4-6pv6), [GHSA-pwm3-7fv4-g6xx](https://github.com/advisories/GHSA-pwm3-7fv4-g6xx), [GHSA-c4mr-889m-vgf6](https://github.com/advisories/GHSA-c4mr-889m-vgf6), [GHSA-c6wj-9vcj-75pj](https://github.com/advisories/GHSA-c6wj-9vcj-75pj): `wagtail <7.0.7` and `>=7.1,<7.3.2` had authorization gaps around copying pages, document/image API restrictions, form-submission deletion, page history, and revision comparison; patch to `7.0.7+` or `7.3.2+`.

## Why this matters

The reusable lesson is that “content” surfaces repeatedly become execution, disclosure, or authorization surfaces: config interpolation reads process secrets, SVG survives sanitizer assumptions, templates execute, build transforms emit code, logs preserve keys, and CMS object actions forget to re-check permissions.

## Triage

1. Patch the affected packages and invalidate/reissue any Firestore keys that may have landed in application, CI, support, crash, or centralized logs.
2. Search logs for Firestore credentials and October/Rain environment-variable names, then rotate anything exposed.
3. Review user-controllable template, Markdown, SVG, and transform-input paths; treat compile/render pipelines as code execution until sandboxed.
4. For Wagtail, enumerate roles with page-copy, history, revision-compare, image/document API, and form-submission permissions; test denied objects directly by URL/API after patching.
5. Hunt for stored SVG uploads, unexpected Jinja render errors, Babel transform crashes, and unusual Wagtail content access in the advisory window.

## Durable controls

- Keep secrets out of logs with structured redaction tests and periodic log-secret scans.
- Disable environment interpolation in user/config inputs unless explicitly required and allowlisted.
- Sanitize SVG as active content or convert it server-side to inert raster output before storage/display.
- Run template and code-transform features in locked-down workers with no secrets and minimal filesystem/network access.
- Make CMS authorization checks object-specific and action-specific; never rely on navigation/UI hiding as the control.
