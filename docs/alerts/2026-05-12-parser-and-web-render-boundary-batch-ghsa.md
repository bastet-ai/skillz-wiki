# Parser and web-render boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because it combines native parser memory safety, mailing-list/admin UI XSS, CRM stored XSS, and job-dashboard URL rendering issues. The shared lesson is to treat imported files, admin metadata, and dashboard URLs as hostile even when they arrive through trusted workflows.

## Advisories covered

- **GDAL out-of-bounds read and heap-based buffer overflow** — [GHSA-j3f5-rw74-g4rv](https://github.com/advisories/GHSA-j3f5-rw74-g4rv), [GHSA-h9rh-5ffh-h669](https://github.com/advisories/GHSA-h9rh-5ffh-h669): `GDAL <3.13.0` has native parser memory-safety issues. Even low-severity parser crashes matter in ingestion, map tiling, geospatial ETL, and upload-preview services.
- **Postorius XSS** — [GHSA-r7c9-7pjq-hmm8](https://github.com/advisories/GHSA-r7c9-7pjq-hmm8): mailing-list administration surfaces often render list names, domains, templates, or moderation metadata supplied by semi-trusted users.
- **Krayin CRM activity-create XSS** — [GHSA-j822-46r5-h4qx](https://github.com/advisories/GHSA-j822-46r5-h4qx): CRM activity fields are collaborative content and need output-context escaping before admin display.
- **Sidekiq-cron crafted-URL XSS** — [GHSA-xv9c-mjw8-79gf](https://github.com/advisories/GHSA-xv9c-mjw8-79gf): operations dashboards are not safe just because they are internal; URL and job metadata still need HTML/attribute/JavaScript-context escaping.

## Operator triage

1. Upgrade GDAL to `3.13.0` or later anywhere it parses uploaded geospatial data, third-party datasets, map archives, or customer files.
2. Patch Krayin CRM to `2.1.6` or later and Sidekiq-cron to `2.4.0` or later; track Postorius vendor guidance where no fixed version is listed in GitHub metadata.
3. Review web logs for stored payload probes in mailing-list fields, CRM activity fields, job names, schedule URLs, and dashboard parameters.
4. If an admin viewed a vulnerable page, assume session theft or privileged action CSRF may have occurred and review account/session history.

## Durable controls

- Put native parsers for uploaded or third-party files behind memory, CPU, wall-clock, and output-size limits; prefer worker isolation over in-process parsing.
- Normalize and validate file type before parser dispatch, but still treat the parser as hostile-input code.
- Escape at render time for the exact sink: HTML body, attribute, URL, JavaScript, CSS, and Markdown all differ.
- Apply Content Security Policy, HttpOnly/SameSite cookies, and admin reauthentication for sensitive actions so XSS has less blast radius.
- Do not exempt internal admin dashboards from XSS testing; they often carry the highest-value sessions.
