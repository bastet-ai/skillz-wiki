# Twig source-policy sandbox, Shopper Livewire, and TinyMCE `data-mce` boundaries

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **template-sandbox policy drift**, **Livewire public-property and per-action authorization bypass**, and **rich-text editor internal-attribute sanitizer confusion**. Use these workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **Twig source-policy sandbox callback bypass** — [GHSA-2q52-x2ff-qgfr](https://github.com/advisories/GHSA-2q52-x2ff-qgfr) / CVE-2026-24425: when Twig's sandbox was enabled by `SourcePolicyInterface` instead of globally, callback-accepting filters (`sort`, `filter`, `map`, `reduce`) could incorrectly skip the non-`Closure` callback restriction for user-controlled templates.
- **Shopper admin RBAC takeover and Livewire object-binding failures** — [GHSA-c3qp-2ggw-xjg7](https://github.com/advisories/GHSA-c3qp-2ggw-xjg7) / CVE-2026-47744, [GHSA-hr9v-r8r2-hg7j](https://github.com/advisories/GHSA-hr9v-r8r2-hg7j) / CVE-2026-47743, [GHSA-fxqw-97cc-7g5c](https://github.com/advisories/GHSA-fxqw-97cc-7g5c) / CVE-2026-47745, and [GHSA-h4mp-g9c6-xwph](https://github.com/advisories/GHSA-h4mp-g9c6-xwph) / CVE-2026-47742: multiple Shopper admin Livewire components trusted page access, read-only permissions, or mutable public model IDs instead of enforcing per-action authorization and locked object bindings.
- **TinyMCE internal `data-mce` and protected-comment sanitizer bypasses** — [GHSA-vg35-5wq7-3x7w](https://github.com/advisories/GHSA-vg35-5wq7-3x7w) / CVE-2026-47761, [GHSA-v98h-vmpc-fpqv](https://github.com/advisories/GHSA-v98h-vmpc-fpqv) / CVE-2026-47762, and [GHSA-q742-qvgc-gc2f](https://github.com/advisories/GHSA-q742-qvgc-gc2f) / CVE-2026-47759: TinyMCE stored-content sanitization could be bypassed through media-plugin `data-mce-object` / `data-mce-p-*` attributes, forged `mce:protected` comments, or `data-mce-href` / `data-mce-src` / `data-mce-style` values that overrode safe attributes during serialization.

## Operator triage

1. Search for applications that let users provide Twig templates, snippets, themes, notification bodies, CMS blocks, email templates, or report templates while enabling Twig's sandbox conditionally by template source.
2. Prioritize Twig targets where templates can call `sort`, `filter`, `map`, or `reduce` and where a non-closure PHP callable could cross from template control into application runtime behavior.
3. Search for Shopper admin panels and other Laravel Livewire admin surfaces. Prioritize low-privilege panel accounts, read-only roles, product/editor sub-forms, team settings, and inline table actions.
4. For Livewire targets, inspect browser payloads for mutable public model IDs, missing `#[Locked]` attributes, and action methods reachable even when the UI hides the button.
5. Search for TinyMCE deployments that expose the media plugin, the `protect` option, HTML import, or stored rich text crossing user-to-admin or tenant-to-support boundaries.
6. Treat TinyMCE `data-mce-*` attributes and `mce:protected` comments as editor-internal trust markers; user input should not be able to preserve or forge them into executable render output.

## Replayable validation boundaries

### Twig source-policy sandbox callback canary

Use a disposable Twig harness or in-scope staging template. Do not attempt destructive PHP callables or filesystem/network access against production.

1. Confirm the target uses an affected Twig version and enables sandboxing through a `SourcePolicyInterface` rather than globally for the current user-controlled template source.
2. Build two baseline templates: one rendered from a globally sandboxed source and one rendered through the source-policy path. Both should exercise one callback-accepting filter such as `filter` or `map`.
3. Use a harmless non-`Closure` callback candidate that produces a visible marker and is safe in the target harness. Avoid callables that execute commands, read files, mutate data, or reach external networks.
4. Vulnerable result: the source-policy-rendered template accepts the non-`Closure` callback while the globally sandboxed template rejects it, proving policy-context drift.
5. Capture the Twig version, sandbox configuration, source policy rule, exact filter used, accepted/rejected callback behavior, and resulting marker. Frame impact around what callables become reachable in that application, not generic RCE unless the allowed callable path proves it safely.

### Shopper Livewire authorization and object-binding canaries

Use seeded lab records and low-privilege test accounts. Do not delete real users, disrupt checkout, change live prices, or expose real customer credentials.

1. Create two panel users: a low-privilege or read-only account and an administrator. Seed at least two products, one customer, roles, payment methods, currencies, and carriers in a lab Shopper instance.
2. Baseline authorized behavior in the UI, then replay Livewire requests directly from the browser dev tools or a proxy. Keep the original CSRF/session context for the low-privilege account.
3. For team settings, test whether `Settings/Team/Index` loads and whether public actions can create roles or delete lab users without `manage_users`.
4. For role permissions, compare read-only `view_users` access with write attempts that grant `manage_users`, `edit_orders`, or another high-impact lab permission.
5. For product sub-forms, alter the public product ID in the Livewire payload and call `store()` on `Edit`, `Inventory`, `Seo`, `Shipping`, or `Files` without `edit_products`.
6. For table actions, call enable/disable/edit/delete actions on payment methods, currencies, or carriers without their matching edit permissions. Use inert lab records only.
7. Vulnerable result: the server accepts the action or binds to the tampered model ID instead of denying based on the account's real permissions and route-scoped object.
8. Capture role, component name, action method, original and tampered model IDs, server response, and before/after lab record diffs. Redact session cookies and CSRF tokens.

### TinyMCE `data-mce` and protected-comment sanitizer canaries

Keep XSS proofs inert until scope explicitly permits active JavaScript. Do not send payloads to real users.

1. Confirm the editor uses TinyMCE 5.x LTS, 7.x, or 8.x in an affected version range and identify enabled plugins/options: media plugin, `protect`, HTML import, and serialization settings.
2. Submit a baseline rich-text fragment with benign links, images, style attributes, media embeds, and comments. Record the parsed, saved, and rendered HTML.
3. Submit inert canaries that try to preserve editor-internal attributes: `data-mce-href`, `data-mce-src`, `data-mce-style`, `data-mce-object`, and `data-mce-p-*`. Use marker values, not exfiltration URLs.
4. If the `protect` option is enabled, submit a forged `mce:protected` comment containing a harmless marker that should not be restored unless it matches the configured protect rule.
5. Vulnerable result: saved/rendered content restores or prioritizes attacker-controlled `data-mce-*` or protected-comment content over sanitized safe attributes, creating an executable or security-relevant render path.
6. Capture editor version, plugin/option state, input HTML, sanitized output, final rendered DOM, required role, and audience that can view the content.

## Reporting heuristics

- Frame Twig findings as **sandbox policy-context drift for callback-accepting filters**. Strong reports compare global-sandbox denial with source-policy acceptance using the same callback canary.
- Frame Shopper findings as **server-side Livewire authorization failure**, not just hidden-button UI bypass. Strong reports show a low-privilege request mutating a lab record through an action method or tampered model ID.
- Frame TinyMCE findings as **stored rich-text internal-attribute trust confusion**. Strong reports include parse/save/render diffs and identify the boundary crossed by stored content.
- Avoid overclaiming: Couchbase Sync Gateway log password disclosure ([GHSA-pqhp-4xfc-hjgq](https://github.com/advisories/GHSA-pqhp-4xfc-hjgq)) was reviewed in the same scan but is not included as an offensive workflow because it is a log-handling disclosure item rather than a distinct validation boundary.

## Sources

- GitHub Advisory Database: [GHSA-2q52-x2ff-qgfr / CVE-2026-24425](https://github.com/advisories/GHSA-2q52-x2ff-qgfr)
- Twig advisory/source: <https://github.com/twigphp/Twig/security/advisories/GHSA-2q52-x2ff-qgfr> and <https://github.com/twigphp/Twig>
- GitHub Advisory Database: [GHSA-c3qp-2ggw-xjg7 / CVE-2026-47744](https://github.com/advisories/GHSA-c3qp-2ggw-xjg7)
- GitHub Advisory Database: [GHSA-hr9v-r8r2-hg7j / CVE-2026-47743](https://github.com/advisories/GHSA-hr9v-r8r2-hg7j)
- GitHub Advisory Database: [GHSA-fxqw-97cc-7g5c / CVE-2026-47745](https://github.com/advisories/GHSA-fxqw-97cc-7g5c)
- GitHub Advisory Database: [GHSA-h4mp-g9c6-xwph / CVE-2026-47742](https://github.com/advisories/GHSA-h4mp-g9c6-xwph)
- Shopper source/advisories: <https://github.com/shopperlabs/shopper> and <https://github.com/shopperlabs/shopper/security/advisories>
- GitHub Advisory Database: [GHSA-vg35-5wq7-3x7w / CVE-2026-47761](https://github.com/advisories/GHSA-vg35-5wq7-3x7w)
- GitHub Advisory Database: [GHSA-v98h-vmpc-fpqv / CVE-2026-47762](https://github.com/advisories/GHSA-v98h-vmpc-fpqv)
- GitHub Advisory Database: [GHSA-q742-qvgc-gc2f / CVE-2026-47759](https://github.com/advisories/GHSA-q742-qvgc-gc2f)
- TinyMCE advisory/source: <https://github.com/tinymce/tinymce/security/advisories> and <https://github.com/tinymce/tinymce>
