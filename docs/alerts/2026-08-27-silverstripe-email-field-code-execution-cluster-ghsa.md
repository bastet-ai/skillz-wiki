# Silverstripe email-field to code execution cluster, operator validation

**Date reviewed:** 2026-08-27  
**Advisories:** [GHSA-g8wr-r2v2-vqc6](https://github.com/advisories/GHSA-g8wr-r2v2-vqc6) / CVE-2026-54721 (high), [GHSA-39mm-rwm3-29jp](https://github.com/advisories/GHSA-39mm-r2v2-vqc6) / CVE-2026-54718 (high), [GHSA-gvrw-qqp5-jgc5](https://github.com/advisories/GHSA-gvrw-qqp5-jgc5) / CVE-2026-54720 (medium)  
**Boundary class:** CMS editor email/template fields → server-side template evaluation; CMS media-embed → untrusted script host

## What is durable here

Silverstripe ships a large family of CMS modules (core `framework`, `userforms`,
`advancedworkflow`) that all render user-authored CMS fields. This wave shows a
recurring trust-boundary defect: **email/template string fields are treated as
trusted server-side markup or code, not as inert text.** Two of the three
advisories are RCE, and both ride on the same primitive, an email-related CMS
field that is evaluated by the server rather than rendered as a plain string.

| Advisory | Product / field | Boundary | Fixed |
| --- | --- | --- | --- |
| [GHSA-g8wr-r2v2-vqc6](https://github.com/advisories/GHSA-g8wr-r2v2-vqc6) / CVE-2026-54721 | `silverstripe/userforms` < 6.4.9 | userform **email subject** field → arbitrary code execution on the server | 6.4.9 |
| [GHSA-39mm-rwm3-29jp](https://github.com/advisories/GHSA-39mm-rwm3-29jp) / CVE-2026-54718 | `symbiote/silverstripe-advancedworkflow` < 6.4.5 | advanced-workflow **email template** field → arbitrary code execution on the server | 6.4.5 |
| [GHSA-gvrw-qqp5-jgc5](https://github.com/advisories/GHSA-gvrw-qqp5-jgc5) / CVE-2026-54720 | `silverstripe/framework` < 6.2.2 | CMS "Insert media from web" **embed** → reflected XSS from a crafted embed | 6.2.2 |

The RCE pair is the high-yield finding: a low- or medium-privilege CMS author
who can write an email subject or an advanced-workflow email template can reach
server-side code execution, because the field is passed to an evaluation sink
instead of being output as escaped text. The media-embed XSS is the same
pattern at lower severity, a web-host string crossing into a rendered
`<script>`/embed context.

The durable operator pattern is: **any CMS string field that is *used to build
an email* or *a template* is a candidate server-side evaluation sink.** Do not
assume "this is just a subject line." Confirm where the value flows before
reporting.

## Recon

- Enumerate Silverstripe modules and versions. `userforms`,
  `advancedworkflow`, and `framework` each have independent version axes and
  independent fixes (6.4.9 / 6.4.5 / 6.2.2 respectively). A host can be
  patched on one module and unpatched on another, check each.
- Identify which CMS roles can author email subjects, advanced-workflow email
  templates, or insert web media. The primitive needs a CMS author, not an
  administrator; the blast radius is the whole web app.
- Silverstripe CMS sites are common in enterprise/intranet and
  content-management deployments and are frequently reachable behind the same
  LB as other apps, so a foothold here often extends to co-located services.

## Validation workflow (authorized lab / customer-approved)

### Proof of the evaluation boundary (no code execution)

1. Confirm the product and module versions from the running install (module
   list / footer / headers as available). Record exact `userforms` /
   `advancedworkflow` / `framework` versions.
2. As a CMS author, open the userform email settings and the advanced-workflow
   email template editor. Record that the fields accept free-form text.
3. The proof of the boundary is **where the value flows**, not a working
   payload. Note:
   - userform email **subject** field,
   - advanced-workflow email **template** field,
   - CMS "insert media from web" embed host field.
4. Do **not** publish a working RCE payload. The report is the
   field-to-evaluation-sink transition: an attacker-controlled CMS string is
   evaluated server-side.

### If execution is in scope and customer-approved

- Demonstrate with the minimal inert marker the lab allows (e.g. a
  `touch` of a canary path or an environment-marker echo) on an isolated VM,
  then stop. Do not install persistence, exfiltrate, or touch co-located data.
- Keep the marker output out of any wiki/report artifact.

## Reporting heuristic

- Lead with the **email-field → server-side evaluation** boundary. Name the
  exact field and the exact module. Distinguish the two RCEs (userforms email
  subject vs advanced-workflow email template), they are separate modules
  with separate fixes.
- Report the media-embed XSS as a lower-severity sibling finding on
  `framework` (embed host → untrusted script execution), not as part of the
  RCE chain.
- Do not publish payloads. The chain is proven by the field-to-sink transition
  and the confirmed unpatched module version.

## Safety constraints

- No code execution on production targets.
- No modification of real forms, workflows, or media libraries.
- Use a throwaway CMS author account and an isolated lab instance.
- Keep any canary output redacted and out of the report.

## Not promoted from the same wave

- [GHSA-r5pm-vrc5-3m73](https://github.com/advisories/GHSA-r5pm-vrc5-3m73) / CVE-2026-54713, `cakephp/queue` `getUniqueId` incomplete-comparison collision: queue identity/DoS surface, no durable offensive exploit path on its own.

## November 16 follow-up: Framework seven-leg wave, dev-task writer parameter mints injector objects for RCE, SecurityAdmin edits its way to ADMIN, and the sanitiser keeps data URIs (7 GHSAs, published 2026-11-16 22:27-22:35Z, fixed 6.2.13)

Second coordinated wave for this product since the August 27 email-field cluster: `silverstripe/framework` shipped seven advisories, all fixed in 6.2.13, CMS 5 not affected. The lead leg turns a **developer task URL into a code-execution endpoint**.

| Advisory | Boundary | Shape |
| --- | --- | --- |
| [GHSA-c94f-87xg-65wf](https://github.com/advisories/GHSA-c94f-87xg-65wf) / CVE-2026-91115 (high) | `i18nTextCollectorTask` **writer parameter passed to the injector unvalidated** → arbitrary object creation with attacker-controlled constructor arguments → code execution | dev task, **no confirmation prompt**; a link click by any admin runs it; on a dev-mode site **no login at all** |
| [GHSA-rg72-5958-c65m](https://github.com/advisories/GHSA-rg72-5958-c65m) / CVE-2026-91112 | `CMS_ACCESS_SecurityAdmin` without ADMIN **edits the group that grants ADMIN** via a role or parent group → self privilege escalation | permission-namespace grant vs transitive effect |
| [GHSA-3qh3-54qg-gpq3](https://github.com/advisories/GHSA-3qh3-54qg-gpq3) / CVE-2026-88989 | GridField detail form: **direct save request creates records** the user has no create permission for | UI-gated form, ungated POST |
| [GHSA-4qv2-g5vp-wjjw](https://github.com/advisories/GHSA-4qv2-g5vp-wjjw) / CVE-2026-91113 | User-controlled **ClassName changes a record's class** without the target class's permission checks | type-swap crosses permission namespaces |
| [GHSA-xwg4-8hqh-79jq](https://github.com/advisories/GHSA-xwg4-8hqh-79jq) / CVE-2026-88988 | Sanitiser does not strip **SVG data URIs** → stored JS against other viewers | deny-list sanitiser scheme gap |
| [GHSA-qqrg-8jpm-8mph](https://github.com/advisories/GHSA-qqrg-8jpm-8mph) / CVE-2026-88987 | Sanitiser does not strip **XHTML/XML data URIs** → stored JS | sibling scheme variant, same sweep |
| (tracked) | remaining informational legs | version-band fill |

Operator rules from this wave:

1. **Dev/debug task endpoints are a second admin panel.** Framework's dev tasks (`/dev/tasks/...`) run without confirmation, so every task parameter that reaches a DI container/injector is a candidate object-mint sink. Recon: enumerate `/dev/`, `/dev/build`, `/dev/tasks` and each task's query parameters on every Silverstripe target; dev-mode detection (verbose errors, build pages) upgrades "needs an admin click" to unauthenticated. The lure leg matters too: a no-confirmation GET-reachable task means the payload ships as a link in the CMS author's inbox, same delivery shape as the Oct 9 SmarterMail and the standing click-to-RCE family.
2. **Permission namespaces are checked, permission effects are not.** SecurityAdmin could not grant ADMIN directly but could **edit the group whose role/parent chain yields ADMIN**. Audit battery for any RBAC UI: for every editable permission-bearing object (groups, roles, policies, API-key templates), ask whether the user can reach a *transitive* grant the direct check forbids. Same genealogy as the Oct 9 Nginx UI 2FA-flag drift: the UI's enable-flag semantics and the enforcement check disagree.
3. **Type-swap is a privilege boundary.** `ClassName` as a writable field lets an editor of class A mutate the row into class B, skipping B's permission checks entirely. Sweep every update endpoint for class/type/kind discriminator fields and diff the authorization applied on create vs on update (see the Directus share-update leg on the Sept 21 precedence page, same day, same rule).
4. **Deny-list HTML sanitisers need a scheme battery, not a tag battery.** The missing cases were `data:` URIs with SVG/XHTML/XML media types, i.e. the sanitizer matched tag names while browsers re-parse embedded markup. Battery: `data:image/svg+xml`, `data:image/svg+xml;base64`, `data:text/html`, `data:application/xhtml+xml`, `data:application/xml`, uppercase/mixed-case media types, whitespace/tab-split schemes (the Sept 21 SPIP-style absent/odd-branch probe applies to the strip rules too).
5. Validation: throwaway CMS author + isolated lab install, marker-only proofs (canary file, no-payload object construction), never run `dev/build` or write real content on a customer site; compare 6.2.12 vs 6.2.13 side by side for the dev-task leg.
