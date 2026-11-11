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
