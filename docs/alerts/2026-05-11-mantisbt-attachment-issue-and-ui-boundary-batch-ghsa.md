# MantisBT attachment, issue, and UI-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11 20:15 UTC.

This burst is durable because it is not one isolated XSS. It shows a mature issue tracker repeatedly crossing the same boundaries: private issue state leaked through REST attachment and bugnote APIs, manager-level workflows crossed into administrator control, and user-controlled issue metadata reached attachment downloads, filters, clones, tags, custom fields, and preferences as executable browser content. Treat MantisBT as an application where issue text, file names, filter metadata, profile preferences, and bugnote history all need output-context encoding and server-side authorization on every read and write.

## Advisories covered

- **MantisBT Vulnerable to Stored XSS in File Download** — [GHSA-p6fr-rxq7-xcg8](https://github.com/advisories/GHSA-p6fr-rxq7-xcg8), CVE-2026-44657 (High): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has Stored XSS on Move Attachments Admin Page** — [GHSA-7mqj-8gj2-cg59](https://github.com/advisories/GHSA-7mqj-8gj2-cg59), CVE-2026-44655 (High): composer `mantisbt/mantisbt` >= 1.3.0, <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has a Private Bugnote Attachment Content Leak via REST API** — [GHSA-pw5x-2mf9-3xc8](https://github.com/advisories/GHSA-pw5x-2mf9-3xc8), CVE-2026-42071 (High): composer `mantisbt/mantisbt` >= 2.23.0, <= 2.28.1; fixed in `2.28.2`.
- **MantisBT: Authorization Bypass in Bugnote Editing via Issue Update API** — [GHSA-pq86-j2c2-47f6](https://github.com/advisories/GHSA-pq86-j2c2-47f6), CVE-2026-42070 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT is Vulnerable to Reflected XSS in Rendering Dynamic Custom Textarea Field** — [GHSA-j7v9-f46r-2rp4](https://github.com/advisories/GHSA-j7v9-f46r-2rp4), CVE-2026-41897 (Medium): composer `mantisbt/mantisbt` >= 1.0.0, < 2.28.2; fixed in `2.28.2`.
- **MantisBT is Vulnerable to Stored XSS in Saved-Filter Owner Column** — [GHSA-f633-865q-2mhh](https://github.com/advisories/GHSA-f633-865q-2mhh), CVE-2026-40607 (High): composer `mantisbt/mantisbt` >= 2.1.0, <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has Potential Referer-Based Reflected HTML Injection / XSS in Tag Update Page** — [GHSA-6jh4-47v2-4g37](https://github.com/advisories/GHSA-6jh4-47v2-4g37), CVE-2026-40598 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has a Content Security Policy bypass via attachments** — [GHSA-9c3j-xm6v-j7j3](https://github.com/advisories/GHSA-9c3j-xm6v-j7j3), CVE-2026-40597 (High): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT is Vulnerable to XSS leading to account takeover via updating a user's font family preference** — [GHSA-j3v9-553h-x28j](https://github.com/advisories/GHSA-j3v9-553h-x28j), CVE-2026-40596 (High): composer `mantisbt/mantisbt` >= 2.11.0, <= 2.28.1; fixed in `2.28.2`.
- **MantisBT is Vulnerable to Stored XSS in Custom Field Textarea Values** — [GHSA-qj6w-v29q-4rgx](https://github.com/advisories/GHSA-qj6w-v29q-4rgx), CVE-2026-39960 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT: Bugnote Revision Page Leaks Private Issue Metadata After Issue Access Is Revoked** — [GHSA-crmx-4p49-46m2](https://github.com/advisories/GHSA-crmx-4p49-46m2), CVE-2026-34970 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has an Authorization Bypass that Allows Uploading Attachments to Private Issues via REST API** — [GHSA-h4x5-gvx6-3rwc](https://github.com/advisories/GHSA-h4x5-gvx6-3rwc), CVE-2026-34754 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has an authorization bypass that allows reading attachments after losing access to a private issue** — [GHSA-rmp5-5jj7-gmvf](https://github.com/advisories/GHSA-rmp5-5jj7-gmvf), CVE-2026-34744 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT has an authorization bypass in private issue monitoring** — [GHSA-ggw7-9675-6v4v](https://github.com/advisories/GHSA-ggw7-9675-6v4v), CVE-2026-34579 (Medium): composer `mantisbt/mantisbt` >= 2.26.1, <= 2.28.1; fixed in `2.28.2`.
- **MantisBT is Vulnerable to Stored HTML Injection/XSS in Clone Issue Form** — [GHSA-fvjf-68wh-rwp2](https://github.com/advisories/GHSA-fvjf-68wh-rwp2), CVE-2026-34463 (High): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.
- **MantisBT Vulnerable to Privilege Escalation from Manager to Administrator** — [GHSA-frf7-jhp9-jxm6](https://github.com/advisories/GHSA-frf7-jhp9-jxm6), CVE-2026-34390 (Medium): composer `mantisbt/mantisbt` <= 2.28.1; fixed in `2.28.2`.

## Operator triage

1. Upgrade `mantisbt/mantisbt` to **2.28.2+** across every deployment, including internal trackers and legacy project portals that still expose REST APIs.
2. Review REST/API logs for attachment reads, private issue uploads, bugnote edits, and monitor-state changes by users that did not have current issue access at request time.
3. Search recent issue activity for suspicious custom-field textarea values, cloned issue metadata, saved-filter owner fields, tag-update referrers, and font-family preferences containing markup, script, CSS functions, or unusual URL schemes.
4. If private issue confidentiality matters, rotate credentials or secrets attached to issues whose access changed during the vulnerable window; the leak paths include attachments after access revocation and private bugnote metadata/content.
5. Re-test custom plugins and themes after patching. MantisBT extensions often add custom fields, file handlers, and REST wrappers; they should inherit fixed escaping and authorization helpers rather than recreating vulnerable logic.

## Durable controls

- Authorization must be checked at the object being returned, not just at the parent issue route. Attachment content, bugnote revisions, monitor relationships, and move/edit actions each need fresh server-side permission checks.
- Stored issue metadata is hostile even when it comes from authenticated users. Escape by output context for HTML text, attributes, CSS, URLs, downloads, and JSON responses; CSP is a backstop, not the primary sanitizer.
- File downloads should send strict `Content-Disposition`, safe content types, `X-Content-Type-Options: nosniff`, and attachment rendering isolation so uploaded content cannot become same-origin active content.
- Administrative thresholds must be enforced on the server from immutable roles. Workflow fields such as owner, reporter, monitor, profile, and target project cannot select the actor's privilege.
- Incident response should group UI XSS and API authorization bugs together: XSS in a tracker can steal sessions/API tokens, then use REST leaks to exfiltrate private vulnerability reports.

## Related Wisdom

- [App file, render, and permission-boundary batch](2026-05-08-app-file-render-and-permission-boundary-batch-ghsa.md)
- [Render, route, and client-input boundary batch](2026-05-05-render-route-and-client-input-boundary-batch-ghsa.md)
- [Identity, build command, and deserialization-boundary batch](2026-05-11-identity-build-command-and-deserialization-boundary-batch-ghsa.md)
