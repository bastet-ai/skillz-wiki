# pretix email placeholder injection

Source: hourly offensive-security scan, 2026-06-09. Primary entry: GitHub advisory [GHSA-2mm6-624x-fqrr](https://github.com/advisories/GHSA-2mm6-624x-fqrr) / CVE-2025-13742 for `pretix`.

This page is durable because it captures a reusable bug-hunting pattern: user-controlled profile, buyer, attendee, or account fields can cross from ordinary form data into trusted transactional messages when template placeholders are rendered as rich text.

## What changed

- **`pretix` rich-text placeholder injection** — emails can use placeholders such as `{name}` that are replaced with customer data. In vulnerable versions, attacker-controlled attendee or buyer names containing HTML or Markdown formatting were rendered as formatted email content instead of inert text.
- **The reported impact is email manipulation, not XSS** — the advisory states pretix uses a strict allowlist for HTML tags, so the issue should not be reported as script execution unless an independent bypass is proven.
- **The useful testing pattern is broader than pretix** — any product that lets administrators customize notification templates, then substitutes user-controlled fields into Markdown/HTML email, in-app messages, receipts, calendar invites, support tickets, or approval workflows, can have the same trust-boundary failure.
- **Known vulnerable `pretix` package ranges** — `>= 1.0.0, < 2025.7.3`, `>= 2025.8.0, < 2025.8.2`, and `>= 2025.9.0, < 2025.9.2`.

## Operator triage

1. **Find template substitution surfaces:** account names, organization names, display names, event attendee names, billing contacts, ticket titles, custom form answers, comments, and uploaded metadata that later appear in system-generated messages.
2. **Identify rendering context:** determine whether the destination is plain text, Markdown, sanitized HTML, HTML attributes, URLs, calendar descriptions, support comments, or admin review panels.
3. **Prefer trust confusion over XSS claims:** for sanitized rich-text email, validate whether links, headings, quotes, images, buttons, or visual separators can make attacker-controlled text appear as official platform content.
4. **Check who receives the message:** prioritize flows where a low-privileged user can cause content to be delivered to admins, organizers, finance users, approvers, support staff, or other tenants.
5. **Trace template ownership:** note whether templates are platform defaults, organization-admin editable, or customer editable. A default template issue usually carries stronger cross-customer relevance than a self-inflicted custom template.

## Safe validation boundaries

- Use harmless markers such as `**CANARY_NAME**`, an inert documentation URL, or a synthetic domain under your control. Do not send phishing copy, credential prompts, or links that collect secrets.
- Capture the original input field, the generated email or notification preview, and the received rendering with message headers redacted.
- If testing email delivery, use accounts and inboxes you control. Avoid sending proof messages to real customer users or third-party staff unless the program explicitly instructs you to do so.
- Distinguish these outcomes in the report:
  - **Plain text preserved:** likely no finding.
  - **Formatting preserved but links neutralized:** low-severity trust-boundary issue at most.
  - **Clickable attacker-controlled links or official-looking callouts preserved:** stronger phishing/trust-confusion impact.
  - **Script, event handlers, unsafe URLs, or attribute breakout:** separate finding; prove independently and avoid overstating without evidence.

## Reporting heuristics

- Lead with the boundary: untrusted user profile/order data rendered as trusted rich text in a system-generated message.
- Include the exact placeholder, source field, destination template, recipient role, and whether the vulnerable template is enabled by default.
- Show a minimal before/after transcript using benign content. Redact email addresses, order IDs, attendee names, event names, and tenant identifiers unless they are synthetic.
- Do not frame the issue as account takeover or XSS unless you demonstrate that specific impact. For sanitized email rendering, the repeatable impact is usually phishing assistance, official-message spoofing, or recipient trust confusion.

## Notes on skipped items from this scan

- CISA KEV published a new catalog version timestamp without a new top-of-catalog CVE beyond already represented LiteLLM and Check Point entries.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, Disclosed, and GitHub Security Blog had no separate new promotable delta during this run.
