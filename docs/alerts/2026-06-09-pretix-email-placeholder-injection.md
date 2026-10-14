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

## October 14 09:31Z follow-up: placeholder pipelines as sinks — unauthenticated LFI through a substituted customer field (ShopMagic) and placeholder-injection as a read primitive (LatePoint) (Oct 14 WP wave)

This page's invariant — user-controlled fields crossing into trusted transactional rendering — produced two legs where the destination is not just *rendered* but *executed or re-parsed*, upgrading trust confusion to a real sink:

- **ShopMagic – email automation ≤4.9.0 unauthenticated PHP code injection via re-rendered placeholder** ([CVE-2026-103367 / GHSA-fqgv-5m94-gg38](https://github.com/advisories/GHSA-fqgv-5m94-gg38), 8.1, CVSS AV:N/AC:H/PR:N/UI:N — no account, cookie, or nonce): the WooCommerce guest-checkout `billing_address.first_name` field flows through `GuestFactory` → the `{{ customer.first_name }}` placeholder resolver (`CustomerFirstName.php`) → `PlaceholderProcessor` into the plugin's vendored **`SimplePhpRenderer`** — a template engine that `include`s/evaluates its template string. Because placeholder substitution happens **before** the render stage, PHP code submitted as a guest's first name becomes *template source* and executes. The published-recipe precondition is satisfied out of the box by the built-in "New Order email with social media profile links" recipe, so default installs are exploitable by anyone who can complete a guest checkout. Durable axes: (1) **substituted data re-entering the template engine = code execution whenever the engine evaluates its input as code** — the fix-diff refs map the exact pipeline (placeholder resolver → processor → PhpRenderer); hunt rule: on any product with a PHP/templating render backend (Zend-style PhpRenderer, `SimplePhpRenderer`, `include`-based templates), test whether user-field placeholders are substituted pre-render; if yes, the placeholder field is a code-exec sink, grep `Placeholder`/`Renderer` classes for the substitution-vs-render ordering; (2) **shipped default recipes/templates as standing prerequisites** — the "published recipe" gate is satisfied by the plugin's own defaults, so treat default-template features as always-on preconditions when reporting; enumerate a target's default-enabled automation recipes before dismissing placeholder bugs as config-gated; (3) the advisory is filed CWE-98 (filename-include) but the refs show code-as-template — when a "LFI" label meets a PHP renderer, check which sink is real before writing the report; either way the entry point is a billing form field.
- **LatePoint ≤5.7.3 placeholder-injection read primitive** ([CVE-2026-103380 / GHSA-vx7p-qcxr-ccm5](https://github.com/advisories/GHSA-vx7p-qcxr-ccm5), medium): a customer stores a placeholder string such as `{{customer_admin_notes}}` in their own `params[customer][first_name]` field; when a booking notification renders, the pipeline resolves the *embedded* placeholder and the customer receives a rendered email containing administrator-only `admin_notes`, assigned-agent internal contacts, transaction tokens, and payment request URLs. This is the read-privilege flavor of the same invariant: **placeholders found inside user-supplied field values are expanded with the rendering context's full privilege**, so a low-priv user smuggles high-priv field names into a self-addressed email. Sweep rule for any notification template system: submit placeholder-syntax strings naming privileged fields (`{{admin_notes}}`, `{{internal}}`, `{{token}}`, `{{order.secret}}`) into every user-writable field that appears in any email — the delivery inbox you control is the oracle; and in the other direction, test whether the template engine *itself* parses braces in variables (escape-on-render gap) versus only in stored templates.
- Both legs sharpen the reporting heuristic at the top of this page: lead with the placeholder + source field + destination + recipient role, but now *state the sink class* separately — formatting confusion (pretix), data disclosure via expansion (LatePoint), or path/include execution (ShopMagic). Same boundary, three severities, one hunt.
