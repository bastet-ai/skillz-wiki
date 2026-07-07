# Langflow, Mailpit, Outerbase, Miniflux, and render-boundary checks

Source: hourly offensive-security scan, 2026-06-19; updated 2026-06-23 for the Langflow monitor API ownership issue and 2026-07-07 for Langflow [CVE-2026-55255](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) KEV user-controlled-key authorization bypass. Primary entries: GitHub advisories [GHSA-wwf9-7jrc-rv4q](https://github.com/advisories/GHSA-wwf9-7jrc-rv4q), [GHSA-ccv6-r384-xp75](https://github.com/advisories/GHSA-ccv6-r384-xp75), [GHSA-qrpv-q767-xqq2](https://github.com/advisories/GHSA-qrpv-q767-xqq2), [GHSA-9c59-2mvc-vfr8](https://github.com/advisories/GHSA-9c59-2mvc-vfr8), [GHSA-w4mc-hhc6-xp28](https://github.com/advisories/GHSA-w4mc-hhc6-xp28), [GHSA-m999-j542-5w3r](https://github.com/advisories/GHSA-m999-j542-5w3r), [GHSA-7h5p-637f-jfr7](https://github.com/advisories/GHSA-7h5p-637f-jfr7), and [GHSA-c29q-5xm7-5p62](https://github.com/advisories/GHSA-c29q-5xm7-5p62).

This batch is durable because each issue maps to a repeatable web-app or AI-workflow boundary: user-controlled dashboard widgets rendered with application tokens in scope, Langflow node configuration crossing into local file reads and execution-capable flows, response and monitor IDs crossing tenant/user ownership checks, mail-link preview APIs missing address-canonicalization coverage, redirect targets bypassing URL policy, and MediaWiki extension template variables crossing into stored HTML.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-wwf9-7jrc-rv4q | Outerbase Studio text widgets | dashboard-authored text widget content rendered in a token-bearing application origin | Treat collaborative dashboard/report widgets as active token-adjacent content; prove with harmless DOM markers and disposable sessions. |
| GHSA-ccv6-r384-xp75 | Langflow `BaseFileComponent` nodes | flow/node configuration could cross into arbitrary local file reads and execution-capable chains | Audit AI workflow builders for file-component parameters, tool chaining, and server-side execution context with synthetic canary files only. |
| GHSA-qrpv-q767-xqq2 | Langflow `/api/v1/responses` | authenticated response IDs were not adequately scoped to the requesting user/flow | Add object-ownership checks to AI workflow response/history APIs; prove with two disposable users and marker responses. |
| GHSA-9c59-2mvc-vfr8 / CVE-2026-33760 | Langflow `/api/v1/monitor` | monitor endpoints accepted `flow_id`, message IDs, and session IDs without consistently joining back to `Flow.user_id` | Extend Langflow ownership checks beyond response APIs to monitor transactions, build artifacts, message edits/deletes, and session rename/delete paths. |
| GHSA-w4mc-hhc6-xp28 | Mailpit Link Check API | SSRF protections missed IPv6 transition and address-encoding mechanisms | Extend SSRF URL-canonicalization tests beyond IPv4 literals to IPv4-mapped IPv6, 6to4/Teredo-style forms, brackets, and encoded hosts. |
| GHSA-m999-j542-5w3r | Miniflux redirect handling | redirect policy could be bypassed by crafted target URLs | Treat feed-reader and login/navigation redirects as URL-parser differentials; capture allowed-vs-denied URL matrix with owned destinations. |
| GHSA-7h5p-637f-jfr7 | StarCitizenWiki Embed Video extension | user-controlled class values reached template rendering as stored HTML | In wiki/CMS extensions, test template variables that look cosmetic, such as CSS classes, as HTML-context sinks. |
| GHSA-c29q-5xm7-5p62 | StarCitizenWiki Embed Video extension | user-controlled service names reached exception output and stored rendering | Include error paths and unsupported-provider messages in render-sink testing; do not stop at the happy-path embed template. |

## Operator triage

1. **Find whether the data is passive or executable in context.** Widgets, flow nodes, embed classes, provider names, and exception text are often treated as metadata until rendered or interpreted in a privileged origin.
2. **Use two-user ownership tests.** Langflow response and monitor APIs need a positive owner, negative non-owner, and preferably a separate flow/workspace control before claiming IDOR/BOLA.
3. **Canonicalize before SSRF or redirect claims.** Record the raw URL, parsed host, normalized address, DNS result, redirect decision, and final callback hit. Parser differentials are the core evidence.
4. **Keep AI-workflow file proofs synthetic.** Use canary files created for the assessment. Never read environment files, SSH keys, model credentials, uploaded datasets, or cloud tokens.
5. **Skip adjacent availability-only items.** Langflow multipart upload DoS and py7zr resource-exhaustion entries were not promoted here because they do not add a stronger offensive validation workflow without a target-specific chain.

## Replayable validation boundaries

### Dashboard/widget content to application-origin token scope

- Create a lab Outerbase Studio workspace with a disposable user and no production data sources.
- Add text/widget content containing inert HTML/DOM markers that prove escaping and origin context. Do not use token-exfiltration JavaScript.
- Load the dashboard as another disposable user if collaboration is in scope and record whether the marker renders in a token-bearing origin.
- Negative controls: sanitized widget renderer, isolated preview origin, CSP that blocks script execution, and widgets rendered without application tokens.

### Langflow file components, response ownership, and monitor ownership

- Build a disposable Langflow instance with two users, two flows, and a synthetic file such as `/tmp/langflow-canary.txt` owned by the test environment.
- For file-component boundaries, identify nodes inheriting from or wrapping file-read behavior and set only the synthetic canary path. Positive evidence is marker content reaching the flow result or a controlled downstream node.
- For execution-capable chains, stop at a visible inert marker or no-op node. Do not run shell payloads, read secrets, or touch production flow storage.
- For response IDOR, create response records as user A, then request the same IDs as user B. Capture status, owner fields, and marker text with all secrets redacted.
- For monitor API ownership, create two disposable users and two flows. Generate synthetic prompt/response messages and build artifacts only; then test user B against user A's `flow_id`, message IDs, and session IDs on the monitor read/update paths.
- Safe positive evidence is limited to a synthetic transaction marker, a build-artifact marker, or a controlled session rename visible in the lab. Do not delete production conversations, collect real prompts, or copy model responses from live tenants.

### Mailpit link-check SSRF canonicalization

- Use an owned callback server and a lab Mailpit instance with no access to production networks.
- Test the same destination represented as hostname, IPv4, IPv6 bracket literal, IPv4-mapped IPv6, 6to4/Teredo-like representation, decimal/octal/hex IPv4, URL-encoded host, and redirect chain.
- Positive evidence is a callback or route-status change for a representation that should have been blocked by the configured policy.
- Do not target cloud metadata endpoints, internal services, RFC1918 production addresses, or tenant infrastructure.

### Redirect URL-policy differentials

- Use owned domains for allowed and disallowed destinations.
- Build a matrix covering scheme case, userinfo, backslashes, encoded slashes, control characters, double-encoded components, punycode, suffix hosts, and nested redirect parameters.
- Record both parser output and browser-followed destination. A redirect bypass report needs a concrete security boundary such as login flow, OAuth return, feed action, or privileged navigation.

### Wiki/CMS extension render sinks

- Use a lab wiki/CMS and a page or embed record controlled by the test account.
- Test variables that feed CSS classes, service/provider names, captions, exception messages, and fallback templates with harmless DOM markers.
- Include unsupported-service and validation-error paths; many render bugs live in error output rather than normal templates.
- Do not publish payloads that steal cookies, administrator tokens, or cross-site request tokens; show marker rendering and context instead.

## July 7 Langflow user-controlled-key auth-bypass KEV follow-up

CISA added [CVE-2026-55255](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to KEV on 2026-07-07 as a Langflow authorization-bypass issue through a user-controlled key. Treat this as an adjacent Langflow API ownership/key-binding workflow rather than a separate generic alert.

Operator validation stays inside the existing two-user Langflow lab:

- Create user A and user B, each with separate flows, sessions, response history, monitor entries, API keys or share keys, and any workspace-scoped objects exposed by the target version.
- For every endpoint that accepts a caller-supplied key, ID, token, `flow_id`, message ID, session ID, project/workspace ID, or share key, test whether the server derives ownership from trusted session context or from the user-controlled parameter.
- Safe positive evidence is a synthetic object marker, controlled route-state change, or redacted metadata field from user A becoming visible or mutable to user B.
- Negative controls should include a patched version, an unrelated random key, a valid key bound to the wrong user, and a valid key with a mismatched flow/workspace ID.
- Do not collect real prompts, model outputs, uploaded documents, vector-store contents, API keys, environment variables, or tenant data.

Add this boundary name to reports when it applies: **caller-controlled Langflow key to cross-user or cross-workspace authorization context**.

## Reporting notes

- Name the crossed boundary precisely: **widget content to token-bearing dashboard origin**, **AI file-node parameter to server file read**, **flow response ID to another user's history**, **monitor `flow_id` to another user's transaction/build logs**, **message/session ID to cross-user history mutation**, **caller-controlled Langflow key to cross-user authorization context**, **IPv6 transition URL to link-check SSRF**, **redirect parser bypass to privileged navigation**, **embed class to stored HTML**, or **provider error text to stored HTML**.
- Include version, authentication role, workspace/tenant IDs, URL parser normalization, network callback evidence, and negative controls. Keep evidence to synthetic markers and owned infrastructure.
