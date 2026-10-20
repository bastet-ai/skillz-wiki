# Net::IMAP raw argument command boundary

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-8p34-64r3-mwg8](https://github.com/advisories/GHSA-8p34-64r3-mwg8) / CVE-2026-47240, [GHSA-c4fp-cxrr-mj66](https://github.com/advisories/GHSA-c4fp-cxrr-mj66) / CVE-2026-47241, and [GHSA-46q3-7gv7-qmgg](https://github.com/advisories/GHSA-46q3-7gv7-qmgg) / CVE-2026-47242 for Ruby `net-imap`.

This page is durable because it captures a reusable protocol-injection pattern: client libraries that expose "raw" protocol fragments may validate CRLF but still mishandle literal framing, continuation markers, and server capability negotiation.

## What changed

- **Command injection via non-synchronizing literals** — affected `Net::IMAP` command helpers accept raw string arguments that are sent verbatim after validation. If an IMAP server does not advertise `LITERAL+`, `LITERAL-`, or `IMAP4rev2`, a non-synchronizing literal marker can be parsed as a malformed line ending and the following bytes can become new pipelined IMAP commands.
- **Affected argument surfaces** — the advisory calls out `criteria` for `#search` and `#uid_search`, `search_keys` for `#sort`, `#thread`, `#uid_sort`, and `#uid_thread`, and `attr` for `#fetch` and `#uid_fetch`.
- **Client identity and capability toggles are also command surfaces** — `#id` hash field values did not reject CRLF, and `#enable` could send argument `#to_s` values verbatim instead of validating them as supported atoms. Untrusted input to either command is uncommon but gives bug hunters another config-to-IMAP-command boundary to audit.
- **Continuation-marker DoS is adjacent evidence** — CVE-2026-47241 shows the same raw-argument boundary can absorb a following command when a string ends in `{0}` or `{0+}`. Treat it as a parser-state validation signal, not as a standalone availability playbook.
- **Fixed versions** — raw-argument command-injection handling is fixed in `net-imap` `0.6.4.1`, `0.5.14.1`, and `0.4.24.1`; `#id`/`#enable` validation is fixed in `0.6.4.1` and `0.5.15`; the adjacent continuation-marker DoS is fixed in `0.6.5`, `0.5.15`, and `0.4.25`.

## Operator triage

1. **Find raw IMAP fragments:** search Ruby repos for `Net::IMAP`, `uid_search`, `search(`, `uid_fetch`, `fetch(`, `sort(`, `thread(`, `id(`, `enable(`, `Net::IMAP::RawData`, and custom wrappers that pass search criteria, fetch attributes, client identity fields, or capability names directly.
2. **Prioritize attacker-shaped query builders:** interesting paths let users, tenants, plugins, workflow rules, mailbox filters, CRM imports, ticket parsers, or automation jobs influence IMAP criteria/search keys/fetch attributes.
3. **Check server capability assumptions:** record whether the target mailbox server advertises `LITERAL+`, `LITERAL-`, or `IMAP4rev2`. The command-injection route depends on non-synchronizing literal support being absent or mishandled.
4. **Trace privilege and mailbox impact:** identify whether injected IMAP commands can read other folders, alter mailbox state, delete messages, exfiltrate message metadata, or pivot through service credentials. Do not touch production mail content.
5. **Separate dependency exposure from reachable exploitability:** a vulnerable gem version is weaker than a demonstrated untrusted-input-to-raw-argument-to-IMAP-socket path.

## Replayable validation boundaries

- Use a lab mailbox and a disposable IMAP server/client pair. Do not validate against customer or employee mailboxes.
- Prove reachability first by showing untrusted input reaches one of the affected raw arguments unchanged or with attacker-controlled literal framing preserved.
- For command-injection validation, use harmless IMAP commands in a lab transcript, such as a tagged `NOOP` marker, and capture only protocol framing and response tags. Do not fetch real message bodies, subjects, addresses, or attachments.
- For continuation-marker validation, demonstrate parser-state confusion with `{0}` or `{0+}` only in a disposable connection; avoid long-running hangs against shared infrastructure.
- Capture the gem version, fixed-version comparison, server capability banner, affected helper method, sanitized request/config input, and raw IMAP transcript with mailbox names and user identifiers redacted.

## Reporting heuristics

- Lead with the **trust boundary**: untrusted application input becomes raw IMAP protocol syntax.
- Include preconditions explicitly: vulnerable `net-imap` version, affected method/argument, server capability state, and whether the issue is command injection or command absorption.
- Keep the proof limited to protocol markers and synthetic mailbox fixtures. A strong report does not need production email data.
- If the app constructs IMAP search/fetch syntax from user filters, recommend a typed criteria builder or strict allowlist rather than passing caller-supplied raw strings.
- Note when modern servers advertise safe literal capabilities; that reduces but does not erase the application-side finding if unsafe raw fragments can reach the socket.

## October 20 follow-up: Roundcube Webmail — CRLF in `_uid` rides the mail/headers and mail/viewsource actions into IMAP commands (CVE-2026-113386 / [GHSA-qwfm-hv5v-vc9r](https://github.com/advisories/GHSA-qwfm-hv5v-vc9r), before 1.6.20 / 1.7.5)

Roundcube shipped fixes (commits 004adaa / bf5bc02 / f62879d) that add `preg_match('/[\r\n]/', $uid)` gates to `program/actions/mail/headers.php` and `mail/viewsource.php` — before the fix, the `_uid` GET/GET-param value flowed into IMAP `UID` commands with only numeric-ish assumptions, so an authenticated attacker (or any XSS/CSRF able to drive the webmail actions) injected CRLF sequences to append arbitrary IMAP commands on the session's authenticated connection.

Durable axes extending this page:

- **The webmail layer is the raw-argument source.** The June advisory was a client library; this one is the same defect class one tier up: a web app that builds IMAP syntax from request parameters. When auditing any webmail/mail-adjacent product, grep the request-parameter-to-IMAP-call sites (`_uid`, `_search`, `_folder`, sort/thread params) — the UI action names (`mail/headers`, `mail/viewsource`, `get.inc`) are the ingress inventory.
- **CRLF-only validation is the fix shape — test the whole newline grammar.** The fix rejects `\r|\n` and nothing else; that is correct for IMAP line framing, but on sibling products check for `\0`, lone CR/LF normalized away by intermediate layers, and encoding shapes that survive to the socket. Run the CRLF/encoding battery per parameter, not per product.
- **Two action files, same parameter, separately patched = parameter-parity rule.** `_uid` was validated in one action's fix commit and needed gates in the sibling action too; when you find one injection point on a shared parameter name, enumerate every route that reads that name (this page's raw-argument inventory rule, applied to a web app's param namespace).
- **Read-back channel:** webmail proxies the IMAP server's response into the rendered message view, so injected `FETCH`/`SEARCH` results return to the attacker — protocol injection through a web UI is a full-read primitive, not a blind one. Validation boundary unchanged: lab mailbox, tagged `NOOP`-style markers, synthetic fixtures only; proof = transcript framing evidence, not message content.
