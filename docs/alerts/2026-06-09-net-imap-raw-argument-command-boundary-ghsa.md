# Net::IMAP raw argument command boundary

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-8p34-64r3-mwg8](https://github.com/advisories/GHSA-8p34-64r3-mwg8) / CVE-2026-47240 and [GHSA-c4fp-cxrr-mj66](https://github.com/advisories/GHSA-c4fp-cxrr-mj66) / CVE-2026-47241 for Ruby `net-imap`.

This page is durable because it captures a reusable protocol-injection pattern: client libraries that expose "raw" protocol fragments may validate CRLF but still mishandle literal framing, continuation markers, and server capability negotiation.

## What changed

- **Command injection via non-synchronizing literals** — affected `Net::IMAP` command helpers accept raw string arguments that are sent verbatim after validation. If an IMAP server does not advertise `LITERAL+`, `LITERAL-`, or `IMAP4rev2`, a non-synchronizing literal marker can be parsed as a malformed line ending and the following bytes can become new pipelined IMAP commands.
- **Affected argument surfaces** — the advisory calls out `criteria` for `#search` and `#uid_search`, `search_keys` for `#sort`, `#thread`, `#uid_sort`, and `#uid_thread`, and `attr` for `#fetch` and `#uid_fetch`.
- **Continuation-marker DoS is adjacent evidence** — CVE-2026-47241 shows the same raw-argument boundary can absorb a following command when a string ends in `{0}` or `{0+}`. Treat it as a parser-state validation signal, not as a standalone availability playbook.
- **Fixed versions** — command-injection handling is fixed in `net-imap` `0.6.4.1`, `0.5.14.1`, and `0.4.24.1`; the adjacent continuation-marker DoS is fixed in `0.6.5`, `0.5.15`, and `0.4.25`.

## Operator triage

1. **Find raw IMAP fragments:** search Ruby repos for `Net::IMAP`, `uid_search`, `search(`, `uid_fetch`, `fetch(`, `sort(`, `thread(`, `Net::IMAP::RawData`, and custom wrappers that pass search criteria or fetch attributes directly.
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
