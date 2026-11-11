---
title: Syslog RFC 5424 frame-forging and structured-data injection testing
---

# Syslog RFC 5424 frame-forging and structured-data injection testing

Use this workflow when a target ships user-controllable fields into RFC 5424 syslog records over TCP or UDP, or when a log-forging finding on one protocol (HTTP access logs, syslog, journald, structured logging frameworks) should be validated as a class. The advisory below (`@logtape/syslog`) is the reference case: two output-encoding bugs let attacker-controlled structured-data values and keys break RFC 5424 framing, so a single tainted log value can terminate the current frame and plant an attacker-authored "authentic-looking" record in a downstream collector.

## Durable pattern

RFC 5424 framing over TCP commonly uses `\n` as the frame delimiter (RFC 6587 non-transparent framing). If a structured-data **value** can carry a literal newline and the serializer does not escape it, the newline terminates the current message. Every byte after it starts a new frame, and if those bytes form a valid `<PRI>1 ...` header, a compliant collector accepts them as a separate, seemingly genuine syslog record.

Two independent boundaries must hold for syslog output to be safe:

| Boundary | Failure mode | Effect |
| --- | --- | --- |
| Structured-data value escaping | `escapeStructuredDataValue()` escapes `\`, `"`, `]` but not `\n`, `\r`, or other C0 controls | Frame termination + record injection |
| SD-NAME key validation | Keys inserted into `key="value"` pairs without rejecting `=`, `]`, `"`, space, controls, or lengths > 32 | Structured-data parse corruption / key forging |

The operator value is the **frame-terminator review pattern**: any serializer that embeds untrusted text into a line- or record-delimited wire format (syslog, CSV, log4j, journald, custom pipe formats) must neutralize the delimiter and any C0 controls that the downstream parser treats as structure.

## Recon

1. Identify where user-controllable data reaches syslog. Common surfaces:
   - WAF/IDS event fields (user agent, request path, source IP as a string)
   - Application log hooks that interpolate request headers or body fragments
   - Auth-event fields (username, device name, OAuth `state`)
   - Structured logging frameworks with RFC 5424 output drivers
2. Confirm the transport:
   - **TCP with `\n` framing** (RFC 6587 non-transparent), newline injection is directly exploitable.
   - **TCP octet-counting**, a newline does not break framing, but C0 controls may still corrupt structured-data parsing.
   - **UDP**, no framing; newline injection is not exploitable, but SD-NAME corruption may still matter for collector-side parsing.
3. Check the serializer. In Node, look for `@logtape/syslog` with `includeStructuredData: true` (non-default). In other languages, find the RFC 5424 writer and verify which characters it escapes in values and keys.
4. Capture the collector-side expectation: does the downstream parser (rsyslog, Fluent Bit, Vector, Splunk HEC, custom) validate SD-NAME grammar, or does it accept whatever arrives?

## Validation workflow (authorized lab only)

All proofs use a local RFC 5424 reference parser or a lab collector that records raw frames. Do not target production collectors, do not inject records that reference real hosts/users, and do not forge records that would trigger automated response.

### Frame-terminator value check

1. Build a local harness: an application that writes one syslog record per request, with a field (e.g., `user_agent`) passed through from the request into a structured-data value.
2. Set `includeStructuredData: true` (or the equivalent structured-data flag).
3. Send a canary value containing a newline followed by a synthetic RFC 5424 header:
   ```text
   value = "SKILLZ-FRAME-CANARY\n<14>1 2026-08-28T00:00:00Z skillz-lab - - - [SkillzCanary@32473 orig=\"SKILLZ_INJECTED_FRAME\"] injected=1"
   ```
4. Capture the raw TCP byte stream from the collector side.
5. Parse it with a reference RFC 5424 parser (or `syslog-ng` in lab mode) and count the accepted messages.
6. Interpret:
   - **Contained:** one message; the newline is escaped or the frame is rejected.
   - **Vulnerable boundary:** two messages; the second is the attacker-authored header. Record the raw bytes proving the split.

### SD-NAME key check

1. Using the same harness, make the structured-data **key** attacker-controllable (e.g., a field name derived from request input).
2. Send a key containing a reserved character:
   ```text
   key = "SkillzCanary[INJECTED]"
   value = "marker"
   ```
3. Capture the serialized record.
4. Interpret:
   - **Contained:** the key is rejected, sanitized, or the entire record is dropped.
   - **Vulnerable boundary:** the record contains `SkillzCanary[INJECTED]="marker"`, which breaks RFC 5424 SD-NAME grammar. A permissive collector may mis-parse the record or treat `INJECTED` as a separate SD element.

### Negative controls

- A value with no C0 controls (baseline single-frame record).
- A value with `\n` escaped as `\\n` (escaped baseline).
- A key that is valid RFC 5424 SD-NAME (baseline structured-data record).
- The patched version of the serializer (e.g., `@logtape/syslog` 2.1.5 / 2.0.14 / 1.3.11) as the "fixed" control.

## Evidence to capture

- Raw TCP capture (pcap or hex dump) showing the frame boundary.
- The parsed message count from the reference parser.
- The serialized record bytes for the injected frame (redacted of any real hostnames).
- A table: input value, expected escape, observed escape, frame count, collector decision.
- For the SD-NAME check: the raw record, the key as sent, the key as parsed by the reference parser.

## Reporting heuristic

Frame the finding as a **frame-terminator escaping failure**, not a generic XSS or log-injection:

- **untrusted structured-data value -> missing C0 control escape -> RFC 5424 frame termination -> attacker-authored record accepted by collector**
- **untrusted SD-NAME key -> missing reserved-character validation -> structured-data parse corruption**

Impact: an attacker who can control one log field can plant arbitrary "authentic-looking" syslog records in a downstream collector, corrupting forensic evidence, triggering false-positive alerts, or (if the collector has log-driven automation) influencing automated response.

Do not claim log injection into a production SIEM. The bounded positive is a lab collector accepting the injected frame; the impact statement should describe the evidence-integrity and automation-trust consequences.

## Safety constraints

- No production syslog collectors, no real hostnames in injected frames.
- No forged records that reference real users, real IPs, or real event IDs.
- No log-driven automation triggered by the injected record (disable alerting in the lab).
- Keep the canary value to a single frame's worth of bytes; do not flood the lab collector.

## Cross-references

- HTTP access-log forging (Basic-auth `:remote-user` control characters): see the 2026-07-10 batch page, `morgan` section, same frame-terminator class, different wire format.
- `secure_headers` CSP directive injection: same "untrusted value serialized into a structured policy" pattern.

## Sources

- GitHub Security Advisory: [GHSA-8h6h-x5pq-56fq / CVE-2026-54511](https://github.com/advisories/GHSA-8h6h-x5pq-56fq), `@logtape/syslog` unescaped C0 controls and unvalidated SD-NAME keys
- Fix: https://github.com/dahlia/logtape/commit/7a6e5b9ddf7915edfff78fa129bc17c979b2a623
- RFC 5424: The Syslog Protocol, https://datatracker.ietf.org/doc/html/rfc5424
- RFC 6587: Non-Transparent Forwarding of Syslog Messages in TCP, https://datatracker.ietf.org/doc/html/rfc6587
