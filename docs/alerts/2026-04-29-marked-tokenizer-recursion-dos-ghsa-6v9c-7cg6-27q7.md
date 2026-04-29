# marked tokenizer infinite-recursion OOM denial of service (GHSA-6v9c-7cg6-27q7)

**Signal:** GitHub Security Advisories published **2026-04-29**. The `marked` Markdown parser fixed an unauthenticated denial-of-service bug triggered by a tiny whitespace sequence.

## What it is
`marked` versions `18.0.0` through `18.0.1` can enter infinite recursion while tokenizing the three-byte input sequence tab, vertical tab, newline (`\x09\x0b\n`). The loop causes unbounded memory allocation and can crash Node.js applications that parse attacker-controlled Markdown.

Affected package: npm `marked`. Fixed version: `18.0.2`.

Reference: <https://github.com/advisories/GHSA-6v9c-7cg6-27q7>

## Triage
1. Inventory services using `marked`, especially comment systems, documentation renderers, ticketing, chat, CMS, or preview endpoints.
2. Check dependency locks for `marked@18.0.0` or `18.0.1`.
3. Identify unauthenticated or low-trust paths that render Markdown synchronously in request handlers.

## Mitigation
- Upgrade `marked` to `18.0.2` or later.
- Put size, time, and memory limits around Markdown rendering; do not parse unbounded user input on critical request threads.
- Normalize or reject control characters that are not needed for the application before parsing.
- Use worker isolation for rich-content rendering so parser crashes do not take down the main service.

## Detection ideas
- Look for request bodies or stored Markdown containing vertical tab (`0x0b`) near tabs and newlines.
- Correlate Node.js OOM crashes or container restarts with Markdown preview/render endpoints.
- Add parser-failure metrics for rendering latency, process RSS growth, and worker restarts.

## Durable lesson
Even mature parsers can fail on tiny edge-case inputs. User-content rendering belongs behind dependency pinning, resource limits, and crash isolation.
