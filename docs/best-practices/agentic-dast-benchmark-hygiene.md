# Agentic DAST Benchmarks Need Isolation, Reset, and Real Validation

**Date**: 2026-04-28  
**Status**: Durable guidance

Autonomous web-testing agents can look impressive in benchmark runs while still measuring the wrong thing. If the harness leaks state, lets challenges reach each other, accepts guessed flags, or reuses memory between attempts, the result is not a security benchmark — it is a contamination experiment.

## What to isolate

- Run each target in its own network segment so a stuck agent cannot pivot into another challenge or service.
- Give every evaluation a clean workspace and empty agent memory.
- Reset applications between attempts when prior actions can change state: passwords, stored XSS payloads, polluted prototypes, uploaded files, queued jobs, or modified admin settings.
- Keep callback servers, admin bots, internal APIs, and target URLs scoped per challenge.
- Pin dependencies so the tested vulnerability does not disappear because an image pulled a patched `latest` package.

## What to validate

- Generate unique secrets or flags at build time for each run.
- Validate success against the exact build-time value, not a regex or flag-shaped string.
- Run a known exploit or health check before evaluation so infrastructure failures do not masquerade as agent failures.
- Review failed trajectories for near-misses, tool gaps, and waste patterns instead of treating “unsolved” as a single bucket.
- Track budget and escalation path separately from raw success rate.

## What to measure

- First-pass solve rate before retries or environment resets.
- Cost per solve and P90 cost, not just average time.
- Which vulnerability classes require model escalation.
- Whether failures come from missing exploitation strategy, bad browsing/tool habits, weak state tracking, or harness instability.
- False submissions and fabricated proof attempts.

## Benchmark red flags

- Shared networks across challenges.
- Static or guessable flags.
- Persistent browser/session/workspace state between runs.
- Dependency versions that are not locked.
- Success checks that accept output shape instead of verified impact.
- No pre-run exploit validation for the challenge itself.

## Operator takeaway

Treat agentic DAST benchmarks like mini cyber ranges. The agent should win only by exploiting the intended target in the current clean run. Everything else — stale state, neighboring services, guessed artifacts, or remembered prior attempts — must be designed out before the numbers mean anything.

## Source

- ProjectDiscovery, “Benchmarking Neo's Black-Box DAST Capabilities,” 2026-04-27: https://projectdiscovery.io/blog/neo-black-box-dast-capabilities
