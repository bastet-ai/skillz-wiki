# AI Safe Harbor & Report Quality (Avoiding the Spam Collapse)

As AI tooling accelerates vulnerability discovery, disclosure channels are increasingly stressed by **high-volume, low-signal** submissions.

This page sets a standard: *responsible AI testing + high-quality reporting*.

## Safe Harbor (what it means)

A “good faith” safe harbor policy typically clarifies:
- what testing is authorized
- how data should be handled
- how to disclose responsibly
- how the org will respond legally

For AI systems, safe harbor often matters because:
- model behavior is unpredictable
- testing can touch sensitive data
- legal ambiguity chills disclosure

## Report quality bar (minimum)

If you file a report—AI-assisted or not—include:

- Clear **scope + target**
- Precise **steps to reproduce** (deterministic when possible)
- Evidence:
  - request/response captures
  - screenshots where relevant
  - exact payloads
- Clear **impact statement**
- Suggested mitigations (if you can)

If you can’t reproduce it twice, it’s probably not ready.

## AI-specific pitfalls

- Hallucinated endpoints / non-existent parameters
- “Vuln-shaped” output without proof
- Overstated impact
- Unsafe testing that violates policy or harms users
- Code-only review that misses runtime/business-logic behavior

## Defender guidance

- Provide explicit safe harbor language for AI research.
- Rate limit + require evidence.
- Use structured intake forms and require minimal PoC.
- Reward quality, not volume.
- Require a validation step that exercises the running system when the claim depends on runtime behavior.
- Treat AI findings as hypotheses until they survive reproducible testing.

## Source / inspiration

- Inspired by recent safe-harbor announcements for AI research and real cases where bug bounty programs were overwhelmed by low-signal submissions.
