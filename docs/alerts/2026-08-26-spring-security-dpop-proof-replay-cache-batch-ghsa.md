# Spring Security DPoP proof cache-based replay

Source: GitHub Security Advisories, 2026-08-26 hourly scan: [GHSA-3488-4mh8-47j4](https://github.com/advisories/GHSA-3488-4mh8-47j4) / [CVE-2026-41707](https://nvd.nist.gov/vuln/detail/CVE-2026-41707) (high). Affected lines: `7.1.0`, `7.0.0`-`7.0.6`, `6.5.0`-`6.5.11` (per the GH advisory record; confirm the exact fixed revision against the vendor release notes before claiming a range).

This is a durable, replayable operator finding because it is a clean **cache-eviction -> replay** primitive against a token-binding mechanism. DPoP (Demonstrating Proof of Possession, RFC 9449) exists to stop exactly the "steal the JWT and reuse it" class of attack; the reusable lesson here is that a replay-prevention cache that is *bounded* can itself be the weakness, an attacker who can send cheap requests can evict the entry for a victim's `jti`, so the victim's still-valid DPoP proof is no longer seen as "already consumed" and can be replayed. It belongs on the same page family as the [2026-04-29 Spring Security batch](2026-04-29-spring-security-servlet-path-and-issuer-validation-batch-ghsa.md) and feeds the [OAuth token-theft methodology](../methodology/oauth-token-theft.md).

## What changed

`DPoPProofJwtDecoderFactory` keeps an internal cache of JWT ID (`jti`) claims so that a DPoP proof JWT is not accepted more than once. That cache has a strict size limit. Because the cache is bounded and evictable, an attacker can flood the server with dummy requests to push out the cache entry for a target `jti`. Once the victim's `jti` is evicted, an intercepted valid DPoP proof (a stolen token that the victim already used once) can be replayed successfully.

The reusable pattern, split into two trust transitions:

1. **Cache-bounded uniqueness.** Uniqueness of a `jti` is enforced only for as long as the `jti` stays in memory. A bounded LRU/size-limited cache makes uniqueness *time- and load-dependent*, not absolute.
2. **Interceptor's ability to drive eviction.** The replay attacker controls the volume of requests that compete for cache slots, so they control when a target `jti` is dropped.

## Operator triage

1. **Fingerprint DPoP usage.** Confirm the target actually uses Spring Security's `DPoPProofJwtDecoderFactory` (DPoP token-binding on a resource server). Look for `DPoP` request headers on protected endpoints, Spring Security OAuth2 resource-server dependencies, and the Spring Security version.
2. **Determine the cache model.** You need to know the cache type (bounded LRU? size-limited? TTL-bucketed?) and its size, because the eviction test depends on being able to push a target `jti` out. The advisory's "strict size limit" is the precondition.
3. **Prioritize by value of the bound endpoint.** The replay is only interesting if the replayed proof authorizes access to a valuable resource. Rank by what the DPoP-protected endpoint returns.
4. **Separate interception from eviction.** The replay needs (a) a captured valid DPoP proof and (b) successful eviction of its `jti`. Report them as two independent, testable steps.

## Replayable validation boundaries

Validate on an authorized lab Spring Security resource server that you control, with a synthetic DPoP-protected endpoint and synthetic keys. Do not target a production resource server, do not capture or replay real user DPoP proofs, and do not retain real tokens.

### Lab setup
- A lab Spring Security resource server (`6.5.x`/`7.0.x` in-range) exposing one DPoP-protected endpoint that returns a canary value when the DPoP proof is valid.
- Synthetic DPoP keys: mint a fresh key pair and issue DPoP proof JWTs yourself, so every `jti` and `jwk` in the test is yours.
- A second actor (attacker) that can send a high volume of cheap requests to the same server to drive cache pressure.

### Interception step (proves possession of a replayable proof)
1. As the synthetic "victim," obtain a valid DPoP proof and call the protected endpoint. Confirm it returns the canary (proof is accepted, `jti` now recorded).
2. Record the exact `jti` and the full DPoP header/proof. This is the "intercepted" artifact you will replay.

### Eviction step (proves the bound can be driven)
1. As the attacker, send a large burst of synthetic requests (dummy DPoP proofs / requests) against the server to fill the bounded cache.
2. Determine whether the victim's `jti` has been evicted, the observable is the next step.

### Replay step (the finding)
1. Resend the victim's captured DPoP proof (same `jti`, same token) after eviction.
2. The vulnerable result is the protected endpoint accepting the replayed proof and returning the canary again. The secure result is rejection (proof already consumed / `jti` still cached / proof expired).
3. Record: the `jti`, the burst size, the time between first use and replay, and accept/reject on both the affected and the patched control. This proves the eviction->replay primitive.

## Reporting heuristics
- Frame as **bounded `jti` replay cache -> attacker-driven eviction -> replay of an intercepted DPoP proof**. Name the factory (`DPoPProofJwtDecoderFactory`), the cache property (strict size limit), and the version range.
- Report eviction and replay as two distinct, reproducible steps, each with its own observable (cache pressure vs. re-acceptance of a known `jti`).
- State the version before/after and the exact fixed revision from the vendor notes (confirm it; the GH record lists the affected lines).
- Distinguish this replay-from-eviction from a plain "proof not bound to the sender" bug: here the proof *was* valid and bound; the cache evictability is what re-exposes it.

## Safety
- **Authorized lab only.** Run a resource server you own; never run eviction bursts against a production resource server.
- **Synthetic keys and proofs only.** Mint your own DPoP keys and `jti`s; never capture, replay, or retain real user DPoP proofs or real tokens.
- **Bounded load.** Keep the eviction burst low-volume and targeted at the lab instance; this is a cache-pressure test, not a production DoS.
- **No real authorization abuse.** The proof endpoint returns a canary; do not wire it to a real, valuable operation in the lab.
