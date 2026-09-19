---
title: Shared HTTP cache boundary testing
---

# Shared HTTP cache boundary testing

Use this workflow when an HTTP client, proxy, SDK, or application cache can reuse one upstream response across callers. The key question is not merely whether two requests have the same cache key: it is whether response directives, request identity, and excluded headers remain bound to the stored object and every later cache hit.

Source: [undici GHSA-4cwx-7wf7-3272 / CVE-2026-13697](https://github.com/advisories/GHSA-4cwx-7wf7-3272), published August 3, 2026. The advisory describes malformed qualified `Cache-Control: private` values being represented differently from the boolean `private` state expected by the shared-cache guard. A response could then enter the default shared cache and be served to another caller. Undici 7.29.0 and 8.9.0 are listed as corrected.

!!! warning "Synthetic two-user fixtures only"
    Use a local upstream, in-memory cache, and random caller canaries. Never place real cookies, authorization headers, account data, or tenant responses in the harness.

## Prerequisites

- affected and corrected client-library versions;
- a local upstream whose response headers and body are fully controlled;
- two synthetic callers, A and B, with distinct random response markers;
- cache-store instrumentation that records key, cache mode, parsed directives, stored headers, and hit/miss state.

## Directive-state matrix

Return the same canary resource under each header while holding request method, URL, and ordinary cache fields constant:

| Case | `Cache-Control` shape | Question |
| --- | --- | --- |
| public baseline | `public, max-age=300` | Can an intentionally shared response be reused? |
| private baseline | `private, max-age=300` | Is shared storage rejected? |
| named private field | `private="set-cookie", max-age=300` | Is the qualified form treated as private and is the named field excluded? |
| empty qualified value | `private="", max-age=300` | Does an empty parsed array become private or bypass a boolean-only guard? |
| delimiter-only value | `private=",", max-age=300` | Does trimming/canonicalization collapse to the secure state? |
| repeated equivalent | mixed case, spacing, and repeated qualified values | Are equivalent forms normalized before policy? |
| mixed boolean/qualified | `private, private="set-cookie", max-age=300` | Does type confusion throw before a safe cache decision? |
| corrected build | replay every case | Are private forms rejected from shared storage without a crash? |

## Two-caller proof

1. Caller A requests a random URL. The upstream returns `A-CANARY`, a fake `Set-Cookie: skillz=A`, and exactly one matrix header.
2. Record the parser's typed representation and whether the response enters shared storage.
3. Change the upstream body/header to `B-CANARY` and `skillz=B` without changing the cache key.
4. Caller B requests the same URL with a distinct synthetic authorization-context marker.
5. Record hit/miss state, returned body/header canaries, upstream request count, and caller identity. Never log bearer values; the context marker is not a credential.
6. Repeat with cache type explicitly private, a distinguishing `Vary` field, no cache interceptor, and corrected releases.

The reportable disclosure signal is **private-form response for caller A -> shared cache store -> caller B receives A's random body or header canary without a second upstream request**. A parser oddity or store event alone is insufficient.

For the mixed-directive crash path, catch the request promise and process exit independently. Report the exact parser exception and consumer behavior, but do not run an availability test against a shared service. The disclosure and crash are separate impacts even though one normalization fix addresses both.

## Evidence schema

```text
library_version:
cache_mode:
request_key:
caller_context: A | B
raw_cache_control:
parsed_directives:
stored: true | false
stored_header_names:
hit: true | false
upstream_request_count:
returned_body_canary:
returned_cookie_canary:
exception:
```

A strong report includes affected-versus-corrected replay and distinguishes four stages: raw header parsing, typed directive normalization, shared-storage policy, and later cache-hit delivery.

## Whitespace-around-equals follow-up

[undici GHSA-jr45-8vmc-qm54 / CVE-2026-14643](https://github.com/advisories/GHSA-jr45-8vmc-qm54) adds an adjacent parser differential: optional whitespace around the `=` in qualified `private` or `no-cache` directives can make the parser drop the directive or retain quote characters in the field name. Affected 7.x releases before 7.29.0 and 8.x releases before 8.9.0 can then store an authenticated response in shared mode and return it to another caller.

Extend the directive matrix with the following raw forms, changing only whitespace placement:

| Raw form | Parser evidence to retain |
| --- | --- |
| `private="authorization"` | canonical qualified baseline |
| `private ="authorization"` | whitespace before `=` |
| `private= "authorization"` | whitespace after `=` |
| `private = "authorization"` | whitespace on both sides |
| `no-cache ="authorization"` | equivalent `no-cache` path |
| mixed case and horizontal tabs | grammar-equivalent controls |

For each form, record the raw bytes, normalized directive name, normalized field-name list, shared-store decision, excluded stored headers, and the later A-to-B hit result. The positive remains end to end: **qualified directive with legal optional whitespace -> parser representation loses or corrupts the qualification -> caller A's synthetic authenticated canary enters shared storage -> caller B receives it without an upstream request**. A parse mismatch without a cross-caller hit is not enough.

## September 18 follow-up: `Vary` wildcard byte-comparison and `max-stale` over security-zeroed entries (http-cache-semantics, 2 GHSAs)

[GHSA-f27v-pv5m-c5g6 / CVE-2026-93750](https://github.com/advisories/GHSA-f27v-pv5m-c5g6): `http-cache-semantics` through 4.2.0 validates `Vary` matching with **byte-for-byte string comparison in `_varyMatches()` instead of honoring wildcard forms**, so a stored entry whose `Vary` policy should exclude the second caller's key still matches → caller B receives a cached response intended for a different client.

[GHSA-ch52-4w7c-c8xp / CVE-2026-93748](https://github.com/advisories/GHSA-ch52-4w7c-c8xp) (same package, 7.5): entries deliberately **security-zeroed** (body/credentials discarded after use) are re-servable when the request carries a client-controlled **`max-stale`** value — `max-stale=86400` on the same URL retrieves another user's zeroed entry, including surviving `Set-Cookie` session material.

Two rows for the matrix above, library-level and end-to-end:

| Probe | Expectation on a correct implementation | Finding shape |
| --- | --- | --- |
| Wildcard `Vary` (e.g. `Vary: Accept, *`-family / named-field mismatch forms) stored for caller A, replayed by caller B with a non-matching field | No shared hit — wildcard/exclusion semantics honored, not exact-string equality | B receives A's canary body without an upstream request |
| Entry security-zeroed after A's use; B requests the same URL with `max-stale: 86400` | Stale-serving refused for security-zeroed entries | B receives the zeroed entry's residual headers (synthetic fake `Set-Cookie`) |

Same rule as the whitespace family: **the policy state (excluded by `Vary`, zeroed for security) must be re-derived from the canonical representation at every hit path — exact string equality and freshness-only checks are both bypassable by header shapes the caller controls.** Fix versions: >4.2.0 per advisories; replay the battery on both affected and corrected releases.
