---
title: Micro-payment credential challenge-binding and amount-equality idempotency
---

# Micro-payment credential challenge-binding and amount-equality idempotency

Source: hourly offensive-security scan, 2026-09-22 (GHSA published 12:30Z). Primary entries: [GHSA-96m7-5wfv-978m](https://github.com/advisories/GHSA-96m7-5wfv-978m) / [CVE-2026-89420](https://nvd.nist.gov/vuln/detail/CVE-2026-89420) and [GHSA-h97r-55w6-6rfg](https://github.com/advisories/GHSA-h97r-55w6-6rfg) / [CVE-2026-87119](https://nvd.nist.gov/vuln/detail/CVE-2026-87119) in ZenHive `mpp` (a machine-to-machine micropayment protocol library for Elixir; affected 0.14.0 before 0.16.2).

This pair is durable because `mpp`-style payment rails sit underneath AI-agent/MCP paid-endpoint infrastructure (the Plug, MCP, JSON-RPC, and WebSocket transports all reach the vulnerable code), and both advisories spell the same reusable rule in opposite directions: **a signed payment credential must be bound to the per-session challenge, and the deduplication/idempotency key must be derived from the credential, not from rotating server state.** When those two derivations diverge, one credential buys unlimited service — or bills the victim unlimited times.

## What changed

| Advisory | Component | Boundary | Direction |
| --- | --- | --- | --- |
| [GHSA-96m7-5wfv-978m](https://github.com/advisories/GHSA-96m7-5wfv-978m) / CVE-2026-89420 | `MPP.Session.Actions.accept_voucher/3` | A voucher whose `cumulativeAmount` **equals the channel's already-accepted cumulative amount** is treated as an idempotent duplicate success: the channel is returned unchanged and `maybe_spend/2` is never called. The credential verifies, the paid resource is served, and spent/units do not move. Because the server issues a **fresh challenge per request** and the replay store keys on challenge id + payload, the same signed voucher re-validates under every new challenge → one paid voucher yields unbounded paid units | attacker gets free paid resources |
| [GHSA-h97r-55w6-6rfg](https://github.com/advisories/GHSA-h97r-55w6-6rfg) / CVE-2026-87119 | `MPP.Methods.Tempo.KeyAuthorization.verify/3` + `MPP.Methods.Tempo.Subscription.activate/4` | The payer's signature covers chain id, key type, key id, expiry, limits, and scopes — **nothing ties it to the challenge that prompted it**. Each signed field is pinned against the subscription request, but the pinned access key is a static per-endpoint server key, so one captured authorization verifies against every challenge issued for the same terms. Activation dedup keys on **challenge id**, so presenting the captured credential under a fresh challenge produces a different dedup key, the activation succeeds again, and the payer's wallet is charged a new settlement each replay | attacker re-charges a victim's wallet |

Common primitive: **challenge-id-keyed dedup + challenge-unbound signature = replayable credential.** The server rotates the nonce the credential should have been bound to, then uses that rotating nonce as the very thing that decides "have I seen this before?" The dedup key and the signature payload must overlap; here they are disjoint.

## Operator test battery

Apply to any payment/entitlement rail: x402-style agent payment headers, MCP paid tools, per-request voucher/micropayment protocols, API-metering systems, and any "signed authorization + server challenge" handshake.

1. **Challenge-binding check.** Capture one valid signed credential (voucher, authorization, activation). Request a fresh challenge/nonce, re-present the old credential under it, and diff the verdict. A credential that verifies under a new challenge is binding-deficient before you even consider dedup. Sweep the signed field list versus the fields the server actually pins at verify time: fields signed but unpinned, and server-side values (static per-endpoint keys, fixed limits) that pin successfully for every request, are the seam.
2. **Idempotency-key derivation check.** Replay the exact same credential under identical server state and confirm the charge/spend state moves exactly once. Then replay after the server rotates its per-request state (new challenge, new session). A server that answers "already seen" without executing the effect — while still serving the paid resource — is collapsing idempotency onto an equality test (`cumulativeAmount == accepted`) instead of credential identity. Positive evidence: the resource is served **and** the ledger/spend counter is unchanged, repeatedly.
3. **Direction control.** Determine which party the replay harms: free resource to the payer (CVE-2026-89420 class) or repeated charges to a wallet (CVE-2026-87119 class). Report them differently — the second is fraud against a third party, and the proof must stay on your own disposable wallet/key.
4. **Transport parity.** The advisory states the path is reachable through Plug, MCP, JSON-RPC, and WebSocket transports. Run the battery once per transport — metering code frequently shares the session layer but not the replay-store lookup.

## Validation boundaries

- Use disposable wallets/keys and the lab endpoint's own pricing (minimum-unit products). Never replay against a third party's payment channel or charge any wallet you do not own.
- Keep evidence to ledger/spend deltas, challenge ids, and response verdicts. Do not extract settlement private keys, channel state of other clients, or production payment data.
- A replay that only "verifies" without a service-delivery or billing-side effect is a parser observation, not a finding — prove the effect leg (resource served / new settlement built) with counters, not inference.

## Reporting heuristics

- Title as **replayable payment credential: signature not bound to server challenge** or **idempotency check keyed on amount equality lets one voucher purchase unlimited units** — the ledger/resource divergence is the impact sentence.
- Include: transport used, the signed field list vs the verify-time pinned field list, the dedup key derivation, and both counters (resource served, units spent) before/after each replay.
- This is the payment-domain sibling of the token-link authority family (signature-valid-but-target/nonce-unbound): recovery tokens unbound to the user-ID parameter (Sept 22 WP wave), reset links unbound to origin (Sept 18 page), TOTP unbound to a consumed-code ledger (Sept 21 fold). Same sweep, different domain: **sweep which copy of the session state the verifier reads versus which copy the dedup/effect layer reads.**
