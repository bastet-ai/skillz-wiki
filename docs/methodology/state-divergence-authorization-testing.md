---
title: State-divergence authorization testing
---

# State-divergence authorization testing

Use this workflow when an authorized review includes an authorization predicate that compares two quantities that can drift apart, a stored counter against a live balance, a cached copy against the source of truth, or a struct field against module state. The recurring bug is an **authorization check that is satisfiable from the attacker's default (empty, zero, or stale) state** because it reads a state field that the system never updates, or that is zero when the object is freshly created.

[Trail of Bits' Provenance Blockchain write-up](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/) is the primary source for this method. In it, the Provenance marker module's `accountControlsAllSupply` read the *stored* `supply` field on the marker struct instead of the live circulating supply in the bank module. For non-fixed-supply markers the stored field was never written back after minting and stayed `0`, so the "caller controls 100% of supply" check reduced to `0 == 0` for any caller holding nothing, letting any user grant themselves `ACCESS_ADMIN` on 82 live mainnet markers and then mint or drain. The durable lesson is general: **an authorization predicate must never be true from the attacker's default state**, and a check of the form `balance == supply` hands access to everyone whenever `supply` can be zero (stale, or simply not-yet-funded).

!!! warning "Authorized, in-scope targets only"
    Run these checks against a lab fork, a pinned local deployment, or an explicitly authorized test chain with synthetic accounts and marker-only balances. Do not mint real tokens, drain real escrow, grant yourself admin on a live marker/account, or send value-moving transactions to a production chain. Use canary denominations and denied value sinks.

## What the bug looks like

The Provenance authorization was a three-branch OR:

```go
if !(caller.Equals(m.GetManager()) && m.GetStatus() == types.StatusFinalized) &&
    !m.AddressHasAccess(caller, types.Access_Admin) &&
    !k.accountControlsAllSupply(ctx, caller, m) {
    return fmt.Errorf("...not authorized...")
}
```

```go
func (k Keeper) accountControlsAllSupply(ctx sdk.Context, caller sdk.AccAddress, m types.MarkerAccountI) bool {
    balance := k.bankKeeper.GetBalance(ctx, caller, m.GetDenom())
    supply  := m.GetSupply()                 // ← stored field, always 0 for non-fixed markers
    return supply.Equal(sdk.NewCoin(m.GetDenom(), balance.Amount))
}
```

For a non-fixed marker activated at zero supply, `m.GetSupply()` is `0` and an attacker's balance is `0`, so `0 == 0 → true`. The check that should mean "you hold all the supply" instead means "you and the supply are both zero." The fix reads live supply from the bank module and adds an explicit **zero-guard** (if live supply is zero, return `false`), closing both the stale-state path and the not-yet-funded path.

## Required inputs

Collect before testing:

- the exact authorization predicate(s) and every source each operand is read from (which field, which module, which cache);
- which operands are *canonical live state* and which are *derived/copied fields* that may go stale;
- the object lifecycle states (created, funded, finalized, active, paused) and which state values each operand can take in each;
- whether the object's supply/balance/total can be zero, stale, or negative in any reachable state;
- the permission model (who may call the gated operation, what the OR-branches are);
- the live-vs-stored divergence: where each value is written and how often;
- affected and fixed builds/commits for negative controls.

Create a trust-boundary map:

| Input or actor | Boundary to verify | Recorder evidence |
| --- | --- | --- |
| authorization predicate | not satisfiable from the caller's default/empty state | predicate-evaluation table across states |
| stored counter vs live source | the two agree whenever the check is evaluated | before/after divergence trace |
| object lifecycle state | every reachable state is covered by the guard | state × operand matrix |
| zero / not-yet-funded object | check fails closed when the total is zero | zero-state negative control |
| OR-branch composition | no single branch is bypassable in isolation | per-branch reach table |

## Campaign 1: enumerate every authorization predicate

List every handler that gates a privileged operation (grant access, mint, withdraw, administer, delete, export, configure). For each, record:

- the exact comparison(s) and every operand;
- the data source of each operand (struct field, module query, cache, request input);
- which branches are OR-composed and whether any one is sufficient.

The target is a predicate whose operands can disagree or whose equality holds for the attacker's default state. A predicate that compares two caller-influenced or two caller-default values is the strongest signal.

## Campaign 2: divergence between stored and live state

For each predicate operand that is a *copied* value (a field on a struct, a cached total, a materialized count), determine whether the system writes it back when the source changes.

Replay, in a lab fork:

1. create the object in its fresh/empty state;
2. perform the operation that changes the source of truth (mint, transfer, add, fund);
3. read back both the copied field and the live source; record whether they match.

A positive is a measurable divergence: the source has advanced (e.g. circulating supply > 0) while the stored operand used by the authorization check remains at its old/default value. Prove it with synthetic canary balances only. **Do not mint real value.**

## Campaign 3: default-state and zero-state bypass

The most exploitable case is the predicate being true when the caller holds nothing.

For each predicate, evaluate it for a caller with the default/empty balance and record the result across object states:

| Object state | Stored operand | Live source | Caller balance | Predicate |
| --- | --- | --- | --- | --- |
| fresh, unfunded | 0 | 0 | 0 | must be **false** |
| funded (live > stored) | 0 | N > 0 | 0 | must be **false** |
| fully held by caller | N | N | N | expected true only here |
| caller holds all but source stale | 0 | N | N | must be **false** |

A positive is the predicate returning true in any row where the caller does **not** actually control the object's live state. The "fresh, unfunded" row is the critical one: even after reading live supply, a check of `balance == live_supply` still passes when both are zero, so the fix needs an explicit zero-guard (`live_supply == 0 → deny`). Verify the guard exists; its absence is a second, distinct finding.

## Campaign 4: OR-branch composition

When authorization is an OR of several conditions, test each branch in isolation from an attacker's default state:

- is any single branch satisfiable without holding the object or the expected role?
- does a stale/zero operand make the "100% control" branch trivially true?
- can the attacker arrange the inputs so that exactly one benign-looking branch (the balance check) does the authorizing?

Record the branch that authorizes and the state that makes it true. This is usually the cleanest reportable primitive: *branch K passes for a zero-balance caller in state S.*

## Campaign 5: property-based / fuzz the invariant

The Provenance team notes the invariant is easy to state: *the predicate returns true only when live supply is positive **and** the caller holds all of it.* Encode it as a property test or fuzz over random sequences of operations:

- create marker / account, mint, transfer, fund, drain, pause;
- after each step, assert the predicate is true **iff** (live_total > 0 AND caller_balance == live_total);
- assert the zero-guard denies when live_total == 0 regardless of balance.

```bash
# Foundry invariant pattern for a Cosmos-marker-style contract
forge test --match-test 'invariant_supplyControl' --fuzz-runs 10000
```

The fuzzer finds both the stale-state mode (funded object, stored operand still zero) and the unfunded mode (both zero) automatically, which is exactly why a property test would have caught this before launch.

## Evidence package

Retain:

- the authorization predicate source with line references and each operand's data source;
- the state × operand matrix showing where the operands diverge;
- the default-state / zero-state evaluation table with the bypass rows marked;
- the per-branch reach table showing which OR-branch authorizes from default state;
- a minimal reproducer (the two-transaction shape: one to gain the permission, one to act on it) and the fixed-build negative control;
- an explicit statement that no live token, escrow, or account was minted, drained, or granted admin.

## Reporting boundaries

Separate these claims:

1. a stored and live operand diverge after the source changes;
2. the authorization predicate is true from the caller's default/empty state;
3. the zero-state / not-yet-funded case is also bypassable (missing zero-guard);
4. a specific OR-branch authorizes a zero-balance caller in a named state;
5. actual value impact (mint or drain), which requires a separately proven reachable value path.

Do not infer live-chain compromise from a lab predicate result, and do not report a "100% control" check as broken merely because it is equality-based, the break is specifically that the compared quantity is stale or zero-by-default. State the object type, the exact operand sources, the reachable state, and the permission the bypass grants.

## Where this pattern recurs

The heuristic is not chain-specific. Look for the same shape anywhere an authorization check compares:

- a cached/materialized count to the live source (row counts, token totals, quota counters);
- a struct field that is set at creation and never updated to an evolving balance;
- a "you own the last item" / "you control 100%" check where the total can be zero or stale;
- a default-deny assumption that actually becomes default-allow because the measured quantity defaults to the attacker's value.

Any predicate that can be satisfied by an empty account, a freshly created object, or a value the system forgot to refresh is a state-divergence authorization bug.
