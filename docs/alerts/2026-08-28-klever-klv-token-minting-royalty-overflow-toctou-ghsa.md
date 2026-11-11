# Klever KLV token-minting via split-royalty integer overflow and marketplace TOCTOU, operator…

**Date reviewed:** 2026-08-28 (updated 2026-08-31: added Boundary 3, the SFT `int64` circulation-overflow cap bypass)
**Advisories:** [GHSA-cgc5-v3f2-8m2v / CVE-2026-54755](https://github.com/advisories/GHSA-cgc5-v3f2-8m2v) (critical), [GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754](https://github.com/advisories/GHSA-p7gw-2pcp-5pf8) (critical), [GHSA-mrpp-v6pg-p54x / CVE-2026-55764](https://github.com/advisories/GHSA-mrpp-v6pg-p54x) (high). All in `klever-io/klever-go` (the Klever node).

Three independent paths let an attacker **mint value out of thin air** by transferring or selling their own throwaway asset. All are durable because they expose a reusable settlement-validation boundary: **percentage/amount accumulation and payout that is not bounded per-entry and not re-checked at the time of value transfer.**

## Boundary 1, split-royalty integer overflow enables unbounded minting (GHSA-cgc5-v3f2-8m2v / CVE-2026-54755)

KDA split-royalty percentages are validated by summing entries into a **`uint32` accumulator** and comparing the *sum* to `HundredPercent (10000)`, **with no per-entry upper bound**. Two entries whose percentages sum to just over `2^32` **wrap around** below `10000` and pass validation, while each stored value stays astronomically large (e.g. `0x80000000 = 2,147,483,648` ≈ 21,474,836%).

At payout, each split recipient is credited `pool × hugePct / 10000`, far more than the royalty pool, and the resulting negative remainder is silently discarded (`if royaltiesToPay <= 0 { return Ok }`). Because **fixed** royalties (and marketplace/ITO royalties) are denominated in **KLV**, the attacker mints KLV on demand by transferring or selling their own asset. Independent of, and not mitigated by, the existing `FixMarketBuyOverflow` guard.

Where to look:

- `core/process/kda/assetHelper.go`, `core/kapp/kda/create.go`, `core/kapp/kda/trigger.go`, `core/kapp/builtInFunctions/utils.go`, validation side (the `uint32` sum).
- `core/kapp/accounts/accounts.go` (transfer) and `core/kapp/market/market.go` (marketplace), the payout/mint sites.

## Boundary 2, marketplace settlement mints KLV when referral% + royalty% exceed the bid (GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754)

On settlement (`MarketBuy` / `BuyItNow`, auction `Claim`), the buyer's payment is split three ways:

```
marketOwnerAmount = CurrentBid − referralAmount − royaltiesAmount
```

Referral and royalties are paid **unconditionally**; the seller remainder is paid **only when positive** (`computeMarketOwnerAmount` returns `Ok` and pays nothing when `<= 0`). When `referral% + royalty%` exceeds 100% of the bid, `marketOwnerAmount` goes negative and is silently skipped, the marketplace pays out **more KLV/sale currency than the buyer paid**, minting the difference.

The `royalty% + referral% <= 100%` ceiling **is** checked once, at listing time (`Sell`). But the two percentages are sourced **asymmetrically** at settlement:

- **referral %** is **snapshotted** into the order at `Sell` (`MarketOrderData.ReferralPercentage`);
- **royalty %** is **never snapshotted**, read **live** from the asset at buy time (`asset.Royalties.MarketPercentage`).

So the listing-time invariant is a **time-of-check/time-of-use** guarantee only: after a valid listing, the asset owner raises the royalty `MarketPercentage` via `AssetTransfer`/update, and the next settlement mints.

## Boundary 3, SFT add-quantity `int64` circulation overflow bypasses the MaxSupply cap (GHSA-mrpp-v6pg-p54x / CVE-2026-55764)

On the SFT (semi-fungible token) add-quantity path, `SFTAddCirculation` does `meta.Circulation += amount` **with no overflow guard** (`core/kapp/systemAccount/systemAccount.go`), then checks `if meta.Circulation > meta.MaxSupply && meta.MaxSupply != 0`. A `mint-role` holder who passes an `amount` that overflows `int64` and wraps **negative** makes the cap check pass (`negative > MaxSupply` is false), the function returns `nil`, and the balance credit stands. A nonce declared with a small `MaxSupply` (e.g. 1000) can thus be minted to ~`MaxInt64` units in one transaction, and the on-chain `Circulation` counter is corrupted to a negative value.

The contrast that makes this a reusable pattern: the **fungible** mint path has a post-increment `MintedValue <= 0` guard that the SFT path lacks. The durable heuristic: **when two sibling mint/credit paths differ in their overflow guards, the unguarded one is the target.** Test the unguarded path with an overflow-sized amount and confirm the cap check evaluates against the wrapped value.

## Boundary 4, percentage-transfer royalty skips the source debit at exactly-100% splits (GHSA-v358-wf77-39xv, high)

In `processPercentageRoyaltiesTransfer` (`core/kapp/accounts/accounts.go`), the royalty pool is collected from the sender via `SubFromBalance` **after** the split loop and **after** the `if royaltiesToPay <= 0 { return Ok }` early-return. The split-payout guard rejects only allocations that *exceed* the pool (strict `splitToPay > royaltiesToPay`), so a split entry of **exactly 100%** (`PercentTransferPercentage = 10000`) is a *valid* config: it drives `royaltiesToPay` to 0, hits the early-return **before the sender is debited**, and the split recipient still keeps the full royalty. The split recipient is owner-controlled; the mint fires on **any holder's** transfer of the asset, not just the owner's, and the supply counter is never updated (off-the-books).

The contrast that makes this reusable: the sibling `processFixedRoyaltiesTransfer` debits the sender **first** and is safe. Durable heuristic: **when a collect-then-distribute path places the debit after an early-return that a *valid* (not just adversarial) config can reach, the debit is bypassable.** Test boundary configs, exactly-100% splits, zero pools, all-zero allocations, not just obviously-invalid ones, because the strict `>` guard accepts the exactly-full case as valid.

## Durable operator value

All four items are the same bug class in a DeFi/token context: **a sum-of-percentages or sum-of-amounts gate that does not bound the components and is not re-evaluated at the value-transfer moment.** Reusable across any settlement engine, fee router, royalty splitter, or dividend distributor:

1. **Check the accumulator type and per-entry bounds.** A `sum <= MAX` gate with unbounded inputs is an overflow/underflow probe. Test two entries that individually exceed the scale but sum into the valid range after wrap.
2. **Check snapshot vs live sourcing of each operand.** If one percentage is fixed at listing/creation and another is read live at payout, the listing-time invariant is TOCTOU. Find the field that is re-fetched between the invariant check and the credit.
3. **Check the negative-remainder / silent-skip path.** `if amount <= 0 { return Ok }` after an unconditional payout is the mint primitive, it converts a bad input into free value instead of reverting.
4. **Confirm the token is the native/guaranteed asset.** Minting the native token (KLV) is the high-impact case; verify the payout currency and that the pool cannot absorb the over-credit.

## Replayable validation path (lab / forked chain only)

- Preconditions: a forked or dev Klever chain (or an isolated testnet), a throwaway KDA asset, and a funded test account. No production chain, no real user assets, no real marketplace liquidity.
- **Overflow path:** create/transfer an asset with two split-royalty entries chosen so their `uint32` sum wraps below `10000` while each entry is huge. Trigger a royalty payout and record the credited amount vs. the pool; the positive is an over-credit in a synthetic recipient.
- **TOCTOU path:** list an asset with a valid combined ceiling, then raise the asset's live royalty `MarketPercentage` so referral + royalty exceed the bid; settle a `BuyItNow` and record the `marketOwnerAmount` going negative and the over-payout.
- **SFT `int64` overflow path:** with the mint role on a disposable nonce with a small `MaxSupply`, call the SFT add-quantity flow with an overflow-sized `amount` (e.g. `MaxInt64` seeded after a small initial credit) and record that the cap check passes while `Circulation` wraps negative. Contrast with the fungible mint path rejecting an over-cap amount.
- **Exact-100% split path:** on a forked/dev chain, configure a KDA with a `TransferPercentage` royalty and a single 100% (`10000`) split to an owner-controlled recipient; transfer the asset from any holder and record that the recipient is credited the full royalty while the sender's balance is unchanged and the supply counter is untouched. Run the 50% split as the negative control where the sender *is* debited.
- Evidence to capture: the exact validator line (accumulator type, per-entry bounds), the two operand sources (snapshot vs live), the negative-remainder branch, the unguarded `+=` vs its guarded sibling, and the over-credit/wrapped value on a forked chain.
- Stop at the over-credit on a forked/dev chain. Do not run this on mainnet, do not drain real pools, do not move real user funds, and do not attempt to extract native-token value on a live chain.

## Safe boundaries

- Forked or isolated dev/test chain only; no production Klever chain, no real marketplace liquidity, no real user assets.
- Throwaway assets and test accounts only; prove the over-credit in a synthetic recipient.
- Report the exact validator type/bounds, the snapshot-vs-live operand sourcing, the negative-remainder branch, the unguarded `+=` vs its guarded sibling, and the measured over-credit/wrapped value, framed as a settlement-validation boundary, not a live-chain drain.

## Sources

- [GitHub Advisory Database: Klever GHSA-cgc5-v3f2-8m2v / CVE-2026-54755](https://github.com/advisories/GHSA-cgc5-v3f2-8m2v)
- [GitHub Advisory Database: Klever GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754](https://github.com/advisories/GHSA-p7gw-2pcp-5pf8)
- [GitHub Advisory Database: Klever GHSA-mrpp-v6pg-p54x / CVE-2026-55764](https://github.com/advisories/GHSA-mrpp-v6pg-p54x)
- [GitHub Advisory Database: Klever GHSA-v358-wf77-39xv (percentage-royalty exact-100% split, `klever-go <= 1.7.19-rc2`)](https://github.com/advisories/GHSA-v358-wf77-39xv)
