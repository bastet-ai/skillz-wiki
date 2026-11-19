---
title: "Mareforma wave (5 GHSAs): unsigned claims reach REPLICATED through signature-blind convergence"
---

# Mareforma wave (5 GHSAs): unsigned claims reach REPLICATED through signature-blind convergence

**Wave in one line:** a Python claim-trust library lets an unsigned claim climb to its highest multi-party trust tier, serves forged high-trust rows on one of its two read paths, treats a post-signing Rekor block as proof of public witness, and never actually checks a per-claim signature in bundle verification.

Source: coordinated GitHub advisory wave published 2026-11-19 16:00-16:07Z against `mareforma` 0.3.x (fixed across 0.3.7 and 0.3.8).

- [GHSA-8776-qf3h-26r3 / CVE-2026-71535](https://github.com/advisories/GHSA-8776-qf3h-26r3) (high, >= 0.3.0 < 0.3.7): the REPLICATED convergence query filters on `status`, `unresolved`, `transparency_logged`, and `artifact_hash`, and has **no predicate on `signature_bundle` or enrolled-key identity**. With the default `rekor_enabled=False` setting `transparency_logged=1` at insert time, every claim satisfies the convergence precondition. An attacker with no key writes an unsigned claim that converges with a legitimate signed peer claim and is promoted to `REPLICATED`, the status the default consumer query (`graph.query(min_support="REPLICATED")`) treats as a multi-party endorsement.
- [GHSA-m29v-3g7g-9c63 / CVE-2026-71533](https://github.com/advisories/GHSA-m29v-3g7g-9c63) (medium, 0.3.7 fixed in 0.3.8): `search_claims` never calls the verify-on-read helper that `query_claims` runs on REPLICATED/ESTABLISHED rows. A tampered or forged high-trust row **splits the two read paths**: `query()` drops it, `search()` serves it at its persisted trust level, and the forged row lacks the `verified` key entirely so the consumer cannot tell it went unchecked. The docstring even promises "the same projection as query_claims."
- [GHSA-hxh5-gp44-rc6p / CVE-2026-71536](https://github.com/advisories/GHSA-hxh5-gp44-rc6p) (high, < 0.3.8): `verify_bundle` documents per-claim signature verification, but the exported JSON-LD node carries **no signature material at all**, so the "verification" loop only re-derives each claim's canonical-statement digest and compares it against the signed subject list. Both sides of that comparison were produced and signed by the same exporter key, so it proves internal consistency, not that each claim's purported asserter ever validly signed it. All trust in a bundle collapses to the single exporter key.
- [GHSA-rgg9-956j-3378 / CVE-2026-71500](https://github.com/advisories/GHSA-rgg9-956j-3378) (medium, < 0.3.8): the convergence promotion path never checks `t_invalid`, so a claim a signed contradiction verdict has marked invalid still climbs to REPLICATED and pulls an honest peer up with it. The other promotion paths (`validate_claim`, `record_replication_verdict`) gate on the verdict; convergence is the one path that ignores it, and the promotion UPDATE gates only on `status = 'open'`, leaving a TOCTOU window.
- [GHSA-xfq4-8hf9-5h43 / CVE-2026-71534](https://github.com/advisories/GHSA-xfq4-8hf9-5h43) (medium, < 0.3.8): restore recomputes `transparency_logged` from a **`rekor.uuid` field inside the unsigned `signature_bundle`**. The Rekor block is attached *after* signing (`attach_rekor_entry` leaves payload and signatures untouched), so a hand-edited `claims.toml` can add `"rekor": {"uuid": "x"}` to any claim and forge the "publicly witnessed by Rekor" state while the claim signature still verifies. Restore never cross-checks the block against recorded inclusions or the log, which is exactly the tamper threat the restore signature check exists to cover. The same leg breaks honest data the other way: a signed non-Rekor claim restores from `transparency_logged=1` to 0 and can never converge again.

## Why it is durable operator guidance

The product is niche; the boundary class is not. Any system with a trust ladder (statuses like PRELIMINARY/REPLICATED/ESTABLISHED, "verified" badges, quorum endorsement, signed artifact registries, attestation pipelines) reproduces these five defects when its invariants are enforced per-path instead of per-invariant. Four reusable hunt rules:

1. **Enumerate every status-transition code path and diff the gates.** The wave is a map of what that diff finds: the primary promotion path checks signatures and the `t_invalid` verdict, the convergence path checks neither, and the promotion UPDATE re-checks less than the SELECT before it. For any trust-tiered system, list every function that can move a record to a high-trust state (`UPDATE ... SET status` greps are the shortcut), then replay the same forged input against each path separately. A check present on one transition is not a system property.
2. **Read-path parity is an exploit surface (query vs search, detail vs list, REST vs MCP).** When one reader re-verifies and its sibling does not, the weaker reader is the attack target, and the advisory's own runtime check is the test template: same forged row, both readers, expect the split (`query()` False / `search()` True, `verified` key absent). Probe any product with two access shapes to the same store, especially where the weaker path's docstring claims equivalence with the stronger one.
3. **Metadata attached after signing is unsigned input.** The Rekor block was added post-signature, so it is attacker-editable while the signature still "verifies." Standing audit question for any signed artifact that carries log/attestation/annotation metadata: which security-relevant fields (transparency flags, policy verdicts, timestamps, provenance labels) are *inside* the signed payload versus bolted on afterward, and does any gate trust the bolted-on copy? Derive security flags from signature-covered material or a live server-side lookup, never from a post-signing block. Same genealogy as the wiki's cosign tag-vs-manifest and rekor-set-vs-payload checks.
4. **A digest recomputed over self-produced content is not verification.** `verify_bundle` compared exporter-built nodes against exporter-signed subject digests and called it per-claim verification. When auditing any bundle/manifest verifier, ask per nested object: whose key covers *this* object, and would a mutation made by the asserted asserter's adversary be caught? Self-referential digest chains confirm internal consistency only. Test the documented contract, not the function name: the docstring promised "per-claim signature failure" errors that the code could never raise, so run the tamper cases the documentation itself enumerates.

## Validation scaffold (authorized lab only)

Install `mareforma` 0.3.3 and 0.3.7 in disposable venvs, create your own validator keypair, and drive the SQLite store directly. Proofs are state assertions only, no third-party graphs.

| Leg | Input | Positive evidence |
| --- | --- | --- |
| Convergence without signature | unsigned claim sharing an anchor with a signed peer claim you minted in-lab | row status reaches `REPLICATED`, returned by `graph.query(min_support="REPLICATED")` |
| Read-path split | flip a row's status to `ESTABLISHED` with a tampered signature (or copy a genuine validation envelope onto a fresh row) | `query()` excludes it, `search()` serves it with `verified` absent |
| Bundle self-verification | reorder/swap claim nodes within a bundle keeping exporter-key consistency | `verify_bundle` accepts, per-claim asserter was never checked |
| Invalidated convergence | set `t_invalid` via a signed contradiction, then assert a peer sharing the anchor | both claims land at `REPLICATED` with `t_invalid` still set |
| Forged Rekor state | hand-edit `claims.toml` to add `"rekor": {"uuid": "x"}`, run restore | `transparency_logged=1` persisted with no log cross-check |

Compare each result on 0.3.8 to confirm the fix band. Record table of (leg, version, pre/post status, read-path result) and stop there.

## Reporting heuristics

State the trust guarantee that broke (which consumer query, which documented promise), the exact gate absent on the exploited path versus present on the sibling path, and the attacker precondition (graph write access, key enrollment, restore-file tamper). Do not collapse "promoted to REPLICATED" into "impersonates a validator": promotion is the endorsement-state write, and downstream impact depends on which consumer trusts that tier.

Adjacent items tracked without publication: two NATS Server MQTT advisories from the same wave folded on the June 11 protocol-codec page, a DOMShell MCP read-tier misclassification folded on the July 26 agent-approval page, and the three-leg jane-php OpenAPI codegen wave folded on the July 24 codegen page.
