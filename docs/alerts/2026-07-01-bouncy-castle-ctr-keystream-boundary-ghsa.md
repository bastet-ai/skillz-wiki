# Bouncy Castle CTR keystream-reuse boundary check

Source: hourly offensive-security scan, 2026-07-01. Primary entry: GitHub Advisory Database [GHSA-574f-3g2m-x479](https://github.com/advisories/GHSA-574f-3g2m-x479) / CVE-2025-14813.

This advisory is durable for operators because it turns a library bug into a repeatable crypto-integration test: a CTR-mode counter that wraps after 255 blocks can reuse keystream and expose relationships between plaintexts when the same key/IV pair is used.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-574f-3g2m-x479](https://github.com/advisories/GHSA-574f-3g2m-x479) / CVE-2025-14813 | Bouncy Castle Java GOST 28147 CTR mode | `G3413CTRBlockCipher` only incremented the final counter byte, causing keystream reuse after 255 blocks | Crypto integration reviews should include block-boundary known-plaintext harnesses for stream/CTR modes, especially in custom or regional algorithm modes. |

Adjacent Netty HTTP/3 QPACK and Micronaut `Accept-Language` cache advisories were processed without promotion because they were resource-exhaustion focused. The FlashAttention checkpoint advisory is already covered in the May 18 ML/parser batch, Jackson Databind authorization edge cases are covered in the June 23 Jackson batch, the updated TinyMCE media-plugin advisory is covered in the June 5 Twig/Shopper/TinyMCE batch, and duplicate Open Babel/Fory/Spring Security updates are covered by the June 30 model parser/deserialization/identity page.

## Replayable validation boundary

### Bouncy Castle CTR keystream-reuse harness

- Preconditions: local Java harness using affected Bouncy Castle `bcprov`, synthetic plaintexts longer than 255 GOST blocks, a disposable key/IV, and no production ciphertexts.
- Encrypt two known plaintext buffers with the same key/IV through `G3413CTRBlockCipher` and compare ciphertext blocks around the counter wrap boundary.
- Positive evidence is repeated keystream behavior: `ciphertextA XOR ciphertextB` equals `plaintextA XOR plaintextB` for blocks after wrap, or identical plaintext blocks produce identical ciphertext blocks where they should not.
- Keep proof fully offline. Do not recover real plaintexts, test against live customer traffic, or publish keys, protocol secrets, or exploit tooling for deployed systems.
- Negative controls: Bouncy Castle 1.84 or fixed backports 1.80.2 / 1.81.1, protocol-level nonce uniqueness checks, and regression tests that cover counter carry across multiple bytes.

## Reporting notes

- Lead with the precise boundary crossed: **CTR counter wrap to keystream reuse**.
- Include affected and fixed versions, exact cipher/mode, synthetic plaintext size, block index where reuse appears, observed XOR relationship, and a fixed-version negative control.
- Keep evidence scoped and inert: disposable keys, synthetic plaintexts, local unit tests, and offline crypto harnesses only.

## October 9 follow-up: Bouncy Castle Java LTS native one-shot CTR packet cipher repeats keystream within one packet (GHSA-qgfp-x9w9-pwj2 / CVE-2026-71884, high, fixed LTS 2.73.13)

The same counter-space boundary this page was built around, now in a different implementation path: BC's **native one-shot CTR packet cipher** never validated that the input length fit the counter space the IV left. A 13–15 byte IV leaves a 1–3 byte counter (256 / 65,536 / 16,777,216 blocks); given longer input the counter **wrapped mid-packet**, the keystream repeated from the start of the same packet, and the call returned full input length as if every byte transformed correctly — no exception, no short length. Two segments of one message encrypted under the same keystream → their plaintexts recoverable from ciphertext alone, key-free. The streaming implementation validates at init *and* during processing, and the portable `AESCTRPacketCipher` rejects with "Counter in CTR/SIC mode out of range" — only the **native one-shot entry point** skipped the preflight. Fix adds the counter-range preflight before any output.

Operator extensions of this page's harness:

- **Implementation-path parity is the finding**: one library ships three CTR packet paths (streaming, portable one-shot, native one-shot) and only one was broken. The July 1 harness (two known plaintexts, same key/IV, XOR-compare around the wrap index) should be run against **every entry point the library exposes**, not one representative. Fingerprint: short-IV + long-message behavior differs per API — if one call path errors with a counter-range message and another returns success for the same (13-byte IV, oversized plaintext) pair, the silent-success path is the vulnerability.
- **Silent-crypto-failure detection battery**: any crypto API that "returns full length" on a wrap/overflow condition is worse than one that throws — integrators have no signal. For packet-mode ciphers, test the boundary triplet IV length × message length × {streaming, one-shot, native/provider-backed} and record which cells reject, which error late, and which return plausible bytes.
- Target-facing relevance: the LTS band (2.7.x) ships in long-lived enterprise/telecom stacks where native fast paths are explicitly enabled for throughput — precisely the deployments handling the most long-lived secrets. Lab-only, synthetic plaintexts, disposable keys, same as the original rules.
