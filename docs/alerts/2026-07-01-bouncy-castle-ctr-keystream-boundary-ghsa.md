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
