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

The same counter-space boundary this page was built around, now in a different implementation path: BC's **native one-shot CTR packet cipher** never validated that the input length fit the counter space the IV left. A 13-15 byte IV leaves a 1-3 byte counter (256 / 65,536 / 16,777,216 blocks); given longer input the counter **wrapped mid-packet**, the keystream repeated from the start of the same packet, and the call returned full input length as if every byte transformed correctly, no exception, no short length. Two segments of one message encrypted under the same keystream → their plaintexts recoverable from ciphertext alone, key-free. The streaming implementation validates at init *and* during processing, and the portable `AESCTRPacketCipher` rejects with "Counter in CTR/SIC mode out of range", only the **native one-shot entry point** skipped the preflight. Fix adds the counter-range preflight before any output.

Operator extensions of this page's harness:

- **Implementation-path parity is the finding**: one library ships three CTR packet paths (streaming, portable one-shot, native one-shot) and only one was broken. The July 1 harness (two known plaintexts, same key/IV, XOR-compare around the wrap index) should be run against **every entry point the library exposes**, not one representative. Fingerprint: short-IV + long-message behavior differs per API, if one call path errors with a counter-range message and another returns success for the same (13-byte IV, oversized plaintext) pair, the silent-success path is the vulnerability.
- **Silent-crypto-failure detection battery**: any crypto API that "returns full length" on a wrap/overflow condition is worse than one that throws, integrators have no signal. For packet-mode ciphers, test the boundary triplet IV length × message length × {streaming, one-shot, native/provider-backed} and record which cells reject, which error late, and which return plausible bytes.
- Target-facing relevance: the LTS band (2.7.x) ships in long-lived enterprise/telecom stacks where native fast paths are explicitly enabled for throughput, precisely the deployments handling the most long-lived secrets. Lab-only, synthetic plaintexts, disposable keys, same as the original rules.

## November 20 follow-up: crypto11 (PKCS#11 Go wrapper) hands any nonce to the token, empty nonce = keystream reuse plus GHASH key recovery (CVE-2026-115407 / [GHSA-9q64-h4f4-jp28](https://github.com/advisories/GHSA-9q64-h4f4-jp28), critical, eclipse-keypont/crypto11/v2 <= 2.0.0-rc8; v1 lines: eclipse-keypont/crypto11 <= 1.6.8, ThalesGroup/crypto11 <= 1.7.0-rc1, ThalesIgnite/crypto11 <= 1.2.5)

The same keystream-reuse boundary, this time one layer up: a **wrapper that validates nothing between the caller and the HSM**. `SecretKey.NewGCM()`'s `cipher.AEAD` passes whatever nonce it receives straight into `CK_GCM_PARAMS` with no length check against `NonceSize()`, and an **empty nonce is accepted**. On a token that tolerates a zero-length GCM IV (SoftHSM2 does), every `Seal` with an empty nonce encrypts under the same IV: keystream reuse across all messages *and* GHASH authentication-key exposure, which yields forgeries. Two adjacent config-path failures ride along:

- `Config.UseGCMIVFromHSM` sends a NULL IV with length zero unless `GCMIVFromHSMControl.SupplyIvForHSMGCMEncrypt` is *also* set, so the token has nowhere to write its generated IV: a non-empty-nonce `Seal` **panics after the plaintext was already encrypted**, and an empty-nonce `Seal` returns ciphertext under an empty IV **without error**. The v1 line additionally never copies the token-generated IV back to the caller, so callers keep tracking their own nonce while data was encrypted under another one.
- Operator rules for any HSM/KMS/crypto-wrapper engagement:
  - **Nonce-contract parity test**: for every AEAD factory in a wrapper, assert `aead.NonceSize()` is actually enforced. Call `Seal` with nonce lengths {NonceSize, NonceSize+1, 1, 0} and record which cells the wrapper rejects vs. forwards to the token. A wrapper that forwards is trusting the token's strictness, which is per-token behavior, not a library guarantee. SoftHSM2 as the lab token is a legitimate test oracle: real deployments run real tokens whose tolerance profiles differ, so "SoftHSM2 accepts empty IV" is a differential signal about token-side validation, not just a SoftHSM bug.
  - **Nonce-carrying fidelity**: in HSM-generated-IV modes, verify the IV returned to the caller equals the IV used on-wire (seal, decrypt round-trip plus an external decrypt with the token-reported IV). The v1 "caller keeps its own nonce while data used another" leg is the same class as the Sept 18 Net::DNS finding: the bookkeeping value and the wire value are different objects.
  - **Panic-after-encrypt is an information-disclosure tell**: an API that crashes *after* the crypto side effect has happened means the plaintext crossed the boundary the caller believed was gated. Same silent-crypto-failure battery as the October 9 leg, extended with a panic column: reject / late-error / silent-success / panic-post-side-effect.
  - Fingerprint for hunting: grep PKCS#11 wrappers for direct `CK_GCM_PARAMS` population without a preceding length comparison against the AEAD interface's `NonceSize()`; the bug shape is "interface method exists but is never consulted on the seal path."
- Proof boundaries: disposable SoftHSM2 token, synthetic plaintexts, own keys only; keystream-reuse evidence is two empty-nonce seals of known plaintexts XOR-compared, per this page's original harness. Never extract production keys or test against shared tokens.
