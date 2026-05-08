# Parser, model, signature, and crypto-boundary batch

**Signal:** The **2026-05-08 18:15 UTC** advisory scan added parser/model-loader, cryptographic verification, and protocol-library failures across phpseclib, GoBGP, bitcoinj, gitsign, jOpenDocument, and Ollama.

## Advisories covered

- **phpseclib ASN.1 OID amplification DoS** — [GHSA-3qpq-r242-jqj7](https://github.com/advisories/GHSA-3qpq-r242-jqj7): `phpseclib/phpseclib` patched in `1.0.29`, `2.0.54`, and `3.0.52`.
- **GoBGP IPv6 extended parser out-of-bounds read** — [GHSA-wmvj-f67g-qg4g](https://github.com/advisories/GHSA-wmvj-f67g-qg4g): `github.com/osrg/gobgp/v4 < 4.4.0`; patch to `4.4.0+`.
- **bitcoinj P2PKH/P2WPKH fast-path verification bypass** — [GHSA-hfcf-v2f8-x9pc](https://github.com/advisories/GHSA-hfcf-v2f8-x9pc): `org.bitcoinj:bitcoinj-core >= 0.15, < 0.17.1`; patch to `0.17.1+`.
- **gitsign empty-certificate PKCS7 panic exits 0 for exit-code callers** — [GHSA-7c37-gx6w-8vc5](https://github.com/advisories/GHSA-7c37-gx6w-8vc5): `github.com/sigstore/gitsign >= 0.4.0, < 0.15.0`; patch to `0.15.0+`.
- **jOpenDocument XXE/entity blowup** — [GHSA-j9rh-p96m-mhhp](https://github.com/advisories/GHSA-j9rh-p96m-mhhp): jOpenDocument XML parsing is unsafe for untrusted documents; no patched version was listed in GitHub metadata.
- **Ollama GGUF model loader heap out-of-bounds read** — [GHSA-x8qc-fggm-mpqg](https://github.com/advisories/GHSA-x8qc-fggm-mpqg): `github.com/ollama/ollama < 0.17.1`; patch to `0.17.1+`.

## Why this is durable

Verification and parsing code often runs in privileged trust positions: certificate/key loading, routing control planes, wallet validation, signed-commit gates, document ingestion, and AI model creation. A single unchecked length, missing binding check, insecure XML parser, or panic-to-success wrapper can turn a defensive control into a bypass or data leak.

## Immediate triage

1. Patch the named packages to the fixed versions above; isolate any component with no patched release behind trusted-only input handling.
2. Search for untrusted ASN.1, certificate, key, OID, XML, BGP UPDATE, GGUF, and PKCS7 signature ingestion paths.
3. For bitcoinj, identify applications using `correctlySpends()` as local proof of spend validity and revalidate affected transactions after patching.
4. For gitsign, audit CI and release scripts that check only process exit code; require status output semantics (`GOODSIG`) and non-zero-on-panic behavior.
5. For Ollama, restrict `/api/create` and `/api/push`, review model artifacts created from untrusted GGUF files, and check whether OLLAMA_HOST exposed the API beyond loopback.

## Durable controls

- Bound every attacker-controlled length/count before allocation and before copying from input buffers.
- Treat signature verification success as a structured result, not a process exit code alone.
- Assert cryptographic binding invariants explicitly: a signature over attacker-controlled key material is not enough if the output commits to a different key hash.
- Disable DTDs and external entities for office/document XML by default; add entity-expansion budgets for legacy parsers.
- Load untrusted models and protocol messages inside constrained workers with memory, CPU, network, and filesystem limits.
- Add negative tests for empty certificate sets, missing arrays, malformed BGP attributes, truncated model tensors, and maximal OID/component encodings.
