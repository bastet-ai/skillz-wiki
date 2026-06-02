# Azure Key Vault Keys Java local-crypto integrity boundary

**Sources:** [GHSA-97jf-46m3-8953](https://github.com/advisories/GHSA-97jf-46m3-8953), [CVE-2026-33117 MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33117), [Azure SDK for Java release commit](https://github.com/Azure/azure-sdk-for-java/commit/1b5c5c79d85a5c9a9cfd07f6cdff6fd0f50eccf9)  
**Affected package:** Maven `com.azure:azure-security-keyvault-keys` before `4.10.6`  
**Operator value:** source-assisted validation for applications that decrypt or unwrap attacker-controlled ciphertext through the Azure Key Vault Keys Java local cryptography path and then trust the resulting plaintext.

## Why this matters

GHSA-97jf-46m3-8953 documents a critical integrity-boundary failure in the Java Azure Key Vault Keys library. The affected local cryptographic verification path compares authentication tags incorrectly, so specially crafted encrypted input can bypass integrity verification in applications that use that local path. Operations delegated to the Key Vault service are not affected by this advisory.

The reusable testing lesson is: **cryptographic helper libraries are still application attack surface when the app accepts externally supplied encrypted blobs, cookies, tokens, envelopes, or wrapped data and decrypts them locally before authorization or parsing.** Treat any local decrypt-and-trust boundary as a tamper-validation target, not just a dependency finding.

## Recon targets

Prioritize Java services where all three conditions are present:

1. the dependency is reachable at an affected version;
2. the application uses local cryptography APIs from the Key Vault Keys client stack rather than only remote Key Vault service operations;
3. an attacker can influence ciphertext, IV/nonce, tag, wrapped key, algorithm metadata, or envelope fields that are decrypted and trusted by the application.

Source-review starting points:

```bash
# Dependency reachability.
grep -R "azure-security-keyvault-keys" -n pom.xml build.gradle gradle.lockfile **/pom.xml 2>/dev/null
mvn -q dependency:tree -Dincludes=com.azure:azure-security-keyvault-keys 2>/dev/null

# Local crypto and envelope-handling clues.
grep -R "CryptographyClient\|LocalCryptographyClient\|decrypt(\|encrypt(\|unwrapKey(\|wrapKey(" -n src 2>/dev/null

grep -R "ciphertext\|iv\|nonce\|tag\|aad\|wrappedKey\|encrypted" -n src 2>/dev/null
```

High-signal application patterns:

- encrypted cookies, invite links, password-reset state, API tokens, or tenant-scoped envelopes parsed after local decrypt;
- request fields named `ciphertext`, `tag`, `iv`, `nonce`, `kid`, `alg`, `wrappedKey`, or `aad`;
- background workers that decrypt user-uploaded encrypted files or message payloads;
- custom envelope formats where the service chooses algorithm/key metadata from attacker-controlled JSON;
- code that catches decrypt exceptions and falls back to partially parsed data or alternate decrypt paths.

## Safe validation workflow

Use a local harness, staging system, or an explicitly authorized test tenant. Do not tamper with production user secrets or data-bearing tokens.

### 1. Confirm affected dependency and reachable local decrypt path

```bash
mvn -q dependency:tree -Dincludes=com.azure:azure-security-keyvault-keys

grep -R "CryptographyClient\|LocalCryptographyClient\|decrypt(\|unwrapKey(" -n src 2>/dev/null
```

A finding is in scope for this advisory only when `com.azure:azure-security-keyvault-keys` resolves below `4.10.6` and the vulnerable local cryptography path is reachable with attacker-influenced encrypted input.

If the application only calls Key Vault service-side operations for cryptographic checks, do not report this as an exploitable application issue without additional evidence.

### 2. Map the envelope boundary

For each encrypted artifact, document the boundary before sending probes:

| Field | Question to answer |
| --- | --- |
| Key selector | Is `kid`, key name, version, or algorithm chosen from user input? |
| Ciphertext body | Can the tester alter bytes without breaking transport encoding? |
| Tag / MAC | Is the authentication tag carried separately or embedded? |
| AAD / context | Are tenant, route, user, or purpose fields authenticated? |
| Trust sink | What plaintext fields drive authorization, identity, file path, SQL, template rendering, or workflow selection? |

Only proceed when the artifact is canary-only and the expected safe behavior is rejection before any trust sink executes.

### 3. Run tamper controls first

Generate or capture a canary encrypted artifact in a test tenant, then alter one field at a time. Keep probes low-impact and non-reusable.

```bash
# Example mutation checklist; adapt to the app's encoding and keep artifacts local.
# - flip one byte in ciphertext
# - flip one byte in authentication tag
# - change algorithm/key metadata to an unsupported or wrong value
# - change AAD/context if the format carries it separately
# - replay the canary under a different low-privilege route or tenant
```

Expected safe behavior is a uniform decrypt/authentication failure before the application parses or trusts plaintext. Strong evidence is any mutated artifact that passes local integrity verification and reaches a trust sink that the unmutated canary controls.

### 4. Separate library behavior from application fallbacks

Use controls to avoid misattribution:

| Control | Expected result |
| --- | --- |
| Same mutated artifact against `azure-security-keyvault-keys` `4.10.6` or later | Rejected |
| Same artifact through Key Vault service-side cryptographic operation | Rejected or not affected by this advisory |
| Invalid base64/JSON/envelope syntax | Rejected before decrypt |
| Wrong key or algorithm metadata | Rejected without fallback to a permissive path |
| Legitimate canary artifact | Accepted only for its intended low-privilege action |

If a fallback path accepts plaintext after any decrypt error, report that application fail-open separately. If every malformed artifact is accepted, report a broader authorization or parser problem instead of overfitting to CVE-2026-33117.

## Reporting heuristic

Frame the issue around a local cryptographic integrity boundary:

- **Expected boundary:** attacker-controlled encrypted artifacts must fail closed when ciphertext, tag, AAD, key selector, or algorithm metadata is modified.
- **Observed bypass:** a tampered canary artifact reaches post-decrypt parsing or authorization in an application using affected `com.azure:azure-security-keyvault-keys` versions.
- **Impact:** integrity bypass for encrypted application state, token envelopes, or wrapped data trusted after local decrypt.
- **Evidence:** dependency tree, reachable decrypt call, redacted envelope structure, mutation matrix, response/status differences, and the trust sink reached by canary-only data.

## Scope and safety notes

- Do not publish real encrypted tokens, keys, plaintext, authentication tags, or tenant identifiers.
- Prefer a local unit harness or staging canary over production request tampering.
- Keep mutations to canary artifacts and low-privilege routes; do not use tampered ciphertext to access real user data.
- Confirm the application uses local cryptography before claiming exploitability; service-delegated Key Vault operations are not affected by this advisory.
