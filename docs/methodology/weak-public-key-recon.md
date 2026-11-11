# Weak public-key recon

Sources: [Trail of Bits, Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/), published 2026-06-12; GeoVision Lighttpd static-key records [GHSA-7p93-2qwj-4g34 / CVE-2026-18753](https://github.com/advisories/GHSA-7p93-2qwj-4g34) and [GHSA-qfjw-8qqh-5c6x / CVE-2026-18754](https://github.com/advisories/GHSA-qfjw-8qqh-5c6x). Tool reference: [badkeys README](https://github.com/badkeys/badkeys/blob/main/README.md) and [badkeys.info](https://badkeys.info/).

Public keys are recon artifacts. A scoped TLS certificate, SSH host key, SAML signing key, PGP key, or appliance-generated key can expose product lineage and sometimes a practical private-key recovery path without touching application data. The durable operator lesson from Trail of Bits' short-sleeve RSA research is to collect public keys at corpus scale, normalize them, and run known-weak-key checks before spending time on harder exploit paths.

Trail of Bits and badkeys found real internet keys with regularly spaced zero-bit blocks in RSA moduli. For some of those keys, the structure let researchers replace integer factoring with polynomial factoring and recover private keys. One confirmed source was old CompleteFTP key-generation code; the same campaign also found vulnerable DSA keys. The wiki value is not the cryptanalytic derivation, it is the repeatable recon workflow for finding weak public-key material in authorized scope.

!!! warning "Authorized testing only"
    Collect and test only public keys from systems in scope, public transparency sources, or lab assets. Do not use recovered private keys for access, impersonation, signing, decryption, or persistence. If a tool flags a recoverable key, stop at evidence that the public key is vulnerable and coordinate disclosure through the authorized channel.

## When to use this playbook

Use it when the target scope includes internet-facing cryptographic endpoints or products that generate long-lived keys.

High-signal conditions:

- SSH, SFTP, FTPS, HTTPS, SMTPS, IMAPS, POP3S, LDAPS, VPN portals, management consoles, or embedded appliances are in scope.
- The same SSH host key or TLS certificate appears across many hosts, tenants, firmware images, or customer deployments.
- A product uses self-generated RSA or DSA keys rather than centrally issued certificates.
- Appliance banners, certificate subjects, or SSH software strings identify a vendor/version with custom crypto or old key-generation code.
- Public CT logs or historical scan datasets are in scope for research and can be checked without touching live production services.

## Operator workflow

1. **Define the public-key corpus.** Keep endpoint, port, protocol, scan time, and collection method with every key.
2. **Collect without authentication.** Pull only public certificates and public SSH host keys. Avoid credentialed login attempts unless explicitly authorized.
3. **Deduplicate by fingerprint.** Weak keys often repeat across many hosts; one vulnerable fingerprint is more important than thousands of duplicate endpoints.
4. **Run known-weak-key checks.** Use `badkeys` or an equivalent offline checker against the collected corpus.
5. **Correlate product evidence.** Pair each weak-key hit with non-sensitive banners, certificate metadata, package/version evidence, or asset-owner confirmation.
6. **Validate the boundary safely.** Report a public-key weakness as soon as the checker identifies a known vulnerable pattern. Do not attempt private-key use against live services.
7. **Preserve negative evidence.** Record parser failures, unsupported key types, and endpoints where no public key was captured so the assessment can be reproduced.

## Collect SSH host keys

For a scoped host list, collect SSH public keys without authenticating:

```bash
mkdir -p evidence/ssh-hostkeys
while read -r host; do
  ssh-keyscan -T 5 -p 22 "$host" 2>/dev/null \
    | tee "evidence/ssh-hostkeys/${host//[^A-Za-z0-9_.-]/_}.pub" >/dev/null
done < scoped-hosts.txt

find evidence/ssh-hostkeys -type f -size +0c -print0 \
  | xargs -0 ssh-keygen -lf \
  | sort -u > evidence/ssh-hostkey-fingerprints.txt
```

If alternate SSH/SFTP ports are in scope, track the port in the output path:

```bash
while read -r host port; do
  ssh-keyscan -T 5 -p "$port" "$host" 2>/dev/null \
    > "evidence/ssh-hostkeys/${host}_${port}.pub"
done < scoped-ssh-endpoints.tsv
```

## Collect TLS certificates

Use SNI when the target is name-based. Store PEM certificates, then derive stable fingerprints:

```bash
mkdir -p evidence/tls-certs
while read -r host port sni; do
  : "${sni:=$host}"
  timeout 10 openssl s_client -connect "$host:$port" -servername "$sni" -showcerts </dev/null 2>/dev/null \
    | awk '/BEGIN CERTIFICATE/{flag=1} flag{print} /END CERTIFICATE/{exit}' \
    > "evidence/tls-certs/${host}_${port}_${sni}.pem"
done < scoped-tls-endpoints.tsv

find evidence/tls-certs -type f -size +0c -print0 \
  | xargs -0 -I{} sh -c 'openssl x509 -in "$1" -noout -fingerprint -sha256 -subject -issuer' sh {}
```

For broad TLS/SSH inventory, prefer existing approved recon output or scanner exports, then run weak-key analysis offline. This keeps the key-checking step deterministic and avoids re-scanning assets just to rerun the checker.

## Run badkeys offline

Install in a disposable virtual environment and update the blocklist before checking the corpus:

```bash
python3 -m venv /tmp/badkeys-venv
/tmp/badkeys-venv/bin/python -m pip install badkeys
/tmp/badkeys-venv/bin/badkeys --update-bl

/tmp/badkeys-venv/bin/badkeys evidence/ssh-hostkeys/*.pub evidence/tls-certs/*.pem \
  | tee evidence/badkeys-findings.txt
```

`badkeys` returns `0` when scanned keys have no detected vulnerabilities, `4` when a vulnerable key is found, `2` when an input cannot be parsed, and combinations as a bitmask. Treat parse failures as corpus-quality issues to fix before closing the assessment.

`badkeys` can also scan hosts directly with `-s` for SSH and `-t` for TLS, but the project notes limitations in direct scanning. Prefer local corpus checks when you need reproducible evidence:

```bash
# Direct scoped spot check only; local corpus scanning is preferred for reports.
/tmp/badkeys-venv/bin/badkeys -s -t example.org
```

## Triage weak-key hits

For each hit, capture:

- Key type, bit length, fingerprint, and vulnerable pattern name from the checker.
- Endpoint(s), protocol(s), ports, and first/last observation times.
- Product/version clues from SSH banners, TLS subject/issuer/SANs, HTTP titles, or scoped inventory.
- Whether the same key appears on multiple hosts or tenants.
- Safe proof boundary: public key is vulnerable; no private-key use, no login attempt, no message signing, no decryption.

High-value report language:

```text
Scoped public key corpus
  -> public SSH/TLS key with known weak pattern
  -> fingerprint repeats on N assets / maps to product X
  -> checker identifies recoverable or known-vulnerable key material
  -> impact: service identity can no longer be trusted if private key is recovered elsewhere
  -> proof stops at public-key evidence; no private-key use against live services
```

## Product-lineage pivots

Weak-key findings become stronger when tied to a repeatable product boundary:

- **Banners:** SSH software strings, SFTP server banners, or appliance headers that identify the generator.
- **Certificate metadata:** Organization, common name, SAN patterns, issuance dates, and self-signed defaults.
- **Firmware or installer review:** Static strings, embedded keys, or custom big-integer/key-generation code in vendor packages that are in scope to analyze.
- **Historical scans:** CT logs or approved historical SSH/TLS datasets showing when a weak key first appeared and whether regeneration happened after upgrades.

Do not infer a product vulnerability from one weak key alone. Tie the key to product behavior only when independent evidence shows the product generated or shipped it.

## Static firmware-key follow-up

The two GeoVision records add a complementary corpus check: firmware may ship the same RSA **private** key for Lighttpd TLS termination across devices. An endpoint certificate is public and safe to fingerprint; obtaining or using the embedded private key is not required to prove that deployed identities share one vendor-shipped key.

1. Confirm the exact owned product, model, firmware, and HTTPS service from inventory or vendor documentation. The initial GitHub records are sparse, so do not infer an affected model from a GeoVision banner alone.
2. Collect only the public leaf certificate from each approved endpoint and from a freshly reset lab device. Record SNI, port, observation time, certificate fingerprint, Subject Public Key Info fingerprint, and non-sensitive product evidence.
3. Compare SPKI fingerprints across devices, firmware releases, resets, and regenerated-certificate controls. Certificate fingerprints may differ while the underlying RSA public key remains the same.
4. If firmware review is explicitly in scope, use a vendor-provided image in an offline disposable workspace. Patch the extraction scanner to report only **private-key present, path class, public-key fingerprint, and file mode**; do not print, archive, or commit PEM bytes.
5. Derive the public half inside the isolated workspace and compare its fingerprint to the lab endpoint. Destroy the extracted image workspace afterward under the engagement's evidence policy.
6. Stop before loading the key into a TLS server, decrypting captures, impersonating a device, signing content, or testing third-party endpoints. Repeat collection after the vendor-fixed firmware or device-specific key regeneration.

The bounded positive is **owned firmware scanner detects embedded private-key material -> derived public fingerprint matches the owned device's live TLS SPKI -> a second reset/device or documented build repeats the fingerprint -> corrected firmware produces a device-specific key**. A repeated self-signed certificate is useful recon evidence but does not by itself prove the corresponding private key was shipped or exposed.

## Reporting checklist

Include:

- Scope statement and collection method.
- Public-key fingerprint(s), not private keys.
- Checker/tool version, blocklist update time, and exact command line.
- Minimal non-sensitive endpoint evidence.
- Clear statement that no recovered private key was used.
- Recommended owner action can be concise: replace affected keys and review key-generation source, but keep the report centered on the exploitability boundary and reproducible public evidence.

## Durable lesson

Weak public-key recon rewards boring corpus hygiene. Gather public keys once, deduplicate fingerprints, run known-weak-key checks offline, and investigate clusters that map to a product or generation path. The strongest finding is not "old crypto exists"; it is a narrow chain from scoped public key to known vulnerable pattern to affected service identity, proven without crossing into private-key use.
