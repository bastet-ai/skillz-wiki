# pyasn1 RELATIVE-OID continuation-octet DoS (CVE-2026-23490)

`pyasn1` is widely embedded (directly or indirectly) in systems that need ASN.1 decoding: certificate validation / X.509 parsing, LDAP tooling, OCSP responders, etc. A parser bug here is frequently **service-impacting**.

In `pyasn1` **v0.6.1**, a Denial-of-Service condition was reported where a malformed **RELATIVE-OID** value containing excessive continuation octets can trigger **unbounded work / memory exhaustion** during BER decoding.

- Advisory: <https://github.com/advisories/GHSA-63vm-454h-vhhq>
- Fix release: <https://github.com/pyasn1/pyasn1/releases/tag/v0.6.2>

## What to do (durable guidance)

### 1) Patch fast (preferred)

- **Upgrade `pyasn1` to v0.6.2 or later.**

If you don’t depend on `pyasn1` directly, still check for it:

- `pipdeptree | grep -i pyasn1` (or `pip list --format=freeze | grep -i pyasn1`)
- your SBOM / lockfile (Poetry/Pipenv requirements)

### 2) Treat ASN.1 decoding as untrusted parsing

Even when patched, ASN.1/BER/DER decoders should be treated like other complex parsers (XML, image codecs, PDF): they can be coerced into expensive behavior.

Defense-in-depth controls that hold up across advisories:

- **Input size limits** before decoding (certificate length, response size, LDAP message size).
- **Timeouts / CPU budgets** around decode operations.
- **Isolation**: decode in a separate worker process/container so a hang or OOM doesn’t take down the API.
- **Rate limiting** for endpoints that trigger decode work (TLS handshakes, OCSP, upload/validation flows).

### 3) Add explicit decoder limits when you can

The advisory recommendation is to **add a limit to allowed bytes in the decoder**.

If your application controls the decode boundary, add hard caps (and tests) that reject:

- Excessive component counts (e.g., OID / RELATIVE-OID arcs)
- Overlong base-128 continuation sequences
- Encodings that exceed a maximum “work factor”

## Where this bites in the real world

This pattern shows up when an attacker can feed ASN.1 into your system, for example:

- A **malicious X.509 certificate** presented during certificate validation
- **OCSP** responses
- **LDAP** attribute values or messages
- Any “paste a cert / upload a cert / validate a cert” workflow

## Quick checklist

- [ ] `pyasn1` version is **>= 0.6.2** everywhere (including transitive deps)
- [ ] Untrusted ASN.1 decode has **size limits**
- [ ] Decode runs with **timeouts** and can’t OOM the whole service
- [ ] Decoder boundary is **isolated** (worker process) where practical
- [ ] Request rate limits in front of decode-heavy endpoints
