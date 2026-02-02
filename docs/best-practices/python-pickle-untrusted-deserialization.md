# Python pickle: never deserialize untrusted data

## Summary

`pickle` is **not a safe data format**. Deserializing attacker-controlled pickle payloads can lead to:

- **Remote Code Execution (RCE)** (common outcome)
- **unexpected side effects** even when “RCE keywords” are filtered
- **arbitrary file creation** / filesystem tampering in some gadget chains

Blocklists (“deny `os.system`”, “deny `subprocess`”) are routinely bypassed.

## Durable guidance

### 1) Policy: treat pickle as code

- Do not accept pickle payloads from:
  - users
  - network clients
  - queues/topics not fully controlled
  - plugins / extensions
  - CI artifacts from untrusted repos

If you cannot strongly prove the source is trusted, it’s untrusted.

### 2) Prefer safe serialization formats

Use formats designed for untrusted data:

- **JSON** (with schema validation)
- **MessagePack** (with explicit type handling)
- **Protocol Buffers / Avro / Thrift** (strong typing)

Store only primitive data types; avoid “object graphs”.

### 3) If you must load pickle (rare), sandbox hard

If you are forced to load pickle for legacy reasons:

- require **integrity + authenticity**:
  - signatures (e.g., Ed25519) or HMAC with rotation
  - explicit key management policy
- load in a **highly constrained environment**:
  - separate service/container
  - read-only filesystem
  - no network egress
  - seccomp/AppArmor, low privileges
- implement **defense-in-depth**:
  - allowlist types (custom restricted unpickler)
  - audit logs + anomaly detection

Even then, assume bypasses exist.

### 4) Don’t “filter” pickle payloads

- String scanning is not a control.
- Gadget chains can trigger side effects without obvious keywords.

## Related Wisdom

- [Supply Chain Malware Triage](supply-chain-malware-triage.md)
- [Untrusted XML parsing hardening](untrusted-xml-parsing-hardening.md)
