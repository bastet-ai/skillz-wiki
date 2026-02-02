# 2026-02-02 — picklescan: arbitrary file create via unsafe pickle deserialization (GHSA-m7j5-r2p5-c39r)

## Summary

A GitHub Security Advisory reports that **picklescan** is vulnerable to **arbitrary file creation** due to unsafe Python **pickle deserialization**.

The write primitive can be achieved by chaining standard library gadgets like `logging.FileHandler`, which can create **zero-byte files** at attacker-chosen paths (and may be chainable with other behaviors in real systems).

- Advisory: https://github.com/advisories/GHSA-m7j5-r2p5-c39r

## What to do (durable guidance)

1. **Assume pickle == code execution surface**
   - Do not deserialize pickle from any untrusted source.

2. **Do not rely on blocklists**
   - “RCE keyword filtering” is routinely bypassed (this report is a concrete example).

3. **Replace serialization format**
   - Prefer JSON/MessagePack/Protobuf with schema validation.

4. **If you must keep it, isolate it**
   - Run deserialization in a sandboxed process/container with:
     - read-only FS where possible
     - no network egress
     - least privilege
     - strong input authentication (signature/HMAC)

## Related Wisdom

- [Python pickle: never deserialize untrusted data](../best-practices/python-pickle-untrusted-deserialization.md)
