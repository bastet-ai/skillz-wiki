# Hyperledger Fabric SDK Java deserialization RCE (GHSA-prf8-cf2x-rhx7)

**Signal:** GitHub Security Advisory published **2026-04-29**. `fabric-sdk-java` uses `ObjectInputStream.readObject()` without an `ObjectInputFilter`, enabling Java deserialization remote code execution.

## What it is
The deprecated Hyperledger Fabric Java SDK can deserialize untrusted data without a class filter. If attacker-controlled serialized objects reach the affected code path, gadget chains in the application classpath can turn deserialization into code execution.

Affected package:

- Maven: `org.hyperledger.fabric-sdk-java:fabric-sdk-java`
- Vulnerable range: `>= 1.0.0, <= 2.2.26`
- Severity: critical
- Advisory CVE: `CVE-2026-41586`

References:

- <https://github.com/advisories/GHSA-prf8-cf2x-rhx7>
- <https://github.com/hyperledger/fabric/security/advisories/GHSA-prf8-cf2x-rhx7>

## Triage
1. Search JVM dependency manifests for `fabric-sdk-java`.
2. Prioritize services that accept Fabric transaction, event, enrollment, or channel data from networks or tenants you do not fully trust.
3. Inventory classpath gadget exposure: legacy commons collections, Groovy, Spring, Xalan, Rome, and application-specific `readObject` classes.
4. Check whether the process has signing keys, enrollment credentials, wallet material, database access, or chaincode deployment rights.

## Mitigation
- Migrate to the supported Fabric Gateway client where possible; the advisory lists no patched `fabric-sdk-java` version.
- If migration cannot happen immediately, isolate the SDK process and apply a restrictive JEP 290 `ObjectInputFilter` allowlist.
- Remove unnecessary gadget-prone dependencies from the classpath.
- Run Fabric client components with least privilege and separate wallet/key material from parsing surfaces.
- Block direct untrusted network access to SDK-facing endpoints.

## Detection ideas
- Hunt for serialized Java stream magic bytes (`AC ED 00 05`) in HTTP, queue, or peer-facing logs.
- Alert on SDK processes spawning shells, loading unexpected classes, opening reverse connections, or reading wallet/key files outside normal workflows.
- Review recent crashes with `InvalidClassException`, `ClassNotFoundException`, or deserialization stack traces around `ObjectInputStream.readObject`.

## Durable lesson
Deprecated SDKs do not become safe just because the system they talk to is permissioned. Any Java deserialization boundary needs an explicit class allowlist, isolation, and a migration plan.
