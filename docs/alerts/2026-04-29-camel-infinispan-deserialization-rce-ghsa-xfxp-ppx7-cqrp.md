# Apache Camel Infinispan ProtoStream deserialization RCE (GHSA-xfxp-ppx7-cqrp)

**Signal:** GitHub Security Advisories updated **2026-04-29**. `camel-infinispan` fixed unsafe deserialization in the ProtoStream remote aggregation repository.

## What it is
A remote low-privileged attacker can send crafted data to `camel-infinispan` deployments using the vulnerable ProtoStream remote aggregation repository and trigger unsafe deserialization, leading to arbitrary code execution.

Affected package: Maven `org.apache.camel:camel-infinispan < 4.20.0`. Fixed version: `4.20.0`.

Reference: <https://github.com/advisories/GHSA-xfxp-ppx7-cqrp>

## Triage
1. Search Java dependency manifests and SBOMs for `org.apache.camel:camel-infinispan` below `4.20.0`.
2. Identify routes using Infinispan remote aggregation repositories or ProtoStream serialization.
3. Determine whether low-privileged users or external systems can write data into the affected cache/repository.
4. Review runtime permissions and network reachability of Camel workers connected to Infinispan.

## Mitigation
- Upgrade `camel-infinispan` to `4.20.0` or later.
- Restrict cache write access to trusted producers; segment aggregation repositories by trust boundary.
- Enforce allowlisted serialization types and reject unexpected classes/schemas.
- Run integration workers with least privilege and constrained network egress to reduce RCE blast radius.

## Detection ideas
- Review Infinispan cache entries and write audit logs for unexpected serialized payloads or schema changes.
- Hunt for Camel worker process children, classloading anomalies, reverse shells, or outbound connections after cache writes.
- Alert on low-privileged principals writing to aggregation caches they normally only read from.

## Durable lesson
Integration middleware often turns message data into code-adjacent state. Treat remote aggregation caches as deserialization boundaries and protect them like RPC endpoints.
