# Active Record YAML serialized-column RCE

Source: GitHub Security Advisory REST fallback updated 2026-05-11.

This advisory is durable because it is the classic deserialization boundary in a web-app shape defenders still miss: database content is treated as trusted application object state. If an attacker can write a YAML-backed serialized column — often through SQL injection, unsafe admin imports, compromised integration tokens, or a lower-privileged data-write path — Active Record can deserialize that database value into Ruby objects and turn a data-write primitive into remote code execution.

## Advisory covered

- **Active Record RCE bug with serialized columns** — [GHSA-3hhc-qp5v-9p2j](https://github.com/advisories/GHSA-3hhc-qp5v-9p2j), CVE-2022-32224: RubyGems `activerecord` used `YAML.unsafe_load` for YAML serialized columns. Affected Rails / Active Record lines are `<=5.2.8`, `>=6.0.0,<=6.0.5`, `>=6.1.0,<=6.1.6`, and `>=7.0.0,<=7.0.3`; patched versions are `5.2.8.1`, `6.0.5.1`, `6.1.6.1`, and `7.0.3.1`. JSON and other non-YAML coders are not impacted by this specific bug.

## Operator triage

1. Patch Rails / Active Record to a fixed version for every supported branch, and prioritize internet-facing apps with any known SQL injection, import, bulk-edit, webhook, or admin data-write surface.
2. Inventory models that use `serialize` or YAML-backed custom types. Treat every serialized column as a code-adjacent sink until the coder and framework version are proven safe.
3. Search logs and database history for suspicious YAML object tags such as `!ruby/object`, `!ruby/hash`, `Gem::`, `ERB`, `ActiveSupport`, or unusually large serialized blobs in fields that should contain simple data.
4. If attacker-written serialized data is plausible, rotate application secrets, review background-job queues and caches that may have loaded the objects, and preserve database snapshots before cleanup.
5. Prefer migrating legacy YAML serialized columns to JSON or typed columns. Do this with a controlled migration that validates expected primitive shapes before rewriting data.

## Durable controls

- Database rows are not inherently trusted. Any field that can be influenced through SQLi, import, integration sync, support tooling, or admin workflow must be treated as attacker-controlled on read.
- Object-graph serializers (`YAML.unsafe_load`, Ruby Marshal, PHP `unserialize()`, Python pickle, Java object streams) are not interchangeable with data formats. Use JSON/schema data or explicit typed columns for application state.
- Deserialization fixes must be paired with write-path review: patching the reader prevents gadget execution, but the same upstream injection or import flaw can still corrupt authorization, workflow, or billing state.
- Monitoring should alert on object tags in columns expected to hold primitive YAML/JSON and on application exceptions raised during deserialization, because failed gadget probes are often visible before successful exploitation.

## Related Wisdom

- [Python pickle: never deserialize untrusted data](../best-practices/python-pickle-untrusted-deserialization.md)
- [Identity, build command, and deserialization-boundary batch](2026-05-11-identity-build-command-and-deserialization-boundary-batch-ghsa.md)
