# OpenClaw, ShellHub, and cloud tenant-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where device pairing, webhook replay, group-DM classification, tenant objects, and cloud/database permissions crossed account boundaries.

## Advisories covered

- **OpenClaw node, device, channel, and gateway boundary issues** — [GHSA-xj9w-5r6q-x6v4](https://github.com/advisories/GHSA-xj9w-5r6q-x6v4), [GHSA-rfqg-qgf8-xr9x](https://github.com/advisories/GHSA-rfqg-qgf8-xr9x), [GHSA-37v6-fxx8-xjmx](https://github.com/advisories/GHSA-37v6-fxx8-xjmx), [GHSA-rvvf-6vh3-9j43](https://github.com/advisories/GHSA-rvvf-6vh3-9j43), [GHSA-mhr7-2xmv-4c4q](https://github.com/advisories/GHSA-mhr7-2xmv-4c4q), [GHSA-wwfp-w96m-c6x8](https://github.com/advisories/GHSA-wwfp-w96m-c6x8), [GHSA-qcc3-jqwp-5vh2](https://github.com/advisories/GHSA-qcc3-jqwp-5vh2), [GHSA-6336-qqw9-v6x6](https://github.com/advisories/GHSA-6336-qqw9-v6x6), [GHSA-2f7j-rp58-mr42](https://github.com/advisories/GHSA-2f7j-rp58-mr42), [GHSA-89r3-6x4j-v7wf](https://github.com/advisories/GHSA-89r3-6x4j-v7wf), [GHSA-hr8g-2q7x-3f4w](https://github.com/advisories/GHSA-hr8g-2q7x-3f4w), [GHSA-6p8r-6m93-557f](https://github.com/advisories/GHSA-6p8r-6m93-557f): device tokens, node scopes, replay checks, channel allowlists, browser-origin validation, pairing caps, pre-auth budgets, hello snapshots, and shared rate limits need account-bound enforcement.
- **ShellHub cross-tenant IDORs** — [GHSA-9w9c-9w8m-w89q](https://github.com/advisories/GHSA-9w9c-9w8m-w89q), [GHSA-j72x-xfwg-783f](https://github.com/advisories/GHSA-j72x-xfwg-783f): session and device APIs could disclose objects from another namespace when UID access was not tenant-bound.
- **AWS Advanced Go Wrapper Aurora PostgreSQL privilege escalation** — [GHSA-7wq2-32h4-9hc9](https://github.com/advisories/GHSA-7wq2-32h4-9hc9): database wrapper behavior can become a cloud privilege boundary.

## Why this is durable

Multi-tenant systems fail when identity is checked at login but not re-bound at every object, callback, websocket, and helper endpoint. Device tokens, group-DM state, replay signatures, and namespace UIDs are all bearer-like authorities unless scoped and revalidated.

## Immediate triage

1. Patch OpenClaw, ShellHub, AWS Advanced Go Wrapper, and related integrations where deployed.
2. Rotate device tokens and ensure active WebSocket sessions terminate immediately after credential rotation.
3. Re-test every API object lookup by UID with a token from a different tenant/namespace/account.
4. Enforce replay detection over canonical signature bytes, not alternate encodings, and apply pre-auth concurrency budgets before body parsing.
5. Remove host/path state, config paths, and control-interface metadata from non-admin hello or discovery snapshots.

## Durable controls

- Require account, tenant, channel, device, node-scope, and session binding on every callback and websocket frame.
- Key rate limits and pending-pairing caps by account plus source, not only by channel or token string.
- Treat group DMs and component/slash interactions as separate policy surfaces; never infer “direct message” from weak channel metadata.
- Build IDOR tests that enumerate object IDs across tenants for sessions, devices, backups, screenshots, and control-plane metadata.
