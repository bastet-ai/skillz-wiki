# 2026-02-04 — Apollo Server standalone (`startStandaloneServer`) DoS via exotic encodings (GHSA-mp6q-xf9x-fwf7)

**Signal:** GitHub Security Advisory published 2026-02-04.

**Impact (per advisory):** The default configuration of `startStandaloneServer` is vulnerable to **Denial of Service** through specially crafted request bodies using exotic character set encodings.

**Product:** Apollo Server
- npm package: `@apollo/server` (standalone server helper)
- legacy package: `apollo-server` (EOL)

## Why this matters
DoS on GraphQL endpoints is often easy to weaponize and can cause broad service disruption. This issue is notable because it can affect deployments that used the standalone helper “as-is”.

## Who is exposed
- **Direct users** of `startStandaloneServer` from `@apollo/server/standalone`.
- Not affected (per advisory): users running Apollo Server via integration packages (Express/Next/etc.) rather than the standalone helper.

## Fix
Upgrade:
- `@apollo/server` **5.4.0** or later (fixes v5)
- `@apollo/server` **4.13.0** or later (fixes v4)

Note: v2/v3 are EOL. Consider upgrading to v5.

## What changed (defensive takeaway)
Fixed versions reject non-standard JSON body encodings and only accept **UTF-8/16/32** (per RFC 7159). This reduces the attack surface for parser/decoder edge cases.

## Detection / hunt ideas
- Spikes in 4xx/5xx around requests with unusual `Content-Type` charset parameters.
- Elevated CPU/memory usage correlated with POSTs to GraphQL endpoints.

## References
- Advisory:
  - <https://github.com/apollographql/apollo-server/security/advisories/GHSA-mp6q-xf9x-fwf7>
- GitHub advisory database mirror:
  - <https://github.com/advisories/GHSA-mp6q-xf9x-fwf7>
