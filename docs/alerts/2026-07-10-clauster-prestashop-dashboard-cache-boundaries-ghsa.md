---
title: Clauster dashboard and PrestaShop faceted-search cache boundary checks from the July 10 GHSA wave
---

# Clauster dashboard and PrestaShop faceted-search cache boundary checks

This late July 10 GHSA update promotes two operator-useful boundaries: developer/agent dashboards that validate “a password exists” but do not enforce authentication on non-loopback binds, and e-commerce filter parameters that cross from front-office URL state into a serialized cache and then native PHP deserialization.

Sources:

- [GHSA-h4g2-xfmw-q2c9: Clauster non-loopback dashboard deployments can be unauthenticated when `auth.enabled` is unset](https://github.com/advisories/GHSA-h4g2-xfmw-q2c9)
- [GHSA-m5f5-28qr-9g9r / CVE-2026-54159: `prestashop/ps_facetedsearch` slider-filter cache PHP object injection](https://github.com/advisories/GHSA-m5f5-28qr-9g9r)

!!! warning "Authorized validation only"
    Keep proofs to disposable Clauster and PrestaShop labs, synthetic project directories, fake Claude Code bridge projects, disposable storefront categories, marker-only slider values, and inert cache/deserialization canaries. Do not expose real developer workspaces, edit production `CLAUDE.md`, start agent bridges against live repositories, write web shells, execute system commands, process real orders, or touch customer data.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-h4g2-xfmw-q2c9](https://github.com/advisories/GHSA-h4g2-xfmw-q2c9) | Clauster dashboard/API | Non-loopback bind plus password/reverse-proxy settings can start with `auth.enabled=false`, so the runtime guard serves dashboard APIs unauthenticated | Add config-vs-runtime auth enforcement checks to agent/developer dashboard exposure reviews. |
| [GHSA-m5f5-28qr-9g9r](https://github.com/advisories/GHSA-m5f5-28qr-9g9r) | PrestaShop `ps_facetedsearch` | Front-office price/weight slider URL values enter a filter-block cache and are later read with native `unserialize()` | Test e-commerce faceted-search modules for request-parameter-to-cache-to-deserialization chains. |

## Clauster non-loopback dashboard auth enforcement

Use this when a scope includes Clauster, Claude Code remote-control dashboards, or similar local-agent orchestration panels that may be Docker-published or LAN-bound.

1. Confirm the instance is in scope and whether the dashboard listens on loopback only, a LAN address, or `0.0.0.0`. Loopback-only developer use is a different trust model.
2. Inspect only authorized config evidence: `host`, `auth.enabled`, `auth.password_required`, `auth.reverse_proxy.enabled`, and any explicit unauthenticated-network opt-out. A password hash by itself is not proof that requests are guarded.
3. From an approved network location, request harmless read-only API routes such as the instance list without credentials.
4. Positive evidence is a decision table where a non-loopback listener with password/reverse-proxy settings still returns dashboard/API data unauthenticated, while `auth.enabled: true` returns `401` in the same lab.
5. If bridge actions are in scope, prove control only with a synthetic project directory and an inert marker command/log entry. Do not run Claude Code bridges against real repositories or alter real project instructions.

Report as **non-loopback agent dashboard -> config validator accepts password intent -> runtime auth guard disabled -> unauthenticated project/bridge control**. Include listener address, deployment mode, exact auth flags, route/status table, and a patched/negative control.

## PrestaShop faceted-search slider cache deserialization

Use this for authorized PrestaShop storefront tests where `ps_facetedsearch` exposes price or weight slider filters.

1. Build or request a disposable storefront with `ps_facetedsearch`, a category/search page that displays slider filters, and no real customer data.
2. Identify the front-office URL parameters that represent price or weight slider state. Record only route, module version, filter template, and whether the vulnerable slider is rendered.
3. Send benign malformed slider values that can be traced into the faceted-search cache without carrying a working gadget chain. Prefer marker strings and local instrumentation around `src/Filters/Block.php`.
4. Positive evidence is the marker value entering the serialized filter-block cache and reaching the native `unserialize()` read path. In an approved lab, an inert PHP object with a non-dangerous magic-method marker is enough; do not write PHP files or command payloads.
5. Add controls: a non-slider filter, a patched module using safe unserialization, and a cache clear/rebuild path that proves the sink is specific to cached slider state.

Report as **front-office slider parameter -> filter-block cache serialization -> native PHP `unserialize()` -> gadget/write precondition**. Keep exploitability statements tied to the lab evidence; do not publish a gadget chain, web-shell path, or command-execution payload.

## Reporting notes

Lead with the trust boundary rather than the headline severity:

- **Dashboard bind/config drift:** network reachability, intended auth mode, runtime guard flag, unauthenticated route evidence, and safe bridge-control canary.
- **Search cache deserialization:** exposed filter type, parameter source, cache key/value path, deserialization call site, marker-only sink evidence, and patched negative control.

Sensitive data to omit: real project names, repository paths, prompt logs, Claude Code transcripts, PrestaShop customer/order IDs, cache rows from production, module filesystem paths that identify tenants, and any executable payload material.
