# Mistune Markdown parser resource-boundary batch

**Sources:** GitHub Security Advisories published 2026-05-06 16:52-16:57 UTC.

## Why this matters

Markdown is often treated as safe text. These Mistune advisories show why untrusted markup is parser input with real CPU-budget risk: tiny link-title payloads can force pathological parsing and make web apps, docs systems, notebooks, or APIs unavailable.

## Advisory summary

| Advisory | Component | Issue | Fixed version |
|---|---|---|---|
| [GHSA-hjph-f4mc-wx4c](https://github.com/advisories/GHSA-hjph-f4mc-wx4c) / CVE-2026-33441 | `mistune` | Crafted reference links can cause excessive parsing in `parse_link_title()` and hang the process. | 3.2.1 |
| [GHSA-8mp2-v27r-99xp](https://github.com/advisories/GHSA-8mp2-v27r-99xp) / CVE-2026-33079 | `mistune` | `LINK_TITLE_RE` has overlapping alternatives around escaped punctuation, creating exponential ReDoS on small crafted link titles. | No patched version listed in GitHub metadata; monitor upstream and avoid 3.0.0a1-3.2.0 in exposed paths. |

## Triage now

- Inventory services that parse user-supplied Markdown with Mistune: comments, issue trackers, CMS fields, documentation previews, notebooks, import pipelines, and API render endpoints.
- Upgrade affected Mistune 3.2.0 deployments to 3.2.1+ for CVE-2026-33441 and watch upstream for the ReDoS fix covering the broader 3.0.0a1-3.2.0 range.
- Add request size and parse-time limits around Markdown rendering even after patching.
- If Markdown rendering is synchronous on request threads, move it behind a worker with a hard timeout and killable process boundary.

## Hunt prompts

- Look for repeated Markdown submissions containing unterminated link titles, many escaped punctuation pairs such as `\\!`, or reference-link definitions with long malformed title segments.
- Correlate high CPU workers with endpoints that render previews, comments, descriptions, notebook cells, or docs imports.
- Review application logs for parse timeouts, worker restarts, gateway 502/504 spikes, and increased queue latency after small Markdown payloads.

## Durable controls

- Treat markup parsers like file parsers: fuzz them, bound them, and isolate them.
- Prefer parser implementations with explicit recursion, token, and backtracking limits.
- Put regexes that process attacker-controlled text through ReDoS review; avoid overlapping alternatives inside repeated groups.
- Add regression tests using minimal worst-case payloads and enforce CPU-time budgets in CI.
