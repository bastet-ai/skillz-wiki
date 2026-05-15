# Open WebUI feedback mass-assignment boundary

**Signal:** The **2026-05-15 06:15 UTC** advisory scan surfaced a medium-severity Open WebUI evaluation feedback flaw where authenticated users could submit server-owned fields through a permissive form model and rewrite attribution for feedback records.

## What changed

- **Open WebUI feedback `user_id` spoofing and evaluation data manipulation** — [GHSA-rjmp-vjf2-qf4g / CVE-2026-45396](https://github.com/advisories/GHSA-rjmp-vjf2-qf4g): `open-webui < 0.9.5`, fixed in `0.9.5`, accepted arbitrary extra fields in `FeedbackForm` and merged `form_data.model_dump()` after server-derived fields in feedback creation. Because later duplicate keys win in Python dict literals, a low-privilege authenticated user could supply `user_id`, `id`, or `version` and create feedback attributed to another user.

## Boundary lesson

Mass assignment is not only a Rails-era controller problem. Any request schema that preserves unknown fields becomes dangerous when those fields are later splatted or merged into persistence models. Server-owned identity, authorization, versioning, ownership, timestamps, and primary-key fields should be assigned after untrusted form data—or, better, never share a generic merge path with form data at all.

For model-evaluation systems, this becomes an integrity boundary: user feedback and Elo-style ranking inputs are security-relevant data because they can influence model routing, procurement decisions, benchmarks, or trust dashboards. Treat evaluation telemetry as authenticated, attributable audit data rather than harmless product analytics.

## Defender checklist

1. Upgrade Open WebUI to `0.9.5+` anywhere evaluation feedback endpoints are exposed.
2. Search application logs for authenticated `POST /api/v1/evaluations/feedback` bodies containing unexpected top-level fields such as `user_id`, `id`, or `version`.
3. Rebuild or quarantine evaluation leaderboards if low-privilege users could have submitted feedback before patching; do not rely on historical Elo scores without checking attribution integrity.
4. In code review, flag Pydantic models using `extra='allow'` when their `model_dump()` output flows into ORM constructors, dict merges, or update statements.
5. For every create/update path, assign server-controlled identity and ownership fields explicitly after untrusted data, or use allowlisted field mapping instead of `**form_data.model_dump()`.

## References

- [GitHub Advisory GHSA-rjmp-vjf2-qf4g](https://github.com/advisories/GHSA-rjmp-vjf2-qf4g)
