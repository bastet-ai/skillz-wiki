# Mongoose `sanitizeFilter` NoSQL-boundary bypass

**Signal:** The **2026-05-11 10:15 UTC** advisory scan found [GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h) / CVE-2026-42334: Mongoose did not recursively sanitize `$nor` clauses when `sanitizeFilter` was enabled.

## Advisory summary

Mongoose `sanitizeFilter` is meant to wrap query operators in `$eq` so user-controlled filters cannot smuggle selectors such as `$ne`, `$gt`, or `$regex` into application queries. The fixed advisory notes that affected releases skipped recursive sanitization for `$nor`. Because `$nor` accepts an array like `$and` and `$or`, malicious operators could survive inside `$nor` filters when an application passed raw request-controlled objects into query methods.

Affected npm `mongoose` ranges:

- `< 6.13.9`
- `>= 7.0.0, <= 7.8.8`
- `>= 8.0.0, <= 8.22.0`
- `>= 9.0.0, <= 9.1.5`

Fixed releases are `6.13.9`, `7.8.9`, `8.22.1`, and `9.1.6`.

## Why this matters

`sanitizeFilter` is a guardrail, not a schema. It reduces accidental operator injection, but it should not be the only boundary between HTTP JSON and database query grammar. The risky pattern is direct filter handoff, for example `Model.findOne(req.body)`, especially in login, lookup, search, tenant-scoped list, or admin-filter endpoints.

The safer pattern builds the query from explicit fields, for example `Model.findOne({ user: req.body.user, pwd: req.body.pwd })`, then validates types and allowed operators before the query reaches Mongoose.

## Triage

1. Patch `mongoose` to the fixed release for the deployed major line: `6.13.9`, `7.8.9`, `8.22.1`, or `9.1.6`.
2. Search code for `sanitizeFilter`, `mongoose.set('sanitizeFilter'`, and request-body filter handoff patterns such as `find(req.body)`, `findOne(req.body)`, `findOneAndUpdate(req.body`, `countDocuments(req.body)`, and helper wrappers around those calls.
3. Prioritize endpoints where a NoSQL selector bypass changes security decisions: authentication, password reset, API-token lookup, account lookup, tenant selection, role/admin filtering, and object ownership checks.
4. Review access logs and application telemetry for `$nor`, `$ne`, `$gt`, `$regex`, `$where`, or nested dollar-prefixed keys in JSON request bodies or query-string filter parameters.
5. If authentication or authorization filters accepted raw request objects, invalidate active sessions or tokens for affected tenants/users after patching and log review.

## Durable controls

- Treat MongoDB operators as query-language syntax. Only allow them through explicit server-owned filter builders.
- Validate request bodies with a schema library before constructing database filters; reject unknown keys and dollar-prefixed keys by default.
- Use field allowlists for user-search and admin-filter APIs. Map public filter names to internal database fields instead of accepting arbitrary object trees.
- Keep `sanitizeFilter` enabled as defense-in-depth, but do not rely on it as the primary NoSQL-injection control.
- Add regression tests with nested `$nor` payloads containing `$ne`, `$gt`, and `$regex` under each endpoint that accepts structured filters.

## References

- [GitHub Advisory GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h)
- [Mongoose `sanitizeFilter` documentation](https://mongoosejs.com/docs/api/mongoose.html#Mongoose.prototype.sanitizeFilter())
- [Original Mongoose sanitizeFilter background](https://thecodebarbarian.com/whats-new-in-mongoose-6-sanitizefilter.html)
