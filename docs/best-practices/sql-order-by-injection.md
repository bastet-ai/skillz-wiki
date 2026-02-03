# SQL injection via `ORDER BY` / identifier injection

Some SQL injection vulnerabilities don’t come from values in a `WHERE` clause — they come from **untrusted identifiers** (column names, directions) being concatenated into an `ORDER BY`, `GROUP BY`, `SELECT <columns>`, or `JOIN <table>` clause.

This is frequently exposed via API parameters like `sort`, `order`, `sortBy`, `direction`, `fields`, etc.

## Why parameterization doesn’t save you here

Prepared statements / parameterized queries protect **values**:

- ✅ `WHERE id = ?`
- ✅ `WHERE email = $1`

They **do not** protect SQL identifiers:

- ❌ `ORDER BY ?` (most drivers will treat this as a string literal, or reject it)
- ❌ concatenating `ORDER BY ${userInput}`

So the only safe approaches are **allowlisting and mapping**.

## Recommended defenses

### 1) Allowlist + map sort keys to known-safe SQL fragments

Treat the API `sort` key as a *logical field name*, not raw SQL.

Example mapping:

```js
const SORT_MAP = {
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  username: 'username',
  // for joins, map to a full, fixed fragment
  orgName: 'orgs.name'
};

const key = req.query.sort;
const col = SORT_MAP[key] ?? SORT_MAP.createdAt;

const dir = (req.query.direction || 'desc').toLowerCase();
const safeDir = dir === 'asc' ? 'ASC' : 'DESC';

sql = `SELECT ... FROM users ORDER BY ${col} ${safeDir} LIMIT ? OFFSET ?`;
```

Notes:

- Don’t allow arbitrary `col` values.
- Keep mapping values *static strings you control*.
- Default to a safe, indexed column.

### 2) If you need multi-sort, parse *tokens* and apply per-token allowlists

Accept `sort=createdAt,-username` or `sort=createdAt:desc,username:asc` and:

- split on commas
- validate token format strictly
- map each field to a known-safe fragment
- cap max sort keys (e.g., 2–3)

### 3) Reject any unknown characters early

If you do any parsing, enforce a tight regex for the logical key:

- `^[a-zA-Z][a-zA-Z0-9_]*$`

…and still map the key to a fixed fragment.

### 4) Beware “identifier injection” beyond ORDER BY

Apply the same mindset for:

- `SELECT ${fields}` (field projection)
- `GROUP BY ${group}`
- `JOIN ${table}` / dynamic table names
- dynamic function names (e.g., `DATE_TRUNC(${bucket})`)

If you must support dynamic selection, allowlist each supported item and build the query from those items.

## Detection / testing notes

- Look for endpoints with `sort`, `order`, `direction`, `fields`, `group`.
- Fuzz with payloads that break identifier contexts:
  - `sort=createdAt desc, (select 1)`
  - `sort=createdAt);--`
  - `sort=createdAt desc nulls last` (sometimes used to change semantics)
- Confirm by observing SQL errors, response ordering changes, or time-based payload effects (where supported).

## Trigger event

This guidance was prompted by real-world advisories where a REST API accepted a `sort` parameter that was concatenated into `ORDER BY` without allowlisting.
