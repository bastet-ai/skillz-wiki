# Query-builder and management-plane execution boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** batch where helper APIs and web launcher controls crossed into database or shell execution: MixPHP Framework SQL injection through crafted builder arrays and PicoClaw Web Launcher command injection.

## Advisories covered

- **MixPHP Framework SQL injection via crafted `data` array** — [GHSA-q57j-rwwx-7rwp](https://github.com/advisories/GHSA-q57j-rwwx-7rwp) / [CVE-2026-42474](https://www.cve.org/CVERecord?id=CVE-2026-42474): MixPHP Framework `2.x` through `2.2.17` can build unsafe SQL from attacker-controlled `data` arrays in `BuildHelper.php`.
- **MixPHP Framework SQL injection via crafted `on` array** — [GHSA-vf35-8m4j-gm8v](https://github.com/advisories/GHSA-vf35-8m4j-gm8v) / [CVE-2026-42475](https://www.cve.org/CVERecord?id=CVE-2026-42475): the `joinOn` helper path can turn crafted join-condition arrays into SQL injection.
- **PicoClaw Web Launcher command injection** — [GHSA-6r3x-h84w-fhxx](https://github.com/advisories/GHSA-6r3x-h84w-fhxx) / [CVE-2026-6987](https://www.cve.org/CVERecord?id=CVE-2026-6987): PicoClaw up to `0.2.4` exposes a remotely reachable `/api/gateway/restart` management-plane path where manipulated input reaches command execution. No fixed version is listed.

## Why this is durable

All three issues hide dangerous sinks behind convenience helpers. A structured array is treated as “already safe” SQL intent, and a launcher API is treated as an administrative action rather than an attacker-controlled command boundary. The durable rule: helper APIs still need grammar-level validation and fixed execution contracts before touching SQL builders or process launchers.

## Immediate triage

1. Inventory MixPHP applications and identify endpoints that pass request-controlled arrays into query builder helpers, especially `data`, `on`, `joinOn`, or dynamic filter/sort/join parameters.
2. Add compensating validation for allowed column names, operators, table aliases, and join shapes; reject nested or raw-expression-like structures from clients.
3. Inspect database logs for unusual join predicates, stacked statements, comment markers, tautologies, or unexpected writes from MixPHP app users.
4. For PicoClaw, isolate Web Launcher management interfaces from the internet and untrusted networks immediately. If exposed, assume remote command execution is possible until remediated.
5. Review PicoClaw process, shell, restart, and gateway logs for unexpected command arguments, spawned shells, downloaded payloads, or persistence after `/api/gateway/restart` calls.

## Hunt prompts

- PHP request logs containing array-shaped query parameters near filter, join, relation, or table-management endpoints.
- SQL errors mentioning malformed joins or column expressions shortly before successful unusual queries.
- Management API calls to `/api/gateway/restart` from non-admin networks, browsers, scanners, or unauthenticated clients.
- Launcher child processes with shell metacharacters, unexpected environment variables, curl/wget/nc, reverse shell patterns, or modified startup scripts.

## Durable controls

- Model query-builder input as an AST with allowlisted node types; never accept client-supplied raw identifiers or operators without canonicalization.
- Bind values separately from identifiers, and validate identifiers against a server-side schema map.
- Keep restart/launcher endpoints behind strong auth, CSRF protection, mTLS or VPN, network allowlists, and detailed audit logs.
- Invoke management actions through fixed argv arrays, not shell strings; if dynamic values are required, constrain them to enumerated tokens.
- Add regression tests that feed malicious arrays and command metacharacters through the same helper paths used in production.
