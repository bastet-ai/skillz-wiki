# Contrast, pgx, copilot-api, and verl execution-boundary batch (GHSA-rh99-wc69-c255 / GHSA-j88v-2chj-qfwx / GHSA-3vr4-cvmg-7fx4 / GHSA-h57c-v2v3-5v3v)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Four advisories highlight execution-boundary mistakes: symlink policy bypass in confidential-container file copy, SQL placeholder parsing confusion, reverse-DNS trust, and unsafe `eval()` in grading code.

## What it is
- `GHSA-rh99-wc69-c255`: Contrast CLI generated Kata agent policies with weak `CopyFile` verification, allowing host-side processes that can reach the Kata agent VSOCK to write arbitrary guest-root files through symlink tricks. Fixed in `github.com/edgelesssys/contrast` `1.19.1`.
- `GHSA-j88v-2chj-qfwx`: Go `pgx` simple protocol can mishandle placeholders inside PostgreSQL dollar-quoted string literals, enabling SQL injection in a narrow but real query shape. Fixed in `github.com/jackc/pgx/v5` `5.9.2`; older major lines have no listed patch.
- `GHSA-3vr4-cvmg-7fx4`: npm `copilot-api` through `0.7.0` relies on reverse DNS / Host header behavior for a security-critical token action; exploit is public and no patch is listed.
- `GHSA-h57c-v2v3-5v3v`: pip `verl` through `0.7.1` uses unsafe `eval()` in `math_equal()` grading code, allowing difficult but public remote code execution paths when attacker-controlled expressions are graded; no patch is listed.

References:

- <https://github.com/advisories/GHSA-rh99-wc69-c255>
- <https://github.com/advisories/GHSA-j88v-2chj-qfwx>
- <https://github.com/advisories/GHSA-3vr4-cvmg-7fx4>
- <https://github.com/advisories/GHSA-h57c-v2v3-5v3v>

## Triage
1. For Contrast, identify workloads where host-side components, orchestrators, or privileged helpers can connect to the Kata agent VSOCK.
2. For pgx, search for `QueryExecModeSimpleProtocol` and SQL strings that contain dollar-quoted literals plus attacker-controlled placeholders.
3. For copilot-api, inspect `/token` exposure and any logic that trusts `Host`, PTR, or reverse-DNS-derived identity.
4. For verl, find grading/evaluation paths where user, model, dataset, or benchmark output reaches `math_equal()`.

## Mitigation
- Upgrade Contrast to `1.19.1+` and pgx v5 to `5.9.2+`; migrate away from unsupported pgx v3/v4 where possible.
- Deny host-to-guest agent channels except from explicitly trusted components; canonicalize paths after symlink resolution and use `openat`/no-follow style controls for file-copy operations.
- Prefer pgx's extended protocol; avoid mixing attacker-controlled values with dollar-quoted SQL literals.
- Do not authorize token issuance or privileged behavior based on reverse DNS or the HTTP `Host` header.
- Replace `eval()`-based graders with parsed AST / symbolic comparison in a locked-down worker with CPU, memory, and filesystem limits.

## Detection ideas
- Contrast: alert on unexpected `CopyFile` calls, symlink-heavy paths, writes to `/etc`, startup scripts, credentials, or workload binaries.
- pgx: grep code and query logs for dollar-quoted strings containing `$1`, `$2`, etc. alongside simple protocol execution.
- copilot-api: hunt token requests with unusual `Host` headers, spoofed PTR expectations, or direct IP access.
- verl: monitor grading workers for shell/process spawns, network access, file reads outside dataset directories, or suspicious math expressions.

## Durable lesson
Execution boundaries fail when strings carry authority: paths, SQL, DNS names, and math expressions all need structural validation. Canonicalize before authorization, bind identities to cryptographic or configured trust anchors, and never run attacker-controlled text through an interpreter in the main process.
