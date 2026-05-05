# uuid caller-provided buffer boundary check (GHSA-w5hq-g745-h8pq)

**Signal:** GitHub Security Advisories REST fallback surfaced **CVE-2026-41907 / GHSA-w5hq-g745-h8pq** for `uuid`: UUID v3, v5, and v6 could silently perform partial writes when callers supplied an undersized output buffer or out-of-range offset. GitHub also surfaced **GHSA-qmq6-f8pr-cx5x**, which was withdrawn as a duplicate of the same issue.

## Advisory details

- **Package:** npm `uuid`
- **Affected:** `>= 11.0.0, < 11.1.1`; `>= 12.0.0, < 12.0.1`; `>= 13.0.0, < 13.0.1`
- **Fixed:** `11.1.1`, `12.0.1`, `13.0.1`; upstream also references the v14.0.0 release line.
- **Impacted APIs:** UUID v3 / v5 name-based generation and UUID v6 when using caller-provided `buf` / `offset` output parameters.
- **Unaffected common path:** UUID v4 string-returning usage is not the primary concern here, and v4/v1/v7 already performed bounds checks in the reported comparison.
- **References:** <https://github.com/advisories/GHSA-w5hq-g745-h8pq>, <https://github.com/uuidjs/uuid/security/advisories/GHSA-w5hq-g745-h8pq>, <https://github.com/uuidjs/uuid/commit/3d2c5b0342f0fcb52a5ac681c3d47c13e7444b34>

## Why this is durable

Caller-provided output buffers are a trust boundary. If an API accepts both a destination buffer and an offset, it must either prove the entire write fits or fail loudly before writing. Silent partial writes are dangerous because downstream code may treat stale, truncated, or mixed bytes as a complete identifier.

For UUIDs, the direct bug is moderate, but the pattern is reusable: identifier generation, binary encoders, token builders, parsers, and crypto-adjacent helpers often expose “write into this buffer” fast paths. Those paths need the same validation as higher-level string-returning APIs.

## Immediate triage

1. **Upgrade `uuid`** to a patched line: `11.1.1`, `12.0.1`, `13.0.1`, or a later major release.
2. Search for `v3(`, `v5(`, or `v6(` calls that pass a second/third buffer or offset argument, especially in serialization, storage-key, cache-key, binary-protocol, or ID-normalization code.
3. Treat attacker-influenced buffer length or offset as security-sensitive. If external input can influence either value, prioritize the finding above routine dependency hygiene.
4. Recheck tests that only assert “no exception.” Add assertions that the full 16-byte output is written, the returned buffer is expected, and invalid ranges throw before mutation.
5. Ignore withdrawn duplicate **GHSA-qmq6-f8pr-cx5x** for patch tracking, but keep it in advisory matching so scanners that report the duplicate still route to the canonical fix.

## Hunt ideas

- Grep JavaScript/TypeScript for `uuid` imports plus calls shaped like `v3(name, namespace, buf`, `v5(name, namespace, buf`, or `v6(options, buf`.
- In binary protocols, inspect records where UUID fields have unexpected zeroes, stale prefix/suffix bytes, inconsistent version bits, or partially repeated IDs.
- Add dependency-policy checks that fail if both `uuid < 11.1.1` and buffer-output UUID APIs are present in the same package.
- Fuzz buffer-output helpers with offsets `-1`, `0`, `len - 15`, `len - 8`, `len`, and oversized values, then assert invalid ranges throw without partial mutation.

## Durable controls

- Validate `offset >= 0` and `offset + 16 <= buf.length` before any UUID byte write.
- Prefer APIs that return fresh immutable values unless performance profiling proves caller-provided buffers are necessary.
- Make partial-write behavior impossible in wrappers: either return a complete value or throw before mutating the destination.
- Use property-based tests for encoder and identifier helpers to verify bounds checks, no-write-on-error behavior, and consistency across API variants.
- Track withdrawn/duplicate advisories separately from canonical advisories so duplicate scanner output does not hide the real patch range.

## Operator lesson

Fast-path buffer APIs should be audited like parsers: the caller controls memory shape, the callee controls trust in the resulting bytes, and partial success is usually a bug. Complete write or clean failure—nothing in between.
