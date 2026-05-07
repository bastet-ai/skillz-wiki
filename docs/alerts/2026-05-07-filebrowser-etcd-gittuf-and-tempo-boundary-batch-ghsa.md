# FileBrowser, etcd, gittuf, and Tempo boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** batch where public file shares, datastore transactions, signed policy history, and observability encryption all depended on boundary checks that should be explicit and testable.

## Advisories covered

- **FileBrowser public-share stored XSS through SVG without CSP** — [GHSA-mmpx-jh39-wrv6](https://github.com/advisories/GHSA-mmpx-jh39-wrv6)
- **FileBrowser public-share DELETE path traversal enabling unauthenticated arbitrary deletion** — [GHSA-fwj3-42wh-8673](https://github.com/advisories/GHSA-fwj3-42wh-8673)
- **etcd RBAC bypass through `PrevKv` / lease attachment in nested transaction `Put` requests** — [GHSA-x35m-3gp4-4fh5](https://github.com/advisories/GHSA-x35m-3gp4-4fh5)
- **gittuf policy rollback to older valid policy versions** — [GHSA-vxvc-cg7j-rwqj](https://github.com/advisories/GHSA-vxvc-cg7j-rwqj)
- **Grafana Tempo inadequate encryption strength** — [GHSA-ffqx-q65f-36jf](https://github.com/advisories/GHSA-ffqx-q65f-36jf)

## Why this is durable

These issues are different products but the same lesson: secondary actions need the same authorization and integrity checks as primary actions. Public-share delete APIs must stay rooted in the share, datastore transaction helpers must enforce RBAC on every nested side effect, policy histories need anti-rollback semantics, and telemetry stores should use cryptography strong enough for the data-retention window.

## Immediate triage

1. Patch FileBrowser, etcd, gittuf, and Grafana Tempo where deployed.
2. Audit FileBrowser public shares for unexpected deletes, SVG/script uploads, public-link abuse, and missing content-security policy headers.
3. Re-test etcd role boundaries with nested transactions that request previous values, attach leases, or combine allowed and denied operations.
4. Verify gittuf repositories reject older-but-valid policy metadata after policy rotation or delegation changes.
5. Review Tempo encryption settings, key length, rotation cadence, retention window, and who can read historical trace/object storage.

## Durable controls

- Bind every file operation to a canonical root and verify the resolved path after symlink, encoding, separator, and normalization handling.
- Apply datastore authorization to transaction-expanded operations, not only to the outer request type.
- Include monotonic versions, freshness checks, or transparency-log style state when validating signed policy metadata.
- Treat observability data as sensitive production data: encrypt strongly, rotate keys, limit readers, and test restore/decrypt paths.
