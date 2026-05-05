# Storage, admin, session, and data-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because storage and admin planes repeatedly fail when path, action, namespace, session, or deletion semantics are inferred instead of checked directly at the boundary.

## Advisories covered

- **RustFS ListServiceAccount** — [GHSA-mm2q-qcmx-gw4w](https://github.com/advisories/GHSA-mm2q-qcmx-gw4w): wrong admin-action authorization can allow cross-user enumeration and root service-account takeover.
- **django-s3file** — [GHSA-67qg-7284-2277](https://github.com/advisories/GHSA-67qg-7284-2277): relative path traversal.
- **MinIO `ReadMultiple` storage-REST endpoint** — [GHSA-xh8f-g2qw-gcm7](https://github.com/advisories/GHSA-xh8f-g2qw-gcm7): path traversal through msgpack request bodies.
- **OpenBao namespace deletion** — [GHSA-vv66-6rp4-wr4f](https://github.com/advisories/GHSA-vv66-6rp4-wr4f): namespace deletion may not delete data properly.
- **Magento LTS API session IDs** — [GHSA-2cwr-gcf9-pvxr](https://github.com/advisories/GHSA-2cwr-gcf9-pvxr): weak API session IDs generated from predictable MD5 time-derived inputs.

## Operator triage

1. For object-storage gateways and file wrappers, test `../`, encoded separators, duplicate slashes, Unicode normalization, archive-like path components, and structured-body path fields.
2. For admin APIs, verify the exact action checked matches the operation performed, especially account listing, service-account management, impersonation, and root/admin transitions.
3. Rotate API sessions and tokens if predictable session generation could have overlapped with exposed timestamps, logs, or traffic captures.
4. For OpenBao/Vault-like namespaces, verify deletion with direct backend inspection, not only API/UI absence.
5. Hunt logs for access to unexpected object keys, storage-REST methods, service-account enumeration, and namespace delete/recreate sequences.

## Durable controls

- Authorization checks should bind `{subject, action, resource}` explicitly; similar admin actions are not interchangeable.
- Canonical paths must be derived after decoding all structured body fields, not only URL path components.
- Session IDs need CSPRNG entropy and should never be time-derived or predictably hashed.
- Delete operations in secret stores need tombstone/garbage-collection verification and tests that prove data is gone from every backing path.
- Storage APIs should log canonical resource identity alongside raw requested identity for detection and forensic review.
