# Sharp generic-download storage-object boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entry: GitHub advisory [GHSA-748w-hm6r-qc7v](https://github.com/advisories/GHSA-748w-hm6r-qc7v) / CVE-2026-44692 for `code16/sharp < 9.22.0`, where authenticated Sharp users can download unrelated Laravel Storage objects through the generic download endpoint.

This advisory is durable for operators because it exposes a reusable bug-hunting question: **does an admin helper authorize access to one entity, then trust caller-controlled storage selectors for a different object?**

## Why it matters for assessments

Sharp's generic download flow can sit behind otherwise legitimate admin permissions. The advisory describes a route that authorizes the user's access to a supplied Sharp entity instance, but then reads the target storage `disk` and `path` from request parameters. If the requested storage object is not cryptographically or server-side bound to the authorized entity, a user who can view one valid record may use that record as an authorization anchor for unrelated objects on configured Laravel Storage disks.

The useful finding is not "Laravel Storage exists" or "an admin can download a file." The useful finding is an object-binding mismatch:

```text
authenticated Sharp user -> viewable entity instance -> generic download endpoint -> unrelated disk/path object
```

The advisory scope is configured Laravel Storage disks. Do not inflate the finding into arbitrary host filesystem read unless the assessed application independently exposes host paths through its configured disks.

## What to map first

1. Confirm authorization for lab, staging, or customer-approved validation.
2. Identify the Sharp version and whether `code16/sharp < 9.22.0` is reachable.
3. Locate the generic download route:

   ```text
   GET /sharp/{globalFilter}/download/{entityKey}/{instanceId?}
   ```

4. Determine the minimum account role that can view at least one benign Sharp entity instance.
5. Inventory only approved, non-sensitive storage disks and create a canary object that is not attached to the authorized entity.
6. Capture redacted requests and a canary response only. Never download backups, invoices, other users' uploads, `.env` files, logs, credentials, or production private documents.

## Safe validation pattern

1. Log in as a low-privilege Sharp user with view access to one harmless entity instance, such as a test customer, product, ticket, or invoice created for the assessment.
2. Generate or capture a legitimate download URL for that entity if the workflow provides one.
3. Place a canary object such as `skillz-sharp-download-canary.txt` on an approved Laravel Storage disk that is reachable by Sharp downloads but not associated with the authorized entity.
4. Modify only the request parameters that select the target object, such as `disk` and `path`, while keeping the entity authorization anchor unchanged.
5. Send one request and record whether the unrelated canary object is returned.
6. If a patched build is available, repeat the same modified request and confirm that the missing or invalid signature is rejected.

Evidence table:

| Test user | Authorized entity | Requested disk/path | Object bound to entity? | Result |
| --- | --- | --- | --- | --- |
| low-priv Sharp user | `invoice:123` | `private/skillz-sharp-download-canary.txt` | no | returned/rejected |

## Evidence to capture

Strong reports include:

- exact `code16/sharp` version and application route shape;
- user role and the entity instance the user is legitimately allowed to view;
- the original versus modified download parameters, with unrelated object paths redacted to canary names;
- response metadata proving the canary object came from a different storage object;
- a statement that no production secrets, customer files, or unrelated private objects were accessed.

## Reporting heuristics

- Lead with **entity authorization anchor does not bind the downloaded storage object**.
- State whether the modified request changed `disk`, `path`, `entityKey`, or `instanceId`.
- Avoid broad filesystem-read claims unless the configured disk root itself is the host filesystem and that scope was explicitly tested with a synthetic canary.
- If the only proof is that an admin can download a file attached to the same entity, do not report it as this issue.
- If a patched deployment rejects modified parameters because the URL signature no longer validates, record it as negative evidence rather than forcing variants.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub security blog, CISA KEV, and GitHub advisory published/updated feeds. Spring Cloud Config path traversal and Google Secret Manager project-boundary updates were already covered in the existing [Config, OT, and web-admin boundary batch](2026-05-11-config-ot-and-web-admin-boundary-batch-ghsa.md). Previously promoted MCP/codegen/redirect/router/PDM, Guzzle, Netty, Undertow, and Dulwich advisories were also present in the feeds. Updated Tomcat/proxy/ImageMagick/OpenEXR/MaterialX/libp2p/Weblate/wangEditor/Survey Creator items were tracked but not promoted because the refreshed advisory text was either availability-oriented, already covered, or lacked a clearer offensive validation boundary than canary object access.
