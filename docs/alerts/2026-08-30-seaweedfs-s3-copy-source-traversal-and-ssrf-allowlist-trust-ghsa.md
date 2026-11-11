# SeaweedFS S3 copy-source traversal, Bifrost SSRF deny-list gaps, and phpSysInfo header trust…

**Date reviewed:** 2026-08-30
**Primary advisories:** [GHSA-56wq-x3wv-3ff4 / CVE-2026-55874](https://github.com/advisories/GHSA-56wq-x3wv-3ff4) (high, 7.7) and [GHSA-hgpf-8634-g44c / CVE-2026-55873](https://github.com/advisories/GHSA-hgpf-8634-g44c) (medium, 4.3), SeaweedFS S3 gateway; [GHSA-w98g-5w9p-p3rc / CVE-2026-55245](https://github.com/advisories/GHSA-w98g-5w9p-p3rc) (high), Bifrost gateway; [GHSA-786w-p5pm-cvgh / CVE-2026-55584](https://github.com/advisories/GHSA-786w-p5pm-cvgh) (high, 7.5), phpSysInfo.
**Boundary class:** object-storage bucket isolation and SSRF/allow-list trust boundaries where the *second* input channel (header, request body URL, forwarded header) escapes the validation applied to the *first* one.

## 1. SeaweedFS S3 gateway: `X-Amz-Copy-Source` traversal breaks bucket isolation

The request URL path was hardened against traversal in 4.30 (CVE-2026-54917), but the `X-Amz-Copy-Source` header used by `CopyObject` and `UploadPartCopy` was only checked for emptiness. A `..` segment in the copy source survives into the server-side filer path and resolves into a *different* bucket.

The trust failure is a confused-deputy authorization mismatch:

- IAM evaluates the caller's policy against the bucket named in the **request URL** (the destination, which the caller owns).
- The copy **reads its source** from the `X-Amz-Copy-Source` value, which is not re-canonicalized against the same `IsValidBucketName` / `IsValidObjectKey` guards.

So an identity scoped to a single bucket (`Read` + `Write` on one bucket it controls) can read any object in any bucket on the instance and land the result in its own bucket:

```http
# caller authorized only for bucket-a
CopyObject destination: s3://bucket-a/stolen.txt
X-Amz-Copy-Source: /bucket-a/../victim-bucket/secret-object
```

`UploadPartCopy` (`CopyObjectPartHandler`) is affected by the same vector. All releases prior to **4.34** are affected; 4.34 validates the copy-source bucket and key with the same guards as the request URL.

Recon heuristic: whenever a product ships a traversal fix, enumerate *every* field that reaches the same path-resolution sink, not just the one that was patched, header-based source/destination selectors (`X-Amz-Copy-Source`, `SourceFile`, `From:`, redirect targets, backup/restore source paths) routinely keep the old validation.

## 2. SeaweedFS S3Tables / Iceberg REST: low-privilege S3 creds cross into management API

Requests signed with SigV4 service `s3tables` route to the S3Tables management API. Authorization on that path collapsed account-less S3 identities into the shared `admin` account and failed open, so a user holding only ordinary S3 `Read` credentials, and no S3Tables-specific permission, could invoke S3Tables management operations such as `GET /buckets` and enumerate administrator-owned table-bucket inventory (names and ARNs). The same handler backs the Iceberg REST catalog, affected by the same flaw.

Affected: SeaweedFS `>= 4.08, < 4.34` (S3Tables management API introduced in 4.08). Fixed in **4.34**: administrator status is decided by the `ACTION_ADMIN` capability rather than a collapsed `admin` account id, S3Tables authorization no longer defaults to allow, and the tautological `ListTableBuckets` gate was removed (related hardening in #9962, #9963, #9971).

Recon heuristic: for any object store that adds a management/catalog API (S3Tables, Iceberg REST, GCS, Azure), test whether an **ordinary data-plane credential** can reach management-plane routes. The two failures to look for are (a) an account-id collapse that maps unknown/absent accounts to a shared admin, and (b) authorization that defaults to allow when the capability model has no entry for the service.

## 3. Bifrost: `isPublicIP` SSRF deny-list omits routable internal-embedding ranges

`isPublicIP` in `core/providers/utils/fetch.go`, the deny-list that gates `FetchAndEncodeURL`, classifies several routable ranges as public:

- Carrier-Grade NAT `100.64.0.0/10` (RFC 6598)
- IPv6 6to4 `2002::/16`
- NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`
- deprecated IPv6 site-local `fec0::/10`

An attacker who controls a multimodal image/document URL in a Bedrock or Vertex request body can drive the gateway to fetch internal services it should not reach, including the cloud instance-metadata endpoint via the 6to4 / NAT64 embeddings of `169.254.169.254`. The rest of the fetch hardening is correct and is **not** part of the finding: dial-time `LookupIP` + pin to `ips[0]` closes the DNS-rebinding TOCTOU, `CheckRedirect` re-validates redirect targets, and the scheme gate / 25 MiB cap / 20 s timeout all work. This is purely a residual IP-classification gap. Fixed in Bifrost `1.5.17`.

This is a durable bug-hunting pattern for **AI-gateway SSRF**: any LLM proxy that fetches user-supplied image/document URLs must have its IP-classifier audited for exactly this gap, "public" ranges that actually embed loopback/link-local/metadata addresses through encoding tricks.

## 4. phpSysInfo: `PSI_ALLOWED` allow-list trusts `X-Forwarded-For` before `REMOTE_ADDR`

phpSysInfo's `PSI_ALLOWED` IP allow-list is trivially bypassed by any unauthenticated remote attacker. The access-control check in `read_config.php` derives the client IP from the attacker-controlled `X-Forwarded-For` and `Client-IP` headers **before** falling back to `REMOTE_ADDR`:

```http
X-Forwarded-For: 10.0.0.1   # any configured allowed IP
```

...and the request is treated as coming from the allowed address, defeating the only IP-based access restriction the application provides. Affects all versions up to and including 3.4.x; fixed in 3.4.6.

Recon heuristic: for any product whose only access control is an IP allow-list, send `X-Forwarded-For` / `X-Real-IP` / `Client-IP` / `X-Forwarded-For` combinations with an allowed address. If the allow-list check reads the header before the socket peer address, it is bypassable end-to-end.

## 5. SeaweedFS follow-up: Filer JWT prefix match and unauth filer IAM gRPC (September 4 wave)

Two later SeaweedFS advisories extend the July/August S3-gateway work to the **Filer** (object-directory) identity layer. They belong on this page because they are the same product and the same class: a credential/policy representation that is checked one way at auth time but interpreted another way at the filer, plus a filer service that exposes S3-credential authority without authentication.

- **[GHSA-gv5w-hfx8-8cwq](https://github.com/advisories/GHSA-gv5w-hfx8-8cwq) / CVE-2026-72921, Filer JWT `allowed_prefixes` literal prefix match.** The Filer authorizer matches a credential's `allowed_prefixes` against the requested path using a **literal string-prefix** comparison instead of a bucket/prefix-boundary match. A caller whose JWT authorizes prefix `/bucket-a/` can therefore construct a requested path that string-prefixes the authorized prefix but resolves into a different bucket or outside it (e.g. `/bucket-a-secret/...`). The operator check: for any JWT/prefix-scoped storage authorizer, test the boundary between the *authorized prefix string* and the *actual path namespace*, especially when prefixes are not delimiter-terminated.
- **[GHSA-2v6v-25fm-p4fg](https://github.com/advisories/GHSA-2v6v-25fm-p4fg) / CVE-2026-72920, unauthenticated filer IAM gRPC service grants S3 credentials.** A filer IAM gRPC endpoint issues S3 credentials without requiring authentication, so a network peer can mint credentials for a bucket/prefix it should not hold. The operator check: for any service that *issues* storage credentials, confirm the minting endpoint itself is authenticated and scoped, not just the endpoints that *consume* credentials.

Both are the same durable axis as the copy-source traversal above: **a storage-identity check whose representation (prefix string, gRPC auth gate) is looser than the namespace it is meant to confine.**

## Replayable validation (lab only)

### SeaweedFS copy-source traversal

Preconditions: a lab SeaweedFS S3 gateway (< 4.34), two buckets, and an IAM identity scoped to only `bucket-a`.

1. Seed `bucket-b/secret.txt` with a canary string the caller has no S3 read permission for; confirm a direct `GetObject` on `bucket-b/secret.txt` fails with AccessDenied (negative control).
2. As the `bucket-a`-only identity, issue `CopyObject` with destination `bucket-a/stolen.txt` and `X-Amz-Copy-Source: /bucket-a/../bucket-b/secret.txt`.
3. Positive: `stolen.txt` appears in `bucket-a` and `GetObject` on it returns the canary. The boundary proof is *destination bucket = caller's own, source bucket = other tenant's*. Stop there, do not enumerate other buckets, read credentials, or copy real tenant data.
4. Negative control on 4.34: the same request is rejected with an invalid copy-source error before any filer access.

### SeaweedFS S3Tables management reach

1. Create two identities in a lab SeaweedFS: one with only S3 `Read` on one bucket, one admin.
2. As the low-priv identity, sign a SigV4 request with service `s3tables` for `GET /buckets` against the management endpoint.
3. Positive on < 4.34: 200 with the admin-owned table-bucket inventory. Negative control on 4.34: 403. Do not create/mutate table buckets; inventory enumeration is the bounded proof.

### SeaweedFS Filer JWT prefix-match boundary

1. In a lab Filer, mint two JWTs: one with `allowed_prefixes: ["/bucket-a/"]` and a second scoped to a sibling bucket `/bucket-b/`. Seed one marker object in `bucket-b`.
2. As the `bucket-a/`-only identity, request a path that **string-prefixes** the authorized prefix but resolves outside it, e.g. a path beginning `/bucket-a-secret/` or `bucket-a/../bucket-b/marker` where the filer's matcher is a literal prefix. Record the filer's allow/deny decision and the resolved object.
3. A positive is the filer authorizing a request whose resolved namespace differs from the authorized prefix string. Capture the prefix string, the requested path, and the resolved path side by side. Do not read real tenant objects, one canary marker is the proof.
4. Negative control: the fixed filer build that matches on a delimiter-terminated bucket/prefix boundary.

### SeaweedFS unauth filer IAM gRPC credential minting

1. In a lab Filer, locate the IAM gRPC endpoint that issues S3 credentials.
2. From a plain network peer (no credentials), call the minting RPC for a bucket/prefix and record whether S3 credentials are returned. A positive is credential issuance without authentication.
3. Stop at the credential-issuance decision. Do not use the minted credentials to read or mutate real objects; confirm only that the minting gate is absent and note which buckets the returned identity would authorize.
4. Negative control: the fixed build, which requires authentication/scoping on the minting RPC.

### Bifrost IP-classifier check

1. Run Bifrost < 1.5.17 in a lab with a Bedrock/Vertex provider key pointing at a local mock.
2. Request a fetch through a multimodal URL whose final IP resolves into one of the omitted ranges (use a lab IP in `100.64.0.0/10` or a 6to4-embedded `169.254.169.254`; in cloud scope, the metadata endpoint itself is the canary, request it only if explicitly authorized).
3. Positive: the fetcher dials the internal address and returns the canary content. Record the classifier's decision per range in a table (range → expected → observed). Negative control on 1.5.17: all omitted ranges are rejected.
4. Do not exfiltrate real metadata credentials or internal service responses beyond the canary.

### phpSysInfo header trust

1. Deploy phpSysInfo ≤ 3.4.5 in a lab with `PSI_ALLOWED` set to a private IP you control.
2. Send `GET /` with no forwarding headers → confirm denial (negative control).
3. Send `GET /` with `X-Forwarded-For: <allowed-IP>` → positive if the system-information page is returned.
4. Record which header won (`X-Forwarded-For` vs `Client-IP` vs `REMOTE_ADDR` fallback order). Negative control on 3.4.6. Do not collect more system data than the access decision itself requires.

## Safe boundaries

- Authorized targets or isolated lab deployments only; exact product versions pinned so the negative control is meaningful.
- Two-tenant/bucket setups with the low-privilege identity scoped to exactly one bucket; no enumeration of unrelated tenants, no credential or key reads, no table-bucket mutation.
- SSRF proofs stop at the canary fetch and the classifier decision table; no internal service enumeration, no real metadata credential use.
- IP-allow-list proofs stop at the access decision; no further information gathering from the exposed system-information page.
- All evidence synthetic and redacted; report the exact input channel (header name, SigV4 service tag, allow-list variable) that escaped validation.

## Sources

- [GitHub Advisory Database: SeaweedFS GHSA-56wq-x3wv-3ff4 / CVE-2026-55874](https://github.com/advisories/GHSA-56wq-x3wv-3ff4), S3 gateway `X-Amz-Copy-Source` path traversal
- [GitHub Advisory Database: SeaweedFS GHSA-hgpf-8634-g44c / CVE-2026-55873](https://github.com/advisories/GHSA-hgpf-8634-g44c), S3Tables/Iceberg REST management API authorization collapse
- [GitHub Advisory Database: Bifrost GHSA-w98g-5w9p-p3rc / CVE-2026-55245](https://github.com/advisories/GHSA-w98g-5w9p-p3rc), `isPublicIP` deny-list gap (CGNAT, 6to4, NAT64, site-local)
- [GitHub Advisory Database: phpSysInfo GHSA-786w-p5pm-cvgh / CVE-2026-55584](https://github.com/advisories/GHSA-786w-p5pm-cvgh), `PSI_ALLOWED` allow-list bypass via `X-Forwarded-For` / `Client-IP`
- [GitHub Advisory Database: SeaweedFS GHSA-gv5w-hfx8-8cwq / CVE-2026-72921](https://github.com/advisories/GHSA-gv5w-hfx8-8cwq), Filer JWT `allowed_prefixes` literal prefix-match boundary escape
- [GitHub Advisory Database: SeaweedFS GHSA-2v6v-25fm-p4fg / CVE-2026-72920](https://github.com/advisories/GHSA-2v6v-25fm-p4fg), unauthenticated filer IAM gRPC service grants S3 credentials
