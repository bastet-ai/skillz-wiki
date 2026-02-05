# 2026-02-05 — Spree guest orders viewable by Order ID (IDOR / CWE-639) (GHSA-p6pv-q7rc-g4h9)

GitHub published an advisory describing an authorization bug where **completed guest orders** can be viewed by **order number alone**, without requiring an order token.

- Advisory: <https://github.com/advisories/GHSA-p6pv-q7rc-g4h9>

## Impact

- **PII disclosure** (names, addresses, phone numbers, limited payment info) for guest checkouts.

## Affected versions

Per advisory:

- `< 5.0.8`
- `>= 5.1.0, < 5.1.10`
- `>= 5.2.0, < 5.2.7`
- `>= 5.3.0, < 5.3.2`

## What to do (durable guidance)

This is a classic **IDOR** shape: using an object identifier as authorization.

### Fix / mitigate

- Upgrade to a patched version:
  - `5.0.8`, `5.1.10`, `5.2.7`, `5.3.2` (per advisory)
- Ensure “guest access” requires a **separate unguessable capability token**.
- Add rate limits + detection on order lookups.

### Detection / hunt

- Look for repeated requests to `/orders/<id>` with:
  - no session
  - no order token
  - many distinct order IDs
- Review logs for abnormal access to completed orders.

## References

- <https://github.com/advisories/GHSA-p6pv-q7rc-g4h9>
- Spree security advisory: <https://github.com/spree/spree/security/advisories/GHSA-p6pv-q7rc-g4h9>
