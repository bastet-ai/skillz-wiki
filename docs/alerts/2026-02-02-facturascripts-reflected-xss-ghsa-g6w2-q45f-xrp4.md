# 2026-02-02 — FacturaScripts reflected XSS via raw error rendering (GHSA-g6w2-q45f-xrp4)

## Summary

GitHub published an advisory describing a **reflected XSS** in FacturaScripts caused by rendering database error messages without escaping.

- Advisory: https://github.com/advisories/GHSA-g6w2-q45f-xrp4
- Root issue (per advisory): Twig templates render messages with `| raw`, allowing attacker-controlled content inside SQL error messages to execute as HTML/JS.
- Impact (per advisory): credential phishing, data access, CSRF token theft from DOM, and other actions as the victim user.

## What to do (durable guidance)

### Immediate actions

- Patch/upgrade to a fixed release when available.
- As an emergency mitigation (per advisory): remove `| raw` from message rendering so Twig escapes by default.

### Defense-in-depth

- Add a **Content Security Policy (CSP)** to reduce the impact of any XSS that slips through.
- Validate/normalize parameters before they reach the database layer (reduce error-message reflection).
- Don’t show raw SQL error messages to end users in production.

## Related Wisdom

- [XSS payloads](../payloads/xss.md)
