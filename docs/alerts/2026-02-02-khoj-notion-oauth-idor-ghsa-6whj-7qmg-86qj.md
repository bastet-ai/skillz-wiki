# 2026-02-02 — Khoj Notion OAuth callback IDOR / state confusion (GHSA-6whj-7qmg-86qj)

## Summary

GitHub published an advisory describing an **IDOR / OAuth state parameter confusion** in Khoj’s Notion OAuth callback.

- Advisory: https://github.com/advisories/GHSA-6whj-7qmg-86qj
- Root issue (per advisory): the callback trusts an attacker-controlled `state` parameter as a user UUID and does not verify the OAuth flow was initiated by that user.
- Impact (per advisory): attacker can overwrite a victim’s Notion integration configuration (leading to index poisoning and potentially unauthorized access, depending on how synced content is used).

## What to do (durable guidance)

### Immediate actions (operators)

- Patch/upgrade Khoj to a fixed version when available.
- If you operate multi-tenant or shared instances:
  - Assume `state` must be untrusted and **audit other OAuth callbacks** for similar patterns.

### How to fix (developers)

1. **Use a real OAuth state value**:
   - Generate a cryptographically-random nonce per auth attempt.
   - Store it server-side (or sign/encrypt it) and bind it to the initiating session/user.
2. **Validate on callback**:
   - Only accept callbacks whose `state` matches the stored nonce for that same user/session.
3. **Avoid leaking stable user identifiers**:
   - Don’t embed user UUIDs in shareable URLs or file paths.
   - Prefer short-lived share tokens or opaque identifiers.

### Post-incident guidance

If you suspect abuse:
- Revoke/rotate Notion OAuth tokens for affected users.
- Review audit logs for unexpected Notion sync events.

## Related Wisdom

- [OAuth token theft](../methodology/oauth-token-theft.md)
- [OAuth misconfigs (MCP/Agents)](../methodology/oauth-mcp-misconfig.md)
