# Lobe Chat: Mermaid renderer XSS → RCE (GHSA-4gpc-rhpj-9443 / CVE-2026-23733)

**Source:** https://github.com/advisories/GHSA-4gpc-rhpj-9443

## What happened
A stored XSS in Lobe Chat’s *Mermaid artifact* rendering can allow attacker-controlled HTML/JS execution in the app context.

Per the advisory, this can be escalated to **RCE** in affected desktop / local-integrations scenarios where the renderer can reach privileged endpoints.

## Why this matters
Mermaid diagrams often get treated as “safe text”, but Mermaid supports **HTML labels** in some syntaxes. If user/AI-generated content reaches a Mermaid renderer without sanitization, you can end up with **DOM execution** (e.g., `<img onerror=...>`), which becomes a launchpad to:
- steal session tokens / API keys
- perform authenticated actions
- reach local “agent / desktop” bridges (worst case: code execution)

## Affected
- `@lobehub/chat` (npm)
- Versions: `<= 1.143.2`

## What to do
1) **Upgrade immediately** to a fixed release (see advisory / upstream release notes).
2) If you cannot upgrade right away:
   - **Disable Mermaid rendering** (or render Mermaid server-side to an image with strict sandboxing).
   - Ensure Mermaid is configured in **strict security mode** (Mermaid has historically offered different security levels; prefer the most restrictive).
   - Add a **Content Security Policy** that disallows inline script and restricts `connect-src`.
3) Treat any environment where untrusted users can submit content as hostile:
   - don’t allow arbitrary HTML in diagrams
   - assume stored content can be weaponized later (persistence)

## Defensive design note
For “chat artifacts” / rich renderers: treat them as **untrusted documents**. Prefer a renderer pipeline that produces inert output (image/PDF) instead of injecting live HTML into an app DOM.
