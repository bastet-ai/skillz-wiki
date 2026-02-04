# 2026-02-04 — n8n improper CSP enforcement in webhook responses may allow stored XSS (GHSA-825q-w924-xhgx)

**Product:** **n8n** (npm package: `n8n`)

**Impact (per advisory):** An **authenticated** user who can create/modify workflows may be able to craft webhook/HTTP responses such that intended CSP sandboxing is not applied correctly, enabling **stored XSS** and potential **session hijacking / account takeover** when other users interact with the workflow.

## Recommended actions
- **Patch/upgrade:** upgrade to **n8n 1.122.5** or **1.123.2** (or later).
- **Access control:** treat workflow authoring as a privileged capability; do not allow untrusted users to author workflows.
- **Workflow review:** review workflows that return HTML or handle webhook responses.

## References
- Advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-825q-w924-xhgx>
- GitHub advisory entry: <https://github.com/advisories/GHSA-825q-w924-xhgx>
