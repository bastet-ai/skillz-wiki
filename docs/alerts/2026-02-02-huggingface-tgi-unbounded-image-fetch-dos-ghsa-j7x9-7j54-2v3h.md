# 2026-02-02 — Hugging Face TGI unbounded image fetch → resource exhaustion (GHSA-j7x9-7j54-2v3h / CVE-2026-0599)

**Summary:** In VLM mode, text-generation-inference (TGI) scans inputs for Markdown image links and performs blocking HTTP GET fetches, reading full responses into memory. This can be abused for **bandwidth + memory + CPU exhaustion** (and can trigger even if the request is later rejected).

- **Component:** `huggingface/text-generation-inference`
- **Impact:** Remote unauthenticated DoS via unbounded external fetch + full-body buffering
- **Fixed:** **3.3.7**
- **Severity:** High (per advisory)

## Durable lesson
**Never perform unbounded external fetches during input validation**.

If you must dereference user-provided URLs:
- Require auth first
- Enforce strict allowlists (schemes/hosts)
- Apply timeouts and size limits
- Stream data (don’t buffer entire bodies)
- Use egress controls (firewall/proxy), and rate limits

## Defensive actions
1. **Upgrade** to **3.3.7+**.
2. If exposing TGI to a network:
   - Put it behind authentication.
   - Add resource limits (cgroups / k8s requests+limits).
   - Restrict outbound egress.

## References
- GitHub Advisory: https://github.com/advisories/GHSA-j7x9-7j54-2v3h
- CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-0599
