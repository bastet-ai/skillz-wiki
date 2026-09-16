# Nuclei template update hygiene

**Signal:** ProjectDiscovery's April 2026 Nuclei Templates release added 226 templates across v10.4.2 and v10.4.3, including 123 CVEs, roughly 10 KEV-listed vulnerabilities, broad AI/LLM exposure coverage, and many false-positive / false-negative fixes.

This is durable because template libraries are security tooling supply chains: stale scanners miss current exploit paths, but noisy scanners train teams to ignore real findings. Treat template updates as controlled detection-content deployments, not passive background data.

## What changed

- **Actively exploited coverage:** new templates for KEV / vKEV items such as cPanel & WHM session-file CRLF auth bypass and Langflow critical RCE/auth-bypass classes.
- **AI and agentic surface:** new checks for Marimo, Flowise, NocoBase, LoLLMs WEBUI, ComfyUI-Manager, Langflow, LiteLLM, LMDeploy, Mesop AI Sandbox, AstrBot, Gradio, AnythingLLM, MCP gateway defaults, Browserless exposure, ChromaDB exposure, and many AI/ML admin panels.
- **Enterprise exposure:** expanded default-login, installer-exposure, unauthenticated-dashboard, blockchain RPC, Perforce, weak-HSTS, macro-policy, schema/API-key, and Supabase Studio coverage.
- **Detection quality:** false positives were reduced for credential disclosure, default logins, subdomain takeover, webpack config, WPS Hide Login, LDAP anonymous login, Sentry panels, and multiple CVE templates; false negatives were fixed for LearnPress blind SQLi and Tomcat default-login lockout ordering.

## Operator guidance

1. **Pin and stage template updates.** Promote template versions through dev/staging before production-wide scans; record the nuclei engine version, template commit/tag, and command flags with each run.
2. **Run high-signal deltas first.** Prioritize KEV/vKEV, exposed admin panels, default logins, installer exposure, AI/LLM tools, Perforce, and unauthenticated dashboards on internet-facing assets.
3. **Treat AI/agent panels as Tier 1 exposure.** Add Flowise, Langflow, OpenHands, AnythingLLM, ChromaDB, Browserless, Gradio, AstrBot, ComfyUI, and MCP gateways to recurring external exposure checks.
4. **Do not run untrusted templates in a privileged environment.** Use a scrubbed environment, no production secrets, read-only target lists, and isolated runners. Avoid `-env-vars` unless you are intentionally testing trusted templates and can tolerate disclosure risk.
5. **Baseline before broad alerting.** Re-run a representative sample after template updates, compare new findings against known inventories, and suppress only with evidence: service owner, version, response proof, and expiration.
6. **Use fixed false-negative notes to revisit old negatives.** Re-scan assets where prior LearnPress blind SQLi, Tomcat default-login, credential disclosure, or default-login templates were relied on for closure.
7. **Version findings in reports.** Include template ID, template version/commit, nuclei engine version, matcher evidence, request/response excerpts, and any local modifications.

## Review checklist

- [ ] Current nuclei engine is at or above the template release's expected compatibility line.
- [ ] Template repository is pinned to a known tag/commit and mirrored internally if used for recurring jobs.
- [ ] Runner environment excludes cloud tokens, CI tokens, SSH keys, kubeconfigs, browser cookies, and `.env` secrets.
- [ ] AI/LLM/admin-panel exposure templates run against all public host inventories.
- [ ] KEV/vKEV templates run with faster SLA than the general template set.
- [ ] New positives are triaged with raw evidence before ticket fan-out.
- [ ] Old suppressions expire after significant template matcher fixes or product-version changes.

## September 16 follow-up: signature-verification cache trusts mtime, not content (CVE-2026-92718)

[GHSA-77rj-h8wx-6cgq](https://github.com/advisories/GHSA-77rj-h8wx-6cgq) / CVE-2026-92718: **Nuclei < 3.11.1 caches template signature verification based on file modification time only — no content checksum.** Replacing a verified template with unsigned malicious content and restoring the original mtime (`touch -r`) passes the signature check, yielding OS command execution on the scanner host when the operator next runs the scan.

Operator impact on template hygiene:

- Signature "verified" status on any runner pinned below 3.11.1 is **not** an integrity signal — anyone with write access to the templates directory (shared runners, forked/mirrored template repos, sync jobs) can persist payloads invisibly.
- Upgrade to ≥ 3.11.1 and additionally hash-pin the template tree yourself (record a manifest hash of the template directory per run and diff it); treat unexpected template-directory write access on a scanner host as host compromise, not config drift.
- This strengthens rule 4 above: scrubbed environments and isolated runners matter *more* when the template set itself can be silently substituted.

Full validation workflow: [Scanner, C2, and SOAR control-plane trust boundaries](../alerts/2026-09-16-nuclei-signature-cache-covenant-hub-token-mint-shuffle-tenant-key-reset-ghsa.md).

## Source

- ProjectDiscovery, "Nuclei Templates - April 2026" (2026-05-12): <https://projectdiscovery.io/blog/nuclei-templates-april-2026>
- GitHub Advisory Database: [GHSA-77rj-h8wx-6cgq / CVE-2026-92718](https://github.com/advisories/GHSA-77rj-h8wx-6cgq) (Nuclei < 3.11.1 signature-cache mtime bypass)

## Related

- [Agent, sandbox, tool, and secret-boundary batch](../alerts/2026-05-11-agent-sandbox-tool-and-secret-boundary-batch-ghsa.md)
- [AI Security Testing Needs Evidence, Bounds, and Audit Trails](ai-security-testing-trust-requirements.md)
- [Verification Before Reporting](verification-before-reporting.md)
