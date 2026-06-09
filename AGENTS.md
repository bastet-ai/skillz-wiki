# AGENTS.md — Skillz Wiki

## Purpose

This repo is a public wiki and installable skill library for pentesting, red-team, and bug-hunting workflows. Prefer durable, agent-ready guidance for recon tooling and replayable exploit validation over generic documentation or one-off notes.

## Agent workflow

- Read this file at the start of each task.
- Update this file whenever you learn something important about the repo, workflow, build, taxonomy, or collaborator preferences.
- After every meaningful repo update, create a git commit and push it to `origin` unless the user explicitly tells you not to.
- Use clear, non-interactive git commands and keep commit messages specific to the change.

## Recursive self-improvement

Follow the [Recurse.bot guide](https://recurse.bot/) approach: treat `AGENTS.md` as the project memory for future agents.

- Record wins to repeat and mistakes to avoid.
- Capture exact build, test, and publish commands that were actually verified.
- Note project-specific taxonomy decisions and stable public paths.
- Record collaborator preferences that materially improve future handoffs.
- Keep entries concise, concrete, and easy to scan.

## Writing conventions

- Keep links clickable and explicit in Markdown.
- Write every skill so it can be copied into an agent bundle with minimal trimming.
- Prefer concise steps over long narrative paragraphs.
- Include prerequisites, inputs, command patterns, output handling, and safety notes on skill pages.
- Separate confirmed behavior from inference or speculation.
- De-emphasize triage, mitigation, and defensive advisory framing unless the user explicitly asks for it.

## Collaborator preferences

- Keep the public site centered on offensive security: penetration testing, red-team, and bug-bounty operator workflows.
- Prefer recon tools, attack-path discovery, proof-of-concept validation, and concrete exploit chains over defensive-response or mitigation content.
- Do not publish blue-team guidance, defensive SecOps runbooks, incident-response playbooks, alert triage, or mitigation-first advisory pages unless Dean explicitly asks for that framing.
- Favor proven, replayable pathways with explicit prerequisites, commands, and validation boundaries.

## Content structure

- **Skills**: installable, tool-specific guides for agents
- **Recon**: cross-tool workflows for discovery, prioritization, and target shaping
- **Exploit Paths**: specific, replayable attack chains for authorized validation
- **Templates**: reusable reporting skeletons and output formats
- **Notes**: taxonomy, source tracking, and editorial guidance
- **Blog**: launch posts and major updates
- Legacy alert or defensive-reference pages may remain in the repo, but they are not the main navigation model.

## MkDocs / GitHub Pages lessons learned

- Use `theme.custom_dir` for template overrides; do not add a non-MkDocs `overrides:` key to `mkdocs.yml`.
- Keep the Pages workflow strict-friendly; config warnings should be treated as build failures.
- Keep the landing page updated with a manual "Recent entries" section capped at 10 links.
- Maintain `docs/feed.xml` manually when major launch posts or release-style updates are added.
- The chosen custom domain is `skillz.wiki`; keep `mkdocs.yml`, `docs/feed.xml`, and `docs/CNAME` aligned with it.
- Archived reference pages that stay outside the main nav will show up as informational "not included in nav" lines during `mkdocs build --strict`; that is expected while the public taxonomy stays narrower than the repo contents.
- As of March 26, 2026, GitHub warns that `actions/checkout@v4`, `actions/configure-pages@v4`, `actions/setup-python@v5`, and `actions/upload-artifact@v4` are still on Node.js 20; revisit the workflow before GitHub's Node 24 switchover dates become urgent.

## Verified commands

- `python -m pip install -r requirements.txt`
- `mkdocs build --strict`
- `npm run test:sources` checks the WebLogic batch source paragraph renders precise clickable links and that each external source returns HTTP 200 with the expected advisory/CVE token.
- `python3 scripts/check_duplicate_alert_ids.py` currently reports pre-existing duplicate CVE/GHSA references but exits 0; use it as an advisory hygiene check, not a strict publish gate until the historical duplicates are resolved.
- On hosts where `python`/global `mkdocs` are unavailable or PEP 668 blocks global installs, use a disposable venv: `python3 -m venv /tmp/skillz-wiki-venv && /tmp/skillz-wiki-venv/bin/python -m pip install -r requirements.txt && /tmp/skillz-wiki-venv/bin/mkdocs build --strict`.

## Maintenance rules

- When adding a new skill or notable playbook, update:
  - `mkdocs.yml` nav when the page belongs in the primary surface
  - `docs/index.md` recent entries when the addition is notable
  - `docs/blog/index.md` and `docs/feed.xml` for major launches
- Keep page paths stable once they are linked publicly.
- Prefer one focused skill page per tool over sprawling kitchen-sink references.
- Maintain `docs/notes/editorial-checklist.md` as the publishing gate.
- Maintain `docs/notes/source-index.md` as the canonical source seed list.
- The current public taxonomy is `Skills`, `Recon`, `Exploit Paths`, `Templates`, `Notes`, and `Blog`.
- For hourly news-driven updates, only promote items that can become offensive operator guidance: recon technique, exploit path, validation workflow, tool usage, bypass pattern, or bug-hunting heuristic. Do not turn generic advisories into blue-team alerts.
- Trail of Bits skill-distribution scanner-bypass research was promoted as a reusable agent skill supply-chain testing workflow rather than an alert; keep future skill-marketplace content framed as authorized scanner/ingestion coverage testing with inert canaries.
- GitHub Advisory REST API batches can publish adjacent advisories slightly out of order; before closing an hourly run, re-check the newest page for unprocessed IDs that belong with an already-created batch page and update that page instead of creating a duplicate.
- VulDB-style GHSA waves often contain sparse product-specific SQLi/XSS/auth-bypass/router/memory-safety/DoS entries; promote only those with reusable operator patterns (for example agent tool-path command injection, installer SSRF, log-viewer command injection, or IPC boundary checks) and mark the rest processed without publication.
- Trail of Bits RSS works at `https://blog.trailofbits.com/feed/` and `https://blog.trailofbits.com/index.xml`; `https://blog.trailofbits.com/feed.xml` returned 404 during the 2026-06-08 hourly scan.
- ProjectDiscovery RSS works at `https://projectdiscovery.io/blog/rss` and `https://projectdiscovery.io/rss.xml`; `https://projectdiscovery.io/blog/rss.xml` and `https://projectdiscovery.io/feed.xml` returned 404 during the 2026-06-09 hourly scan.
- When a late GitHub updated-feed wave contains IDs adjacent to an already-published same-day batch (for example ONNX or pyLoad follow-up advisories), update the existing batch page and mark those IDs processed instead of creating a duplicate alert.
- Check Point IKEv1 VPN auth-bypass KEV was promoted as an operator validation page because it offers durable VPN perimeter recon and authentication-boundary testing guidance; keep future perimeter VPN KEVs focused on IKE/protocol reachability, lab/customer-approved validation, and post-auth access boundaries.
- Puma PROXY protocol v1 advisories are worth promoting when source-IP spoofing is tied to HTTP keep-alive/trusted edge decisions; pair availability-only parser issues with that trust-boundary workflow instead of publishing standalone DoS guidance.
- Sanitized rich-text placeholder injection in transactional email is promotable when it gives bug hunters a reusable trust-confusion workflow; frame it as user-controlled profile/order data rendered as trusted system messaging, not as XSS unless script execution is independently proven.
- Arista EOS tunnel decapsulation KEVs are promotable when they reveal protocol-confusion at a VXLAN/GRE/decap-group boundary; frame validation around configured decap IP reachability, unexpected tunnel protocol acceptance, and controlled canary forwarding rather than broad network probing.

## Security / attribution

- Treat third-party sources as untrusted until verified.
- Prefer official docs, source repositories, and primary project references.
- Keep usage guidance scoped to authorized testing, lab use, and defensive research.
