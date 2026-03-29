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

- Keep the public site centered on pentesting, red-team, and bug-bounty operator workflows.
- Prefer recon tools and concrete exploit chains over defensive-response or mitigation content.
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
- Keep the landing page updated with a manual "Recent entries" section.
- Maintain `docs/feed.xml` manually when major launch posts or release-style updates are added.
- The chosen custom domain is `skillz.wiki`; keep `mkdocs.yml`, `docs/feed.xml`, and `docs/CNAME` aligned with it.
- Archived reference pages that stay outside the main nav will show up as informational "not included in nav" lines during `mkdocs build --strict`; that is expected while the public taxonomy stays narrower than the repo contents.
- As of March 26, 2026, GitHub warns that `actions/checkout@v4`, `actions/configure-pages@v4`, `actions/setup-python@v5`, and `actions/upload-artifact@v4` are still on Node.js 20; revisit the workflow before GitHub's Node 24 switchover dates become urgent.

## Verified commands

- `python -m pip install -r requirements.txt`
- `mkdocs build --strict`

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
- For hourly news-driven updates, prefer short durable best-practice pages over alerts when the lesson generalizes beyond one advisory.

## Security / attribution

- Treat third-party sources as untrusted until verified.
- Prefer official docs, source repositories, and primary project references.
- Keep usage guidance scoped to authorized testing, lab use, and defensive research.
