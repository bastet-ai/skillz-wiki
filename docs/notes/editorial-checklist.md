# Editorial checklist

Use this before publishing a new skill or major update.

## Basics

- [ ] Title is short and specific. **Display title (the `# ` H1) and nav titles: max 100 characters, NO em-dashes or en-dashes (Dean requests 2026-10-09 and 2026-11-10; hard-gated by `python3 scripts/audit_titles.py --check`, wired into `scripts/build.sh` so violations fail the deploy build).** Shape: `<Product> wave (<N> GHSAs): <one short clause naming the single most interesting boundary>`. The page's multi-clause thesis belongs in the Signal/lead paragraph, not the headline; if everything must stay visible, add it verbatim under the H1 as a `**Wave in one line:**` sub-line. Titles feed nav, feeds, and mobile headers. File names/slug stay descriptive (stable public paths beat short filenames).
- [ ] Links are clickable Markdown links
- [ ] Commands are reproducible and minimally scoped
- [ ] Page is in the right section
- [ ] Safety, scope, and authorization limits are stated

## Content fit

- [ ] Page is primarily useful to authorized penetration testers, red-teamers, or bug hunters
- [ ] Offensive workflow, recon value, exploit validation, or reporting value is explicit
- [ ] Blue-team/SecOps material is omitted or reframed as operator context only
- [ ] Mitigation or incident-response guidance is not the main purpose unless explicitly requested

## Operator quality

- [ ] Tool trigger conditions or exploit preconditions are clear
- [ ] Required inputs, prerequisites, and environment assumptions are listed
- [ ] Output handling and evidence capture are explained
- [ ] Replay steps are specific enough to run again later
- [ ] Claims match observed behavior and label any inference

## Maintenance

- [ ] `mkdocs.yml` nav is updated when the page is first-class content
- [ ] `docs/index.md` recent entries are updated if the addition is notable. Title-only lines: bold core title plus link, capped at 10, no summaries, fold lists, ids, or KEV status on the landing page (Dean request, 2026-10-01; write-ups live on their own pages, scan narratives in `source-index.md`). The title states the FINDING a pentester cares about (product + boundary + impact in plain language), NOT the scanning process: no "NN:xxZ scan", no "1 new page + N folds", no feed-head/KEV/baseline tracking (Dean request, 2026-11-10).
- [ ] `docs/feed.xml` and blog index are updated for major launches or major repositioning posts
- [ ] `docs/notes/source-index.md` is extended if a new tool family is added
- [ ] Alert, mitigation-heavy, incident-response, or defensive-SecOps pages are not promoted in nav unless the user explicitly wants that framing
